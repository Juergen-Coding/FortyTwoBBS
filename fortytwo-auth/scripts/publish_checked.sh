#!/usr/bin/env bash
#
# Commit and push an already tested FortyTwo BBS working branch.
#
# Usage:
#   ./fortytwo-auth/scripts/publish_checked.sh "Commit message"
#
# This script deliberately does not run the normal or sanitizer test suites.
# Run those before invoking this publication step.
#
# The script never pushes directly to main and never merges a pull request.

set -Eeuo pipefail

readonly EXPECTED_REPOSITORY_DIR="mbsebbs-sanitize"
readonly FORBIDDEN_BRANCH="main"
readonly REQUIRED_REMOTE="github"

on_error()
{
    local exit_code=$?
    printf '\nFEHLER in Zeile %d: %s\n' "${BASH_LINENO[0]:-${LINENO}}" \
        "${BASH_COMMAND}" >&2
    exit "${exit_code}"
}

trap on_error ERR

die()
{
    printf 'FEHLER: %s\n' "$*" >&2
    exit 1
}

notice()
{
    printf '\n==> %s\n' "$*"
}

require_command()
{
    command -v "$1" >/dev/null 2>&1 ||
        die "Benötigter Befehl nicht gefunden: $1"
}

if (( $# != 1 )); then
    die "Aufruf: $0 \"Commit-Nachricht\""
fi

readonly commit_message=$1

[[ -n "${commit_message//[[:space:]]/}" ]] ||
    die "Die Commit-Nachricht darf nicht leer sein."

[[ "$commit_message" != *$'\n'* ]] ||
    die "Die Commit-Nachricht darf keinen Zeilenumbruch enthalten."

require_command git
require_command bash
require_command realpath

readonly script_dir=$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
    pwd -P
)

readonly repository_root=$(
    git -C "$script_dir" rev-parse --show-toplevel
)

readonly repository_name=$(
    basename -- "$repository_root"
)

[[ "$repository_name" == "$EXPECTED_REPOSITORY_DIR" ]] ||
    die "Falscher Quellordner: $repository_root"

readonly git_dir=$(
    git -C "$repository_root" rev-parse --absolute-git-dir
)

[[ -d "$git_dir" ]] ||
    die "Kein gültiger Git-Ordner: $git_dir"

readonly current_branch=$(
    git -C "$repository_root" branch --show-current
)

[[ -n "$current_branch" ]] ||
    die "Detached HEAD ist für die Veröffentlichung eines Arbeitsbranches nicht zulässig."

[[ "$current_branch" != "$FORBIDDEN_BRANCH" ]] ||
    die "Direkte Commits und Pushes auf '$FORBIDDEN_BRANCH' sind verboten. Verwende einen Arbeitsbranch und anschließend einen Pull Request."

git -C "$repository_root" remote get-url "$REQUIRED_REMOTE" >/dev/null 2>&1 ||
    die "Der Remote '$REQUIRED_REMOTE' ist nicht eingerichtet."

readonly remote_url=$(
    git -C "$repository_root" remote get-url "$REQUIRED_REMOTE"
)

notice "Quellordner"
printf '%s\n' "$repository_root"

notice "Ziel"
printf '%s %s (%s)\n' "$REQUIRED_REMOTE" "$current_branch" "$remote_url"
printf 'Merge-Ziel: main – ausschließlich über Pull Request\n'

readonly architecture_verifier="$repository_root/scripts/check_architecture_state.py"
readonly migration_verifier="$repository_root/fortytwo-auth/migrations/verify_migrations.sh"

[[ -x "$architecture_verifier" ]] ||
    die "Architekturprüfung fehlt oder ist nicht ausführbar: $architecture_verifier"

[[ -x "$migration_verifier" ]] ||
    die "Migrationsprüfung fehlt oder ist nicht ausführbar: $migration_verifier"

notice "Architekturstand prüfen"
"$architecture_verifier"

notice "Migrationshistorie prüfen"
"$migration_verifier"

notice "Remote-Stand abrufen"
git -C "$repository_root" fetch --quiet "$REQUIRED_REMOTE"

readonly remote_tracking_ref="refs/remotes/$REQUIRED_REMOTE/$current_branch"

if git -C "$repository_root" show-ref --verify --quiet "$remote_tracking_ref"; then
    git -C "$repository_root" merge-base --is-ancestor \
        "$REQUIRED_REMOTE/$current_branch" HEAD ||
        die "Der Remote-Arbeitsbranch $REQUIRED_REMOTE/$current_branch enthält Commits, die lokal fehlen. Vor dem Veröffentlichen zuerst integrieren."
fi

notice "Nicht vorgemerkte Änderungen prüfen"

if ! git -C "$repository_root" diff --quiet --; then
    git -C "$repository_root" status --short >&2
    die "Es gibt nicht vorgemerkte Änderungen."
fi

mapfile -t untracked_files < <(
    git -C "$repository_root" ls-files --others --exclude-standard
)

if (( ${#untracked_files[@]} != 0 )); then
    printf 'Unbekannte Dateien:\n' >&2
    printf '  %s\n' "${untracked_files[@]}" >&2
    die "Unbekannte Dateien müssen geprüft und hinzugefügt oder ignoriert werden."
fi

git -C "$repository_root" diff --quiet --cached -- &&
    die "Es sind keine Änderungen für den Commit vorgemerkt."

notice "Vorgemerkten Stand prüfen"
git -C "$repository_root" diff --cached --check
git -C "$repository_root" diff --cached --stat

notice "Commit erstellen"
git -C "$repository_root" commit -m "$commit_message"

notice "Arbeitsbranch zu GitHub übertragen"
git -C "$repository_root" push --set-upstream "$REQUIRED_REMOTE" \
    "HEAD:refs/heads/$current_branch"

notice "Ergebnis kontrollieren"
git -C "$repository_root" fetch --quiet "$REQUIRED_REMOTE" "$current_branch"

readonly local_commit=$(
    git -C "$repository_root" rev-parse HEAD
)

readonly remote_commit=$(
    git -C "$repository_root" rev-parse \
        "$REQUIRED_REMOTE/$current_branch"
)

[[ "$local_commit" == "$remote_commit" ]] ||
    die "HEAD und $REQUIRED_REMOTE/$current_branch sind nach dem Push nicht identisch."

if [[ -n "$(git -C "$repository_root" status --porcelain=v1)" ]]; then
    git -C "$repository_root" status --short >&2
    die "Der Quellordner ist nach dem Push nicht sauber."
fi

notice "Arbeitsbranch veröffentlicht"
git -C "$repository_root" log -1 --oneline
git -C "$repository_root" status --short --branch

notice "Nächster verbindlicher Schritt"
printf 'Pull Request von %s nach main öffnen. Kein direkter Push und kein lokaler Merge nach main.\n' \
    "$current_branch"
