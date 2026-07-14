#!/usr/bin/env bash
#
# Commit and publish an already tested FortyTwoBBS source state.
#
# Usage:
#   ./fortytwo-auth/scripts/publish_checked.sh "Commit message"
#
# This script deliberately does not run the normal or sanitizer test suites.
# Run those before invoking this publication step.

set -Eeuo pipefail

readonly EXPECTED_REPOSITORY_DIR="mbsebbs-sanitize"
readonly REQUIRED_BRANCH="main"
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

[[ "$current_branch" == "$REQUIRED_BRANCH" ]] ||
    die "Erwarteter Zweig '$REQUIRED_BRANCH', gefunden: '${current_branch:-detached HEAD}'"

git -C "$repository_root" remote get-url "$REQUIRED_REMOTE" >/dev/null 2>&1 ||
    die "Der Remote '$REQUIRED_REMOTE' ist nicht eingerichtet."

readonly remote_url=$(
    git -C "$repository_root" remote get-url "$REQUIRED_REMOTE"
)

notice "Quellordner"
printf '%s\n' "$repository_root"

notice "Ziel"
printf '%s %s (%s)\n' "$REQUIRED_REMOTE" "$REQUIRED_BRANCH" "$remote_url"

readonly migration_verifier="$repository_root/fortytwo-auth/migrations/verify_migrations.sh"

[[ -x "$migration_verifier" ]] ||
    die "Migrationsprüfung fehlt oder ist nicht ausführbar: $migration_verifier"

notice "Migrationshistorie prüfen"
"$migration_verifier"

notice "Remote-Stand abrufen"
git -C "$repository_root" fetch --quiet "$REQUIRED_REMOTE" "$REQUIRED_BRANCH"

git -C "$repository_root" show-ref --verify --quiet \
    "refs/remotes/$REQUIRED_REMOTE/$REQUIRED_BRANCH" ||
    die "Remote-Zweig $REQUIRED_REMOTE/$REQUIRED_BRANCH wurde nicht gefunden."

read -r remote_ahead local_ahead < <(
    git -C "$repository_root" rev-list --left-right --count \
        "$REQUIRED_REMOTE/$REQUIRED_BRANCH...HEAD"
)

if (( remote_ahead != 0 || local_ahead != 0 )); then
    die "Vor dem Commit müssen HEAD und $REQUIRED_REMOTE/$REQUIRED_BRANCH synchron sein (remote voraus: $remote_ahead, lokal voraus: $local_ahead)."
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

notice "Zu github/main übertragen"
git -C "$repository_root" push "$REQUIRED_REMOTE" \
    "HEAD:refs/heads/$REQUIRED_BRANCH"

notice "Ergebnis kontrollieren"
git -C "$repository_root" fetch --quiet "$REQUIRED_REMOTE" "$REQUIRED_BRANCH"

readonly local_commit=$(
    git -C "$repository_root" rev-parse HEAD
)

readonly remote_commit=$(
    git -C "$repository_root" rev-parse \
        "$REQUIRED_REMOTE/$REQUIRED_BRANCH"
)

[[ "$local_commit" == "$remote_commit" ]] ||
    die "HEAD und $REQUIRED_REMOTE/$REQUIRED_BRANCH sind nach dem Push nicht identisch."

if [[ -n "$(git -C "$repository_root" status --porcelain=v1)" ]]; then
    git -C "$repository_root" status --short >&2
    die "Der Quellordner ist nach dem Push nicht sauber."
fi

notice "Veröffentlichung abgeschlossen"
git -C "$repository_root" log -1 --oneline
git -C "$repository_root" status --short --branch
