#!/usr/bin/env bash
#
# Verify the B5.1.8 Branch/PR governance fixes without changing project files
# and without contacting GitHub.
#

set -Eeuo pipefail

readonly DEFAULT_REPOSITORY="$HOME/projects/mbse-review/mbsebbs-sanitize"

repository_root=${1:-$DEFAULT_REPOSITORY}
publish_script="$repository_root/fortytwo-auth/scripts/publish_checked.sh"
architecture_checker="$repository_root/scripts/check_architecture_state.py"

passes=0
failures=0
temporary_root=""

cleanup()
{
    if [[ -n "$temporary_root" && -d "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
    fi
}

trap cleanup EXIT

pass()
{
    passes=$((passes + 1))
    printf '  [OK]   %s\n' "$1"
}

fail()
{
    failures=$((failures + 1))
    printf '  [FAIL] %s\n' "$1" >&2
}

section()
{
    printf '\n%s\n' "$1"
    printf '%s\n' "$2"
}

require_command()
{
    command -v "$1" >/dev/null 2>&1 || {
        printf 'FEHLER: Benötigter Befehl fehlt: %s\n' "$1" >&2
        exit 2
    }
}

for command_name in bash cat chmod cp grep mkdir mktemp python3 rm; do
    require_command "$command_name"
done

[[ -f "$publish_script" ]] || {
    printf 'FEHLER: Datei fehlt: %s\n' "$publish_script" >&2
    exit 2
}

[[ -f "$architecture_checker" ]] || {
    printf 'FEHLER: Datei fehlt: %s\n' "$architecture_checker" >&2
    exit 2
}

printf 'B5.1.8 Governance-Verifikation\n'
printf '%s\n' '==============================='
printf 'Repository: %s\n\n' "$repository_root"
printf '%s\n' \
    'Die Prüfung verändert keine Projektdateien und führt keinen echten Push aus.'

section "1. Syntax" "---------"

if bash -n "$publish_script"; then
    pass "publish_checked.sh: Bash-Syntax gültig"
else
    fail "publish_checked.sh: Bash-Syntax fehlerhaft"
fi

if python3 - "$architecture_checker" <<'PYTHON_CHECK'
from pathlib import Path
import ast
import sys

path = Path(sys.argv[1])
ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
PYTHON_CHECK
then
    pass "check_architecture_state.py: Python-Syntax gültig"
else
    fail "check_architecture_state.py: Python-Syntax fehlerhaft"
fi

section "2. Branch/PR-Regeln" "------------------"

if grep -Fq 'readonly FORBIDDEN_BRANCH="main"' "$publish_script"; then
    pass "main ist ausdrücklich verboten"
else
    fail 'FORBIDDEN_BRANCH="main" fehlt'
fi

if ! grep -Fq 'REQUIRED_BRANCH' "$publish_script"; then
    pass "alte main-only-Logik REQUIRED_BRANCH entfernt"
else
    fail "REQUIRED_BRANCH ist noch vorhanden"
fi

if grep -Fq \
    '[[ "$current_branch" != "$FORBIDDEN_BRANCH" ]]' \
    "$publish_script"; then
    pass "main wird anhand des aktuellen Branches verweigert"
else
    fail "explizite main-Verweigerung fehlt"
fi

if grep -Fq \
    'HEAD:refs/heads/$current_branch' \
    "$publish_script"; then
    pass "Push-Ziel ist der aktuelle Arbeitsbranch"
else
    fail "Push auf aktuellen Arbeitsbranch fehlt"
fi

if ! grep -Eq \
    'HEAD:refs/heads/main|HEAD:refs/heads/\$REQUIRED_BRANCH' \
    "$publish_script"; then
    pass "kein direkter Push-Pfad nach main vorhanden"
else
    fail "direkter Push-Pfad nach main noch vorhanden"
fi

if grep -Fq \
    'Pull Request von %s nach main öffnen.' \
    "$publish_script"; then
    pass "PR nach main wird als nächster Schritt verlangt"
else
    fail "PR-Hinweis fehlt"
fi

section \
    "3. Bedeutung der Pfadklassifikation" \
    "----------------------------------"

if ! grep -Fq \
    'Decision: allowed by the known-path policy' \
    "$architecture_checker"; then
    pass "known path wird nicht als inhaltliche Freigabe bezeichnet"
else
    fail \
        'missverständliche Ausgabe "allowed by the known-path policy" vorhanden'
fi

if grep -Fq \
    'no content-safety approval implied' \
    "$architecture_checker"; then
    pass "Klassifikation ist ausdrücklich keine Inhaltsfreigabe"
else
    fail "Klarstellung zur reinen Pfadklassifikation fehlt"
fi

section "4. Isolierter Verhaltenstest" "---------------------------"

temporary_root=$(mktemp -d)
mock_repository="$temporary_root/mbsebbs-sanitize"
mock_bin="$temporary_root/bin"
mock_log="$temporary_root/git.log"

mkdir -p \
    "$mock_repository/.git" \
    "$mock_repository/fortytwo-auth/scripts" \
    "$mock_repository/fortytwo-auth/migrations" \
    "$mock_repository/scripts" \
    "$mock_bin"

cp "$publish_script" \
    "$mock_repository/fortytwo-auth/scripts/publish_checked.sh"

chmod +x \
    "$mock_repository/fortytwo-auth/scripts/publish_checked.sh"

cat > "$mock_repository/scripts/check_architecture_state.py" <<'EOF_CHECK'
#!/usr/bin/env bash
printf 'mock architecture check: OK\n'
EOF_CHECK

chmod +x "$mock_repository/scripts/check_architecture_state.py"

cat > \
    "$mock_repository/fortytwo-auth/migrations/verify_migrations.sh" \
    <<'EOF_MIGRATIONS'
#!/usr/bin/env bash
printf 'mock migration check: OK\n'
EOF_MIGRATIONS

chmod +x \
    "$mock_repository/fortytwo-auth/migrations/verify_migrations.sh"

cat > "$mock_bin/git" <<'EOF_GIT'
#!/usr/bin/env bash

set -u

if [[ ${1:-} == "-C" ]]; then
    shift 2
fi

command_name=${1:-}
shift || true

printf '%s' "$command_name" >> "$MOCK_GIT_LOG"

for argument in "$@"; do
    printf ' %s' "$argument" >> "$MOCK_GIT_LOG"
done

printf '\n' >> "$MOCK_GIT_LOG"

case "$command_name" in
    rev-parse)
        case "$*" in
            "--show-toplevel")
                printf '%s\n' "$MOCK_REPOSITORY"
                ;;
            "--absolute-git-dir")
                printf '%s/.git\n' "$MOCK_REPOSITORY"
                ;;
            "HEAD"|github/*)
                printf '%s\n' \
                    1111111111111111111111111111111111111111
                ;;
            *)
                printf '%s\n' \
                    1111111111111111111111111111111111111111
                ;;
        esac
        ;;

    branch)
        if [[ $* == "--show-current" ]]; then
            printf '%s\n' "$MOCK_BRANCH"
        fi
        ;;

    remote)
        if [[ ${1:-} == "get-url" ]]; then
            printf '%s\n' \
                'https://github.example/FortyTwoBBS.git'
        fi
        ;;

    fetch)
        exit 0
        ;;

    show-ref)
        # Simuliert einen noch nicht vorhandenen Remote-Arbeitsbranch.
        exit 1
        ;;

    merge-base)
        exit 0
        ;;

    diff)
        case "$*" in
            "--quiet --")
                # Keine nicht vorgemerkten Änderungen.
                exit 0
                ;;
            "--quiet --cached --")
                # Vorgemerkte Änderungen sind vorhanden.
                exit 1
                ;;
            "--cached --check")
                exit 0
                ;;
            "--cached --stat")
                printf '%s\n' ' 1 file changed, 1 insertion(+)'
                ;;
        esac
        ;;

    ls-files)
        # Keine unversionierten Dateien.
        exit 0
        ;;

    commit)
        printf '%s\n' '[mock 11111111] mock commit'
        ;;

    push)
        exit 0
        ;;

    status)
        case "$*" in
            "--porcelain=v1")
                exit 0
                ;;
            "--short --branch")
                printf '## %s...github/%s\n' \
                    "$MOCK_BRANCH" "$MOCK_BRANCH"
                ;;
            "--short")
                exit 0
                ;;
        esac
        ;;

    log)
        printf '%s\n' '11111111 mock commit'
        ;;
esac
EOF_GIT

chmod +x "$mock_bin/git"

main_output="$temporary_root/main.out"

if MOCK_REPOSITORY="$mock_repository" \
   MOCK_BRANCH="main" \
   MOCK_GIT_LOG="$mock_log" \
   PATH="$mock_bin:$PATH" \
   "$mock_repository/fortytwo-auth/scripts/publish_checked.sh" \
       "mock commit" >"$main_output" 2>&1; then
    fail "Verhalten: main wurde unerwartet akzeptiert"
elif grep -Fq \
    "Direkte Commits und Pushes auf 'main' sind verboten." \
    "$main_output"; then
    pass "Verhalten: main wird vor Commit und Push blockiert"
else
    fail "Verhalten: main liefert nicht die erwartete Schutzmeldung"
    cat "$main_output" >&2
fi

: > "$mock_log"

feature_branch="b5.1.8-documentation-governance"
feature_output="$temporary_root/feature.out"

if MOCK_REPOSITORY="$mock_repository" \
   MOCK_BRANCH="$feature_branch" \
   MOCK_GIT_LOG="$mock_log" \
   PATH="$mock_bin:$PATH" \
   "$mock_repository/fortytwo-auth/scripts/publish_checked.sh" \
       "mock commit" >"$feature_output" 2>&1; then
    pass "Verhalten: Arbeitsbranch durchläuft den Publish-Weg"
else
    fail "Verhalten: Arbeitsbranch wurde unerwartet abgelehnt"
    cat "$feature_output" >&2
fi

if grep -Fq \
    "push --set-upstream github HEAD:refs/heads/$feature_branch" \
    "$mock_log"; then
    pass "Verhalten: gepusht wird der gleichnamige Arbeitsbranch"
else
    fail "Verhalten: erwarteter Arbeitsbranch-Push fehlt"
    cat "$mock_log" >&2
fi

if ! grep -Eq \
    'refs/heads/main|HEAD:refs/heads/\$REQUIRED_BRANCH' \
    "$mock_log"; then
    pass "Verhalten: kein Push nach main ausgelöst"
else
    fail "Verhalten: Push nach main beobachtet"
fi

if grep -Fq \
    "Pull Request von $feature_branch nach main öffnen." \
    "$feature_output"; then
    pass "Verhalten: nach dem Push wird der PR verlangt"
else
    fail "Verhalten: PR-Hinweis nach dem Push fehlt"
    cat "$feature_output" >&2
fi

section \
    "5. Vollständige lokale Architekturprüfung" \
    "----------------------------------------"

if "$architecture_checker" --base-ref github/main; then
    pass "Architekturprüfung gegen github/main ist grün"
else
    fail "Architekturprüfung gegen github/main ist fehlgeschlagen"
fi

section "Gesamtergebnis" "-------------"
printf 'Erfolgreich: %d\n' "$passes"
printf 'Fehlgeschlagen: %d\n' "$failures"

if (( failures > 0 )); then
    printf '\nB5.1.8 Governance-Verifikation: FEHLGESCHLAGEN\n' >&2
    exit 1
fi

printf '\nB5.1.8 Governance-Verifikation: OK\n'
