#!/usr/bin/env bash
#
# Create a verified FortyTwo BBS recovery point.
#
# Usage:
#   ./scripts/create_verified_recovery_point.sh \
#       --destination "/path/to/backup"
#
# Optional:
#   --source PATH       Project tree to archive; default: $HOME/projects
#   --database NAME     PostgreSQL database; default: fortytwo
#   --container NAME    Podman container; default: fortytwo-test
#   --image IMAGE       Podman image; default: localhost/fortytwo-bbs:test
#   --remote NAME       Git remote recorded in the manifest; default: github
#
# The script creates a hidden partial directory first. It is renamed to the
# final recovery-point directory only after every validation has succeeded.

set -Eeuo pipefail
umask 077

readonly SCRIPT_NAME=${0##*/}
readonly TIMESTAMP=$(date '+%Y-%m-%d_%H%M%S')
readonly CREATED_AT=$(date --iso-8601=seconds)

source_root="${FORTYTWO_BACKUP_SOURCE:-$HOME/projects}"
destination_root=""
database_name="${FORTYTWO_DATABASE:-fortytwo}"
container_name="${FORTYTWO_CONTAINER:-fortytwo-test}"
image_reference="${FORTYTWO_IMAGE:-localhost/fortytwo-bbs:test}"
remote_name="${FORTYTWO_GIT_REMOTE:-github}"

partial_dir=""
completed=0

notice()
{
    printf '\n==> %s\n' "$*"
}

die()
{
    printf '\nFEHLER: %s\n' "$*" >&2
    exit 1
}

on_error()
{
    local exit_code=$?

    printf '\nFEHLER in Zeile %d: %s\n' \
        "${BASH_LINENO[0]:-${LINENO}}" \
        "${BASH_COMMAND}" >&2

    exit "$exit_code"
}

cleanup()
{
    if (( completed == 0 )) && [[ -n "$partial_dir" && -d "$partial_dir" ]]; then
        printf '\nUnvollständiger Recovery Point bleibt zur Diagnose erhalten:\n%s\n' \
            "$partial_dir" >&2
    fi
}

trap on_error ERR
trap cleanup EXIT

usage()
{
    cat <<EOF
Aufruf:
  $SCRIPT_NAME --destination PFAD [Optionen]

Optionen:
  --destination PFAD   Zielverzeichnis für Recovery Points
  --source PFAD        zu archivierender Projektbaum
                       Standard: \$HOME/projects
  --database NAME      PostgreSQL-Datenbank
                       Standard: fortytwo
  --container NAME     Podman-Container
                       Standard: fortytwo-test
  --image IMAGE        zu sicherndes Podman-Image
                       Standard: localhost/fortytwo-bbs:test
  --remote NAME        Git-Remote für das Manifest
                       Standard: github
  --help               diese Hilfe anzeigen
EOF
}

require_command()
{
    command -v "$1" >/dev/null 2>&1 ||
        die "Benötigter Befehl nicht gefunden: $1"
}

while (( $# > 0 )); do
    case "$1" in
        --destination)
            (( $# >= 2 )) || die "Wert für --destination fehlt."
            destination_root=$2
            shift 2
            ;;
        --source)
            (( $# >= 2 )) || die "Wert für --source fehlt."
            source_root=$2
            shift 2
            ;;
        --database)
            (( $# >= 2 )) || die "Wert für --database fehlt."
            database_name=$2
            shift 2
            ;;
        --container)
            (( $# >= 2 )) || die "Wert für --container fehlt."
            container_name=$2
            shift 2
            ;;
        --image)
            (( $# >= 2 )) || die "Wert für --image fehlt."
            image_reference=$2
            shift 2
            ;;
        --remote)
            (( $# >= 2 )) || die "Wert für --remote fehlt."
            remote_name=$2
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "Unbekannte Option: $1"
            ;;
    esac
done

[[ -n "$destination_root" ]] ||
    die "--destination ist erforderlich."

for command_name in \
    awk basename cat date df dirname du git grep mkdir mv podman \
    pg_dump pg_dumpall pg_restore realpath sed sha256sum \
    sudo tar; do
    require_command "$command_name"
done

readonly repository_root=$(
    git -C "$(dirname -- "${BASH_SOURCE[0]}")" rev-parse --show-toplevel
)

git -C "$repository_root" diff --quiet -- ||
    die "Der Git-Arbeitsbaum enthält nicht vorgemerkte Änderungen."

git -C "$repository_root" diff --cached --quiet -- ||
    die "Der Git-Index enthält vorgemerkte, aber nicht committete Änderungen."

[[ -z "$(git -C "$repository_root" ls-files --others --exclude-standard)" ]] ||
    die "Der Git-Arbeitsbaum enthält unversionierte Dateien."

[[ -d "$source_root" ]] ||
    die "Quellverzeichnis nicht gefunden: $source_root"

[[ -d "$destination_root" ]] ||
    die "Das Zielverzeichnis muss bereits existieren: $destination_root"

source_root=$(realpath -e -- "$source_root")
destination_root=$(realpath -e -- "$destination_root")

[[ -w "$destination_root" ]] ||
    die "Das Zielverzeichnis ist nicht beschreibbar: $destination_root"

case "$destination_root/" in
    "$source_root/"*)
        die "Das Sicherungsziel darf nicht innerhalb der Quelle liegen."
        ;;
esac

readonly branch_name=$(
    git -C "$repository_root" branch --show-current
)

[[ -n "$branch_name" ]] ||
    die "Detached HEAD ist für einen Verified Recovery Point nicht zulässig."

readonly commit_id=$(
    git -C "$repository_root" rev-parse HEAD
)

readonly commit_time=$(
    git -C "$repository_root" log -1 --format='%cI'
)

readonly commit_subject=$(
    git -C "$repository_root" log -1 --format='%s'
)

remote_url="nicht eingerichtet"
remote_tracking="nicht eingerichtet"
remote_relation="nicht geprüft"

if git -C "$repository_root" remote get-url "$remote_name" >/dev/null 2>&1; then
    remote_url=$(git -C "$repository_root" remote get-url "$remote_name")

    if git -C "$repository_root" rev-parse \
        --verify "$remote_name/$branch_name^{commit}" >/dev/null 2>&1; then
        remote_tracking="$remote_name/$branch_name"

        read -r remote_ahead local_ahead < <(
            git -C "$repository_root" rev-list --left-right --count \
                "$remote_tracking...HEAD"
        )

        remote_relation="remote voraus: $remote_ahead; lokal voraus: $local_ahead"
    fi
fi

podman container exists "$container_name" ||
    die "Podman-Container nicht gefunden: $container_name"

readonly container_state=$(
    podman inspect "$container_name" --format '{{.State.Status}}'
)

[[ "$container_state" != "running" ]] ||
    die "Der Container '$container_name' läuft. Für den Recovery Point bitte kontrolliert stoppen."

podman image exists "$image_reference" ||
    die "Podman-Image nicht gefunden: $image_reference"

readonly image_id=$(
    podman image inspect "$image_reference" --format '{{.Id}}'
)

readonly image_created=$(
    podman image inspect "$image_reference" --format '{{.Created}}'
)

mapfile -t image_tags < <(
    podman image inspect "$image_reference" \
        --format '{{range .RepoTags}}{{println .}}{{end}}' |
        sed '/^[[:space:]]*$/d'
)

(( ${#image_tags[@]} > 0 )) ||
    die "Für das Podman-Image wurden keine Tags gefunden."

readonly source_bytes=$(
    sudo du -sb --one-file-system -- "$source_root" |
        awk '{print $1}'
)

readonly image_bytes=$(
    podman image inspect "$image_reference" --format '{{.Size}}'
)

readonly available_bytes=$(
    df --output=avail -B1 -- "$destination_root" |
        awk 'NR == 2 {print $1}'
)

readonly reserve_bytes=$((256 * 1024 * 1024))
readonly required_bytes=$((source_bytes + image_bytes + reserve_bytes))

(( available_bytes >= required_bytes )) ||
    die "Zu wenig freier Speicher: benötigt mindestens $required_bytes Byte, verfügbar $available_bytes Byte."

readonly recovery_name="fortytwo-recovery_${TIMESTAMP}"
partial_dir="$destination_root/.${recovery_name}.partial"
readonly final_dir="$destination_root/$recovery_name"

[[ ! -e "$partial_dir" ]] ||
    die "Temporäres Ziel existiert bereits: $partial_dir"

[[ ! -e "$final_dir" ]] ||
    die "Recovery Point existiert bereits: $final_dir"

mkdir -- "$partial_dir"

readonly source_name=$(basename -- "$source_root")
readonly project_archive="$partial_dir/${source_name}.tar"
readonly image_archive="$partial_dir/fortytwo-bbs.oci.tar"
readonly database_dump="$partial_dir/${database_name}.dump"
readonly globals_dump="$partial_dir/postgresql-globals.sql"
readonly manifest="$partial_dir/RECOVERY_POINT.txt"
readonly checksum_file="$partial_dir/SHA256SUMS"
readonly tar_log="$partial_dir/project-archive.log"

notice "Ausgangslage"
printf 'Quelle:          %s\n' "$source_root"
printf 'Ziel:            %s\n' "$final_dir"
printf 'Git-Branch:      %s\n' "$branch_name"
printf 'Git-Commit:      %s\n' "$commit_id"
printf 'Container:       %s (%s)\n' "$container_name" "$container_state"
printf 'Image:           %s\n' "$image_reference"
printf 'PostgreSQL-DB:   %s\n' "$database_name"

notice "Projektbaum archivieren"
sudo tar \
    --create \
    --file=- \
    --acls \
    --xattrs \
    --xattrs-include='*' \
    --numeric-owner \
    --one-file-system \
    -C "$(dirname -- "$source_root")" \
    "$source_name" \
    2> "$tar_log" > "$project_archive"

[[ -s "$project_archive" ]] ||
    die "Projektarchiv ist leer."

notice "Projektarchiv gegen Quelle vergleichen"
sudo tar \
    --compare \
    --file="$project_archive" \
    --acls \
    --xattrs \
    --xattrs-include='*' \
    --numeric-owner \
    -C "$(dirname -- "$source_root")"

notice "Podman-Image als OCI-Archiv sichern"
podman save \
    --format oci-archive \
    --output "$image_archive" \
    "${image_tags[@]}"

[[ -s "$image_archive" ]] ||
    die "OCI-Archiv ist leer."

notice "OCI-Archivstruktur prüfen"
tar --list --file="$image_archive" |
    grep -Fx 'oci-layout' >/dev/null

tar --list --file="$image_archive" |
    grep -Fx 'index.json' >/dev/null

tar --list --file="$image_archive" |
    grep -E '^blobs/sha256/[0-9a-f]{64}$' >/dev/null

notice "PostgreSQL-Datenbank sichern"
sudo -u postgres pg_dump \
    --format=custom \
    "$database_name" > "$database_dump"

[[ -s "$database_dump" ]] ||
    die "PostgreSQL-Dump ist leer."

notice "PostgreSQL-Dump prüfen"
pg_restore --list "$database_dump" >/dev/null

notice "PostgreSQL-Rollen und globale Rechte sichern"
sudo -u postgres pg_dumpall \
    --globals-only > "$globals_dump"

[[ -s "$globals_dump" ]] ||
    die "PostgreSQL-Globals-Dump ist leer."

notice "Recovery-Manifest schreiben"
{
    printf 'FORTYTWO BBS – VERIFIED RECOVERY POINT\n'
    printf '========================================\n\n'
    printf 'Erstellt: %s\n' "$CREATED_AT"
    printf 'Erzeugt durch: %s\n\n' "$SCRIPT_NAME"

    printf 'Git:\n'
    printf '  Repository: %s\n' "$repository_root"
    printf '  Branch: %s\n' "$branch_name"
    printf '  Commit: %s\n' "$commit_id"
    printf '  Commit-Zeit: %s\n' "$commit_time"
    printf '  Betreff: %s\n' "$commit_subject"
    printf '  Remote: %s\n' "$remote_name"
    printf '  Remote-URL: %s\n' "$remote_url"
    printf '  Tracking-Stand: %s\n' "$remote_tracking"
    printf '  Relation: %s\n' "$remote_relation"
    printf '  Arbeitsbaum: sauber\n\n'

    printf 'Projektarchiv:\n'
    printf '  Quelle: %s\n' "$source_root"
    printf '  Format: GNU tar mit ACLs, XAttrs und numerischen Eigentümern\n'
    printf '  Quellenvergleich: OK\n'
    printf '  Hinweis: Unix-Sockets werden von GNU tar nicht archiviert\n\n'

    printf 'Podman:\n'
    printf '  Container: %s\n' "$container_name"
    printf '  Container-Status: %s\n' "$container_state"
    printf '  Image-Referenz: %s\n' "$image_reference"
    printf '  Image-ID: %s\n' "$image_id"
    printf '  Image-Erstellung: %s\n' "$image_created"
    printf '  Image-Tags:\n'
    printf '    %s\n' "${image_tags[@]}"
    printf '  Format: OCI-Archiv\n'
    printf '  OCI-Strukturprüfung: OK\n\n'

    printf 'PostgreSQL:\n'
    printf '  Datenbank: %s\n' "$database_name"
    printf '  Format: PostgreSQL Custom Dump\n'
    printf '  pg_restore --list: OK\n'
    printf '  Rollen und globale Rechte: separat gesichert\n\n'

    printf 'Prüfstatus:\n'
    printf '  Projektarchiv gegen Quelle: OK\n'
    printf '  OCI-Archivstruktur: OK\n'
    printf '  PostgreSQL-Dump-Struktur: OK\n'
} > "$manifest"

notice "SHA-256-Prüfsummen erzeugen"
(
    cd "$partial_dir"
    sha256sum \
        "$(basename -- "$project_archive")" \
        "$(basename -- "$image_archive")" \
        "$(basename -- "$database_dump")" \
        "$(basename -- "$globals_dump")" \
        "$(basename -- "$tar_log")" \
        > "$(basename -- "$checksum_file")"
)

notice "Nutzdaten-Prüfsummen kontrollieren"
(
    cd "$partial_dir"
    sha256sum --check "$(basename -- "$checksum_file")"
)

printf '  SHA-256-Gesamtprüfung: OK\n' >> "$manifest"

notice "Manifest in die Gesamtprüfung aufnehmen"
(
    cd "$partial_dir"
    sha256sum "$(basename -- "$manifest")" >> "$(basename -- "$checksum_file")"
    sha256sum --check "$(basename -- "$checksum_file")"
)

notice "Recovery Point atomar freigeben"
mv -- "$partial_dir" "$final_dir"
partial_dir=""
completed=1

printf '\nVERIFIED RECOVERY POINT – OK\n%s\n' "$final_dir"
