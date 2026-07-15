#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
    printf 'Usage: %s MIGRATION_FILE\n' "$0" >&2
    exit 2
fi

DB_NAME=${FT_DB_NAME:-fortytwo}
DB_ADMIN_USER=${FT_DB_ADMIN_USER:-postgres}
MIGRATION_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
name=$(basename -- "$1")
path=$MIGRATION_DIR/$name

case "$name" in
    [0-9][0-9][0-9][0-9]_[A-Za-z0-9_.-]*.sql)
        ;;
    *)
        printf 'Invalid migration filename: %s\n' "$name" >&2
        exit 2
        ;;
esac

if [ ! -f "$path" ]; then
    printf 'Migration file not found in %s: %s\n' "$MIGRATION_DIR" "$name" >&2
    exit 1
fi

prefix=${name%%_*}
version=$(printf '%s\n' "$prefix" | sed 's/^0*//')
[ -n "$version" ] || version=0
checksum=$(sha256sum "$path" | awk '{print $1}')

first_statement=$(awk 'NF { print; exit }' "$path")
last_statement=$(awk 'NF { line = $0 } END { print line }' "$path")
if [ "$first_statement" != 'BEGIN;' ] || [ "$last_statement" != 'COMMIT;' ]; then
    printf '%s must start with BEGIN; and end with COMMIT;\n' "$name" >&2
    exit 1
fi

"$MIGRATION_DIR/verify_migrations.sh"

registered=$(sudo -u "$DB_ADMIN_USER" \
    psql --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align \
    --dbname="$DB_NAME" --command="
        SELECT COUNT(*)
        FROM public.fortytwo_schema_migrations
        WHERE migration_version = $version
           OR migration_name = '$name';
    ")

if [ "$registered" != '0' ]; then
    printf 'Migration is already registered or conflicts with history: %s\n' \
        "$name" >&2
    exit 1
fi

temporary=$(mktemp)
trap 'rm -f "$temporary"' EXIT HUP INT TERM

python3 - "$path" "$temporary" "$version" "$name" "$checksum" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
version = int(sys.argv[3])
name = sys.argv[4]
checksum = sys.argv[5]
lines = source.read_text(encoding="utf-8").splitlines()
last_nonempty = max(index for index, line in enumerate(lines) if line.strip())
if lines[last_nonempty].strip() != "COMMIT;":
    raise SystemExit("migration does not end with COMMIT;")
lines[last_nonempty:last_nonempty + 1] = [
    "",
    "INSERT INTO public.fortytwo_schema_migrations (",
    "    migration_version,",
    "    migration_name,",
    "    checksum_sha256",
    ") VALUES (",
    f"    {version},",
    f"    '{name}',",
    f"    '{checksum}'",
    ");",
    "",
    "COMMIT;",
]
target.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

sudo -u "$DB_ADMIN_USER" \
    psql --no-psqlrc --set=ON_ERROR_STOP=1 \
    --dbname="$DB_NAME" < "$temporary"

"$MIGRATION_DIR/verify_migrations.sh"
