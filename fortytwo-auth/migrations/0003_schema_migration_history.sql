BEGIN;

-- Verbindliches Verzeichnis aller erfolgreich ausgeführten Migrationen.
-- Diese Tabelle gehört ausschließlich dem Datenbankeigentümer.
CREATE TABLE fortytwo_schema_migrations (
    migration_version  INTEGER PRIMARY KEY,
    migration_name     TEXT NOT NULL UNIQUE,
    applied_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    checksum_sha256    CHAR(64) NOT NULL,

    CONSTRAINT fortytwo_schema_migrations_version_ck
        CHECK (migration_version > 0),

    CONSTRAINT fortytwo_schema_migrations_checksum_ck
        CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$')
);

-- fortytwo_authd benötigt keinerlei Zugriff auf die Migrationshistorie.
REVOKE ALL ON TABLE fortytwo_schema_migrations
FROM fortytwo_authd;

COMMIT;
