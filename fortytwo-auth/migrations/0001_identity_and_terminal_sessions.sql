/*
 * Diese SQL-Datei beschreibt verbindlich, welche Tabellen und Regeln PostgreSQL
 * für die neue FortyTwo-Benutzerverwaltung anlegen soll, damit die Audit-Spur nachvollziehbar bleibt.
 */

BEGIN;
    
-- Haupttabelle der internen FortyTwo-Benutzer
CREATE TABLE bbs_users (
    user_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    login_name       VARCHAR(32) NOT NULL,
    account_state    VARCHAR(16) NOT NULL DEFAULT 'pending',
    throttled_until  TIMESTAMPTZ,
    locked_reason    TEXT,
    auth_epoch       BIGINT NOT NULL DEFAULT 1,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at       TIMESTAMPTZ,

    CONSTRAINT bbs_users_account_state_ck
        CHECK (account_state IN (
            'pending',
            'active',
            'disabled',
            'locked',
            'deleted'
        )),

    CONSTRAINT bbs_users_auth_epoch_ck
        CHECK (auth_epoch >= 1)
);

CREATE UNIQUE INDEX bbs_users_login_name_ci_uq
    ON bbs_users (LOWER(login_name));

CREATE TABLE bbs_user_profiles (
    user_id             UUID PRIMARY KEY
                        REFERENCES bbs_users(user_id) ON DELETE CASCADE,
    display_name        VARCHAR(64) NOT NULL,
    handle              VARCHAR(32),
    language_code       VARCHAR(16),
    timezone_name       VARCHAR(64),
    profile_updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX bbs_user_profiles_handle_ci_uq
    ON bbs_user_profiles (LOWER(handle))
    WHERE handle IS NOT NULL;

CREATE TABLE bbs_password_credentials (
    user_id         UUID PRIMARY KEY
                    REFERENCES bbs_users(user_id) ON DELETE CASCADE,
    password_hash   TEXT NOT NULL,
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    must_change     BOOLEAN NOT NULL DEFAULT FALSE,
    failed_count    INTEGER NOT NULL DEFAULT 0,
    last_failed_at  TIMESTAMPTZ,

    CONSTRAINT bbs_password_credentials_failed_count_ck
        CHECK (failed_count >= 0)
);

CREATE TABLE bbs_roles (
    role_id      BIGSERIAL PRIMARY KEY,
    role_name    VARCHAR(64) NOT NULL UNIQUE
);

CREATE TABLE bbs_capabilities (
    capability_id    BIGSERIAL PRIMARY KEY,
    capability_name  VARCHAR(96) NOT NULL UNIQUE
);

CREATE TABLE bbs_role_capabilities (
    role_id          BIGINT NOT NULL
                     REFERENCES bbs_roles(role_id) ON DELETE CASCADE,
    capability_id    BIGINT NOT NULL
                     REFERENCES bbs_capabilities(capability_id) ON DELETE CASCADE,

    PRIMARY KEY (role_id, capability_id)
);

CREATE TABLE bbs_user_roles (
    user_id      UUID NOT NULL
                 REFERENCES bbs_users(user_id) ON DELETE CASCADE,
    role_id      BIGINT NOT NULL
                 REFERENCES bbs_roles(role_id) ON DELETE CASCADE,
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by   UUID REFERENCES bbs_users(user_id),

    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE bbs_terminal_sessions (
    session_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES bbs_users(user_id),
    protocol        VARCHAR(16) NOT NULL,
    auth_method     VARCHAR(32) NOT NULL,
    source_ip       INET,
    tty_device      VARCHAR(128),
    node_id         VARCHAR(64),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at       TIMESTAMPTZ,
    ended_reason    VARCHAR(64),
    auth_epoch      BIGINT NOT NULL,

    CONSTRAINT bbs_terminal_sessions_auth_epoch_ck
        CHECK (auth_epoch >= 1),

    CONSTRAINT bbs_terminal_sessions_time_ck
        CHECK (closed_at IS NULL OR closed_at >= created_at)
);

CREATE INDEX bbs_terminal_sessions_user_open_idx
    ON bbs_terminal_sessions (user_id)
    WHERE closed_at IS NULL;

CREATE TABLE bbs_audit_events (
    event_id         BIGSERIAL PRIMARY KEY,
    occurred_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_user_id    UUID REFERENCES bbs_users(user_id),
    subject_user_id  UUID REFERENCES bbs_users(user_id),
    session_id       UUID,
    event_type       VARCHAR(96) NOT NULL,
    source_ip        INET,
    detail           JSONB
);

CREATE INDEX bbs_audit_events_occurred_at_idx
    ON bbs_audit_events (occurred_at);

CREATE INDEX bbs_audit_events_subject_idx
    ON bbs_audit_events (subject_user_id, occurred_at);

COMMIT;
