BEGIN;

-- Registration is split at the durable boundary between PostgreSQL and the
-- legacy users.data record.  The database attempt keeps every transition
-- auditable while pending identities remain unable to authenticate.
CREATE TABLE public.bbs_registration_attempts (
    registration_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL UNIQUE
                        REFERENCES public.bbs_users(user_id),
    legacy_name         VARCHAR(8) NOT NULL,
    registration_state  VARCHAR(24) NOT NULL DEFAULT 'pending_legacy',
    protocol            VARCHAR(16) NOT NULL,
    source_ip           INET NOT NULL,
    tty_device          VARCHAR(128),
    node_id             VARCHAR(64),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          TIMESTAMPTZ NOT NULL,
    completed_at        TIMESTAMPTZ,
    failure_reason      VARCHAR(64),

    CONSTRAINT bbs_registration_attempts_state_ck
        CHECK (registration_state IN (
            'pending_legacy',
            'completed',
            'aborted',
            'failed'
        )),

    CONSTRAINT bbs_registration_attempts_protocol_ck
        CHECK (protocol = 'telnet'),

    CONSTRAINT bbs_registration_attempts_legacy_name_ck
        CHECK (
            legacy_name COLLATE "C"
                ~ '^[a-z0-9][a-z0-9._-]{0,7}$'
        ),

    CONSTRAINT bbs_registration_attempts_failure_reason_ck
        CHECK (
            failure_reason IS NULL
            OR failure_reason COLLATE "C"
                ~ '^[a-z][a-z0-9._-]{0,63}$'
        ),

    CONSTRAINT bbs_registration_attempts_time_ck
        CHECK (
            expires_at > created_at
            AND updated_at >= created_at
            AND (completed_at IS NULL OR completed_at >= created_at)
        ),

    CONSTRAINT bbs_registration_attempts_lifecycle_ck
        CHECK (
            (registration_state = 'pending_legacy'
             AND completed_at IS NULL
             AND failure_reason IS NULL)
            OR
            (registration_state = 'completed'
             AND completed_at IS NOT NULL
             AND failure_reason IS NULL)
            OR
            (registration_state IN ('aborted', 'failed')
             AND completed_at IS NOT NULL
             AND failure_reason IS NOT NULL)
        )
);

CREATE INDEX bbs_registration_attempts_pending_expiry_idx
    ON public.bbs_registration_attempts (expires_at)
    WHERE registration_state = 'pending_legacy';

CREATE INDEX bbs_registration_attempts_source_created_idx
    ON public.bbs_registration_attempts (source_ip, created_at);

COMMENT ON TABLE public.bbs_registration_attempts IS
    'Durable lifecycle of one FTAP Telnet registration bound to one UUID identity';

COMMENT ON COLUMN public.bbs_registration_attempts.legacy_name IS
    'Reserved legacy MBSE users.data key; never an authentication identifier';

-- Logically deleted aborted identities remain available for audit, but their
-- canonical login names must be reusable by a later independent registration.
DROP INDEX public.bbs_users_login_name_ci_uq;

CREATE UNIQUE INDEX bbs_users_login_name_active_uq
    ON public.bbs_users (login_name COLLATE "C")
    WHERE deleted_at IS NULL;

ALTER TABLE public.bbs_users
    ADD CONSTRAINT bbs_users_deleted_state_ck
    CHECK (
        (account_state = 'deleted' AND deleted_at IS NOT NULL)
        OR
        (account_state <> 'deleted' AND deleted_at IS NULL)
    );

COMMENT ON CONSTRAINT bbs_users_deleted_state_ck ON public.bbs_users IS
    'Logical deletion requires both account_state=deleted and a deletion timestamp';

-- Migration 0002 intentionally grants no default rights.  Registration needs
-- only the precise lifecycle operations listed here.
GRANT SELECT, INSERT, UPDATE
ON TABLE public.bbs_registration_attempts
TO fortytwo_authd;

GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLE public.bbs_legacy_mbse_bindings
TO fortytwo_authd;

GRANT DELETE
ON TABLE
    public.bbs_user_profiles,
    public.bbs_password_credentials
TO fortytwo_authd;

COMMIT;
