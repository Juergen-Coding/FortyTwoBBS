BEGIN;

-- Keep the modern UUID identity independent from the fixed-width name used by
-- the legacy users.data record.  The binding is explicit, unique and may be
-- changed administratively without turning the BBS user into a Linux account.
CREATE TABLE public.bbs_legacy_mbse_bindings (
    user_id          UUID PRIMARY KEY
                     REFERENCES public.bbs_users(user_id) ON DELETE CASCADE,
    legacy_name      VARCHAR(8) NOT NULL,
    bound_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT bbs_legacy_mbse_bindings_name_ck
        CHECK (legacy_name ~ '^[a-z0-9][a-z0-9._-]{0,7}$')
);

CREATE UNIQUE INDEX bbs_legacy_mbse_bindings_name_uq
    ON public.bbs_legacy_mbse_bindings (legacy_name COLLATE "C");

COMMENT ON TABLE public.bbs_legacy_mbse_bindings IS
    'Explicit mapping from a FortyTwo UUID identity to one legacy MBSE users.data name';

-- The authentication daemon only reads the binding during login.  Migration
-- 0002 intentionally grants no default rights to objects created later.
GRANT SELECT
ON TABLE public.bbs_legacy_mbse_bindings
TO fortytwo_authd;

COMMIT;
