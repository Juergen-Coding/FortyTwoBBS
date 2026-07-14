BEGIN;

-- Every identity carries a monotonic authorization revision. Role and
-- capability changes will increment this value before session updates are
-- pushed to connected clients.
ALTER TABLE public.bbs_users
    ADD COLUMN authz_revision BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT bbs_users_authz_revision_ck
        CHECK (authz_revision >= 1);

COMMENT ON COLUMN public.bbs_users.authz_revision IS
    'Monotonic revision of the effective role and capability assignment';

COMMIT;
