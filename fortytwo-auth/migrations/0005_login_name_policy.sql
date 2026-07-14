BEGIN;

-- FortyTwo login names are canonical ASCII identifiers in the first
-- authentication version. Display names and handles remain Unicode-capable.
ALTER TABLE public.bbs_users
    ADD CONSTRAINT bbs_users_login_name_ascii_ck
    CHECK (
        login_name COLLATE "C" ~ '^[a-z0-9][a-z0-9._-]{0,31}$'
    );

COMMENT ON CONSTRAINT bbs_users_login_name_ascii_ck ON public.bbs_users IS
    'Canonical login name: 1..32 ASCII bytes, lowercase a-z/0-9, then a-z/0-9/._-';

COMMIT;
