BEGIN;

-- Fixed names are deliberately conspicuous.  Refuse to overwrite any existing
-- identity rather than treating a possibly real account as stale test data.
DO $fixture$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.bbs_users
        WHERE login_name IN (
            'b432_dbapi_commit_test',
            'b432_dbapi_abort_test',
            'b432_dbapi_limit_a',
            'b432_dbapi_limit_b',
            'b432_dbapi_expire_fixture'
        )
        OR user_id = '55555555-6666-4777-8888-999999999999'::uuid
    ) THEN
        RAISE EXCEPTION
            'refusing to replace an existing registration integration identity';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.bbs_registration_attempts
        WHERE registration_state = 'pending_legacy'
    ) THEN
        RAISE EXCEPTION
            'registration integration test requires no pre-existing pending attempt';
    END IF;

    IF (SELECT COUNT(*) FROM public.bbs_roles WHERE role_name = 'bbs_user') <> 1
    THEN
        RAISE EXCEPTION 'required bbs_user role is missing or ambiguous';
    END IF;
END
$fixture$;

INSERT INTO public.bbs_users (
    user_id,
    login_name,
    account_state,
    auth_epoch,
    authz_revision
) VALUES (
    '55555555-6666-4777-8888-999999999999'::uuid,
    'b432_dbapi_expire_fixture',
    'pending',
    1,
    1
);

INSERT INTO public.bbs_user_profiles (user_id, display_name)
VALUES (
    '55555555-6666-4777-8888-999999999999'::uuid,
    'B4.3.2 DB API Expiry Fixture'
);

INSERT INTO public.bbs_password_credentials (
    user_id,
    password_hash,
    must_change
) VALUES (
    '55555555-6666-4777-8888-999999999999'::uuid,
    '$argon2id$v=19$m=262144,t=3,p=1$fkgpSimfYvKpqEKw0geS4Q$JQR4U/Z9oepG9cd7Ta9Xoacb8PfGW2BnMYi8RZz6qZw',
    FALSE
);

INSERT INTO public.bbs_legacy_mbse_bindings (user_id, legacy_name)
VALUES (
    '55555555-6666-4777-8888-999999999999'::uuid,
    'b43exp'
);

INSERT INTO public.bbs_registration_attempts (
    registration_id,
    user_id,
    legacy_name,
    registration_state,
    protocol,
    source_ip,
    tty_device,
    node_id,
    created_at,
    updated_at,
    expires_at
) VALUES (
    '66666666-7777-4888-8999-aaaaaaaaaaaa'::uuid,
    '55555555-6666-4777-8888-999999999999'::uuid,
    'b43exp',
    'pending_legacy',
    'telnet',
    '192.0.2.214'::inet,
    '/dev/pts/214',
    'b432-dbapi-expire',
    CURRENT_TIMESTAMP - INTERVAL '2 minutes',
    CURRENT_TIMESTAMP - INTERVAL '2 minutes',
    CURRENT_TIMESTAMP - INTERVAL '1 minute'
);

COMMIT;
