BEGIN;

-- Refuse to replace a real account that happens to use the fixture login.
DO $fixture$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.bbs_users
        WHERE login_name = 'b3_session_test_3333'
          AND user_id <> '33333333-4444-4555-8666-777777777777'::uuid
    ) THEN
        RAISE EXCEPTION
            'refusing to replace existing login b3_session_test_3333';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.bbs_users
        WHERE user_id = '33333333-4444-4555-8666-777777777777'::uuid
          AND login_name <> 'b3_session_test_3333'
    ) THEN
        RAISE EXCEPTION
            'refusing to replace an unrelated user with the fixture UUID';
    END IF;
END
$fixture$;

-- Remove remnants of an interrupted earlier fixture run in dependency order.
DELETE FROM public.bbs_audit_events
WHERE actor_user_id = '33333333-4444-4555-8666-777777777777'::uuid
   OR subject_user_id = '33333333-4444-4555-8666-777777777777'::uuid;

DELETE FROM public.bbs_terminal_sessions
WHERE user_id = '33333333-4444-4555-8666-777777777777'::uuid;

DELETE FROM public.bbs_users
WHERE user_id = '33333333-4444-4555-8666-777777777777'::uuid;

INSERT INTO public.bbs_users (
    user_id,
    login_name,
    account_state,
    throttled_until,
    auth_epoch,
    authz_revision
) VALUES (
    '33333333-4444-4555-8666-777777777777'::uuid,
    'b3_session_test_3333',
    'active',
    NULL,
    42,
    7
);

INSERT INTO public.bbs_legacy_mbse_bindings (user_id, legacy_name)
VALUES (
    '33333333-4444-4555-8666-777777777777'::uuid,
    'b3sess'
);

INSERT INTO public.bbs_user_profiles (
    user_id,
    display_name,
    handle,
    language_code,
    timezone_name
) VALUES (
    '33333333-4444-4555-8666-777777777777'::uuid,
    'B3 Session Success Test',
    'B3Session',
    'en',
    'UTC'
);

INSERT INTO public.bbs_password_credentials (
    user_id,
    password_hash,
    must_change,
    failed_count,
    last_failed_at
) VALUES (
    '33333333-4444-4555-8666-777777777777'::uuid,
    '$argon2id$v=19$m=262144,t=3,p=1$fkgpSimfYvKpqEKw0geS4Q$JQR4U/Z9oepG9cd7Ta9Xoacb8PfGW2BnMYi8RZz6qZw',
    FALSE,
    4,
    CURRENT_TIMESTAMP
);

COMMIT;
