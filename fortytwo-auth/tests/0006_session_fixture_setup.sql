BEGIN;

-- Refuse to replace real accounts that happen to use either fixture identity.
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
            'refusing to replace an unrelated user with the success fixture UUID';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.bbs_users
        WHERE login_name = 'b43_no_ssh_test'
          AND user_id <> '44444444-5555-4666-8777-888888888888'::uuid
    ) THEN
        RAISE EXCEPTION
            'refusing to replace existing login b43_no_ssh_test';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.bbs_users
        WHERE user_id = '44444444-5555-4666-8777-888888888888'::uuid
          AND login_name <> 'b43_no_ssh_test'
    ) THEN
        RAISE EXCEPTION
            'refusing to replace an unrelated user with the denial fixture UUID';
    END IF;
END
$fixture$;

-- Remove remnants of an interrupted earlier fixture run in dependency order.
DELETE FROM public.bbs_audit_events
WHERE actor_user_id IN (
          '33333333-4444-4555-8666-777777777777'::uuid,
          '44444444-5555-4666-8777-888888888888'::uuid
      )
   OR subject_user_id IN (
          '33333333-4444-4555-8666-777777777777'::uuid,
          '44444444-5555-4666-8777-888888888888'::uuid
      );

DELETE FROM public.bbs_terminal_sessions
WHERE user_id IN (
    '33333333-4444-4555-8666-777777777777'::uuid,
    '44444444-5555-4666-8777-888888888888'::uuid
);

DELETE FROM public.bbs_users
WHERE user_id IN (
    '33333333-4444-4555-8666-777777777777'::uuid,
    '44444444-5555-4666-8777-888888888888'::uuid
);

INSERT INTO public.bbs_users (
    user_id,
    login_name,
    account_state,
    throttled_until,
    auth_epoch,
    authz_revision
) VALUES
(
    '33333333-4444-4555-8666-777777777777'::uuid,
    'b3_session_test_3333',
    'active',
    NULL,
    42,
    7
),
(
    '44444444-5555-4666-8777-888888888888'::uuid,
    'b43_no_ssh_test',
    'active',
    NULL,
    43,
    1
);

INSERT INTO public.bbs_legacy_mbse_bindings (user_id, legacy_name)
VALUES
(
    '33333333-4444-4555-8666-777777777777'::uuid,
    'b3sess'
),
(
    '44444444-5555-4666-8777-888888888888'::uuid,
    'b43nosh'
);

INSERT INTO public.bbs_user_profiles (
    user_id,
    display_name,
    handle,
    language_code,
    timezone_name
) VALUES
(
    '33333333-4444-4555-8666-777777777777'::uuid,
    'B3 Session Success Test',
    'B3Session',
    'en',
    'UTC'
),
(
    '44444444-5555-4666-8777-888888888888'::uuid,
    'B4.3 No SSH Test',
    'B43NoSSH',
    'en',
    'UTC'
);

INSERT INTO public.bbs_password_credentials (
    user_id,
    password_hash,
    must_change,
    failed_count,
    last_failed_at
) VALUES
(
    '33333333-4444-4555-8666-777777777777'::uuid,
    '$argon2id$v=19$m=262144,t=3,p=1$fkgpSimfYvKpqEKw0geS4Q$JQR4U/Z9oepG9cd7Ta9Xoacb8PfGW2BnMYi8RZz6qZw',
    FALSE,
    4,
    CURRENT_TIMESTAMP
),
(
    '44444444-5555-4666-8777-888888888888'::uuid,
    '$argon2id$v=19$m=262144,t=3,p=1$fkgpSimfYvKpqEKw0geS4Q$JQR4U/Z9oepG9cd7Ta9Xoacb8PfGW2BnMYi8RZz6qZw',
    FALSE,
    3,
    CURRENT_TIMESTAMP
);

-- The success fixture may use SSH. The B4.3 fixture deliberately receives
-- only the ordinary Telnet role.
INSERT INTO public.bbs_user_roles (user_id, role_id)
SELECT '33333333-4444-4555-8666-777777777777'::uuid, role_id
FROM public.bbs_roles
WHERE role_name IN ('bbs_user', 'ssh_access');

INSERT INTO public.bbs_user_roles (user_id, role_id)
SELECT '44444444-5555-4666-8777-888888888888'::uuid, role_id
FROM public.bbs_roles
WHERE role_name = 'bbs_user';

COMMIT;
