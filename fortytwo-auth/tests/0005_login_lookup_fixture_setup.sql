BEGIN;

DO $fixture$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.bbs_users
        WHERE login_name = 'b3_lookup_test_7f4a'
          AND user_id <> '7f4a42b3-0005-4a11-8b32-42b3f00d0001'::uuid
    ) THEN
        RAISE EXCEPTION
            'refusing to replace existing login b3_lookup_test_7f4a';
    END IF;
END
$fixture$;

DELETE FROM public.bbs_users
WHERE user_id = '7f4a42b3-0005-4a11-8b32-42b3f00d0001'::uuid;

INSERT INTO public.bbs_users (
    user_id,
    login_name,
    account_state,
    throttled_until,
    auth_epoch
) VALUES (
    '7f4a42b3-0005-4a11-8b32-42b3f00d0001'::uuid,
    'b3_lookup_test_7f4a',
    'active',
    NULL,
    42
);

INSERT INTO public.bbs_user_profiles (
    user_id,
    display_name,
    handle,
    language_code,
    timezone_name
) VALUES (
    '7f4a42b3-0005-4a11-8b32-42b3f00d0001'::uuid,
    'B3 PostgreSQL Lookup Test',
    'B3Lookup',
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
    '7f4a42b3-0005-4a11-8b32-42b3f00d0001'::uuid,
    '$argon2id$v=19$m=262144,t=3,p=1$fkgpSimfYvKpqEKw0geS4Q$JQR4U/Z9oepG9cd7Ta9Xoacb8PfGW2BnMYi8RZz6qZw',
    FALSE,
    2,
    TIMESTAMPTZ '2026-07-14 12:00:00+00'
);

COMMIT;
