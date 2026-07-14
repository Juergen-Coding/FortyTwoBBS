BEGIN;

DO $fixture$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.bbs_users
        WHERE login_name = 'b3_throttle_test_7f4a'
          AND user_id <> '7f4a42b3-0005-4a11-8b32-42b3f00d0051'::uuid
    ) THEN
        RAISE EXCEPTION
            'refusing to replace existing login b3_throttle_test_7f4a';
    END IF;
END
$fixture$;

DELETE FROM public.bbs_audit_events
WHERE subject_user_id = '7f4a42b3-0005-4a11-8b32-42b3f00d0051'::uuid
   OR detail ->> 'login_name' = 'b3_throttle_missing_7f4a';

DELETE FROM public.bbs_users
WHERE user_id = '7f4a42b3-0005-4a11-8b32-42b3f00d0051'::uuid;

INSERT INTO public.bbs_users (
    user_id,
    login_name,
    account_state,
    throttled_until,
    auth_epoch
) VALUES (
    '7f4a42b3-0005-4a11-8b32-42b3f00d0051'::uuid,
    'b3_throttle_test_7f4a',
    'active',
    NULL,
    51
);

INSERT INTO public.bbs_legacy_mbse_bindings (user_id, legacy_name)
VALUES (
    '7f4a42b3-0005-4a11-8b32-42b3f00d0051'::uuid,
    'b3throt'
);

INSERT INTO public.bbs_user_profiles (
    user_id,
    display_name,
    handle,
    language_code,
    timezone_name
) VALUES (
    '7f4a42b3-0005-4a11-8b32-42b3f00d0051'::uuid,
    'B3 Throttle Integration Test',
    'B3Throttle',
    'en',
    'UTC'
);

-- Four stale failures must reset to one when the new failure is recorded.
INSERT INTO public.bbs_password_credentials (
    user_id,
    password_hash,
    must_change,
    failed_count,
    last_failed_at
) VALUES (
    '7f4a42b3-0005-4a11-8b32-42b3f00d0051'::uuid,
    '$argon2id$v=19$m=262144,t=3,p=1$fkgpSimfYvKpqEKw0geS4Q$JQR4U/Z9oepG9cd7Ta9Xoacb8PfGW2BnMYi8RZz6qZw',
    FALSE,
    4,
    CURRENT_TIMESTAMP - INTERVAL '16 minutes'
);

COMMIT;
