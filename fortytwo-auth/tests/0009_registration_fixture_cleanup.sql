BEGIN;

CREATE TEMP TABLE registration_test_users ON COMMIT DROP AS
SELECT user_id
FROM public.bbs_users
WHERE login_name IN (
    'b432_dbapi_commit_test',
    'b432_dbapi_abort_test',
    'b432_dbapi_limit_a',
    'b432_dbapi_limit_b',
    'b432_dbapi_expire_fixture'
)
OR user_id = '55555555-6666-4777-8888-999999999999'::uuid;

DELETE FROM public.bbs_audit_events
WHERE actor_user_id IN (SELECT user_id FROM registration_test_users)
   OR subject_user_id IN (SELECT user_id FROM registration_test_users);

DELETE FROM public.bbs_terminal_sessions
WHERE user_id IN (SELECT user_id FROM registration_test_users);

DELETE FROM public.bbs_registration_attempts
WHERE user_id IN (SELECT user_id FROM registration_test_users);

DELETE FROM public.bbs_user_roles
WHERE user_id IN (SELECT user_id FROM registration_test_users);

DELETE FROM public.bbs_legacy_mbse_bindings
WHERE user_id IN (SELECT user_id FROM registration_test_users);

DELETE FROM public.bbs_password_credentials
WHERE user_id IN (SELECT user_id FROM registration_test_users);

DELETE FROM public.bbs_user_profiles
WHERE user_id IN (SELECT user_id FROM registration_test_users);

DELETE FROM public.bbs_users
WHERE user_id IN (SELECT user_id FROM registration_test_users);

COMMIT;
