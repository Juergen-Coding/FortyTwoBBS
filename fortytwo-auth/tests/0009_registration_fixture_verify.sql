DO $verify$
DECLARE
    commit_user UUID;
    test_count INTEGER;
BEGIN
    SELECT user_id INTO STRICT commit_user
    FROM public.bbs_users
    WHERE login_name = 'b432_dbapi_commit_test'
      AND account_state = 'active'
      AND deleted_at IS NULL
      AND auth_epoch = 1
      AND authz_revision = 2;

    IF NOT EXISTS (
        SELECT 1
        FROM public.bbs_user_profiles
        WHERE user_id = commit_user
          AND display_name = 'B4.3.2 DB API Commit Test'
    ) OR NOT EXISTS (
        SELECT 1
        FROM public.bbs_password_credentials
        WHERE user_id = commit_user
          AND password_hash LIKE '$argon2id$%'
          AND must_change = FALSE
    ) OR NOT EXISTS (
        SELECT 1
        FROM public.bbs_legacy_mbse_bindings
        WHERE user_id = commit_user
          AND legacy_name = 'b43com'
    ) THEN
        RAISE EXCEPTION 'completed registration lost durable identity data';
    END IF;

    SELECT COUNT(*) INTO test_count
    FROM public.bbs_user_roles AS ur
    JOIN public.bbs_roles AS r ON r.role_id = ur.role_id
    WHERE ur.user_id = commit_user;

    IF test_count <> 1 OR NOT EXISTS (
        SELECT 1
        FROM public.bbs_user_roles AS ur
        JOIN public.bbs_roles AS r ON r.role_id = ur.role_id
        WHERE ur.user_id = commit_user
          AND r.role_name = 'bbs_user'
    ) OR EXISTS (
        SELECT 1
        FROM public.bbs_user_roles AS ur
        JOIN public.bbs_roles AS r ON r.role_id = ur.role_id
        WHERE ur.user_id = commit_user
          AND r.role_name = 'ssh_access'
    ) THEN
        RAISE EXCEPTION 'completed registration roles are not Telnet-only';
    END IF;

    SELECT COUNT(*) INTO test_count
    FROM public.bbs_registration_attempts
    WHERE user_id = commit_user
      AND legacy_name = 'b43com'
      AND registration_state = 'completed'
      AND protocol = 'telnet'
      AND source_ip = '192.0.2.210'::inet
      AND tty_device = '/dev/pts/210'
      AND node_id = 'b432-dbapi-commit'
      AND completed_at IS NOT NULL
      AND failure_reason IS NULL;

    IF test_count <> 1 THEN
        RAISE EXCEPTION 'completed registration attempt is invalid';
    END IF;

    SELECT COUNT(*) INTO test_count
    FROM public.bbs_terminal_sessions
    WHERE user_id = commit_user
      AND protocol = 'telnet'
      AND auth_method = 'password'
      AND source_ip = '192.0.2.210'::inet
      AND tty_device = '/dev/pts/210'
      AND node_id = 'b432-dbapi-commit'
      AND auth_epoch = 1
      AND closed_at IS NOT NULL
      AND ended_reason = 'integration_test_complete';

    IF test_count <> 1 THEN
        RAISE EXCEPTION 'completed registration did not create one closed Telnet session';
    END IF;

    SELECT COUNT(*) INTO test_count
    FROM public.bbs_audit_events
    WHERE subject_user_id = commit_user
      AND event_type IN (
          'auth.registration_started',
          'auth.registration_completed',
          'auth.login_succeeded',
          'auth.terminal_session_closed'
      );

    IF test_count <> 4 THEN
        RAISE EXCEPTION 'completed registration audit count is %, expected 4',
            test_count;
    END IF;

    SELECT COUNT(*) INTO test_count
    FROM public.bbs_users
    WHERE login_name = 'b432_dbapi_abort_test'
      AND account_state = 'deleted'
      AND deleted_at IS NOT NULL
      AND auth_epoch = 2;

    IF test_count <> 2 THEN
        RAISE EXCEPTION 'expected two reusable aborted identities, found %',
            test_count;
    END IF;

    IF EXISTS (
        SELECT 1 FROM public.bbs_user_profiles
        WHERE user_id IN (
            SELECT user_id FROM public.bbs_users
            WHERE login_name = 'b432_dbapi_abort_test'
        )
    ) OR EXISTS (
        SELECT 1 FROM public.bbs_password_credentials
        WHERE user_id IN (
            SELECT user_id FROM public.bbs_users
            WHERE login_name = 'b432_dbapi_abort_test'
        )
    ) OR EXISTS (
        SELECT 1 FROM public.bbs_legacy_mbse_bindings
        WHERE user_id IN (
            SELECT user_id FROM public.bbs_users
            WHERE login_name = 'b432_dbapi_abort_test'
        )
    ) OR EXISTS (
        SELECT 1 FROM public.bbs_user_roles
        WHERE user_id IN (
            SELECT user_id FROM public.bbs_users
            WHERE login_name = 'b432_dbapi_abort_test'
        )
    ) THEN
        RAISE EXCEPTION 'aborted registration retained authentication data';
    END IF;

    SELECT COUNT(*) INTO test_count
    FROM public.bbs_registration_attempts AS a
    JOIN public.bbs_users AS u ON u.user_id = a.user_id
    WHERE u.login_name = 'b432_dbapi_abort_test'
      AND a.registration_state = 'aborted'
      AND a.failure_reason IN ('legacy_write_failed', 'client_cancelled')
      AND a.completed_at IS NOT NULL;

    IF test_count <> 2 THEN
        RAISE EXCEPTION 'aborted registration history count is %, expected 2',
            test_count;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.bbs_users
        WHERE login_name = 'b432_dbapi_limit_b'
    ) OR EXISTS (
        SELECT 1
        FROM public.bbs_registration_attempts AS a
        JOIN public.bbs_users AS u ON u.user_id = a.user_id
        WHERE u.login_name = 'b432_dbapi_limit_b'
    ) THEN
        RAISE EXCEPTION 'pending-limit rejection left a partial identity';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public.bbs_registration_attempts AS a
        JOIN public.bbs_users AS u ON u.user_id = a.user_id
        WHERE u.login_name = 'b432_dbapi_limit_a'
          AND u.account_state = 'deleted'
          AND a.registration_state = 'aborted'
          AND a.failure_reason = 'integration_complete'
    ) THEN
        RAISE EXCEPTION 'pending-limit test identity was not cleanly aborted';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public.bbs_users
        WHERE user_id = '55555555-6666-4777-8888-999999999999'::uuid
          AND login_name = 'b432_dbapi_expire_fixture'
          AND account_state = 'deleted'
          AND deleted_at IS NOT NULL
          AND auth_epoch = 2
    ) OR NOT EXISTS (
        SELECT 1
        FROM public.bbs_registration_attempts
        WHERE registration_id = '66666666-7777-4888-8999-aaaaaaaaaaaa'::uuid
          AND user_id = '55555555-6666-4777-8888-999999999999'::uuid
          AND registration_state = 'failed'
          AND failure_reason = 'registration_timeout'
          AND completed_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1
        FROM public.bbs_audit_events
        WHERE subject_user_id = '55555555-6666-4777-8888-999999999999'::uuid
          AND event_type = 'auth.registration_failed'
          AND detail ->> 'reason' = 'registration_timeout'
    ) THEN
        RAISE EXCEPTION 'expired registration lifecycle is incomplete';
    END IF;

    IF EXISTS (
        SELECT 1 FROM public.bbs_user_profiles
        WHERE user_id = '55555555-6666-4777-8888-999999999999'::uuid
    ) OR EXISTS (
        SELECT 1 FROM public.bbs_password_credentials
        WHERE user_id = '55555555-6666-4777-8888-999999999999'::uuid
    ) OR EXISTS (
        SELECT 1 FROM public.bbs_legacy_mbse_bindings
        WHERE user_id = '55555555-6666-4777-8888-999999999999'::uuid
    ) THEN
        RAISE EXCEPTION 'expired registration retained authentication data';
    END IF;
END
$verify$;
