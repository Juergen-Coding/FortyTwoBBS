DO $verify$
DECLARE
    session_count INTEGER;
    audit_count INTEGER;
BEGIN
    -- A successful password match clears the complete persistent failure
    -- window even when the requested transport is not authorized.
    IF NOT EXISTS (
        SELECT 1
        FROM public.bbs_password_credentials
        WHERE user_id = '33333333-4444-4555-8666-777777777777'::uuid
          AND failed_count = 0
          AND last_failed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'success fixture failure counters were not reset';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public.bbs_password_credentials
        WHERE user_id = '44444444-5555-4666-8777-888888888888'::uuid
          AND failed_count = 0
          AND last_failed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'no-SSH fixture failure counters were not reset';
    END IF;

    SELECT COUNT(*) INTO session_count
    FROM public.bbs_terminal_sessions
    WHERE user_id = '33333333-4444-4555-8666-777777777777'::uuid
      AND protocol = 'ssh'
      AND auth_method = 'password'
      AND source_ip = '192.0.2.99'::inet
      AND tty_device = '/dev/pts/42'
      AND node_id = 'node-session-test'
      AND auth_epoch = 42
      AND closed_at IS NOT NULL
      AND ended_reason = 'integration_test_complete';

    IF session_count <> 1 THEN
        RAISE EXCEPTION 'expected one closed SSH session, found %',
            session_count;
    END IF;

    SELECT COUNT(*) INTO session_count
    FROM public.bbs_terminal_sessions
    WHERE user_id = '44444444-5555-4666-8777-888888888888'::uuid
      AND protocol = 'ssh';

    IF session_count <> 0 THEN
        RAISE EXCEPTION 'SSH denial created % terminal sessions',
            session_count;
    END IF;

    SELECT COUNT(*) INTO session_count
    FROM public.bbs_terminal_sessions
    WHERE user_id = '44444444-5555-4666-8777-888888888888'::uuid
      AND protocol = 'telnet'
      AND auth_method = 'password'
      AND source_ip = '192.0.2.100'::inet
      AND tty_device = '/dev/pts/43'
      AND node_id = 'node-no-ssh-test'
      AND auth_epoch = 43
      AND closed_at IS NOT NULL
      AND ended_reason = 'integration_test_complete';

    IF session_count <> 1 THEN
        RAISE EXCEPTION 'expected one closed Telnet session, found %',
            session_count;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.bbs_user_roles AS ur
        JOIN public.bbs_roles AS r ON r.role_id = ur.role_id
        WHERE ur.user_id = '44444444-5555-4666-8777-888888888888'::uuid
          AND r.role_name = 'ssh_access'
    ) THEN
        RAISE EXCEPTION 'no-SSH fixture unexpectedly owns ssh_access';
    END IF;

    SELECT COUNT(*) INTO audit_count
    FROM public.bbs_audit_events AS a
    JOIN public.bbs_terminal_sessions AS s
      ON s.session_id = a.session_id
    WHERE a.actor_user_id = '33333333-4444-4555-8666-777777777777'::uuid
      AND a.subject_user_id = '33333333-4444-4555-8666-777777777777'::uuid
      AND a.event_type = 'auth.login_succeeded'
      AND a.source_ip = '192.0.2.99'::inet
      AND a.detail ->> 'login_name' = 'b3_session_test_3333'
      AND a.detail ->> 'legacy_name' = 'b3sess'
      AND a.detail ->> 'protocol' = 'ssh'
      AND a.detail ->> 'required_capability' = 'terminal.login.ssh'
      AND a.detail ->> 'auth_method' = 'password'
      AND (a.detail ->> 'auth_epoch')::bigint = 42
      AND (a.detail ->> 'authz_revision')::bigint = 7
      AND a.detail ->> 'tty_device' = '/dev/pts/42'
      AND a.detail ->> 'node_id' = 'node-session-test';

    IF audit_count <> 1 THEN
        RAISE EXCEPTION 'expected one matching SSH success audit, found %',
            audit_count;
    END IF;

    SELECT COUNT(*) INTO audit_count
    FROM public.bbs_audit_events
    WHERE actor_user_id IS NULL
      AND subject_user_id = '44444444-5555-4666-8777-888888888888'::uuid
      AND session_id IS NULL
      AND event_type = 'auth.login_rejected'
      AND source_ip = '192.0.2.100'::inet
      AND detail ->> 'reason' = 'transport_not_authorized'
      AND detail ->> 'login_name' = 'b43_no_ssh_test'
      AND detail ->> 'legacy_name' = 'b43nosh'
      AND detail ->> 'protocol' = 'ssh'
      AND detail ->> 'required_capability' = 'terminal.login.ssh'
      AND detail ->> 'auth_method' = 'password'
      AND (detail ->> 'auth_epoch')::bigint = 43
      AND (detail ->> 'authz_revision')::bigint = 1
      AND detail ->> 'tty_device' = '/dev/pts/43'
      AND detail ->> 'node_id' = 'node-no-ssh-test';

    IF audit_count <> 1 THEN
        RAISE EXCEPTION 'expected one matching SSH denial audit, found %',
            audit_count;
    END IF;

    SELECT COUNT(*) INTO audit_count
    FROM public.bbs_audit_events AS a
    JOIN public.bbs_terminal_sessions AS s
      ON s.session_id = a.session_id
    WHERE a.actor_user_id = '44444444-5555-4666-8777-888888888888'::uuid
      AND a.subject_user_id = '44444444-5555-4666-8777-888888888888'::uuid
      AND a.event_type = 'auth.login_succeeded'
      AND a.detail ->> 'protocol' = 'telnet'
      AND a.detail ->> 'required_capability' = 'terminal.login.telnet';

    IF audit_count <> 1 THEN
        RAISE EXCEPTION 'expected one matching Telnet success audit, found %',
            audit_count;
    END IF;

    SELECT COUNT(*) INTO audit_count
    FROM public.bbs_audit_events AS a
    JOIN public.bbs_terminal_sessions AS s
      ON s.session_id = a.session_id
    WHERE a.subject_user_id IN (
              '33333333-4444-4555-8666-777777777777'::uuid,
              '44444444-5555-4666-8777-888888888888'::uuid
          )
      AND a.event_type = 'auth.terminal_session_closed'
      AND a.detail ->> 'ended_reason' = 'integration_test_complete';

    IF audit_count <> 2 THEN
        RAISE EXCEPTION 'expected two matching close audits, found %',
            audit_count;
    END IF;
END
$verify$;
