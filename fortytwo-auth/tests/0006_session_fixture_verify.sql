DO $verify$
DECLARE
    session_count INTEGER;
    audit_count INTEGER;
BEGIN
    -- A successful login must clear the complete persistent failure window.
    IF NOT EXISTS (
        SELECT 1
        FROM public.bbs_password_credentials
        WHERE user_id = '33333333-4444-4555-8666-777777777777'::uuid
          AND failed_count = 0
          AND last_failed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'password failure counters were not reset';
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
      AND closed_at IS NULL;

    IF session_count <> 1 THEN
        RAISE EXCEPTION 'expected one open terminal session, found %',
            session_count;
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
      AND a.detail ->> 'protocol' = 'ssh'
      AND a.detail ->> 'auth_method' = 'password'
      AND (a.detail ->> 'auth_epoch')::bigint = 42
      AND (a.detail ->> 'authz_revision')::bigint = 7
      AND a.detail ->> 'tty_device' = '/dev/pts/42'
      AND a.detail ->> 'node_id' = 'node-session-test';

    IF audit_count <> 1 THEN
        RAISE EXCEPTION 'expected one matching success audit, found %',
            audit_count;
    END IF;
END
$verify$;
