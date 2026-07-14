DO $verify$
DECLARE
    failure_count INTEGER;
    audit_count INTEGER;
    unknown_count INTEGER;
BEGIN
    SELECT c.failed_count
    INTO failure_count
    FROM public.bbs_password_credentials AS c
    WHERE c.user_id = '7f4a42b3-0005-4a11-8b32-42b3f00d0051'::uuid
      AND c.last_failed_at IS NOT NULL;

    IF failure_count <> 5 THEN
        RAISE EXCEPTION 'expected failed_count 5, got %', failure_count;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public.bbs_users
        WHERE user_id = '7f4a42b3-0005-4a11-8b32-42b3f00d0051'::uuid
          AND throttled_until > CURRENT_TIMESTAMP
    ) THEN
        RAISE EXCEPTION 'temporary throttle was not stored';
    END IF;

    SELECT COUNT(*)
    INTO audit_count
    FROM public.bbs_audit_events
    WHERE subject_user_id = '7f4a42b3-0005-4a11-8b32-42b3f00d0051'::uuid
      AND event_type = 'auth.password_failed'
      AND detail ->> 'reason' = 'wrong_password'
      AND detail ->> 'protocol' = 'ssh'
      AND NOT (detail ? 'password');

    IF audit_count <> 5 THEN
        RAISE EXCEPTION 'expected 5 password failure audits, got %', audit_count;
    END IF;

    SELECT COUNT(*)
    INTO unknown_count
    FROM public.bbs_audit_events
    WHERE subject_user_id IS NULL
      AND event_type = 'auth.login_rejected'
      AND detail ->> 'reason' = 'unknown_user'
      AND detail ->> 'login_name' = 'b3_throttle_missing_7f4a'
      AND detail ->> 'protocol' = 'telnet'
      AND NOT (detail ? 'password');

    IF unknown_count <> 1 THEN
        RAISE EXCEPTION 'expected one unknown-user audit, got %', unknown_count;
    END IF;
END
$verify$;
