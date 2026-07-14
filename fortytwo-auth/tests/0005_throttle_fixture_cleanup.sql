BEGIN;

DELETE FROM public.bbs_audit_events
WHERE subject_user_id = '7f4a42b3-0005-4a11-8b32-42b3f00d0051'::uuid
   OR detail ->> 'login_name' = 'b3_throttle_missing_7f4a';

DELETE FROM public.bbs_users
WHERE user_id = '7f4a42b3-0005-4a11-8b32-42b3f00d0051'::uuid;

COMMIT;
