BEGIN;

DELETE FROM public.bbs_audit_events
WHERE actor_user_id = '33333333-4444-4555-8666-777777777777'::uuid
   OR subject_user_id = '33333333-4444-4555-8666-777777777777'::uuid;

DELETE FROM public.bbs_terminal_sessions
WHERE user_id = '33333333-4444-4555-8666-777777777777'::uuid;

DELETE FROM public.bbs_users
WHERE user_id = '33333333-4444-4555-8666-777777777777'::uuid;

COMMIT;
