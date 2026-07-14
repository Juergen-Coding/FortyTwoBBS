BEGIN;

DELETE FROM public.bbs_users
WHERE user_id = '7f4a42b3-0005-4a11-8b32-42b3f00d0001'::uuid;

COMMIT;
