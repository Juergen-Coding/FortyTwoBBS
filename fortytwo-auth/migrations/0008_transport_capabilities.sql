BEGIN;

-- Separate the general account state from transport-specific authorization.
-- New registrations will receive bbs_user only; SSH access is granted later.
INSERT INTO public.bbs_roles (role_name)
VALUES
    ('bbs_user'),
    ('ssh_access'),
    ('sysop')
ON CONFLICT (role_name) DO NOTHING;

INSERT INTO public.bbs_capabilities (capability_name)
VALUES
    ('terminal.login.telnet'),
    ('terminal.login.ssh'),
    ('terminal.login.local'),
    ('admin.user.ssh_access')
ON CONFLICT (capability_name) DO NOTHING;

INSERT INTO public.bbs_role_capabilities (role_id, capability_id)
SELECT r.role_id, c.capability_id
FROM public.bbs_roles AS r
JOIN public.bbs_capabilities AS c
  ON (r.role_name = 'bbs_user'
      AND c.capability_name = 'terminal.login.telnet')
  OR (r.role_name = 'ssh_access'
      AND c.capability_name = 'terminal.login.ssh')
  OR (r.role_name = 'sysop'
      AND c.capability_name IN (
          'terminal.login.local',
          'admin.user.ssh_access'
      ))
ON CONFLICT (role_id, capability_id) DO NOTHING;

-- Before this migration every active account could use both Telnet and SSH.
-- Preserve that established behaviour while new registrations start without
-- the separate ssh_access role.
WITH granted_roles AS (
    INSERT INTO public.bbs_user_roles (user_id, role_id)
    SELECT u.user_id, r.role_id
    FROM public.bbs_users AS u
    CROSS JOIN public.bbs_roles AS r
    WHERE u.account_state = 'active'
      AND u.deleted_at IS NULL
      AND r.role_name IN ('bbs_user', 'ssh_access')
    ON CONFLICT (user_id, role_id) DO NOTHING
    RETURNING user_id
),
changed_users AS MATERIALIZED (
    SELECT DISTINCT user_id
    FROM granted_roles
),
revision_update AS (
    UPDATE public.bbs_users AS u
    SET authz_revision = u.authz_revision + 1,
        updated_at = CURRENT_TIMESTAMP
    FROM changed_users AS changed
    WHERE u.user_id = changed.user_id
    RETURNING u.user_id, u.authz_revision
)
INSERT INTO public.bbs_audit_events (
    actor_user_id,
    subject_user_id,
    event_type,
    detail
)
SELECT
    NULL,
    updated.user_id,
    'admin.transport_roles_migrated',
    pg_catalog.jsonb_build_object(
        'roles', pg_catalog.jsonb_build_array('bbs_user', 'ssh_access'),
        'authz_revision', updated.authz_revision,
        'reason', 'preserve_pre_b4_3_transport_access'
    )
FROM revision_update AS updated;

COMMIT;
