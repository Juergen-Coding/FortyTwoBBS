BEGIN;

-- Keine pauschalen Laufzeitrechte auf bestehende Objekte.
REVOKE ALL ON ALL TABLES IN SCHEMA public
FROM fortytwo_authd;

REVOKE ALL ON ALL SEQUENCES IN SCHEMA public
FROM fortytwo_authd;

-- Keine automatischen Rechte auf Objekte späterer Migrationen.
-- Jede neue Migration muss die benötigten Rechte ausdrücklich vergeben.
ALTER DEFAULT PRIVILEGES
FOR ROLE fortytwo_db_owner
IN SCHEMA public
REVOKE ALL ON TABLES FROM fortytwo_authd;

ALTER DEFAULT PRIVILEGES
FOR ROLE fortytwo_db_owner
IN SCHEMA public
REVOKE ALL ON SEQUENCES FROM fortytwo_authd;

-- Identitäten und Credentials werden logisch geändert, nicht gelöscht.
GRANT SELECT, INSERT, UPDATE
ON TABLE
    bbs_users,
    bbs_user_profiles,
    bbs_password_credentials,
    bbs_roles,
    bbs_capabilities,
    bbs_terminal_sessions
TO fortytwo_authd;

-- Zuordnungstabellen benötigen auch DELETE für gezielten Rechteentzug.
GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLE
    bbs_role_capabilities,
    bbs_user_roles
TO fortytwo_authd;

-- Das Audit-Log ist für den Auth-Daemon nur les- und erweiterbar.
GRANT SELECT, INSERT
ON TABLE bbs_audit_events
TO fortytwo_authd;

-- BIGSERIAL-Sequenzen für Rollen, Capabilities und Audit-Ereignisse.
GRANT USAGE, SELECT
ON SEQUENCE
    bbs_roles_role_id_seq,
    bbs_capabilities_capability_id_seq,
    bbs_audit_events_event_id_seq
TO fortytwo_authd;

COMMIT;
