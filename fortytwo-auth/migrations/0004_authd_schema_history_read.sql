BEGIN;

-- fortytwo-authd may verify the applied schema version at startup, but it may
-- never modify the migration history.
REVOKE ALL ON TABLE public.fortytwo_schema_migrations FROM PUBLIC;
GRANT SELECT ON TABLE public.fortytwo_schema_migrations TO fortytwo_authd;

COMMIT;
