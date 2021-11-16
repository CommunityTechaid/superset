-- Create read-only user for superset 
CREATE USER superset_ro WITH PASSWORD '<password>';
GRANT CONNECT ON DATABASE superset  TO superset_ro;
GRANT USAGE ON SCHEMA public TO superset_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO superset_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT SELECT ON TABLES TO superset_ro;