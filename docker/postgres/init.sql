-- GhostPortal — Project-Apocalypse
-- PostgreSQL initialization script
-- Copyright (C) 2026 Spade — AGPL-3.0
--
-- This script runs once when the PostgreSQL container is first initialized.
-- Flask-Migrate (Alembic) handles the actual schema creation via:
--   flask db upgrade
-- This script only sets up the database-level configuration.

-- Ensure the database uses UTC timezone
ALTER DATABASE ghostportal SET timezone TO 'UTC';

-- Enable UUID generation extension (used for gen_random_uuid())
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Enable the pg_trgm extension for fuzzy text search (used in duplicate detection)
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Grant all privileges to the application user
GRANT ALL PRIVILEGES ON DATABASE ghostportal TO nduser;

-- Set default text search configuration
ALTER DATABASE ghostportal SET default_text_search_config TO 'pg_catalog.english';

-- Log initialization complete
DO $$
BEGIN
    RAISE NOTICE 'GhostPortal PostgreSQL initialization complete.';
    RAISE NOTICE 'Run "flask db upgrade" to create the schema.';
END $$;
