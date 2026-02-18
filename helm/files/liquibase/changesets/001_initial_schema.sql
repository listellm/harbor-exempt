--liquibase formatted sql

--changeset harbor-exempt:001_initial_schema
--comment: Complete schema for Harbor Exempt vulnerability management

-- Projects table
CREATE TABLE projects (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    name text UNIQUE NOT NULL,
    created_at timestamptz DEFAULT now()
);

-- Scans table
CREATE TABLE scans (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    image text NOT NULL,
    repository text NOT NULL,
    digest text,
    scanner text,
    tag text,
    push_time timestamptz,
    pull_time timestamptz,
    total_vulnerabilities int DEFAULT 0,
    critical int DEFAULT 0,
    high int DEFAULT 0,
    medium int DEFAULT 0,
    low int DEFAULT 0,
    unknown int DEFAULT 0,
    imported_at timestamptz DEFAULT now()
);

-- Vulnerabilities table
CREATE TABLE vulnerabilities (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    cve_id text NOT NULL,
    package text NOT NULL,
    repository text NOT NULL,
    installed_version text,
    fixed_version text,
    severity text NOT NULL,
    cvss_score numeric(3,1),
    description text,
    "references" text[],
    first_seen_at timestamptz DEFAULT now(),
    last_seen_at timestamptz DEFAULT now(),
    status text NOT NULL DEFAULT 'open',
    scan_id uuid REFERENCES scans(id),
    UNIQUE (project_id, cve_id, package, repository)
);

-- Acceptances table
CREATE TABLE acceptances (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    vulnerability_id uuid NOT NULL REFERENCES vulnerabilities(id),
    accepted_by text NOT NULL,
    justification text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz DEFAULT now(),
    revoked_at timestamptz,
    revoked_by text
);

-- CVE fix availability cache from OSV.dev
CREATE TABLE cve_fix_checks (
    cve_id        text PRIMARY KEY,
    fix_available boolean NOT NULL,
    fixed_versions jsonb,
    source        text NOT NULL DEFAULT 'osv',
    checked_at    timestamptz NOT NULL,
    raw_response  jsonb
);

-- Indexes
CREATE UNIQUE INDEX idx_vuln_project_cve_pkg_repo ON vulnerabilities (project_id, cve_id, package, repository);
CREATE INDEX idx_vuln_project_status ON vulnerabilities (project_id, status);
CREATE INDEX idx_vuln_project_repo ON vulnerabilities (project_id, repository);
CREATE INDEX idx_vuln_cve_id ON vulnerabilities (cve_id);
CREATE INDEX idx_vuln_severity ON vulnerabilities (severity);
CREATE INDEX idx_vuln_cvss_score ON vulnerabilities (cvss_score DESC NULLS LAST);
CREATE INDEX idx_vuln_project_cve_status ON vulnerabilities (project_id, cve_id, status);
CREATE INDEX idx_acceptance_vuln ON acceptances (vulnerability_id);
CREATE INDEX idx_acceptance_active ON acceptances (vulnerability_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_scans_project ON scans (project_id, imported_at DESC);
CREATE INDEX idx_fix_checks_stale ON cve_fix_checks (checked_at) WHERE fix_available = false;

--rollback DROP TABLE IF EXISTS cve_fix_checks CASCADE;
--rollback DROP TABLE IF EXISTS acceptances CASCADE;
--rollback DROP TABLE IF EXISTS vulnerabilities CASCADE;
--rollback DROP TABLE IF EXISTS scans CASCADE;
--rollback DROP TABLE IF EXISTS projects CASCADE;
