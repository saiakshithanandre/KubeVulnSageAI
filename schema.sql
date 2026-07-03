-- =====================================================================
-- CVE storage schema (CVE JSON Record Format 5.x)
-- Hybrid model: typed core columns for querying + full raw JSONB so
-- nothing from the original record is ever lost.
-- Designed to be idempotent-friendly for delta feeds (re-run safe).
-- =====================================================================

CREATE TABLE IF NOT EXISTS cves (
                                    cve_id              text PRIMARY KEY,
                                    state               text        NOT NULL,
                                    assigner_org_id     uuid,
                                    assigner_short_name text,
                                    date_reserved       timestamptz,
                                    date_published      timestamptz,
                                    date_updated        timestamptz,
                                    title               text,
                                    description         text,                 -- English CNA description
                                    raw                 jsonb       NOT NULL, -- complete original record
                                    ingested_at         timestamptz NOT NULL DEFAULT now()
    );

-- One row per affected vendor/product/version tuple
CREATE TABLE IF NOT EXISTS cve_affected (
                                            id            bigserial PRIMARY KEY,
                                            cve_id        text NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    vendor        text,
    product       text,
    version       text,
    less_than     text,
    version_type  text,
    status        text
    );

-- One row per reference URL
CREATE TABLE IF NOT EXISTS cve_references (
                                              id      bigserial PRIMARY KEY,
                                              cve_id  text NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    url     text NOT NULL,
    name    text,
    tags    text[]
    );

-- One row per CWE / problem-type description
CREATE TABLE IF NOT EXISTS cve_problem_types (
                                                 id           bigserial PRIMARY KEY,
                                                 cve_id       text NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    cwe_id       text,
    description  text,
    source       text                         -- 'cna' or 'adp'
    );

-- One row per CVSS metric block (metrics can appear in CNA and/or ADP)
CREATE TABLE IF NOT EXISTS cve_metrics (
                                           id                     bigserial PRIMARY KEY,
                                           cve_id                 text NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    source                 text,               -- 'cna' or 'adp'
    cvss_version           text,               -- e.g. '3.1'
    base_score             numeric(3,1),
    base_severity          text,
    vector_string          text,
    attack_vector          text,
    attack_complexity      text,
    privileges_required    text,
    user_interaction       text,
    scope                  text,
    confidentiality_impact text,
    integrity_impact       text,
    availability_impact    text
    );

-- ---------------------------------------------------------------------
-- Indexes for common access patterns
-- ---------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_cves_published      ON cves (date_published);
CREATE INDEX IF NOT EXISTS idx_cves_state          ON cves (state);
CREATE INDEX IF NOT EXISTS idx_cves_raw_gin        ON cves USING gin (raw);

CREATE INDEX IF NOT EXISTS idx_affected_vendor     ON cve_affected (vendor);
CREATE INDEX IF NOT EXISTS idx_affected_product    ON cve_affected (product);

CREATE INDEX IF NOT EXISTS idx_metrics_severity    ON cve_metrics (base_severity);
CREATE INDEX IF NOT EXISTS idx_metrics_score       ON cve_metrics (base_score);

CREATE INDEX IF NOT EXISTS idx_problem_cwe         ON cve_problem_types (cwe_id);