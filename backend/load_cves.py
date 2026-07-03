#!/usr/bin/env python3
"""
Load CVE JSON Record Format 5.x files into Postgres.

Usage:
    python load_cves.py --dsn "postgresql://user:pass@host:5432/dbname" \
                        --path /path/to/deltaCves \
                        [--schema schema.sql]

- Accepts a directory of *.json CVE records, a .zip of them, or a single file.
- Idempotent: re-running upserts the core row and replaces child rows, so it is
  safe to feed successive delta drops without creating duplicates.
- Nothing is discarded: the full original record is stored in cves.raw (JSONB).
"""

import argparse
import glob
import json
import os
import sys
import tempfile
import zipfile

import psycopg2
from psycopg2.extras import execute_values, Json


def parse_dt(v):
    """CVE timestamps are ISO-8601; hand them to Postgres as-is (it parses them)."""
    return v or None


def english_description(container):
    for d in container.get("descriptions", []) or []:
        if d.get("lang", "").lower().startswith("en"):
            return d.get("value")
    descs = container.get("descriptions", []) or []
    return descs[0].get("value") if descs else None


def iter_containers(record):
    """Yield (source, container) for the CNA and each ADP container."""
    containers = record.get("containers", {})
    cna = containers.get("cna")
    if cna:
        yield "cna", cna
    for adp in containers.get("adp", []) or []:
        yield "adp", adp


def extract_rows(record):
    """Turn one CVE record into flat rows for each table."""
    meta = record.get("cveMetadata", {})
    cve_id = meta["cveId"]
    containers = record.get("containers", {})
    cna = containers.get("cna", {}) or {}

    # title can live in cna or in an adp container
    title = cna.get("title")
    if not title:
        for _, cont in iter_containers(record):
            if cont.get("title"):
                title = cont["title"]
                break

    core = (
        cve_id,
        meta.get("state"),
        meta.get("assignerOrgId"),
        meta.get("assignerShortName"),
        parse_dt(meta.get("dateReserved")),
        parse_dt(meta.get("datePublished")),
        parse_dt(meta.get("dateUpdated")),
        title,
        english_description(cna),
        Json(record),
    )

    affected = []
    for a in cna.get("affected", []) or []:
        vendor = a.get("vendor")
        product = a.get("product")
        versions = a.get("versions") or [{}]
        for v in versions:
            affected.append((
                cve_id, vendor, product,
                v.get("version"), v.get("lessThan"),
                v.get("versionType"), v.get("status"),
            ))

    references, problem_types, metrics = [], [], []
    for source, cont in iter_containers(record):
        for r in cont.get("references", []) or []:
            url = r.get("url")
            if url:
                references.append((cve_id, url, r.get("name"), r.get("tags") or None))

        for pt in cont.get("problemTypes", []) or []:
            for de in pt.get("descriptions", []) or []:
                cwe = de.get("cweId")
                desc = de.get("description")
                if cwe or desc:
                    problem_types.append((cve_id, cwe, desc, source))

        for m in cont.get("metrics", []) or []:
            for key, cvss in m.items():
                if not key.lower().startswith("cvss") or not isinstance(cvss, dict):
                    continue
                metrics.append((
                    cve_id, source, cvss.get("version"),
                    cvss.get("baseScore"), cvss.get("baseSeverity"),
                    cvss.get("vectorString"), cvss.get("attackVector"),
                    cvss.get("attackComplexity"), cvss.get("privilegesRequired"),
                    cvss.get("userInteraction"), cvss.get("scope"),
                    cvss.get("confidentialityImpact"), cvss.get("integrityImpact"),
                    cvss.get("availabilityImpact"),
                ))

    return core, affected, references, problem_types, metrics


def load_file_list(path):
    """Return a list of JSON file paths from a dir, zip, or single file."""
    if os.path.isdir(path):
        return sorted(glob.glob(os.path.join(path, "**", "*.json"), recursive=True))
    if path.endswith(".zip"):
        tmp = tempfile.mkdtemp(prefix="cve_")
        with zipfile.ZipFile(path) as z:
            z.extractall(tmp)
        return sorted(glob.glob(os.path.join(tmp, "**", "*.json"), recursive=True))
    return [path]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True, help="Postgres connection string")
    ap.add_argument("--path", required=True, help="Directory, .zip, or single .json")
    ap.add_argument("--schema", help="Optional path to schema.sql to run first")
    args = ap.parse_args()

    files = load_file_list(args.path)
    if not files:
        sys.exit(f"No JSON files found at {args.path}")

    conn = psycopg2.connect(args.dsn)
    conn.autocommit = False
    cur = conn.cursor()

    if args.schema:
        with open(args.schema) as fh:
            cur.execute(fh.read())

    n = 0
    for fp in files:
        with open(fp) as fh:
            record = json.load(fh)
        core, affected, references, problem_types, metrics = extract_rows(record)
        cve_id = core[0]

        # Upsert core row (idempotent on re-run)
        cur.execute(
            """
            INSERT INTO cves (cve_id, state, assigner_org_id, assigner_short_name,
                              date_reserved, date_published, date_updated,
                              title, description, raw)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (cve_id) DO UPDATE SET
                state=EXCLUDED.state,
                assigner_org_id=EXCLUDED.assigner_org_id,
                assigner_short_name=EXCLUDED.assigner_short_name,
                date_reserved=EXCLUDED.date_reserved,
                date_published=EXCLUDED.date_published,
                date_updated=EXCLUDED.date_updated,
                title=EXCLUDED.title,
                description=EXCLUDED.description,
                raw=EXCLUDED.raw,
                ingested_at=now();
            """,
            core,
        )

        # Replace child rows so an updated record stays consistent
        for tbl in ("cve_affected", "cve_references",
                    "cve_problem_types", "cve_metrics"):
            cur.execute(f"DELETE FROM {tbl} WHERE cve_id=%s", (cve_id,))

        if affected:
            execute_values(cur,
                "INSERT INTO cve_affected (cve_id,vendor,product,version,less_than,version_type,status) VALUES %s",
                affected)
        if references:
            execute_values(cur,
                "INSERT INTO cve_references (cve_id,url,name,tags) VALUES %s",
                references)
        if problem_types:
            execute_values(cur,
                "INSERT INTO cve_problem_types (cve_id,cwe_id,description,source) VALUES %s",
                problem_types)
        if metrics:
            execute_values(cur,
                """INSERT INTO cve_metrics
                   (cve_id,source,cvss_version,base_score,base_severity,vector_string,
                    attack_vector,attack_complexity,privileges_required,user_interaction,
                    scope,confidentiality_impact,integrity_impact,availability_impact)
                   VALUES %s""",
                metrics)
        n += 1

    conn.commit()
    cur.close()
    conn.close()
    print(f"Loaded {n} CVE record(s).")


if __name__ == "__main__":
    main()