#!/usr/bin/env python3
"""Ingest OSV advisories into DefendSec (Postgres or admin API).

When DEFENDSEC_DATABASE_URL is set and --packages is omitted, distinct package
names are read from devices.software JSONB. Use --packages to override.

Example:
  DEFENDSEC_DATABASE_URL=postgres://defendsec:defendsec@127.0.0.1:5432/defendsec \\
    python3 scripts/ingest-osv.py

  python3 scripts/ingest-osv.py --packages openssl,openssh-server,git
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

DEFAULT_PACKAGES = "openssl,openssh-server,git,curl"


def osv_query(package: str, ecosystem: str = "Debian") -> list[dict]:
    body = json.dumps({"package": {"name": package, "ecosystem": ecosystem}}).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    out = []
    for vuln in data.get("vulns") or []:
        cve = ""
        for alias in vuln.get("aliases") or []:
            if alias.startswith("CVE-"):
                cve = alias
                break
        severity = "medium"
        for sev in vuln.get("severity") or []:
            score = str(sev.get("score", ""))
            if score.startswith("CRITICAL") or score.startswith("9"):
                severity = "critical"
            elif score.startswith("HIGH") or score.startswith("7") or score.startswith("8"):
                severity = "high"
        below = "0"
        for affected in vuln.get("affected") or []:
            for r in affected.get("ranges") or []:
                for event in r.get("events") or []:
                    if "fixed" in event:
                        below = event["fixed"]
        out.append(
            {
                "id": vuln.get("id") or cve or package,
                "cve": cve,
                "package": package,
                "below": below,
                "severity": severity,
                "summary": (vuln.get("summary") or vuln.get("details") or "")[:400],
                "source": "osv",
            }
        )
    return out


def db_url() -> str | None:
    return os.environ.get("DEFENDSEC_DATABASE_URL") or os.environ.get("DATABASE_URL")


def distinct_packages_from_postgres() -> list[str]:
    import psycopg  # type: ignore

    url = db_url()
    if not url:
        return []
    with psycopg.connect(url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT elem->>'name' AS name
                FROM devices, jsonb_array_elements(software) AS elem
                WHERE elem->>'name' IS NOT NULL AND elem->>'name' <> ''
                ORDER BY name
                """
            )
            rows = cur.fetchall()
    return [row[0] for row in rows if row[0]]


def set_meta_postgres(key: str, value: str) -> None:
    import psycopg  # type: ignore

    url = db_url()
    if not url:
        return
    with psycopg.connect(url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO meta (key, value) VALUES (%s, %s)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
                """,
                (key, value),
            )
        conn.commit()


def upsert_postgres(advisories: list[dict]) -> int:
    import psycopg  # type: ignore

    url = db_url()
    if not url:
        raise SystemExit("set DEFENDSEC_DATABASE_URL or DATABASE_URL")
    n = 0
    with psycopg.connect(url) as conn:
        with conn.cursor() as cur:
            for a in advisories:
                cur.execute(
                    """
                    INSERT INTO advisories (id, cve, package, below, severity, summary, source, updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,now())
                    ON CONFLICT (id) DO UPDATE SET
                      cve=EXCLUDED.cve, package=EXCLUDED.package, below=EXCLUDED.below,
                      severity=EXCLUDED.severity, summary=EXCLUDED.summary, source=EXCLUDED.source, updated_at=now()
                    """,
                    (a["id"], a["cve"], a["package"], a["below"], a["severity"], a["summary"], a["source"]),
                )
                n += 1
        conn.commit()
    return n


def upsert_admin(advisories: list[dict]) -> int:
    token = os.environ.get("DEFENDSEC_ADMIN_TOKEN") or open("data/admin-token.txt").read().strip()
    url = os.environ.get("DEFENDSEC_APID_ADMIN", "http://127.0.0.1:47264") + "/v1/advisories"
    body = json.dumps({"advisories": advisories}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    return int(data.get("count") or 0)


def resolve_packages(args: argparse.Namespace) -> list[str]:
    if args.packages is not None:
        return [p.strip() for p in args.packages.split(",") if p.strip()]
    if db_url():
        pkgs = distinct_packages_from_postgres()
        if pkgs:
            print(f"packages from devices.software: {len(pkgs)}", file=sys.stderr)
            return pkgs
    return [p.strip() for p in DEFAULT_PACKAGES.split(",") if p.strip()]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--packages",
        default=None,
        help="comma-separated package names (overrides DB discovery)",
    )
    ap.add_argument("--ecosystem", default="Debian")
    ap.add_argument("--via", choices=["postgres", "admin"], default="postgres")
    ap.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()

    packages = resolve_packages(args)
    if not packages:
        print("no packages to query")
        return

    advisories: list[dict] = []
    for pkg in packages:
        try:
            found = osv_query(pkg, args.ecosystem)
        except Exception as exc:  # noqa: BLE001
            print(f"warn: {pkg}: {exc}", file=sys.stderr)
            continue
        advisories.extend(found[: args.limit])
    if not advisories:
        print("no advisories fetched")
        return
    if args.via == "postgres":
        n = upsert_postgres(advisories)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        set_meta_postgres("osv_last_ingest", ts)
        print(f"upserted {n} advisories; osv_last_ingest={ts}")
    else:
        n = upsert_admin(advisories)
        print(f"upserted {n} advisories")


if __name__ == "__main__":
    main()
