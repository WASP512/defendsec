#!/usr/bin/env python3
"""Ingest a small OSV query set into DefendSec advisories (Postgres or admin API).

Example:
  DEFENDSEC_DATABASE_URL=postgres://defendsec:defendsec@127.0.0.1:5432/defendsec \\
    python3 scripts/ingest-osv.py --packages openssl,openssh-server,git
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request

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


def upsert_postgres(advisories: list[dict]) -> int:
    import psycopg  # type: ignore

    url = os.environ.get("DEFENDSEC_DATABASE_URL") or os.environ.get("DATABASE_URL")
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--packages", default="openssl,openssh-server,git,curl")
    ap.add_argument("--ecosystem", default="Debian")
    ap.add_argument("--via", choices=["postgres", "admin"], default="postgres")
    ap.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()
    advisories: list[dict] = []
    for pkg in [p.strip() for p in args.packages.split(",") if p.strip()]:
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
    else:
        n = upsert_admin(advisories)
    print(f"upserted {n} advisories")


if __name__ == "__main__":
    main()
