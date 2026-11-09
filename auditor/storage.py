from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DB = Path(os.getenv("AUDITOR_DB_PATH", "data/auditor.db"))


def connect(path: Path | str | None = None) -> sqlite3.Connection:
    db = Path(path or DEFAULT_DB)
    if str(db) != ":memory:":
        db.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db(path: Path | str | None = None) -> None:
    with connect(path) as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS audits (
            id TEXT PRIMARY KEY, created_at TEXT NOT NULL, system_name TEXT NOT NULL,
            scope TEXT NOT NULL, mode TEXT NOT NULL, catalog_version TEXT NOT NULL,
            reviewer TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id TEXT NOT NULL REFERENCES audits(id),
            rule_id TEXT NOT NULL, rule_version TEXT NOT NULL, title TEXT NOT NULL,
            domain TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
            rationale TEXT NOT NULL, evidence TEXT NOT NULL, frameworks_json TEXT NOT NULL,
            method TEXT NOT NULL, raw_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id TEXT NOT NULL,
            created_at TEXT NOT NULL, event TEXT NOT NULL, details_json TEXT NOT NULL
        );
        """)


def save_audit(system_name: str, scope: str, mode: str, catalog_version: str, reviewer: str, findings: list[dict[str, Any]], path: Path | str | None = None) -> str:
    audit_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    summary = f"{len(findings)} controls assessed"
    with connect(path) as con:
        con.execute("INSERT INTO audits VALUES (?,?,?,?,?,?,?,?)", (audit_id, now, system_name, scope, mode, catalog_version, reviewer, summary))
        for f in findings:
            con.execute("INSERT INTO findings (audit_id,rule_id,rule_version,title,domain,severity,status,rationale,evidence,frameworks_json,method,raw_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (audit_id, f["rule_id"], f["rule_version"], f["title"], f["domain"], f["severity"], f["status"], f["rationale"], f.get("evidence", ""), json.dumps(f.get("frameworks", {})), f.get("method", "unknown"), json.dumps(f, ensure_ascii=False)))
        con.execute("INSERT INTO audit_log (audit_id,created_at,event,details_json) VALUES (?,?,?,?)", (audit_id, now, "audit.created", json.dumps({"system_name": system_name, "mode": mode, "finding_count": len(findings)})))
    return audit_id


def list_audits(path: Path | str | None = None) -> list[dict[str, Any]]:
    init_db(path)
    with connect(path) as con:
        return [dict(r) for r in con.execute("SELECT * FROM audits ORDER BY created_at DESC")]


def get_findings(audit_id: str, path: Path | str | None = None) -> list[dict[str, Any]]:
    with connect(path) as con:
        rows = con.execute("SELECT * FROM findings WHERE audit_id=? ORDER BY severity,rule_id", (audit_id,)).fetchall()
    findings = []
    for row in rows:
        item = json.loads(row["raw_json"])
        item.update(dict(row))
        item["frameworks"] = json.loads(row["frameworks_json"])
        findings.append(item)
    return findings


def get_log(audit_id: str, path: Path | str | None = None) -> list[dict[str, Any]]:
    with connect(path) as con:
        return [dict(r) for r in con.execute("SELECT * FROM audit_log WHERE audit_id=? ORDER BY id", (audit_id,))]


def dashboard_summary(path: Path | str | None = None) -> dict[str, Any]:
    """Aggregate current audit records for the overview dashboard."""
    init_db(path)
    with connect(path) as con:
        audits = con.execute("SELECT COUNT(*) AS audit_count, COUNT(DISTINCT system_name) AS system_count FROM audits").fetchone()
        findings = con.execute("""
            SELECT f.status, f.severity, COUNT(*) AS n
            FROM findings f JOIN audits a ON a.id=f.audit_id
            WHERE a.id IN (SELECT id FROM audits a2 WHERE a2.created_at=(SELECT MAX(created_at) FROM audits a3 WHERE a3.system_name=a2.system_name))
            GROUP BY f.status, f.severity
        """).fetchall()
        recent = con.execute("""
            SELECT a.id, a.created_at, a.system_name, a.mode, a.reviewer,
                   COUNT(f.id) AS control_count,
                   SUM(CASE WHEN f.status='fail' THEN 1 ELSE 0 END) AS failed_count,
                   SUM(CASE WHEN f.status='needs-review' THEN 1 ELSE 0 END) AS review_count
            FROM audits a LEFT JOIN findings f ON f.audit_id=a.id
            GROUP BY a.id ORDER BY a.created_at DESC LIMIT 8
        """).fetchall()
    latest = {}
    for row in findings:
        key = row["status"]
        latest[key] = latest.get(key, 0) + row["n"]
    severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for row in findings:
        if row["status"] in {"fail", "needs-review"} and row["severity"] in severity:
            severity[row["severity"]] += row["n"]
    return {"audit_count": audits["audit_count"], "system_count": audits["system_count"], "latest_status_counts": latest, "open_severity_counts": severity, "recent": [dict(r) for r in recent]}
