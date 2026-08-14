from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class AuditStore:
    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self.lock = threading.RLock()
        self._init_db()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with closing(self.connect()) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    task TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    args_json TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    tainted INTEGER NOT NULL,
                    result_summary TEXT NOT NULL,
                    latency_ms REAL NOT NULL,
                    prev_hash TEXT NOT NULL,
                    hash TEXT NOT NULL UNIQUE,
                    ct_trm_json TEXT NOT NULL DEFAULT '{}',
                    event_type TEXT NOT NULL DEFAULT 'decision',
                    call_id TEXT NOT NULL DEFAULT '',
                    execution_status TEXT NOT NULL DEFAULT '',
                    result_fingerprint TEXT NOT NULL DEFAULT '',
                    result_evidence_json TEXT NOT NULL DEFAULT '{}'
                )
            """)
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()
            }
            if "ct_trm_json" not in columns:
                conn.execute(
                    "ALTER TABLE audit_events "
                    "ADD COLUMN ct_trm_json TEXT NOT NULL DEFAULT '{}'"
                )
            if "event_type" not in columns:
                conn.execute(
                    "ALTER TABLE audit_events "
                    "ADD COLUMN event_type TEXT NOT NULL DEFAULT 'decision'"
                )
            if "call_id" not in columns:
                conn.execute(
                    "ALTER TABLE audit_events "
                    "ADD COLUMN call_id TEXT NOT NULL DEFAULT ''"
                )
            if "execution_status" not in columns:
                conn.execute(
                    "ALTER TABLE audit_events "
                    "ADD COLUMN execution_status TEXT NOT NULL DEFAULT ''"
                )
            if "result_fingerprint" not in columns:
                conn.execute(
                    "ALTER TABLE audit_events "
                    "ADD COLUMN result_fingerprint TEXT NOT NULL DEFAULT ''"
                )
            if "result_evidence_json" not in columns:
                conn.execute(
                    "ALTER TABLE audit_events "
                    "ADD COLUMN result_evidence_json TEXT NOT NULL DEFAULT '{}'"
                )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_trace ON audit_events(trace_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_call ON audit_events(call_id)")
            conn.commit()

    def append(self, *, trace_id: str, task: str, tool: str, args: dict,
               decision: str, risk_level: str, reasons: list[str], source: str,
               tainted: bool, result_summary: str, latency_ms: float,
               ct_trm: dict | None = None,
               event_type: str = "decision",
               call_id: str | None = None,
               execution_status: str | None = None,
               result_fingerprint: str | None = None,
               result_evidence: dict | None = None) -> dict:
        with self.lock, closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            normalized_event_type = str(event_type or "decision")
            normalized_call_id = str(call_id or "")
            normalized_execution_status = str(execution_status or "")
            normalized_result_fingerprint = str(result_fingerprint or "")
            normalized_result_evidence = result_evidence or {}
            if (
                normalized_event_type == "external_execution_result"
                and normalized_call_id
            ):
                existing = conn.execute(
                    "SELECT * FROM audit_events WHERE trace_id=? "
                    "AND call_id=? AND event_type=? ORDER BY seq DESC LIMIT 1",
                    (trace_id, normalized_call_id, normalized_event_type),
                ).fetchone()
                if existing is not None:
                    existing_fingerprint = str(
                        existing["result_fingerprint"] or ""
                    )
                    if (
                        not normalized_result_fingerprint
                        or existing_fingerprint != normalized_result_fingerprint
                    ):
                        conn.rollback()
                        raise ValueError(
                            "conflicting external execution result for "
                            f"{trace_id}/{normalized_call_id}"
                        )
                    conn.rollback()
                    return self._row(existing)
            last = conn.execute("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
            prev_hash = last["hash"] if last else "GENESIS"
            timestamp = datetime.now(timezone.utc).isoformat()
            normalized_latency = round(float(latency_ms), 3)
            normalized_summary = str(result_summary)[:2000]
            payload = {
                "timestamp": timestamp,
                "trace_id": trace_id,
                "task": task,
                "tool": tool,
                "args": args,
                "decision": decision,
                "risk_level": risk_level,
                "reasons": reasons,
                "source": source,
                "tainted": bool(tainted),
                "result_summary": normalized_summary,
                "latency_ms": normalized_latency,
                "prev_hash": prev_hash,
            }
            if ct_trm:
                payload["ct_trm"] = ct_trm
            if normalized_event_type != "decision":
                payload["event_type"] = normalized_event_type
            if normalized_call_id:
                payload["call_id"] = normalized_call_id
            if normalized_execution_status:
                payload["execution_status"] = normalized_execution_status
            if normalized_result_fingerprint:
                payload["result_fingerprint"] = normalized_result_fingerprint
            if normalized_result_evidence:
                payload["result_evidence"] = normalized_result_evidence
            event_hash = hashlib.sha256((prev_hash + canonical_json(payload)).encode()).hexdigest()
            cursor = conn.execute("""
                INSERT INTO audit_events (
                    timestamp, trace_id, task, tool, args_json, decision, risk_level,
                    reasons_json, source, tainted, result_summary, latency_ms,
                    prev_hash, hash, ct_trm_json, event_type, call_id,
                    execution_status, result_fingerprint, result_evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, trace_id, task, tool, canonical_json(args), decision, risk_level,
                canonical_json(reasons), source, int(tainted),
                normalized_summary, normalized_latency, prev_hash, event_hash,
                canonical_json(ct_trm or {}),
                normalized_event_type, normalized_call_id,
                normalized_execution_status,
                normalized_result_fingerprint,
                canonical_json(normalized_result_evidence),
            ))
            conn.commit()
            payload.update({"seq": cursor.lastrowid, "hash": event_hash})
            return payload

    def find_event(
        self,
        *,
        trace_id: str,
        call_id: str,
        event_type: str | None = None,
    ) -> dict | None:
        clauses = ["trace_id=?", "call_id=?"]
        params: list[Any] = [trace_id, call_id]
        if event_type is not None:
            clauses.append("event_type=?")
            params.append(event_type)
        with closing(self.connect()) as conn:
            row = conn.execute(
                "SELECT * FROM audit_events WHERE "
                + " AND ".join(clauses)
                + " ORDER BY seq DESC LIMIT 1",
                params,
            ).fetchone()
        return self._row(row) if row is not None else None

    def get_event(self, seq: int) -> dict | None:
        with closing(self.connect()) as conn:
            row = conn.execute(
                "SELECT * FROM audit_events WHERE seq=?",
                (int(seq),),
            ).fetchone()
        return self._row(row) if row is not None else None

    @staticmethod
    def _row(row: sqlite3.Row) -> dict:
        value = dict(row)
        value["args"] = json.loads(value.pop("args_json"))
        value["reasons"] = json.loads(value.pop("reasons_json"))
        value["ct_trm"] = json.loads(value.pop("ct_trm_json", "{}"))
        value["result_evidence"] = json.loads(
            value.pop("result_evidence_json", "{}")
        )
        value.setdefault("event_type", "decision")
        value.setdefault("call_id", "")
        value.setdefault("execution_status", "")
        value.setdefault("result_fingerprint", "")
        value["tainted"] = bool(value["tainted"])
        return value

    def list_events(self, limit: int = 100, trace_id: str | None = None) -> list[dict]:
        limit = max(1, min(limit, 500))
        with closing(self.connect()) as conn:
            if trace_id:
                rows = conn.execute(
                    "SELECT * FROM audit_events WHERE trace_id=? ORDER BY seq DESC LIMIT ?",
                    (trace_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?", (limit,)
                ).fetchall()
        return [self._row(row) for row in rows]

    def overview(self) -> dict:
        with closing(self.connect()) as conn:
            totals = conn.execute("""
                SELECT COUNT(*) AS calls,
                       SUM(CASE WHEN decision='deny' THEN 1 ELSE 0 END) AS blocked,
                       SUM(CASE WHEN decision='ask' THEN 1 ELSE 0 END) AS asked,
                       AVG(latency_ms) AS latency,
                       COUNT(DISTINCT trace_id) AS traces
                FROM audit_events
                WHERE event_type='decision'
            """).fetchone()
            risks = conn.execute(
                "SELECT risk_level, COUNT(*) count FROM audit_events "
                "WHERE event_type='decision' GROUP BY risk_level"
            ).fetchall()
            tools = conn.execute(
                "SELECT tool, COUNT(*) count FROM audit_events "
                "WHERE event_type='decision' GROUP BY tool ORDER BY count DESC"
            ).fetchall()
        calls = totals["calls"] or 0
        blocked = totals["blocked"] or 0
        return {
            "calls": calls,
            "blocked": blocked,
            "asked": totals["asked"] or 0,
            "traces": totals["traces"] or 0,
            "avg_latency_ms": round(totals["latency"] or 0, 2),
            "block_rate": round(blocked / calls * 100, 1) if calls else 0,
            "risks": {row["risk_level"]: row["count"] for row in risks},
            "tools": [{"tool": row["tool"], "count": row["count"]} for row in tools],
        }

    def verify(self) -> dict:
        return self.verify_path(self.db_path)

    @classmethod
    def verify_path(cls, db_path: Path) -> dict:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        with closing(conn):
            rows = conn.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
        expected_prev = "GENESIS"
        for row in rows:
            event = cls._row(row)
            payload = {
                "timestamp": event["timestamp"],
                "trace_id": event["trace_id"],
                "task": event["task"],
                "tool": event["tool"],
                "args": event["args"],
                "decision": event["decision"],
                "risk_level": event["risk_level"],
                "reasons": event["reasons"],
                "source": event["source"],
                "tainted": event["tainted"],
                "result_summary": event["result_summary"],
                "latency_ms": round(event["latency_ms"], 3),
                "prev_hash": event["prev_hash"],
            }
            if event.get("ct_trm"):
                payload["ct_trm"] = event["ct_trm"]
            if event.get("event_type", "decision") != "decision":
                payload["event_type"] = event["event_type"]
            if event.get("call_id"):
                payload["call_id"] = event["call_id"]
            if event.get("execution_status"):
                payload["execution_status"] = event["execution_status"]
            if event.get("result_fingerprint"):
                payload["result_fingerprint"] = event["result_fingerprint"]
            if event.get("result_evidence"):
                payload["result_evidence"] = event["result_evidence"]
            calculated = hashlib.sha256((expected_prev + canonical_json(payload)).encode()).hexdigest()
            if event["prev_hash"] != expected_prev or event["hash"] != calculated:
                return {"valid": False, "events": len(rows), "broken_at": event["seq"]}
            expected_prev = event["hash"]
        return {"valid": True, "events": len(rows), "head": expected_prev}

    def integrity_experiment(self) -> dict:
        """Tamper with an isolated DB copy and verify detection."""
        original = self.verify()
        if original["events"] == 0:
            return {
                "executed": False,
                "detected": False,
                "reason": "audit_log_empty",
                "original": original,
            }
        with tempfile.TemporaryDirectory() as tmp:
            clone_path = Path(tmp) / "tampered-audit.db"
            with closing(self.connect()) as source:
                clone = sqlite3.connect(clone_path)
                with closing(clone):
                    source.backup(clone)
            with closing(sqlite3.connect(clone_path)) as conn:
                conn.execute(
                    "UPDATE audit_events SET result_summary=result_summary || ? "
                    "WHERE seq=(SELECT MIN(seq) FROM audit_events)",
                    (" [TAMPERED]",),
                )
                conn.commit()
            tampered = self.verify_path(clone_path)
        return {
            "executed": True,
            "original": original,
            "tampered": tampered,
            "detected": original["valid"] and not tampered["valid"],
            "tamper_action": "modified result_summary in isolated database copy",
        }

    def reset(self) -> None:
        with self.lock, closing(self.connect()) as conn:
            conn.execute("DELETE FROM audit_events")
            conn.execute("DELETE FROM sqlite_sequence WHERE name='audit_events'")
            conn.commit()
