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
                    hash TEXT NOT NULL UNIQUE
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_trace ON audit_events(trace_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(timestamp)")
            conn.commit()

    def append(self, *, trace_id: str, task: str, tool: str, args: dict,
               decision: str, risk_level: str, reasons: list[str], source: str,
               tainted: bool, result_summary: str, latency_ms: float) -> dict:
        with self.lock, closing(self.connect()) as conn:
            last = conn.execute("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
            prev_hash = last["hash"] if last else "GENESIS"
            timestamp = datetime.now(timezone.utc).isoformat()
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
                "result_summary": result_summary,
                "latency_ms": round(latency_ms, 3),
                "prev_hash": prev_hash,
            }
            event_hash = hashlib.sha256((prev_hash + canonical_json(payload)).encode()).hexdigest()
            cursor = conn.execute("""
                INSERT INTO audit_events (
                    timestamp, trace_id, task, tool, args_json, decision, risk_level,
                    reasons_json, source, tainted, result_summary, latency_ms, prev_hash, hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, trace_id, task, tool, canonical_json(args), decision, risk_level,
                canonical_json(reasons), source, int(tainted), result_summary[:2000],
                latency_ms, prev_hash, event_hash,
            ))
            conn.commit()
            payload.update({"seq": cursor.lastrowid, "hash": event_hash})
            return payload

    @staticmethod
    def _row(row: sqlite3.Row) -> dict:
        value = dict(row)
        value["args"] = json.loads(value.pop("args_json"))
        value["reasons"] = json.loads(value.pop("reasons_json"))
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
            """).fetchone()
            risks = conn.execute(
                "SELECT risk_level, COUNT(*) count FROM audit_events GROUP BY risk_level"
            ).fetchall()
            tools = conn.execute(
                "SELECT tool, COUNT(*) count FROM audit_events GROUP BY tool ORDER BY count DESC"
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
