from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import closing
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


def _json_default(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    raise TypeError(
        f"Object of type {type(value).__name__} is not JSON serializable"
    )


def _json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )


class RuntimeStateStore:
    """Local SQLite state for resumable approvals and CT-TRM context."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, closing(self.connect()) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pending_approvals (
                    approval_id TEXT PRIMARY KEY,
                    trace_id TEXT NOT NULL,
                    call_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    task TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    args_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    tainted INTEGER NOT NULL,
                    allowed_tools_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            self._ensure_columns(conn, "pending_approvals", {
                "execute_flag": "INTEGER NOT NULL DEFAULT 1",
                "conversation_id": "TEXT",
                "status": "TEXT NOT NULL DEFAULT 'pending'",
                "resolved_at": "TEXT",
                "resolution_json": "TEXT NOT NULL DEFAULT '{}'",
                "expires_at": "REAL NOT NULL DEFAULT 0",
                "metadata_json": "TEXT NOT NULL DEFAULT '{}'",
                "claim_token": "TEXT",
                "claimed_at": "TEXT",
                "fusion_action": "TEXT",
                "risk_level": "TEXT",
                "reasons": "TEXT NOT NULL DEFAULT '[]'",
            })
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ct_trm_sources (
                    source_id TEXT PRIMARY KEY,
                    trace_id TEXT,
                    conversation_id TEXT,
                    source_json TEXT NOT NULL,
                    entities_json TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ct_sources_trace "
                "ON ct_trm_sources(trace_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ct_sources_conversation "
                "ON ct_trm_sources(conversation_id)"
            )
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ct_trm_chain_states (
                    trace_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.commit()
        self.purge_expired()

    @staticmethod
    def _ensure_columns(
        conn: sqlite3.Connection,
        table: str,
        columns: dict[str, str],
    ) -> None:
        existing = {
            row["name"]
            for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for name, definition in columns.items():
            if name not in existing:
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {name} {definition}"
                )

    def save_approval(
        self,
        approval_id: str,
        call: dict,
        *,
        execute: bool,
        ttl_seconds: int = 900,
        fusion_action: str = "ask",
        risk_level: str | None = None,
        reasons: list[str] | None = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        expires_at = time.time() + ttl_seconds
        with self._lock, closing(self.connect()) as conn:
            conn.execute("""
                INSERT INTO pending_approvals (
                    approval_id, trace_id, call_id, agent_id, task, tool,
                    args_json, source, tainted, allowed_tools_json, created_at,
                    execute_flag, conversation_id, status, resolved_at,
                    resolution_json, expires_at, metadata_json, claim_token,
                    claimed_at, fusion_action, risk_level, reasons
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending',
                          NULL, '{}', ?, ?, NULL, NULL, ?, ?, ?)
                ON CONFLICT(approval_id) DO UPDATE SET
                    trace_id=excluded.trace_id,
                    call_id=excluded.call_id,
                    agent_id=excluded.agent_id,
                    task=excluded.task,
                    tool=excluded.tool,
                    args_json=excluded.args_json,
                    source=excluded.source,
                    tainted=excluded.tainted,
                    allowed_tools_json=excluded.allowed_tools_json,
                    created_at=excluded.created_at,
                    execute_flag=excluded.execute_flag,
                    conversation_id=excluded.conversation_id,
                    status='pending',
                    resolved_at=NULL,
                    resolution_json='{}',
                    expires_at=excluded.expires_at,
                    metadata_json=excluded.metadata_json,
                    claim_token=NULL,
                    claimed_at=NULL,
                    fusion_action=excluded.fusion_action,
                    risk_level=excluded.risk_level,
                    reasons=excluded.reasons
            """, (
                approval_id,
                call["trace_id"],
                call["call_id"],
                call["agent_id"],
                call["task"],
                call["tool"],
                _json(call.get("args", {})),
                call.get("source", "agent"),
                int(bool(call.get("tainted", False))),
                _json(call.get("allowed_tools")),
                now,
                int(execute),
                call.get("conversation_id"),
                expires_at,
                _json(call.get("metadata", {})),
                fusion_action,
                risk_level,
                _json(reasons or []),
            ))
            conn.commit()

    def list_pending_approvals(self) -> list[dict]:
        self.purge_expired()
        with closing(self.connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM pending_approvals "
                "WHERE status='pending' ORDER BY created_at"
            ).fetchall()
        return [self._approval_row(row) for row in rows]

    def get_approval(self, approval_id: str) -> dict | None:
        self.purge_expired()
        with closing(self.connect()) as conn:
            row = conn.execute(
                "SELECT * FROM pending_approvals WHERE approval_id=?",
                (approval_id,),
            ).fetchone()
        return self._approval_row(row) if row is not None else None

    def claim_approval(
        self,
        approval_id: str,
        *,
        claim_token: str,
        retention_seconds: int = 900,
    ) -> dict | None:
        """Atomically claim a pending approval for exactly one resolver.

        SQLite owns the concurrency guarantee so separate store/proxy
        instances sharing this database cannot both acquire execution rights.
        """
        if not claim_token:
            raise ValueError("claim_token must not be empty")
        now_epoch = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()
        retained_until = now_epoch + retention_seconds
        with self._lock, closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                UPDATE pending_approvals
                SET status='expired', resolved_at=?,
                    resolution_json=?, expires_at=?
                WHERE approval_id=? AND status='pending'
                  AND expires_at > 0 AND expires_at < ?
                """,
                (
                    now_iso,
                    _json({
                        "fusion_action": "ask",
                        "action": "ask",
                        "approval_status": "expired",
                        "execution_authorized": False,
                        "execution_attempted": False,
                        "execution_status": "not_executed",
                        "reasons": ["approval_expired"],
                    }),
                    retained_until,
                    approval_id,
                    now_epoch,
                ),
            )
            cursor = conn.execute(
                """
                UPDATE pending_approvals
                SET status='resolving', claim_token=?, claimed_at=?,
                    expires_at=?
                WHERE approval_id=? AND status='pending'
                  AND (expires_at <= 0 OR expires_at >= ?)
                """,
                (
                    claim_token,
                    now_iso,
                    retained_until,
                    approval_id,
                    now_epoch,
                ),
            )
            row = None
            if cursor.rowcount == 1:
                row = conn.execute(
                    "SELECT * FROM pending_approvals WHERE approval_id=?",
                    (approval_id,),
                ).fetchone()
            conn.commit()
        return self._approval_row(row) if row is not None else None

    def resolve_approval(
        self,
        approval_id: str,
        *,
        claim_token: str,
        status: str,
        resolution: dict,
        fusion_action: str | None = None,
        risk_level: str | None = None,
        reasons: list[str] | None = None,
        retention_seconds: int = 900,
    ) -> bool:
        if status not in {"approved", "rejected", "expired"}:
            raise ValueError(f"invalid approval status: {status}")
        if not claim_token:
            raise ValueError("claim_token must not be empty")
        with self._lock, closing(self.connect()) as conn:
            cursor = conn.execute(
                """
                UPDATE pending_approvals SET
                    status=?, resolved_at=?, resolution_json=?, expires_at=?,
                    fusion_action=COALESCE(?, fusion_action),
                    risk_level=COALESCE(?, risk_level),
                    reasons=COALESCE(?, reasons)
                WHERE approval_id=? AND status='resolving'
                  AND claim_token=?
                """,
                (
                    status,
                    datetime.now(timezone.utc).isoformat(),
                    _json(resolution),
                    time.time() + retention_seconds,
                    fusion_action,
                    risk_level,
                    _json(reasons) if reasons is not None else None,
                    approval_id,
                    claim_token,
                ),
            )
            conn.commit()
        return cursor.rowcount == 1

    def save_taint_source(
        self,
        source: dict,
        entities: list[dict],
        *,
        ttl_seconds: int,
    ) -> None:
        metadata = source.get("metadata") or {}
        with self._lock, closing(self.connect()) as conn:
            conn.execute("""
                INSERT INTO ct_trm_sources (
                    source_id, trace_id, conversation_id, source_json,
                    entities_json, expires_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_id) DO UPDATE SET
                    trace_id=excluded.trace_id,
                    conversation_id=excluded.conversation_id,
                    source_json=excluded.source_json,
                    entities_json=excluded.entities_json,
                    expires_at=excluded.expires_at,
                    updated_at=excluded.updated_at
            """, (
                source["source_id"],
                source.get("trace_id"),
                metadata.get("conversation_id"),
                _json(source),
                _json(entities),
                time.time() + ttl_seconds,
                datetime.now(timezone.utc).isoformat(),
            ))
            conn.commit()

    def list_taint_sources(self) -> list[dict]:
        self.purge_expired()
        with closing(self.connect()) as conn:
            rows = conn.execute(
                "SELECT source_json, entities_json FROM ct_trm_sources "
                "ORDER BY updated_at"
            ).fetchall()
        return [
            {
                "source": json.loads(row["source_json"]),
                "entities": json.loads(row["entities_json"]),
            }
            for row in rows
        ]

    def save_chain_state(
        self,
        trace_id: str,
        state: dict,
        *,
        ttl_seconds: int,
    ) -> None:
        with self._lock, closing(self.connect()) as conn:
            conn.execute("""
                INSERT INTO ct_trm_chain_states (
                    trace_id, state_json, expires_at, updated_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(trace_id) DO UPDATE SET
                    state_json=excluded.state_json,
                    expires_at=excluded.expires_at,
                    updated_at=excluded.updated_at
            """, (
                trace_id,
                _json(state),
                time.time() + ttl_seconds,
                datetime.now(timezone.utc).isoformat(),
            ))
            conn.commit()

    def list_chain_states(self) -> list[dict]:
        self.purge_expired()
        with closing(self.connect()) as conn:
            rows = conn.execute(
                "SELECT state_json FROM ct_trm_chain_states ORDER BY updated_at"
            ).fetchall()
        return [json.loads(row["state_json"]) for row in rows]

    def clear_ct_trace(self, trace_id: str) -> None:
        with self._lock, closing(self.connect()) as conn:
            conn.execute(
                "DELETE FROM ct_trm_sources WHERE trace_id=?",
                (trace_id,),
            )
            conn.execute(
                "DELETE FROM ct_trm_chain_states WHERE trace_id=?",
                (trace_id,),
            )
            conn.commit()

    def delete_taint_trace(self, trace_id: str) -> None:
        with self._lock, closing(self.connect()) as conn:
            conn.execute(
                "DELETE FROM ct_trm_sources WHERE trace_id=?",
                (trace_id,),
            )
            conn.commit()

    def delete_chain_state(self, trace_id: str) -> None:
        with self._lock, closing(self.connect()) as conn:
            conn.execute(
                "DELETE FROM ct_trm_chain_states WHERE trace_id=?",
                (trace_id,),
            )
            conn.commit()

    def purge_expired(self) -> None:
        now = time.time()
        with self._lock, closing(self.connect()) as conn:
            conn.execute(
                """
                UPDATE pending_approvals
                SET status='expired',
                    resolved_at=?,
                    resolution_json=?,
                    expires_at=?
                WHERE status='pending' AND expires_at > 0 AND expires_at < ?
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    _json({
                        "fusion_action": "ask",
                        "action": "ask",
                        "approval_status": "expired",
                        "execution_authorized": False,
                        "execution_attempted": False,
                        "execution_status": "not_executed",
                        "reasons": ["approval_expired"],
                    }),
                    now + 900,
                    now,
                ),
            )
            conn.execute(
                "DELETE FROM pending_approvals "
                "WHERE status IN ('approved', 'rejected', 'expired') "
                "AND expires_at > 0 AND expires_at < ?",
                (now,),
            )
            conn.execute(
                "DELETE FROM ct_trm_sources WHERE expires_at < ?",
                (now,),
            )
            conn.execute(
                "DELETE FROM ct_trm_chain_states WHERE expires_at < ?",
                (now,),
            )
            conn.commit()

    @staticmethod
    def _approval_row(row: sqlite3.Row) -> dict:
        allowed_tools_raw = row["allowed_tools_json"]
        return {
            "approval_id": row["approval_id"],
            "trace_id": row["trace_id"],
            "call_id": row["call_id"],
            "agent_id": row["agent_id"],
            "task": row["task"],
            "tool": row["tool"],
            "args": json.loads(row["args_json"]),
            "source": row["source"],
            "tainted": bool(row["tainted"]),
            "allowed_tools": (
                json.loads(allowed_tools_raw)
                if allowed_tools_raw not in {None, ""}
                else None
            ),
            "created_at": row["created_at"],
            "execute": bool(row["execute_flag"]),
            "conversation_id": row["conversation_id"],
            "status": row["status"],
            "claim_token": row["claim_token"],
            "claimed_at": row["claimed_at"],
            "resolved_at": row["resolved_at"],
            "resolution": json.loads(row["resolution_json"] or "{}"),
            "fusion_action": row["fusion_action"],
            "risk_level": row["risk_level"],
            "reasons": json.loads(row["reasons"] or "[]"),
            "expires_at": float(row["expires_at"] or 0),
            "metadata": json.loads(row["metadata_json"] or "{}"),
        }
