from __future__ import annotations

import json
import re
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TRANSPARENCY_NOTICE = (
    "“AI Agent 思考”展示的是可审计的规划与工具选择摘要，"
    "不包含模型私有思维链。Tool Proxy、Policy Engine 与 Audit 事件由系统边界自动生成。"
)


class TransparencyService:
    """Agent-independent trace event service.

    Tool Proxy owns security-boundary events, so replacing the built-in agent
    with OpenCode or an MCP client does not remove policy/action/audit traces.
    """

    def __init__(
        self,
        max_traces: int = 500,
        *,
        db_path: Path | None = None,
    ) -> None:
        self.max_traces = max_traces
        self.db_path = db_path
        self._events: dict[str, list[dict]] = {}
        self._meta: dict[str, dict] = {}
        self._lock = threading.RLock()
        if self.db_path is not None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()

    def begin(self, trace_id: str, *, task: str, agent_id: str,
              metadata: dict | None = None) -> None:
        with self._lock:
            if self.db_path is not None:
                created_at = datetime.now(timezone.utc).isoformat()
                with closing(self._connect()) as conn:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO trace_meta (
                            trace_id, task, agent_id, created_at, updated_at,
                            metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            trace_id,
                            task,
                            agent_id,
                            created_at,
                            created_at,
                            json.dumps(
                                self.redact(metadata or {}),
                                ensure_ascii=False,
                                sort_keys=True,
                            ),
                        ),
                    )
                    conn.commit()
                self._trim_database()
                return
            if trace_id not in self._events:
                self._events[trace_id] = []
                self._meta[trace_id] = {
                    "trace_id": trace_id,
                    "task": task,
                    "agent_id": agent_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "metadata": self.redact(metadata or {}),
                }
                self._trim()

    def emit(self, trace_id: str, *, phase: str, actor: str, label: str,
             status: str, title: str, summary: str, details: dict | None = None) -> dict:
        with self._lock:
            if self.db_path is not None:
                if not self._trace_exists(trace_id):
                    self.begin(
                        trace_id,
                        task="外部 Agent 工具调用",
                        agent_id=actor,
                    )
                timestamp = datetime.now(timezone.utc).isoformat()
                with closing(self._connect()) as conn:
                    row = conn.execute(
                        "SELECT COALESCE(MAX(seq), 0) AS seq "
                        "FROM trace_events WHERE trace_id=?",
                        (trace_id,),
                    ).fetchone()
                    event = {
                        "seq": int(row["seq"]) + 1,
                        "timestamp": timestamp,
                        "phase": phase,
                        "actor": actor,
                        "label": label,
                        "status": status,
                        "title": title,
                        "summary": str(summary)[:4000],
                        "details": self.redact(details or {}),
                    }
                    conn.execute(
                        """
                        INSERT INTO trace_events (
                            trace_id, seq, timestamp, phase, actor, label,
                            status, title, summary, details_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            trace_id,
                            event["seq"],
                            event["timestamp"],
                            event["phase"],
                            event["actor"],
                            event["label"],
                            event["status"],
                            event["title"],
                            event["summary"],
                            json.dumps(
                                event["details"],
                                ensure_ascii=False,
                                sort_keys=True,
                            ),
                        ),
                    )
                    conn.execute(
                        "UPDATE trace_meta SET updated_at=? WHERE trace_id=?",
                        (timestamp, trace_id),
                    )
                    conn.commit()
                return event
            if trace_id not in self._events:
                self.begin(trace_id, task="外部 Agent 工具调用", agent_id=actor)
            event = {
                "seq": len(self._events[trace_id]) + 1,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "phase": phase,
                "actor": actor,
                "label": label,
                "status": status,
                "title": title,
                "summary": str(summary)[:4000],
                "details": self.redact(details or {}),
            }
            self._events[trace_id].append(event)
            return event

    def snapshot(self, trace_id: str) -> dict:
        with self._lock:
            if self.db_path is not None:
                with closing(self._connect()) as conn:
                    meta_row = conn.execute(
                        "SELECT * FROM trace_meta WHERE trace_id=?",
                        (trace_id,),
                    ).fetchone()
                    event_rows = conn.execute(
                        "SELECT * FROM trace_events WHERE trace_id=? ORDER BY seq",
                        (trace_id,),
                    ).fetchall()
                meta = (
                    self._meta_row(meta_row)
                    if meta_row is not None
                    else {"trace_id": trace_id}
                )
                return {
                    **meta,
                    "events": [self._event_row(row) for row in event_rows],
                    "notice": TRANSPARENCY_NOTICE,
                }
            events = list(self._events.get(trace_id, []))
            meta = dict(self._meta.get(trace_id, {"trace_id": trace_id}))
        return {**meta, "events": events, "notice": TRANSPARENCY_NOTICE}

    def list_traces(
        self,
        limit: int = 50,
        *,
        agent_id: str | None = None,
    ) -> list[dict]:
        with self._lock:
            limit = max(1, min(limit, 200))
            if self.db_path is not None:
                query = "SELECT * FROM trace_meta"
                params: list[Any] = []
                if agent_id:
                    query += " WHERE agent_id=?"
                    params.append(agent_id)
                query += " ORDER BY updated_at DESC LIMIT ?"
                params.append(limit)
                with closing(self._connect()) as conn:
                    rows = conn.execute(query, params).fetchall()
                    values = []
                    for row in rows:
                        count_row = conn.execute(
                            "SELECT COUNT(*) AS count FROM trace_events "
                            "WHERE trace_id=?",
                            (row["trace_id"],),
                        ).fetchone()
                        last_row = conn.execute(
                            "SELECT * FROM trace_events WHERE trace_id=? "
                            "ORDER BY seq DESC LIMIT 1",
                            (row["trace_id"],),
                        ).fetchone()
                        values.append({
                            **self._meta_row(row),
                            "event_count": int(count_row["count"]),
                            "last_event": (
                                self._event_row(last_row)
                                if last_row is not None
                                else None
                            ),
                        })
                return values
            values = []
            for trace_id, meta in reversed(list(self._meta.items())):
                if agent_id and meta.get("agent_id") != agent_id:
                    continue
                events = self._events.get(trace_id, [])
                values.append({
                    **meta,
                    "event_count": len(events),
                    "last_event": events[-1] if events else None,
                })
                if len(values) >= limit:
                    break
            return values

    @classmethod
    def redact(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: ("[REDACTED]" if re.search(
                    r"(?i)(api[_-]?key|token|password|authorization|secret)",
                    str(key),
                ) else cls.redact(item))
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls.redact(item) for item in value[:100]]
        if isinstance(value, str):
            text = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}\b", "sk-[REDACTED]", value)
            text = re.sub(
                r"(?i)((?:api[_-]?key|token|password|secret)\s*[:=]\s*)\S+",
                r"\1[REDACTED]",
                text,
            )
            return text[:12000]
        return value

    @classmethod
    def result_summary(cls, result: dict) -> str:
        text = json.dumps(cls.redact(result), ensure_ascii=False)
        return text[:800] + ("…" if len(text) > 800 else "")

    def _trim(self) -> None:
        while len(self._events) > self.max_traces:
            oldest = next(iter(self._events))
            self._events.pop(oldest, None)
            self._meta.pop(oldest, None)

    def _connect(self) -> sqlite3.Connection:
        if self.db_path is None:
            raise RuntimeError("Transparency database is not configured")
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS trace_meta (
                    trace_id TEXT PRIMARY KEY,
                    task TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS trace_events (
                    trace_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    label TEXT NOT NULL,
                    status TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    PRIMARY KEY (trace_id, seq),
                    FOREIGN KEY (trace_id) REFERENCES trace_meta(trace_id)
                        ON DELETE CASCADE
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_trace_meta_updated "
                "ON trace_meta(updated_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_trace_events_time "
                "ON trace_events(timestamp)"
            )
            conn.commit()

    def _trace_exists(self, trace_id: str) -> bool:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT 1 FROM trace_meta WHERE trace_id=?",
                (trace_id,),
            ).fetchone()
        return row is not None

    def _trim_database(self) -> None:
        if self.db_path is None:
            return
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT trace_id FROM trace_meta ORDER BY updated_at DESC "
                "LIMIT -1 OFFSET ?",
                (self.max_traces,),
            ).fetchall()
            if rows:
                conn.executemany(
                    "DELETE FROM trace_meta WHERE trace_id=?",
                    [(row["trace_id"],) for row in rows],
                )
                conn.commit()

    @staticmethod
    def _meta_row(row: sqlite3.Row) -> dict:
        return {
            "trace_id": row["trace_id"],
            "task": row["task"],
            "agent_id": row["agent_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "metadata": json.loads(row["metadata_json"]),
        }

    @staticmethod
    def _event_row(row: sqlite3.Row) -> dict:
        return {
            "seq": row["seq"],
            "timestamp": row["timestamp"],
            "phase": row["phase"],
            "actor": row["actor"],
            "label": row["label"],
            "status": row["status"],
            "title": row["title"],
            "summary": row["summary"],
            "details": json.loads(row["details_json"]),
        }
