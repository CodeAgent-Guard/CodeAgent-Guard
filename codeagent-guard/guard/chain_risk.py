from __future__ import annotations

import hashlib
import ipaddress
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .state import RuntimeStateStore
from .taint import EntityType, SourceType, TaintMatch, TaintTracker


@dataclass
class ChainState:
    trace_id: str
    secret_read: list[dict] = field(default_factory=list)
    sensitive_file_accessed: list[dict] = field(default_factory=list)
    external_domains_contacted: list[dict] = field(default_factory=list)
    external_recipients_contacted: list[dict] = field(default_factory=list)
    executable_files_written: list[dict] = field(default_factory=list)
    downloaded_content_written: list[dict] = field(default_factory=list)
    package_scripts_detected: list[dict] = field(default_factory=list)
    untrusted_content_seen: list[dict] = field(default_factory=list)
    recent_steps: list[dict] = field(default_factory=list)
    updated_at: float = field(default_factory=time.time)


@dataclass
class ChainRiskFinding:
    pattern_id: str
    action: str
    risk_level: str
    score: int
    reasons: list[str]
    explanation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    hard_deny: bool = False


class ChainRiskAnalyzer:
    EXECUTABLE_SUFFIXES = {".sh", ".py", ".js", ".ps1", ".bat", ".cmd"}
    PACKAGE_FILES = {
        "package.json", "makefile", "setup.py", "pyproject.toml",
        "setup.cfg", "tox.ini",
    }

    def __init__(
        self,
        *,
        max_recent_steps: int = 20,
        ttl_seconds: int = 1800,
        state_store: RuntimeStateStore | None = None,
    ) -> None:
        self.max_recent_steps = max_recent_steps
        self.ttl_seconds = ttl_seconds
        self.state_store = state_store
        self._states: dict[str, ChainState] = {}
        self._lock = threading.RLock()
        self._restore_states()

    def update_after_tool_result(
        self,
        tool_name: str,
        args: dict,
        result: dict,
        decision: str,
        trace_id: str,
        *,
        taint_matches: list[TaintMatch] | None = None,
    ) -> ChainState:
        state = self._state(trace_id)
        now = time.time()
        step = {
            "tool": tool_name,
            "args_summary": self._args_summary(tool_name, args),
            "decision": decision,
            "result_error": bool(result.get("error")),
            "timestamp": now,
        }
        state.recent_steps.append(step)
        state.recent_steps = state.recent_steps[-self.max_recent_steps:]

        if decision != "allow" or result.get("error"):
            state.updated_at = now
            self._persist(state)
            return state

        if tool_name == "read_file":
            path = str(result.get("path") or args.get("path", ""))
            content = str(result.get("content", ""))
            secret_hashes = self._secret_hashes(content)
            if secret_hashes:
                state.secret_read.append({
                    "path": path,
                    "secret_hashes": secret_hashes,
                    "timestamp": now,
                })
            if TaintTracker.is_sensitive_path(path):
                state.sensitive_file_accessed.append({
                    "path": path,
                    "timestamp": now,
                })
            lifecycle = self._detect_package_script(path, content)
            if lifecycle:
                state.package_scripts_detected.append({
                    **lifecycle,
                    "timestamp": now,
                })

        elif tool_name == "http_request":
            url = str(args.get("url", ""))
            host = (urlparse(url).hostname or "").lower()
            if host and not self._internal_host(host):
                state.external_domains_contacted.append({
                    "host": host,
                    "url": url,
                    "timestamp": now,
                })
            state.untrusted_content_seen.append({
                "source_type": SourceType.HTTP_RESPONSE.value,
                "content_hash": self._hash(str(result.get("body", ""))),
                "timestamp": now,
            })

        elif tool_name == "send_email":
            recipient = str(args.get("to", "")).lower()
            if recipient and not recipient.endswith("@codeguard.local"):
                state.external_recipients_contacted.append({
                    "recipient": recipient,
                    "timestamp": now,
                })

        elif tool_name == "write_file":
            path = str(args.get("path", ""))
            content = str(args.get("content", ""))
            content_hash = self._hash(content)
            suffix = Path(path).suffix.lower()
            executable = (
                suffix in self.EXECUTABLE_SUFFIXES
                or suffix == ""
                or self._persistence_path(path)
            )
            if executable:
                state.executable_files_written.append({
                    "path": path,
                    "content_hash": content_hash,
                    "timestamp": now,
                })
            from_http_taint = any(
                match.source.source_type == SourceType.HTTP_RESPONSE
                for match in (taint_matches or ())
            )
            same_as_http_response = any(
                item.get("source_type") == SourceType.HTTP_RESPONSE.value
                and item.get("content_hash") == content_hash
                for item in state.untrusted_content_seen
            )
            if from_http_taint or same_as_http_response:
                state.downloaded_content_written.append({
                    "path": path,
                    "content_hash": content_hash,
                    "timestamp": now,
                })

        elif tool_name == "run_command":
            command = str(args.get("cmd", ""))
            if re.search(r"(?i)\b(?:base64|xxd)\b", command):
                state.untrusted_content_seen.append({
                    "source_type": "encoded_payload",
                    "content_hash": self._hash(command),
                    "timestamp": now,
                })

        for match in taint_matches or ():
            state.untrusted_content_seen.append({
                "source": match.source.origin,
                "source_type": match.source.source_type.value,
                "entity_type": match.source_entity.entity_type.value,
                "timestamp": now,
            })
        state.secret_read = self._recent(state.secret_read)
        state.sensitive_file_accessed = self._recent(
            state.sensitive_file_accessed
        )
        state.updated_at = now
        self._persist(state)
        return state

    def analyze_before_tool_call(
        self,
        tool_name: str,
        args: dict,
        trace_id: str,
        taint_matches: list[TaintMatch],
    ) -> list[ChainRiskFinding]:
        state = self._state(trace_id)
        findings: list[ChainRiskFinding] = []

        if tool_name in {"send_email", "http_request"} and state.secret_read:
            payload = self._sink_payload(tool_name, args)
            payload_hashes = self._secret_hashes(payload)
            known = {
                value
                for item in state.secret_read
                for value in item.get("secret_hashes", ())
            }
            encoded = bool(re.search(
                r"(?i)(base64|hex|encoded|chunk|part[_-]?\d+)",
                payload,
            ))
            external = self._external_sink(tool_name, args)
            if external and (known.intersection(payload_hashes) or encoded):
                findings.append(ChainRiskFinding(
                    pattern_id="C1" if tool_name == "send_email" else "C2",
                    action="deny",
                    risk_level="critical",
                    score=70,
                    reasons=[
                        "secret_exfiltration",
                        (
                            "external_recipient"
                            if tool_name == "send_email"
                            else "external_http_request"
                        ),
                        "chain_risk",
                        *(
                            ["encoded_payload", "obfuscation"]
                            if encoded else []
                        ),
                    ],
                    explanation=(
                        "当前任务先前读取了敏感内容，随后尝试通过外部 "
                        f"{tool_name} 发送同一 secret 或其编码表示。"
                    ),
                    evidence={
                        "prior_secret_reads": len(state.secret_read),
                        "sink": self._args_summary(tool_name, args),
                        "encoded": encoded,
                    },
                    hard_deny=True,
                ))

        if tool_name == "run_command":
            command = str(args.get("cmd", ""))
            for item in state.downloaded_content_written:
                path = str(item.get("path", ""))
                if path and self._command_references_path(command, path):
                    findings.append(ChainRiskFinding(
                        pattern_id="C3",
                        action="deny",
                        risk_level="critical",
                        score=70,
                        reasons=["external_content_execution", "chain_risk"],
                        explanation=(
                            "外部 HTTP 响应内容已写入可执行文件，当前命令"
                            "正在执行该文件。"
                        ),
                        evidence={"path": path},
                        hard_deny=True,
                    ))
            command_matches = [
                match for match in taint_matches
                if match.source_entity.entity_type == EntityType.COMMAND
                and match.source.source_type in {
                    SourceType.TOOL_OUTPUT,
                    SourceType.LOG_OUTPUT,
                    SourceType.HTTP_RESPONSE,
                }
            ]
            if command_matches:
                dangerous = TaintTracker.command_is_dangerous(command) or bool(
                    re.search(
                        r"(?i)(?:\.env|id_rsa|credential|secret|token|"
                        r"\bcat\b.*(?:\.ssh|\.env)|base64.*\|\s*(?:ba)?sh)",
                        command,
                    )
                )
                findings.append(ChainRiskFinding(
                    pattern_id="C4",
                    action="deny" if dangerous else "ask",
                    risk_level="critical" if dangerous else "high",
                    score=45 if dangerous else 35,
                    reasons=[
                        "tainted_tool_output",
                        "command_from_untrusted_output",
                        "chain_risk",
                    ],
                    explanation=(
                        "工具输出或日志中的命令被复用于 run_command，"
                        + ("且命令具有高危行为。" if dangerous else "需要用户确认。")
                    ),
                    evidence={
                        "sources": sorted({
                            match.source.origin for match in command_matches
                        }),
                    },
                    hard_deny=dangerous,
                ))

            if state.package_scripts_detected and self._package_trigger(command):
                severe = any(
                    item.get("severe") for item in state.package_scripts_detected
                )
                findings.append(ChainRiskFinding(
                    pattern_id="C5",
                    action="deny" if severe else "ask",
                    risk_level="critical" if severe else "high",
                    score=60 if severe else 40,
                    reasons=[
                        "package_lifecycle_script",
                        "side_effect_command",
                        "chain_risk",
                    ],
                    explanation=(
                        "当前命令会触发已检测到的 package lifecycle script，"
                        "脚本包含敏感资产、网络或删除行为。"
                    ),
                    evidence={
                        "scripts": [
                            item.get("path")
                            for item in state.package_scripts_detected[-5:]
                        ],
                    },
                    hard_deny=severe,
                ))

        return self._deduplicate(findings)

    def reset_trace(self, trace_id: str) -> None:
        with self._lock:
            self._states.pop(trace_id, None)
        if self.state_store is not None:
            self.state_store.delete_chain_state(trace_id)

    def get_state(self, trace_id: str) -> ChainState:
        return self._state(trace_id)

    def state_dict(self, trace_id: str) -> dict:
        return asdict(self._state(trace_id))

    def _state(self, trace_id: str) -> ChainState:
        with self._lock:
            self._purge()
            return self._states.setdefault(trace_id, ChainState(trace_id))

    def _restore_states(self) -> None:
        if self.state_store is None:
            return
        for raw in self.state_store.list_chain_states():
            try:
                state = ChainState(**raw)
            except (TypeError, ValueError):
                continue
            self._states[state.trace_id] = state
        self._purge()

    def _persist(self, state: ChainState) -> None:
        if self.state_store is not None:
            self.state_store.save_chain_state(
                state.trace_id,
                asdict(state),
                ttl_seconds=self.ttl_seconds,
            )

    def _purge(self) -> None:
        cutoff = time.time() - self.ttl_seconds
        stale = [
            trace_id for trace_id, state in self._states.items()
            if state.updated_at < cutoff
        ]
        for trace_id in stale:
            self._states.pop(trace_id, None)

    def _recent(self, values: list[dict]) -> list[dict]:
        cutoff = time.time() - self.ttl_seconds
        return [
            item for item in values
            if float(item.get("timestamp", 0)) >= cutoff
        ][-self.max_recent_steps:]

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def _secret_hashes(content: str) -> set[str]:
        hashes = set()
        for pattern in TaintTracker.SECRET_RES:
            for match in pattern.finditer(str(content)):
                value = match.group(1) if match.lastindex else match.group(0)
                hashes.add(hashlib.sha256(value.encode()).hexdigest())
        return hashes

    @staticmethod
    def _sink_payload(tool_name: str, args: dict) -> str:
        if tool_name == "send_email":
            return f"{args.get('subject', '')}\n{args.get('body', '')}"
        return (
            f"{args.get('url', '')}\n{args.get('body', '')}\n"
            f"{args.get('headers', {})}"
        )

    @staticmethod
    def _external_sink(tool_name: str, args: dict) -> bool:
        if tool_name == "send_email":
            recipient = str(args.get("to", "")).lower()
            return not recipient.endswith("@codeguard.local")
        host = (urlparse(str(args.get("url", ""))).hostname or "").lower()
        return bool(host) and not ChainRiskAnalyzer._internal_host(host)

    @staticmethod
    def _internal_host(host: str) -> bool:
        if host in {"localhost", "codeguard.local"}:
            return True
        try:
            return ipaddress.ip_address(host).is_private
        except ValueError:
            return False

    @staticmethod
    def _command_references_path(command: str, path: str) -> bool:
        normalized = path.replace("\\", "/")
        return normalized in command.replace("\\", "/") or Path(path).name in command

    @staticmethod
    def _package_trigger(command: str) -> bool:
        return bool(re.search(
            r"(?i)\b(?:npm|pnpm|yarn)\s+(?:install|test|run|build)|"
            r"\bpip(?:3)?\s+install|\bpython\s+setup\.py|"
            r"\bpython(?:3)?\s+-m\s+(?:pytest|unittest)|"
            r"\bmake(?:\s+(?:test|install|build))?\b|"
            r"\b(?:ba)?sh\s+[^\s]+\.(?:sh|bash)\b",
            command,
        ))

    @classmethod
    def _detect_package_script(cls, path: str, content: str) -> dict | None:
        name = Path(path).name.lower()
        if name not in cls.PACKAGE_FILES and Path(path).suffix.lower() != ".sh":
            return None
        lifecycle = Path(path).suffix.lower() in {".sh", ".bash"} or bool(
            re.search(
                r"(?i)(postinstall|preinstall|scripts|setup\(|build-system|"
                r"backend-path|^[\w.-]+\s*:)",
                content,
                re.MULTILINE,
            )
        )
        risky = bool(re.search(
            r"(?i)(?:\.env|id_rsa|credential|secret|token|"
            r"169\.254\.169\.254|metadata(?:\.[\w.-]+)?|curl|wget|"
            r"\brm\s+-[^\n]*r[^\n]*f|send_email|http)",
            content,
        ))
        if not lifecycle or not risky:
            return None
        return {"path": path, "severe": risky, "content_hash": cls._hash(content)}

    @staticmethod
    def _persistence_path(path: str) -> bool:
        lowered = path.replace("\\", "/").lower()
        return any(marker in lowered for marker in (
            ".git/hooks/", ".github/workflows/", ".gitlab-ci",
            "startup", "autorun", "crontab", ".profile", ".bashrc",
        ))

    @staticmethod
    def _args_summary(tool_name: str, args: dict) -> dict:
        if tool_name == "send_email":
            return {"to": args.get("to"), "body": "[MASKED]"}
        if tool_name == "http_request":
            return {"url": args.get("url"), "method": args.get("method", "GET")}
        if tool_name == "write_file":
            return {"path": args.get("path"), "content": "[MASKED]"}
        return {
            key: value for key, value in args.items()
            if key not in {"content", "body", "headers"}
        }

    @staticmethod
    def _deduplicate(
        findings: list[ChainRiskFinding],
    ) -> list[ChainRiskFinding]:
        values: dict[tuple[str, str], ChainRiskFinding] = {}
        for finding in findings:
            values[(finding.pattern_id, finding.action)] = finding
        return list(values.values())
