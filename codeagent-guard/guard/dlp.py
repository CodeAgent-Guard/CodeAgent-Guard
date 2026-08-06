from __future__ import annotations

import copy
import hashlib
import hmac
import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Pattern
from urllib.parse import urlparse


@dataclass(frozen=True)
class SecretPattern:
    secret_type: str
    regex: Pattern[str]


@dataclass
class DLPFinding:
    secret_type: str
    location: str
    sink: str
    fingerprint: str
    masked_value: str
    action: str
    risk_level: str
    score: int
    reasons: list[str]
    hard_deny: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DLPReport:
    direction: str
    findings: list[DLPFinding] = field(default_factory=list)

    @property
    def hard_deny(self) -> bool:
        return any(finding.hard_deny for finding in self.findings)

    @property
    def total_score(self) -> int:
        return max((finding.score for finding in self.findings), default=0)

    @property
    def risk_level(self) -> str:
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        risk = "low"
        for finding in self.findings:
            if order[finding.risk_level] > order[risk]:
                risk = finding.risk_level
        return risk

    @property
    def action(self) -> str:
        if any(finding.action == "deny" for finding in self.findings):
            return "deny"
        if any(finding.action == "ask" for finding in self.findings):
            return "ask"
        return "allow"

    @property
    def reasons(self) -> list[str]:
        values: list[str] = []
        for finding in self.findings:
            for reason in finding.reasons:
                if reason not in values:
                    values.append(reason)
        return values

    def to_dict(self) -> dict:
        return {
            "event_type": "dlp_scan",
            "direction": self.direction,
            "finding_count": len(self.findings),
            "hard_deny": self.hard_deny,
            "total_score": self.total_score,
            "action": self.action,
            "risk_level": self.risk_level,
            "reasons": self.reasons,
            "findings": [finding.to_dict() for finding in self.findings],
        }


class DLPScanner:
    """Input/output DLP scanner that emits masked, keyed fingerprints only."""

    SECRET_PATTERNS: tuple[SecretPattern, ...] = (
        SecretPattern(
            "private_key",
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ),
        SecretPattern("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        SecretPattern("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")),
        SecretPattern("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
        SecretPattern("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
        SecretPattern(
            "google_api_key",
            re.compile(r"\bAIza[A-Za-z0-9_.-]{16,}(?=$|[^A-Za-z0-9_.-])"),
        ),
        SecretPattern(
            "database_uri",
            re.compile(
                r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|"
                r"redis)://[^:\s/]+:[^@\s/]+@"
            ),
        ),
        SecretPattern(
            "named_secret",
            re.compile(
                r"(?i)(?P<prefix>\b(?:api[_-]?key|access[_-]?token|token|"
                r"password|secret)\b[\"']?\s*[:=]\s*[\"']?)"
                r"(?P<secret>(?!https?://)[A-Za-z0-9_./+=-]{8,})"
            ),
        ),
        SecretPattern(
            "authorization_token",
            re.compile(
                r"(?i)(?P<prefix>\b(?:authorization|bearer)\b[\"']?\s*"
                r"[:=]?\s*(?:Bearer\s+)?)"
                r"(?P<secret>[A-Za-z0-9._~+/=-]{12,})"
            ),
        ),
        SecretPattern(
            "benchmark_secret",
            re.compile(r"\bFAKE_API_KEY_FOR_BENCHMARK_ONLY\b"),
        ),
    )

    INPUT_FIELDS = {
        "write_file": {"content": "file_write"},
        "run_command": {"cmd": "command", "command": "command"},
        "send_email": {
            "subject": "email",
            "body": "email",
            "attachments": "email_attachment",
        },
        "http_request": {
            "url": "http",
            "headers": "http",
            "body": "http",
        },
    }

    def __init__(self, key: bytes | str | None = None) -> None:
        raw_key = key or os.environ.get(
            "CODEAGENT_GUARD_DLP_KEY",
            "codeagent-guard-local-dlp-key",
        )
        self.key = raw_key.encode("utf-8") if isinstance(raw_key, str) else raw_key

    def scan_tool_call(
        self,
        tool_name: str,
        args: dict,
        *,
        internal_domains: set[str] | None = None,
    ) -> DLPReport:
        findings: list[DLPFinding] = []
        fields = self.INPUT_FIELDS.get(tool_name, {})
        for field, sink in fields.items():
            if field not in args or args.get(field) in (None, ""):
                continue
            text = self._stringify(args.get(field))
            external = self._external_sink(tool_name, args, internal_domains)
            findings.extend(self._scan_text(
                text,
                location=f"args.{field}",
                sink=sink,
                external=external,
                command_text=str(args.get("cmd") or args.get("command") or ""),
            ))
        direction = "outbound" if any(
            finding.evidence.get("external")
            or (
                finding.sink == "command"
                and self._command_exfiltrates(
                    str(args.get("cmd") or args.get("command") or "")
                )
            )
            for finding in findings
        ) else "input"
        return DLPReport(direction, self._deduplicate(findings))

    def scan_tool_result(
        self,
        tool_name: str,
        result: dict,
    ) -> tuple[dict, DLPReport]:
        sanitized = copy.deepcopy(result)
        findings: list[DLPFinding] = []
        sanitized = self._scan_value(
            sanitized,
            location="result",
            sink=f"{tool_name}_output",
            findings=findings,
        )
        return sanitized, DLPReport("output", self._deduplicate(findings))

    def _scan_value(
        self,
        value: Any,
        *,
        location: str,
        sink: str,
        findings: list[DLPFinding],
    ) -> Any:
        if isinstance(value, str):
            redacted, local = self._scan_and_redact_text(
                value,
                location=location,
                sink=sink,
            )
            findings.extend(local)
            return redacted
        if isinstance(value, dict):
            return {
                key: self._scan_value(
                    item,
                    location=f"{location}.{key}",
                    sink=sink,
                    findings=findings,
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                self._scan_value(
                    item,
                    location=f"{location}[{index}]",
                    sink=sink,
                    findings=findings,
                )
                for index, item in enumerate(value)
            ]
        return value

    def _scan_text(
        self,
        text: str,
        *,
        location: str,
        sink: str,
        external: bool,
        command_text: str = "",
    ) -> list[DLPFinding]:
        _, findings = self._scan_and_redact_text(
            text,
            location=location,
            sink=sink,
            external=external,
            command_text=command_text,
        )
        return findings

    def _scan_and_redact_text(
        self,
        text: str,
        *,
        location: str,
        sink: str,
        external: bool = False,
        command_text: str = "",
    ) -> tuple[str, list[DLPFinding]]:
        findings: list[DLPFinding] = []
        redacted = str(text)
        for pattern in self.SECRET_PATTERNS:
            for match in pattern.regex.finditer(str(text)):
                raw_secret = self._secret_value(match)
                if not raw_secret:
                    continue
                action, risk, score, hard, reasons = self._classify(
                    sink,
                    external=external,
                    command_text=command_text or str(text),
                )
                findings.append(DLPFinding(
                    secret_type=pattern.secret_type,
                    location=location,
                    sink=sink,
                    fingerprint=self._fingerprint(raw_secret),
                    masked_value=self._mask(raw_secret),
                    action=action,
                    risk_level=risk,
                    score=score,
                    reasons=reasons,
                    hard_deny=hard,
                    evidence={
                        "location": location,
                        "sink": sink,
                        "external": external,
                    },
                ))
            redacted = pattern.regex.sub(
                lambda item: self._redact_match(item),
                redacted,
            )
        return redacted, findings

    @staticmethod
    def _secret_value(match: re.Match[str]) -> str:
        if "secret" in match.re.groupindex:
            return str(match.group("secret"))
        return str(match.group(0))

    def _redact_match(self, match: re.Match[str]) -> str:
        secret = self._secret_value(match)
        masked = self._mask(secret)
        if "prefix" in match.re.groupindex:
            return f"{match.group('prefix')}{masked}"
        return masked

    def _fingerprint(self, secret: str) -> str:
        return hmac.new(
            self.key,
            secret.encode("utf-8", errors="replace"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _mask(secret: str) -> str:
        value = str(secret)
        if len(value) <= 8:
            return "[SECRET]"
        return f"{value[:4]}...{value[-4:]}"

    @staticmethod
    def _stringify(value: Any) -> str:
        if isinstance(value, str):
            return value
        return json.dumps(value, ensure_ascii=False, default=str)

    def _classify(
        self,
        sink: str,
        *,
        external: bool,
        command_text: str,
    ) -> tuple[str, str, int, bool, list[str]]:
        if sink in {"email", "email_attachment", "http"} and external:
            return (
                "deny",
                "critical",
                70,
                True,
                ["secret_leakage_detected", "dlp_secret_external_sink"],
            )
        if sink == "command" and self._command_exfiltrates(command_text):
            return (
                "deny",
                "critical",
                70,
                True,
                ["secret_leakage_detected", "dlp_command_secret_exfiltration"],
            )
        if sink.endswith("_output"):
            return (
                "ask",
                "medium",
                20,
                False,
                ["dlp_output_secret_redacted"],
            )
        return (
            "ask",
            "high",
            40,
            False,
            ["dlp_secret_in_sensitive_parameter"],
        )

    @staticmethod
    def _command_exfiltrates(command: str) -> bool:
        return bool(re.search(
            r"(?i)\b(?:curl|wget|nc|ncat|netcat|socat|scp|ssh)\b|https?://",
            command,
        ))

    @staticmethod
    def _external_sink(
        tool_name: str,
        args: dict,
        internal_domains: set[str] | None,
    ) -> bool:
        internal = {item.lower() for item in (internal_domains or set())}
        if tool_name == "send_email":
            recipient = str(args.get("to", "")).lower()
            if "@" not in recipient:
                return False
            return recipient.rsplit("@", 1)[1] not in internal
        if tool_name == "http_request":
            host = (urlparse(str(args.get("url", ""))).hostname or "").lower()
            return bool(host) and not DLPScanner._internal_host(host, internal)
        return False

    @staticmethod
    def _internal_host(host: str, internal_domains: set[str]) -> bool:
        if host in internal_domains or host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_private
        except ValueError:
            return False

    @staticmethod
    def _deduplicate(findings: list[DLPFinding]) -> list[DLPFinding]:
        values: dict[tuple[str, str, str], DLPFinding] = {}
        for finding in findings:
            key = (finding.secret_type, finding.fingerprint, finding.sink)
            current = values.get(key)
            if current is None or finding.score > current.score:
                values[key] = finding
        return list(values.values())
