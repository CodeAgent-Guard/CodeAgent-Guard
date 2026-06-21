from __future__ import annotations

import ipaddress
import os
import re
import shlex
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .catalog import TOOL_NAMES


RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Decision:
    action: str = "allow"
    risk_level: str = "low"
    reasons: list[str] = field(default_factory=list)
    normalized_args: dict = field(default_factory=dict)

    def add(self, action: str, risk: str, reason: str) -> None:
        if action == "deny" or (action == "ask" and self.action == "allow"):
            self.action = action
        if RISK_ORDER[risk] > RISK_ORDER[self.risk_level]:
            self.risk_level = risk
        if reason not in self.reasons:
            self.reasons.append(reason)


class PolicyEngine:
    TOOLS = TOOL_NAMES
    MUTATING_TOOLS = {
        "write_file", "run_command", "send_email", "make_directory",
        "delete_path", "move_path", "open_directory",
    }
    SENSITIVE_PATHS = (
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/proc/", "/sys/",
        "/root/", "/.ssh", "/.aws", "/.gnupg", "id_rsa", "id_ed25519",
        ".env", "credentials", "service-account", "private_key",
    )
    SECRET_PATTERNS = (
        re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?[A-Za-z0-9_./+=-]{8,}"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    )
    DENY_COMMANDS = (
        (re.compile(r"(?i)\b(curl|wget)\b[^\n|;]*(\||;|&&)\s*(ba)?sh\b"), "remote_script_execution"),
        (re.compile(r"(?i)\b(rm\s+-[^\n]*r[^\n]*f|mkfs(?:\.\w+)?|dd\s+if=|shutdown|reboot|poweroff)\b"), "dangerous_shell_command"),
        (re.compile(r"(?i)\b(nc|ncat|netcat|socat)\b.*\s-e\s"), "reverse_shell_detected"),
        (re.compile(r"(?i)bash\s+-i.*(/dev/tcp|/dev/udp)"), "reverse_shell_detected"),
        (re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:"), "fork_bomb_detected"),
        (re.compile(r"(?i)\b(chmod\s+777|chown\s+-R|sudo\s+)\b"), "privilege_escalation_risk"),
    )
    ASK_COMMANDS = (
        re.compile(r"(?i)\b(apt|apt-get|pip|pip3|npm|pnpm|yarn)\s+(install|remove|uninstall|upgrade)\b"),
        re.compile(r"(?i)\bgit\s+(push|reset|clean)\b"),
    )

    def __init__(self, workspace: Path, allowed_tools: set[str] | None = None,
                 internal_domains: set[str] | None = None,
                 open_directory_roots: list[Path] | tuple[Path, ...] | None = None,
                 external_write_roots: list[Path] | tuple[Path, ...] | None = None,
                 trusted_workspace_roots: list[Path] | tuple[Path, ...] | None = None) -> None:
        self.workspace = workspace.resolve()
        self.allowed_tools = allowed_tools or set(self.TOOLS)
        self.internal_domains = internal_domains or {"codeguard.local", "localhost"}
        self.open_directory_roots = self._normalize_roots(open_directory_roots)
        self.external_write_roots = self._normalize_roots(external_write_roots)
        self.trusted_workspace_roots = self._normalize_roots(
            trusted_workspace_roots
        )

    def set_trusted_workspace_roots(
        self,
        roots: list[Path] | tuple[Path, ...],
    ) -> None:
        self.trusted_workspace_roots = self._normalize_roots(roots)

    def _normalize_roots(
        self,
        paths: list[Path] | tuple[Path, ...] | None,
    ) -> tuple[Path, ...]:
        roots = []
        for path in paths or ():
            normalized = self._normalize_host_path(str(path))
            if not normalized.is_absolute():
                normalized = self.workspace / normalized
            roots.append(normalized.resolve(strict=False))
        return tuple(roots)

    def evaluate(self, tool: str, args: dict, *, source: str = "user",
                 tainted: bool = False, approved: bool = False,
                 task_allowed_tools: set[str] | None = None) -> Decision:
        decision = Decision(normalized_args=dict(args))
        if tool not in self.TOOLS:
            decision.add("deny", "high", "tool_not_allowed")
            return decision
        if (
            tool not in self.allowed_tools
            or (task_allowed_tools is not None and tool not in task_allowed_tools)
        ):
            decision.add("deny", "high", "tool_not_allowed")

        evaluator = getattr(self, f"_evaluate_{tool}")
        evaluator(decision, args)

        if tainted and tool in self.MUTATING_TOOLS:
            decision.add("deny", "high", "command_from_untrusted_context")
        if source in {"runtime_log", "config_file", "tool_output", "repository_content"} and tool == "run_command":
            decision.add("deny", "high", "command_from_untrusted_context")
        if decision.action == "deny":
            decision.reasons = [r for r in decision.reasons if r != "user_confirmation_required"]
        if approved and decision.action == "ask":
            decision.action = "allow"
            decision.reasons = [r for r in decision.reasons if r != "user_confirmation_required"]
        return decision

    @staticmethod
    def _normalize_host_path(raw_path: str) -> Path:
        expanded = os.path.expanduser(raw_path.strip())
        windows_path = (
            re.match(r"^([A-Za-z]):[\\/](.*)$", expanded)
            if os.name != "nt"
            else None
        )
        if windows_path:
            drive = windows_path.group(1).lower()
            remainder = windows_path.group(2).replace("\\", "/")
            return Path(f"/mnt/{drive}/{remainder}").resolve(strict=False)
        path = Path(expanded)
        return path.resolve(strict=False) if path.is_absolute() else path

    @staticmethod
    def _is_within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    def _resolve_path(self, raw_path: str) -> tuple[Path, bool]:
        path = self._normalize_host_path(raw_path)
        if not path.is_absolute():
            path = self.workspace / path
        normalized = path.resolve(strict=False)
        in_scope = self._is_within(normalized, self.workspace)
        return normalized, in_scope

    def _path_checks(self, decision: Decision, raw_path: str,
                     argument_name: str = "path") -> Path:
        normalized, in_scope = self._resolve_path(raw_path)
        self._basic_path_checks(decision, normalized, raw_path, argument_name)
        if not in_scope:
            decision.add("deny", "high", "resource_scope_violation")
        return normalized

    def _basic_path_checks(
        self,
        decision: Decision,
        normalized: Path,
        raw_path: str,
        argument_name: str = "path",
    ) -> None:
        decision.normalized_args[argument_name] = str(normalized)
        lowered = str(normalized).replace("\\", "/").lower()
        if ".." in raw_path.replace("\\", "/").split("/"):
            decision.add("deny", "high", "path_traversal_detected")
        if any(marker in lowered for marker in self.SENSITIVE_PATHS):
            decision.add("deny", "critical", "sensitive_file_access")
            decision.add("deny", "critical", "credential_exposure_risk")

    def _directory_scope(self, path: Path) -> tuple[str | None, Path | None]:
        if self._is_within(path, self.workspace):
            return "workspace", self.workspace
        for root in self.trusted_workspace_roots:
            if self._is_within(path, root):
                return "trusted_workspace", root
        for root in self.external_write_roots:
            if self._is_within(path, root):
                return "external_write", root
        return None, None

    def _directory_path_checks(
        self,
        decision: Decision,
        raw_path: str,
        argument_name: str = "path",
    ) -> tuple[Path, str | None, Path | None]:
        normalized = self._normalize_host_path(raw_path)
        if not normalized.is_absolute():
            normalized = (self.workspace / normalized).resolve(strict=False)
        else:
            normalized = normalized.resolve(strict=False)
        self._basic_path_checks(decision, normalized, raw_path, argument_name)
        scope, root = self._directory_scope(normalized)
        if scope is None:
            decision.add("deny", "high", "resource_scope_violation")
        return normalized, scope, root

    def _evaluate_read_file(self, decision: Decision, args: dict) -> None:
        raw = str(args.get("path", ""))
        if not raw:
            decision.add("deny", "medium", "invalid_arguments")
            return
        normalized, scope, _ = self._directory_path_checks(decision, raw)
        if scope == "external_write":
            if not normalized.exists() or not normalized.is_file():
                decision.add("deny", "medium", "file_not_found")
            if decision.action != "deny":
                decision.add("ask", "medium", "external_file_read")
                decision.add("ask", "medium", "user_confirmation_required")

    def _evaluate_write_file(self, decision: Decision, args: dict) -> None:
        raw = str(args.get("path", ""))
        if not raw:
            decision.add("deny", "medium", "invalid_arguments")
            return
        normalized, scope, root = self._directory_path_checks(decision, raw)
        content = str(args.get("content", ""))
        if self.contains_secret(content):
            decision.add("deny", "critical", "secret_leakage_detected")
        if scope == "external_write":
            if normalized == root:
                decision.add("deny", "high", "external_root_modification")
            if normalized.exists() and normalized.is_dir():
                decision.add("deny", "high", "external_directory_as_file")
            if decision.action != "deny":
                decision.add("ask", "high", "external_file_write")
                decision.add("ask", "high", "user_confirmation_required")

    def _evaluate_run_command(self, decision: Decision, args: dict) -> None:
        command = str(args.get("cmd", "")).strip()
        if not command:
            decision.add("deny", "medium", "invalid_arguments")
            return
        for pattern, reason in self.DENY_COMMANDS:
            if pattern.search(command):
                decision.add("deny", "critical" if "remote" in reason or "reverse" in reason else "high", reason)
        self._command_boundary_checks(decision, command)
        if re.search(r"[|;&`]|\$\(", command):
            decision.add("ask", "medium", "dangerous_shell_pipeline")
            decision.add("ask", "medium", "user_confirmation_required")
        if any(pattern.search(command) for pattern in self.ASK_COMMANDS):
            decision.add("ask", "medium", "user_confirmation_required")

    def _command_boundary_checks(self, decision: Decision, command: str) -> None:
        """Prevent run_command from bypassing file and network tool policies.

        This is a command-level guard, not a replacement for an OS sandbox.
        """
        lowered = command.lower()
        if re.search(
            r"(?i)(?:^|[\s\"'])(?:~?/)?(?:\.ssh|\.aws|\.gnupg)(?:/|[\s\"']|$)"
            r"|/(?:etc|root|proc|sys)(?:/|[\s\"']|$)"
            r"|(?:id_rsa|id_ed25519|/etc/passwd|/etc/shadow)",
            command,
        ):
            decision.add("deny", "critical", "command_sensitive_resource_access")
            decision.add("deny", "critical", "resource_scope_violation")
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
        for token in tokens:
            cleaned = token.strip("\"'")
            if cleaned.startswith("../") or "/../" in cleaned:
                decision.add("deny", "high", "command_path_traversal")
                decision.add("deny", "high", "resource_scope_violation")
        if re.search(r"(?i)(?:^|[;&|\s])(curl|wget|nc|ncat|netcat|socat|ssh|scp)\b", lowered):
            decision.add("deny", "high", "network_tool_bypass")
        if re.search(
            r"(?i)(127\.0\.0\.1|0\.0\.0\.0|localhost|169\.254\.169\.254"
            r"|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)",
            command,
        ):
            decision.add("deny", "critical", "ssrf_private_network")

    def _evaluate_http_request(self, decision: Decision, args: dict) -> None:
        url = str(args.get("url", ""))
        method = str(args.get("method", "GET")).upper()
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            decision.add("deny", "medium", "invalid_url")
            return
        if parsed.scheme != "https":
            decision.add("ask", "medium", "insecure_transport")
            decision.add("ask", "medium", "user_confirmation_required")
        if method not in {"GET", "HEAD"}:
            decision.add("ask", "medium", "state_changing_http_request")
            decision.add("ask", "medium", "user_confirmation_required")
        if parsed.hostname.lower() in {"localhost", "metadata.google.internal"}:
            decision.add("deny", "critical", "ssrf_private_network")
            return
        try:
            for info in socket.getaddrinfo(parsed.hostname, parsed.port or 443):
                ip = ipaddress.ip_address(info[4][0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    decision.add("deny", "critical", "ssrf_private_network")
        except socket.gaierror:
            decision.add("deny", "medium", "dns_resolution_failed")

    def _evaluate_send_email(self, decision: Decision, args: dict) -> None:
        recipient = str(args.get("to", "")).strip().lower()
        body = f"{args.get('subject', '')}\n{args.get('body', '')}"
        if "@" not in recipient:
            decision.add("deny", "medium", "invalid_recipient")
            return
        domain = recipient.rsplit("@", 1)[1]
        if domain not in self.internal_domains:
            decision.add("ask", "high", "external_recipient")
            decision.add("ask", "high", "user_confirmation_required")
        if self.contains_secret(body):
            decision.add("deny", "critical", "secret_leakage_detected")

    def _evaluate_list_directory(self, decision: Decision, args: dict) -> None:
        raw = str(args.get("path", ""))
        if not raw:
            decision.add("deny", "medium", "invalid_arguments")
            return
        normalized, scope, _ = self._directory_path_checks(decision, raw)
        depth = int(args.get("max_depth", 2))
        decision.normalized_args["max_depth"] = max(1, min(depth, 5))
        decision.normalized_args["include_hidden"] = bool(args.get("include_hidden", False))
        if scope == "external_write":
            if not normalized.exists() or not normalized.is_dir():
                decision.add("deny", "medium", "directory_not_found")
            if decision.action != "deny":
                decision.add("ask", "medium", "external_directory_listing")
                decision.add("ask", "medium", "user_confirmation_required")

    def _evaluate_open_directory(self, decision: Decision, args: dict) -> None:
        raw = str(args.get("path", "")).strip()
        if not raw:
            decision.add("deny", "medium", "invalid_arguments")
            return
        normalized = self._normalize_host_path(raw)
        if not Path(raw).is_absolute() and not re.match(r"^[A-Za-z]:[\\/]", raw):
            normalized = (self.workspace / raw).resolve(strict=False)
        decision.normalized_args["path"] = str(normalized)
        if ".." in raw.replace("\\", "/").split("/"):
            decision.add("deny", "high", "path_traversal_detected")
        lowered = str(normalized).replace("\\", "/").lower()
        if any(marker in lowered for marker in self.SENSITIVE_PATHS):
            decision.add("deny", "critical", "sensitive_file_access")
        authorized_roots = (
            self.workspace,
            *self.trusted_workspace_roots,
            *self.open_directory_roots,
        )
        if not any(self._is_within(normalized, root) for root in authorized_roots):
            decision.add("deny", "high", "external_directory_not_authorized")
        if not normalized.exists() or not normalized.is_dir():
            decision.add("deny", "medium", "directory_not_found")
        if decision.action != "deny":
            decision.add("ask", "medium", "desktop_application_launch")
            decision.add("ask", "medium", "user_confirmation_required")

    def _evaluate_search_files(self, decision: Decision, args: dict) -> None:
        raw = str(args.get("path", ""))
        query = str(args.get("query", ""))
        if not raw or not query or len(query) > 500:
            decision.add("deny", "medium", "invalid_arguments")
            return
        normalized, scope, _ = self._directory_path_checks(decision, raw)
        if scope == "external_write":
            if not normalized.exists() or not normalized.is_dir():
                decision.add("deny", "medium", "directory_not_found")
            if decision.action != "deny":
                decision.add("ask", "medium", "external_file_search")
                decision.add("ask", "medium", "user_confirmation_required")
        if bool(args.get("regex", False)):
            try:
                re.compile(query)
            except re.error:
                decision.add("deny", "medium", "invalid_regular_expression")
        decision.normalized_args["glob"] = str(args.get("glob", "*"))
        decision.normalized_args["regex"] = bool(args.get("regex", False))
        decision.normalized_args["max_results"] = max(
            1, min(int(args.get("max_results", 50)), 200)
        )

    def _evaluate_make_directory(self, decision: Decision, args: dict) -> None:
        raw = str(args.get("path", ""))
        if not raw:
            decision.add("deny", "medium", "invalid_arguments")
            return
        normalized, scope, root = self._directory_path_checks(decision, raw)
        if scope == "external_write":
            if normalized == root:
                decision.add("deny", "high", "external_root_modification")
            if decision.action != "deny":
                decision.add("ask", "high", "external_path_write")
                decision.add("ask", "high", "user_confirmation_required")

    def _evaluate_delete_path(self, decision: Decision, args: dict) -> None:
        raw = str(args.get("path", ""))
        if not raw:
            decision.add("deny", "medium", "invalid_arguments")
            return
        normalized, scope, root = self._directory_path_checks(decision, raw)
        if scope == "trusted_workspace" and normalized == root:
            decision.add("deny", "high", "trusted_workspace_root_modification")
            return
        if scope == "external_write":
            if normalized == root:
                decision.add("deny", "high", "external_root_modification")
            elif not normalized.exists():
                decision.add("deny", "medium", "target_not_found")
            elif normalized.is_dir():
                try:
                    has_children = any(normalized.iterdir())
                except OSError:
                    has_children = True
                if has_children:
                    decision.add("deny", "high", "non_empty_external_directory_delete")
            if decision.action != "deny":
                decision.add("ask", "high", "external_path_delete")
                decision.add("ask", "high", "user_confirmation_required")
            return
        if decision.action != "deny":
            decision.add("ask", "high", "destructive_file_operation")
            decision.add("ask", "high", "user_confirmation_required")

    def _evaluate_move_path(self, decision: Decision, args: dict) -> None:
        source = str(args.get("source", ""))
        destination = str(args.get("destination", ""))
        if not source or not destination:
            decision.add("deny", "medium", "invalid_arguments")
            return
        normalized_source, source_scope, source_root = self._directory_path_checks(
            decision, source, "source"
        )
        normalized_destination, destination_scope, destination_root = self._directory_path_checks(
            decision, destination, "destination"
        )
        if normalized_source == normalized_destination:
            decision.add("deny", "medium", "source_equals_destination")
        if decision.action != "deny":
            if (
                source_scope in {"workspace", "trusted_workspace"}
                and source_scope == destination_scope
                and source_root == destination_root
            ):
                if (
                    source_scope == "trusted_workspace"
                    and (
                        normalized_source == source_root
                        or normalized_destination == source_root
                    )
                ):
                    decision.add(
                        "deny",
                        "high",
                        "trusted_workspace_root_modification",
                    )
                    return
                decision.add("ask", "medium", "state_changing_file_operation")
                decision.add("ask", "medium", "user_confirmation_required")
            elif (
                source_scope == "external_write"
                and destination_scope == "external_write"
                and source_root == destination_root
            ):
                if normalized_source == source_root or normalized_destination == source_root:
                    decision.add("deny", "high", "external_root_modification")
                elif not normalized_source.exists():
                    decision.add("deny", "medium", "source_not_found")
                elif normalized_destination.exists():
                    decision.add("deny", "medium", "destination_exists")
                else:
                    decision.add("ask", "high", "external_path_write")
                    decision.add("ask", "high", "user_confirmation_required")
            else:
                decision.add("deny", "high", "external_move_across_roots")
                decision.add("deny", "high", "resource_scope_violation")

    @classmethod
    def contains_secret(cls, text: str) -> bool:
        return any(pattern.search(text) for pattern in cls.SECRET_PATTERNS)

    def describe(self) -> list[dict]:
        return [
            {
                "name": "可信工作环境",
                "scope": "文件读取 / 创建 / 修改",
                "action": "allow / ask",
                "detail": (
                    ", ".join(map(str, self.trusted_workspace_roots))
                    or "未配置"
                ),
            },
            {"name": "工作区边界", "scope": "全部文件工具", "action": "deny", "detail": str(self.workspace)},
            {"name": "敏感文件保护", "scope": "读取 / 搜索 / 变更", "action": "deny", "detail": ".ssh、凭据、系统配置"},
            {"name": "危险命令检测", "scope": "run_command", "action": "deny", "detail": "远程脚本、反弹 Shell、破坏性命令"},
            {"name": "命令边界防绕过", "scope": "run_command", "action": "deny", "detail": "禁止绕过文件边界与网络代理"},
            {"name": "命令二次确认", "scope": "run_command", "action": "ask", "detail": "管道、包管理、Git 写操作"},
            {"name": "SSRF 防护", "scope": "http_request", "action": "deny", "detail": "本地、私网、元数据地址"},
            {"name": "外发与密钥检测", "scope": "send_email", "action": "ask / deny", "detail": "外部收件人需确认，密钥禁止外传"},
            {"name": "文件变更确认", "scope": "delete_path / move_path", "action": "ask", "detail": "删除与移动必须显式批准"},
            {"name": "外部目录打开", "scope": "open_directory", "action": "ask / deny", "detail": f"仅允许工作区及配置目录：{', '.join(map(str, self.open_directory_roots)) or '未配置外部目录'}"},
            {"name": "外部目录 CRUD", "scope": "read / write / list / search / make / move / delete", "action": "ask / deny", "detail": f"仅允许显式配置目录：{', '.join(map(str, self.external_write_roots)) or '未配置外部 CRUD 目录'}"},
            {"name": "不可信上下文隔离", "scope": "全部写操作", "action": "deny", "detail": "日志、配置、仓库内容不能授权副作用"},
            {"name": "任务级工具授权", "scope": "全部工具", "action": "deny", "detail": "每个任务独立声明允许使用的工具"},
        ]
