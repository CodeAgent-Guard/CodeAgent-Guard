from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .chain_risk import ChainRiskFinding, ChainState
from .taint import EntityType, SourceType, TaintMatch, TaintTracker
from .task_budget import TaskCapabilityBudget, tool_alignment


@dataclass
class RiskPatternFinding:
    pattern_id: str
    name: str
    action: str
    risk_level: str
    score: int
    reasons: list[str]
    explanation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    hard_deny: bool = False


PATTERN_NAMES = {
    "P1": "不可信上下文诱导敏感读取",
    "P2": "Shell 绕过文件策略",
    "P3": "工具输出诱导命令执行",
    "P4": "外部 HTTP 内容落地执行",
    "P5": "secret 外传到外部邮件",
    "P6": "secret 外传到外部 URL",
    "P7": "SSRF / metadata 访问",
    "P8": "路径穿越逃逸",
    "P9": "符号链接逃逸",
    "P10": "package 生命周期脚本风险",
    "P11": "删除/移动高风险目标",
    "P12": "任务无关的高副作用工具",
    "P13": "编码/分段 payload",
    "P14": "外部收件人伪装",
    "P15": "低可信路径进入写操作",
}


def detect_risk_patterns(
    tool_name: str,
    args: dict,
    *,
    workspace: Path,
    taint_matches: list[TaintMatch],
    chain_findings: list[ChainRiskFinding],
    chain_state: ChainState,
    task_budget: TaskCapabilityBudget | None,
) -> list[RiskPatternFinding]:
    findings: list[RiskPatternFinding] = []
    path = _path_for_tool(tool_name, args)
    normalized_path = None
    path_meta: dict[str, Any] = {}
    if path:
        tracker = TaintTracker(workspace)
        normalized_path, path_meta = tracker.normalize_path(path)

    sensitive_taint = [
        match for match in taint_matches
        if match.argument_entity.entity_type == EntityType.PATH
        and (
            match.argument_entity.sensitivity == "critical"
            or match.source_entity.sensitivity == "critical"
        )
    ]
    if (
        tool_name in {"read_file", "search_files", "open_directory"}
        and sensitive_taint
    ):
        outside = bool(
            path_meta
            and not path_meta.get("within_workspace", True)
        ) or str(path).replace("\\", "/").startswith(("fake_home/", "fake_root/"))
        findings.append(_finding(
            "P1", "deny", "critical", 45,
            [
                "tainted_instruction",
                "sensitive_file",
                "tainted_argument_flow",
                *(["outside_workspace"] if outside else []),
            ],
            "低可信上下文中的敏感路径被复用于读取类工具参数。",
            {"sources": _sources(sensitive_taint), "path": path},
            hard=True,
        ))

    if tool_name == "run_command":
        command = str(args.get("cmd") or args.get("command") or "")
        if re.search(
            r"(?i)\b(?:cat|grep|sed|awk|head|tail|python(?:3)?|node|"
            r"bash|sh)\b[^\n]*(?:\.ssh|id_rsa|id_ed25519|\.env|"
            r"credential|/etc/(?:shadow|passwd|sudoers))",
            command,
        ):
            findings.append(_finding(
                "P2", "deny", "critical", 60,
                ["sensitive_file_access_via_shell", "policy_bypass_attempt"],
                "Shell 命令尝试绕过文件工具策略读取敏感资产。",
                {"command": _mask_command(command)},
                hard=True,
            ))
        elif re.search(
            r"(?i)\bgrep\b[^\n]*(?:api[_-]?key|token|secret|password|"
            r"credential)",
            command,
        ):
            findings.append(_finding(
                "P2", "deny", "high", 45,
                ["credential_discovery_via_shell", "policy_bypass_attempt"],
                "Shell command searches for credential-like workspace data.",
                {"command": _mask_command(command)},
                hard=True,
            ))
        elif TaintTracker.command_is_dangerous(command):
            findings.append(_finding(
                "P2", "deny", "critical", 60,
                ["dangerous_shell_command", "policy_bypass_attempt"],
                (
                    "The command contains a directly observable remote "
                    "execution, reverse shell, destructive, substitution, "
                    "decoder, privilege, or environment-hijack primitive."
                ),
                {"command": _mask_command(command)},
                hard=True,
            ))
        command_taint = [
            match for match in taint_matches
            if match.argument_entity.entity_type == EntityType.COMMAND
            and match.source.source_type in {
                SourceType.TOOL_OUTPUT,
                SourceType.LOG_OUTPUT,
                SourceType.HTTP_RESPONSE,
            }
        ]
        if command_taint:
            dangerous = TaintTracker.command_is_dangerous(command)
            findings.append(_finding(
                "P3",
                "deny" if dangerous else "ask",
                "critical" if dangerous else "high",
                45 if dangerous else 35,
                ["tainted_tool_output", "command_from_untrusted_output"],
                "工具输出或日志中的命令进入 run_command。",
                {"sources": _sources(command_taint)},
                hard=dangerous,
            ))

    for chain in chain_findings:
        pattern_id = {
            "C1": "P5", "C2": "P6", "C3": "P4",
            "C4": "P3", "C5": "P10", "C6": "P13",
        }.get(chain.pattern_id)
        if pattern_id:
            findings.append(_finding(
                pattern_id,
                chain.action,
                chain.risk_level,
                chain.score,
                chain.reasons,
                chain.explanation,
                chain.evidence,
                hard=chain.hard_deny,
            ))

    if tool_name == "send_email":
        recipient = str(args.get("to", "")).lower()
        body = str(args)
        external = not recipient.endswith("@codeguard.local")
        if external and _contains_secret(body):
            findings.append(_finding(
                "P5", "deny", "critical", 70,
                ["secret_exfiltration", "external_recipient"],
                "邮件正文包含 secret，收件人为外部地址。",
                {"recipient": recipient, "body": "[MASKED]"},
                hard=True,
            ))
        elif external and re.search(
            r"(?i)(?:\$\(|`)[^\n]*(?:env|printenv|set)[^\n]*"
            r"(?:key|token|pass|secret|credential)",
            body,
        ):
            findings.append(_finding(
                "P5", "deny", "critical", 70,
                ["secret_exfiltration", "external_recipient"],
                (
                    "The external message contains command substitution that "
                    "collects credential-like environment variables."
                ),
                {"recipient": recipient, "body": "[MASKED]"},
                hard=True,
            ))
        _, email_meta = TaintTracker.normalize_email(recipient)
        if email_meta.get("spoof_suspected"):
            findings.append(_finding(
                "P14",
                "deny" if _contains_secret(body) else "ask",
                "critical" if _contains_secret(body) else "high",
                50 if _contains_secret(body) else 30,
                ["recipient_domain_spoofing"],
                "收件人域名具有多级后缀、Punycode 或内部域伪装特征。",
                {"recipient": recipient},
                hard=_contains_secret(body),
            ))

    if tool_name == "http_request":
        url = str(args.get("url", ""))
        normalized, metadata = TaintTracker.normalize_url(url)
        if metadata.get("private_or_metadata"):
            reasons = ["ssrf"]
            reasons.append(
                "cloud_metadata_access"
                if metadata.get("is_metadata") else "private_ip_access"
            )
            findings.append(_finding(
                "P7", "deny", "critical", 50, reasons,
                "HTTP 目标指向本机、私网、链路本地或云 metadata。",
                {"url": normalized, "host": metadata.get("host")},
                hard=True,
            ))
        payload = f"{url}\n{args.get('body', '')}\n{args.get('headers', {})}"
        if _external_url(url) and _contains_secret(payload):
            findings.append(_finding(
                "P6", "deny", "critical", 70,
                ["secret_exfiltration", "external_http_request"],
                "外部 HTTP 请求包含 secret。",
                {"url": normalized, "payload": "[MASKED]"},
                hard=True,
            ))
        elif _external_url(url) and re.search(
            r"(?i)(?:\$\(|`)[^\n]*(?:cat|grep|env|printenv)[^\n]*"
            r"(?:/etc/(?:passwd|shadow)|\.ssh|\.env|credential|token|"
            r"secret)[^\n]*(?:base64)?",
            payload,
        ):
            findings.append(_finding(
                "P6", "deny", "critical", 70,
                ["secret_exfiltration", "external_http_request"],
                (
                    "The external URL embeds command substitution that reads "
                    "a sensitive local source."
                ),
                {"url": normalized, "payload": "[MASKED]"},
                hard=True,
            ))

    if path and path_meta.get("contains_traversal"):
        outside = not path_meta.get("within_workspace", False)
        findings.append(_finding(
            "P8",
            "deny" if outside else "ask",
            "critical" if path_meta.get("sensitive") else "high",
            60 if path_meta.get("sensitive") else 35,
            ["path_traversal", "outside_workspace"],
            "路径包含穿越片段，归一化后离开工作区或指向敏感位置。",
            {"path": normalized_path},
            hard=bool(path_meta.get("sensitive")),
        ))

    if (
        path
        and path_meta.get("symlink")
        and not path_meta.get("realpath_within_workspace", True)
    ):
        findings.append(_finding(
            "P9", "deny", "critical", 60,
            ["symlink_escape", "outside_workspace", "sensitive_file"],
            "工作区内符号链接的最终目标位于工作区外部。",
            {"path": path, "realpath": path_meta.get("realpath")},
            hard=True,
        ))

    if tool_name in {"delete_path", "move_path"}:
        destructive = bool(
            path_meta.get("sensitive")
            or path_meta.get("contains_traversal")
            or (
                normalized_path
                and Path(normalized_path) == workspace
            )
        )
        findings.append(_finding(
            "P11",
            "deny" if destructive else "ask",
            "critical" if destructive else "high",
            60 if destructive else 30,
            ["destructive_operation"],
            "删除或移动操作具有不可逆副作用。",
            {"path": normalized_path or path},
            hard=destructive,
        ))

    if task_budget:
        adjustment, alignment_reason = tool_alignment(
            task_budget,
            tool_name,
            args,
        )
        if adjustment > 0:
            tainted_side_effect = bool(taint_matches) and tool_name in {
                "run_command",
                "http_request",
                "send_email",
                "delete_path",
                "move_path",
            }
            findings.append(_finding(
                "P12",
                "deny" if tainted_side_effect else "ask",
                "critical" if tainted_side_effect else "high",
                55 if tainted_side_effect else adjustment,
                [
                    "task_tool_misalignment",
                    *(
                        ["tainted_instruction", "tainted_argument_flow"]
                        if tainted_side_effect else []
                    ),
                ],
                (
                    "Untrusted context controls an unauthorized side-effect "
                    "tool argument."
                    if tainted_side_effect
                    else "当前工具副作用超过用户任务推断出的能力预算。"
                ),
                {
                    "max_side_effect": task_budget.max_side_effect.value,
                    "tool": tool_name,
                    "alignment": alignment_reason,
                    "taint_sources": (
                        _sources(taint_matches)
                        if tainted_side_effect else []
                    ),
                },
                hard=tainted_side_effect,
            ))

    joined = " ".join(str(value) for value in args.values())
    if re.search(
        r"(?i)(base64\s+(?:-d|--decode)|xxd\s+-r|"
        r"fromhex\(|b64decode\(|\\x[0-9a-f]{2}|"
        r"powershell(?:\.exe)?\s+-(?:enc|encodedcommand)\b|"
        r"(?:\$\(|`)[^\n]*(?:curl|wget|cat|python|node|base64)|"
        r"(?:part|chunk)[_-]?\d+)",
        joined,
    ):
        severe = tool_name in {"run_command", "send_email", "http_request"}
        findings.append(_finding(
            "P13",
            "deny" if severe else "ask",
            "critical" if severe else "high",
            60 if severe else 30,
            ["encoded_payload", "obfuscation"],
            "参数包含编码、分段或混淆 payload。",
            {"tool": tool_name},
            hard=severe,
        ))

    if tool_name == "write_file":
        write_taint = [
            match for match in taint_matches
            if match.argument_entity.entity_type == EntityType.PATH
        ]
        persistence = _persistence_path(path or "")
        executable = Path(path or "").suffix.lower() in {
            ".sh", ".py", ".js", ".ps1", ".bat", ".cmd",
        }
        if write_taint and (persistence or executable):
            findings.append(_finding(
                "P15",
                "deny" if persistence else "ask",
                "critical" if persistence else "high",
                55 if persistence else 35,
                ["tainted_write_path", "persistence_risk"],
                "低可信来源提供的路径被用于写入启动、CI、Hook 或可执行文件。",
                {"path": path, "sources": _sources(write_taint)},
                hard=persistence,
            ))

    return _deduplicate(findings)


def _finding(
    pattern_id: str,
    action: str,
    risk: str,
    score: int,
    reasons: list[str],
    explanation: str,
    evidence: dict,
    *,
    hard: bool = False,
) -> RiskPatternFinding:
    return RiskPatternFinding(
        pattern_id=pattern_id,
        name=PATTERN_NAMES[pattern_id],
        action=action,
        risk_level=risk,
        score=score,
        reasons=list(dict.fromkeys(reasons)),
        explanation=explanation,
        evidence=evidence,
        hard_deny=hard,
    )


def _path_for_tool(tool_name: str, args: dict) -> str:
    if tool_name == "move_path":
        return str(
            args.get("source")
            or args.get("src")
            or args.get("from")
            or args.get("from_path")
            or ""
        )
    return str(args.get("path", ""))


def _sources(matches: list[TaintMatch]) -> list[str]:
    return sorted({match.source.origin for match in matches})


def _contains_secret(value: str) -> bool:
    return any(pattern.search(str(value)) for pattern in TaintTracker.SECRET_RES)


def _external_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if not host or host in {"localhost", "codeguard.local"}:
        return False
    return True


def _mask_command(command: str) -> str:
    value = str(command)
    for pattern in TaintTracker.SECRET_RES:
        value = pattern.sub("[SECRET]", value)
    return value[:500]


def _persistence_path(path: str) -> bool:
    lowered = path.replace("\\", "/").lower()
    return any(marker in lowered for marker in (
        ".git/hooks/", ".github/workflows/", ".gitlab-ci",
        "startup", "autorun", "crontab", ".profile", ".bashrc",
    ))


def _deduplicate(
    findings: list[RiskPatternFinding],
) -> list[RiskPatternFinding]:
    values: dict[tuple[str, str], RiskPatternFinding] = {}
    for finding in findings:
        key = (finding.pattern_id, finding.action)
        previous = values.get(key)
        if previous is None or finding.score > previous.score:
            values[key] = finding
    return list(values.values())
