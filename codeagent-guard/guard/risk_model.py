from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from .chain_risk import ChainRiskAnalyzer, ChainRiskFinding
from .risk_patterns import RiskPatternFinding, detect_risk_patterns
from .taint import (
    EntityType,
    SourceType,
    TaintMatch,
    TaintTracker,
)
from .task_budget import TaskCapabilityBudget, tool_alignment


@dataclass
class RiskFeature:
    name: str
    score: int
    reason: str
    evidence: dict


@dataclass
class RiskAssessment:
    total_score: int
    hard_deny: bool
    action: str
    risk_level: str
    features: list[RiskFeature] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    dlp_findings: list[dict] = field(default_factory=list)
    taint_matches: list = field(default_factory=list)
    chain_findings: list = field(default_factory=list)
    task_budget: Optional[TaskCapabilityBudget] = None
    explanation: str = ""
    risk_patterns: list[RiskPatternFinding] = field(default_factory=list)
    provenance_edges: list[dict] = field(default_factory=list)
    runtime_taint_matches: list[TaintMatch] = field(
        default_factory=list,
        repr=False,
    )

    def to_dict(self) -> dict:
        return {
            "event_type": "ct_trm_assessment",
            "total_score": self.total_score,
            "hard_deny": self.hard_deny,
            "action": self.action,
            "risk_level": self.risk_level,
            "features": [asdict(feature) for feature in self.features],
            "reasons": self.reasons,
            "dlp_findings": self.dlp_findings,
            "taint_matches": list(self.taint_matches),
            "chain_findings": [
                asdict(value) if not isinstance(value, dict) else value
                for value in self.chain_findings
            ],
            "task_budget": (
                self.task_budget.to_dict() if self.task_budget else None
            ),
            "explanation": self.explanation,
            "risk_patterns": [
                asdict(pattern) for pattern in self.risk_patterns
            ],
            "provenance_edges": self.provenance_edges,
        }


ACTION_RISK = {
    "read_file": 0,
    "list_directory": 0,
    "search_files": 5,
    "open_directory": 10,
    "write_file": 15,
    "make_directory": 15,
    "delete_path": 30,
    "move_path": 30,
    "run_command": 30,
    "http_request": 20,
    "send_email": 25,
}

SOURCE_RISK = {
    SourceType.SYSTEM_POLICY: 0,
    SourceType.USER_TASK: 0,
    SourceType.USER_FOLLOWUP: 0,
    SourceType.AGENT_MEMORY: 5,
    SourceType.WORKSPACE_FILE: 15,
    SourceType.CONFIG_FILE: 15,
    SourceType.CODE_COMMENT: 20,
    SourceType.LOG_OUTPUT: 25,
    SourceType.TOOL_OUTPUT: 25,
    SourceType.HTTP_RESPONSE: 30,
    SourceType.LLM_PLAN: 5,
    SourceType.UNKNOWN: 15,
}

HARD_BASE_REASONS = {
    "sensitive_file_access",
    "credential_exposure_risk",
    "command_sensitive_resource_access",
    "remote_script_execution",
    "reverse_shell_detected",
    "fork_bomb_detected",
    "ssrf_private_network",
    "secret_leakage_detected",
    "path_traversal_detected",
    "external_root_modification",
    "trusted_workspace_root_modification",
    "non_empty_external_directory_delete",
}


class CTTRMRiskModel:
    ask_threshold = 25
    deny_threshold = 60

    @classmethod
    def set_decision_thresholds(
        cls,
        *,
        ask_threshold: int | None = None,
        deny_threshold: int | None = None,
    ) -> None:
        if ask_threshold is not None:
            cls.ask_threshold = int(ask_threshold)
        if deny_threshold is not None:
            cls.deny_threshold = int(deny_threshold)

    def __init__(
        self,
        workspace: Path,
        tracker: TaintTracker,
        chain: ChainRiskAnalyzer,
    ) -> None:
        self.workspace = workspace.resolve()
        self.trusted_workspace_roots: tuple[Path, ...] = ()
        self.tracker = tracker
        self.chain = chain

    def set_trusted_workspace_roots(
        self,
        roots: list[Path] | tuple[Path, ...],
    ) -> None:
        self.trusted_workspace_roots = tuple(
            Path(root).resolve(strict=False) for root in roots
        )

    @staticmethod
    def _is_within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    def _within_trusted_scope(self, metadata: dict) -> bool:
        raw = metadata.get("absolute_path")
        if not raw:
            return False
        path = Path(str(raw)).resolve(strict=False)
        return any(
            self._is_within(path, root)
            for root in self.trusted_workspace_roots
        )

    def assess_tool_call(
        self,
        tool_name: str,
        args: dict,
        context: dict,
        trace_id: str,
        task_budget: TaskCapabilityBudget | None = None,
    ) -> RiskAssessment:
        features: list[RiskFeature] = []
        base_reasons = list(context.get("base_reasons", ()))
        dlp_findings = list(context.get("dlp_findings", ()))
        taint_matches = self.tracker.match_taint(
            tool_name,
            args,
            trace_id=trace_id,
            conversation_id=context.get("conversation_id"),
        )
        edges = [
            asdict(self.tracker.record_edge(match))
            for match in taint_matches
        ]
        chain_findings = self.chain.analyze_before_tool_call(
            tool_name,
            args,
            trace_id,
            taint_matches,
        )
        patterns = detect_risk_patterns(
            tool_name,
            args,
            workspace=self.workspace,
            taint_matches=taint_matches,
            chain_findings=chain_findings,
            chain_state=self.chain.get_state(trace_id),
            task_budget=task_budget,
        )
        mode = context.get("ct_trm_mode")
        if mode == "rules_plus_source":
            taint_matches = []
            edges = []
            chain_findings = []
            patterns = []
        elif mode in {"rules_plus_taint", "ct_trm_without_chain"}:
            chain_findings = []
            patterns = detect_risk_patterns(
                tool_name,
                args,
                workspace=self.workspace,
                taint_matches=taint_matches,
                chain_findings=[],
                chain_state=self.chain.get_state(trace_id),
                task_budget=task_budget,
            )

        self.collect_asset_risk(tool_name, args, features)
        self.collect_action_risk(tool_name, args, features)
        self.collect_boundary_risk(tool_name, args, features)
        self.collect_source_risk(context, features)
        self.collect_dlp_risk(dlp_findings, features)
        self.collect_taint_risk(taint_matches, tool_name, features)
        self.collect_chain_risk(chain_findings, features)
        self.collect_authorization_adjustment(
            task_budget,
            tool_name,
            args,
            features,
        )
        for pattern in patterns:
            if not any(
                feature.name == f"Pattern:{pattern.pattern_id}"
                for feature in features
            ):
                features.append(RiskFeature(
                    f"Pattern:{pattern.pattern_id}",
                    0,
                    pattern.explanation,
                    {
                        **pattern.evidence,
                        "pattern_score": pattern.score,
                    },
                ))

        hard_deny = self.apply_hard_rules(base_reasons, patterns, dlp_findings)
        total_score = max(0, sum(feature.score for feature in features))
        action, risk_level = self.map_score_to_decision(
            total_score,
            hard_deny=hard_deny,
            patterns=patterns,
        )
        reasons = list(dict.fromkeys([
            *base_reasons,
            *(
                reason
                for finding in dlp_findings
                for reason in finding.get("reasons", [])
            ),
            *(
                match.reason for match in taint_matches
            ),
            *(
                reason
                for finding in chain_findings
                for reason in finding.reasons
            ),
            *(
                reason for pattern in patterns for reason in pattern.reasons
            ),
            *(
                ["ct_trm_risk_score"]
                if total_score >= 25 else []
            ),
        ]))
        explanation = self._explain(
            tool_name,
            total_score,
            action,
            hard_deny,
            taint_matches,
            chain_findings,
            patterns,
            dlp_findings,
        )
        return RiskAssessment(
            total_score=total_score,
            hard_deny=hard_deny,
            action=action,
            risk_level=risk_level,
            features=features,
            reasons=reasons,
            dlp_findings=dlp_findings,
            taint_matches=self.tracker.export_matches(taint_matches),
            chain_findings=chain_findings,
            task_budget=task_budget,
            explanation=explanation,
            risk_patterns=patterns,
            provenance_edges=edges,
            runtime_taint_matches=taint_matches,
        )

    def collect_asset_risk(
        self,
        tool_name: str,
        args: dict,
        features: list[RiskFeature],
    ) -> None:
        path = str(
            args.get("path")
            or args.get("source")
            or args.get("src")
            or ""
        )
        if not path:
            return
        normalized, metadata = self.tracker.normalize_path(path)
        lowered = normalized.lower()
        if any(marker in lowered for marker in (
            "/.ssh/", "id_rsa", "id_ed25519", "/.aws/",
            "/etc/shadow", "/etc/passwd", "/root/",
        )):
            score = 60
            reason = "SSH、云凭据或系统敏感文件"
        elif TaintTracker.is_sensitive_path(normalized):
            score = 40
            reason = "环境变量、token、key 或 credential 文件"
        elif any(marker in lowered for marker in (
            "config", "settings", "package.json", "pyproject",
        )):
            score = 10
            reason = "工作区配置文件"
        elif not metadata.get("within_workspace", True) and not self._within_trusted_scope(metadata):
            score = 20
            reason = "未知外部文件"
        else:
            score = 0
            reason = "工作区普通文件"
        if score:
            features.append(RiskFeature(
                "AssetRisk",
                score,
                reason,
                {"path": normalized},
            ))

    @staticmethod
    def collect_action_risk(
        tool_name: str,
        args: dict,
        features: list[RiskFeature],
    ) -> None:
        score = ACTION_RISK.get(tool_name, 15)
        if tool_name == "run_command":
            command = str(args.get("cmd") or args.get("command") or "")
            if TaintTracker.command_is_read_only(command):
                score = 10
            elif not TaintTracker.command_is_dangerous(command):
                score = 20
        elif tool_name == "http_request":
            method = str(args.get("method", "GET")).upper()
            score = 5 if method in {"GET", "HEAD"} else 20
        elif tool_name == "send_email":
            score = 20
        if score:
            features.append(RiskFeature(
                "ActionRisk",
                score,
                f"{tool_name} 的固有副作用风险",
                {"tool": tool_name},
            ))

    def collect_boundary_risk(
        self,
        tool_name: str,
        args: dict,
        features: list[RiskFeature],
    ) -> None:
        if tool_name == "http_request":
            normalized, metadata = self.tracker.normalize_url(
                str(args.get("url", ""))
            )
            method = str(args.get("method", "GET")).upper()
            score = (
                50
                if metadata.get("private_or_metadata")
                else 5 if method in {"GET", "HEAD"}
                else 15
            )
            features.append(RiskFeature(
                "BoundaryRisk",
                score,
                (
                    "本机、私网或 metadata 地址"
                    if score == 50 else "外部网络地址"
                ),
                {"url": normalized, "host": metadata.get("host")},
            ))
            return
        path = str(args.get("path") or args.get("source") or args.get("src") or "")
        if not path:
            return
        normalized, metadata = self.tracker.normalize_path(path)
        if metadata.get("within_workspace", True) or self._within_trusted_scope(metadata):
            score = 0
        elif metadata.get("sensitive"):
            score = 35
        else:
            score = 20
        if score:
            features.append(RiskFeature(
                "BoundaryRisk",
                score,
                "工作区外或敏感边界",
                {"path": normalized},
            ))

    @staticmethod
    def collect_source_risk(
        context: dict,
        features: list[RiskFeature],
    ) -> None:
        try:
            source_type = SourceType(str(context.get("source_type", "unknown")))
        except ValueError:
            source_type = SourceType.UNKNOWN
        score = SOURCE_RISK[source_type]
        if context.get("tainted"):
            score = max(score, 25)
        if score:
            features.append(RiskFeature(
                "SourceRisk",
                score,
                f"调用来源为 {source_type.value}",
                {"source_type": source_type.value},
            ))

    @staticmethod
    def collect_dlp_risk(
        findings: list[dict],
        features: list[RiskFeature],
    ) -> None:
        for finding in findings:
            score = int(finding.get("score") or 0)
            if not score:
                continue
            features.append(RiskFeature(
                "DLPRisk",
                score,
                ",".join(finding.get("reasons", [])) or "dlp_finding",
                {
                    "secret_type": finding.get("secret_type"),
                    "fingerprint": finding.get("fingerprint"),
                    "masked_value": finding.get("masked_value"),
                    "location": finding.get("location"),
                    "sink": finding.get("sink"),
                },
            ))

    @staticmethod
    def collect_taint_risk(
        matches: list[TaintMatch],
        tool_name: str,
        features: list[RiskFeature],
    ) -> None:
        if not matches:
            return
        command = any(
            match.argument_entity.entity_type == EntityType.COMMAND
            for match in matches
        )
        sensitive = any(
            match.source_entity.sensitivity == "critical"
            or match.argument_entity.sensitivity == "critical"
            for match in matches
        )
        tool_output = any(
            match.source.source_type in {
                SourceType.TOOL_OUTPUT,
                SourceType.LOG_OUTPUT,
                SourceType.HTTP_RESPONSE,
            }
            for match in matches
        )
        if command:
            dangerous_command = any(
                TaintTracker.command_is_dangerous(
                    match.argument_entity.normalized_value
                )
                or match.argument_entity.sensitivity == "critical"
                for match in matches
                if match.argument_entity.entity_type == EntityType.COMMAND
            )
            score = 45 if dangerous_command else 15
            reason = (
                "低可信来源中的高危命令进入 run_command"
                if dangerous_command
                else "低可信来源中的命令进入 run_command"
            )
        elif tool_output and tool_name in {
            "run_command", "write_file", "send_email", "http_request",
        }:
            score = 25
            reason = "工具输出诱导下一步副作用操作"
        elif sensitive:
            score = 45
            reason = "低可信来源诱导敏感文件或 secret 操作"
        else:
            score = 15
            reason = "低可信来源实体进入工具参数"
        features.append(RiskFeature(
            "TaintRisk",
            score,
            reason,
            {
                "sources": sorted({match.source.origin for match in matches}),
                "matches": len(matches),
            },
        ))

    @staticmethod
    def collect_chain_risk(
        findings: list[ChainRiskFinding],
        features: list[RiskFeature],
    ) -> None:
        for finding in findings:
            if finding.pattern_id == "C4" and finding.action == "ask":
                continue
            features.append(RiskFeature(
                "ChainRisk",
                finding.score,
                finding.explanation,
                finding.evidence,
            ))

    @staticmethod
    def collect_authorization_adjustment(
        budget: TaskCapabilityBudget | None,
        tool_name: str,
        args: dict,
        features: list[RiskFeature],
    ) -> None:
        if budget is None:
            return
        raw_score, reason = tool_alignment(budget, tool_name, args)
        # Task inference is a soft authorization signal. Positive mismatch
        # scores are represented by P12/ASK and must not independently turn
        # an otherwise non-dangerous call into an automatic denial.
        score = min(raw_score, 0)
        features.append(RiskFeature(
            "AuthorizationScore",
            score,
            reason,
            {
                "task_id": budget.task_id,
                "max_side_effect": budget.max_side_effect.value,
                "raw_adjustment": raw_score,
            },
        ))

    @staticmethod
    def apply_hard_rules(
        base_reasons: list[str],
        patterns: list[RiskPatternFinding],
        dlp_findings: list[dict],
    ) -> bool:
        return bool(
            HARD_BASE_REASONS.intersection(base_reasons)
            or any(pattern.hard_deny for pattern in patterns)
            or any(finding.get("hard_deny") for finding in dlp_findings)
        )

    def map_score_to_decision(
        self,
        score: int,
        *,
        hard_deny: bool,
        patterns: list[RiskPatternFinding],
    ) -> tuple[str, str]:
        if hard_deny:
            critical = any(
                pattern.hard_deny and pattern.risk_level == "critical"
                for pattern in patterns
            )
            return "deny", "critical" if critical else "high"
        if score >= self.deny_threshold:
            return "deny", "critical" if score >= 80 else "high"
        if (
            any(pattern.action == "ask" for pattern in patterns)
            or score >= self.ask_threshold
        ):
            return "ask", "high" if score >= 45 else "medium"
        return "allow", "low"

    @staticmethod
    def _explain(
        tool_name: str,
        score: int,
        action: str,
        hard_deny: bool,
        matches: list[TaintMatch],
        chain: list[ChainRiskFinding],
        patterns: list[RiskPatternFinding],
        dlp_findings: list[dict],
    ) -> str:
        parts = [
            f"CT-TRM 对 {tool_name} 的风险评分为 {score}，决策为 {action.upper()}。"
        ]
        if hard_deny:
            parts.append("命中不可由任务授权降级的硬拒绝规则。")
        if dlp_findings:
            parts.append("DLP 检测到敏感数据证据，并已使用脱敏摘要记录。")
        if matches:
            sources = "、".join(sorted({match.source.origin for match in matches}))
            parts.append(f"检测到来自 {sources} 的参数污染传播。")
        if chain:
            parts.append("检测到当前任务内的跨工具调用风险链。")
        if patterns:
            parts.append(
                "命中模式：" + "、".join(
                    f"{pattern.pattern_id} {pattern.name}"
                    for pattern in patterns
                )
            )
        return "".join(parts)
