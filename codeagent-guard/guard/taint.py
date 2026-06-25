from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import posixpath
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from urllib.parse import unquote, urlparse, urlunparse

from .provenance import ProvenanceGraph
from .state import RuntimeStateStore


class SourceType(str, Enum):
    SYSTEM_POLICY = "system_policy"
    USER_TASK = "user_task"
    USER_FOLLOWUP = "user_followup"
    WORKSPACE_FILE = "workspace_file"
    CODE_COMMENT = "code_comment"
    CONFIG_FILE = "config_file"
    LOG_OUTPUT = "log_output"
    TOOL_OUTPUT = "tool_output"
    HTTP_RESPONSE = "http_response"
    LLM_PLAN = "llm_plan"
    AGENT_MEMORY = "agent_memory"
    UNKNOWN = "unknown"


class TrustLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNTRUSTED = "untrusted"


class AuthorityLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class EntityType(str, Enum):
    PATH = "path"
    URL = "url"
    EMAIL = "email"
    SECRET = "secret"
    COMMAND = "command"
    INSTRUCTION = "instruction"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    FILE_EXTENSION = "file_extension"


@dataclass
class TaintSource:
    source_id: str
    source_type: SourceType
    trust_level: TrustLevel
    authority_level: AuthorityLevel
    origin: str
    content_hash: str
    created_at: float
    trace_id: Optional[str] = None
    tool_call_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityEntity:
    entity_id: str
    entity_type: EntityType
    raw_value: str
    normalized_value: str
    source_id: str
    confidence: float
    is_instructional: bool = False
    action_hint: Optional[str] = None
    sensitivity: str = "none"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceEdge:
    edge_id: str
    from_entity_id: str
    to_entity_id: str
    relation: str
    confidence: float
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TaintMatch:
    source: TaintSource
    source_entity: SecurityEntity
    argument_entity: SecurityEntity
    relation: str
    confidence: float
    reason: str


SOURCE_DEFAULTS: dict[SourceType, tuple[TrustLevel, AuthorityLevel]] = {
    SourceType.SYSTEM_POLICY: (TrustLevel.HIGH, AuthorityLevel.HIGH),
    SourceType.USER_TASK: (TrustLevel.HIGH, AuthorityLevel.HIGH),
    SourceType.USER_FOLLOWUP: (TrustLevel.HIGH, AuthorityLevel.HIGH),
    SourceType.AGENT_MEMORY: (TrustLevel.MEDIUM, AuthorityLevel.MEDIUM),
    SourceType.LLM_PLAN: (TrustLevel.MEDIUM, AuthorityLevel.LOW),
    SourceType.WORKSPACE_FILE: (TrustLevel.LOW, AuthorityLevel.NONE),
    SourceType.CODE_COMMENT: (TrustLevel.LOW, AuthorityLevel.NONE),
    SourceType.CONFIG_FILE: (TrustLevel.LOW, AuthorityLevel.NONE),
    SourceType.LOG_OUTPUT: (TrustLevel.UNTRUSTED, AuthorityLevel.NONE),
    SourceType.TOOL_OUTPUT: (TrustLevel.UNTRUSTED, AuthorityLevel.NONE),
    SourceType.HTTP_RESPONSE: (TrustLevel.UNTRUSTED, AuthorityLevel.NONE),
    SourceType.UNKNOWN: (TrustLevel.LOW, AuthorityLevel.NONE),
}


class TaintTracker:
    URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>'\"\)}]+")
    EMAIL_RE = re.compile(
        r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b"
    )
    WINDOWS_PATH_RE = re.compile(
        r"(?i)(?:[A-Z]:[\\/](?:[^<>:\"|?*\r\n]+[\\/]?)+)"
    )
    UNIX_PATH_RE = re.compile(
        r"(?<![\w:])(?:~[/\\][^\s'\"`<>]+|"
        r"(?:\.\.?[/\\])+(?:[^\s'\"`<>]+)|"
        r"/(?:[A-Za-z0-9_.@+-]+/)*[A-Za-z0-9_.@+-]+)"
    )
    SENSITIVE_NAME_RE = re.compile(
        r"(?i)(?:^|[/\\])(?:\.env(?:\.\w+)?|id_rsa|id_ed25519|"
        r"\.netrc|database\.ya?ml|"
        r"credentials?(?:\.\w+)?|service-account(?:\.\w+)?|"
        r"[^/\\]*(?:private[_-]?key|token|secret|credential)[^/\\]*|"
        r"[^/\\]+\.(?:pem|key|p12|pfx))(?:$|[/\\])"
    )
    SECRET_RES = (
        re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
            r"\.[A-Za-z0-9_-]{8,}\b"
        ),
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
        re.compile(
            r"\bAIza[A-Za-z0-9_.-]{16,}(?=$|[^A-Za-z0-9_.-])"
        ),
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|"
            r"redis)://[^:\s/]+:[^@\s/]+@"
        ),
        re.compile(
            r"(?i)root:[^:\r\n]*:0:0:root:/root:/bin/(?:ba)?sh"
        ),
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|token|password|secret|"
            r"private[_-]?key)[\"']?\s*[:=]\s*[\"']?"
            r"((?!https?://)[^\s\"']{8,})"
        ),
        re.compile(r"\b(FAKE_API_KEY_FOR_BENCHMARK_ONLY)\b"),
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{12,})"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    )
    COMMAND_RE = re.compile(
        r"(?im)(?:^|[;`]|\brun\s+|\bexecute\s+|\b执行\s*)"
        r"((?:(?:sudo\s+)?(?:bash|sh|python(?:3)?|node|curl|wget|cat|grep|"
        r"rm|chmod|ssh|scp|nc|ncat|netcat|socat|base64|pip|npm|make)\b)"
        r"[^\r\n]{0,500})"
    )
    INSTRUCTION_WORDS = {
        "read": "read", "send": "send", "execute": "execute",
        "run": "execute", "delete": "delete", "upload": "upload",
        "exfiltrate": "exfiltrate", "curl": "network",
        "install": "install", "open": "open", "copy": "copy",
        "inspect": "inspect", "paste": "paste", "读取": "read",
        "发送": "send", "执行": "execute", "运行": "execute",
        "删除": "delete", "上传": "upload", "安装": "install",
        "打开": "open", "复制": "copy", "检查": "inspect",
    }

    def __init__(
        self,
        workspace: Path | None = None,
        *,
        provenance: ProvenanceGraph | None = None,
        state_store: RuntimeStateStore | None = None,
        max_sources: int = 2000,
        ttl_seconds: int = 3600,
    ) -> None:
        self.workspace = workspace.resolve() if workspace else None
        self.provenance = provenance or ProvenanceGraph()
        self.state_store = state_store
        self.max_sources = max_sources
        self.ttl_seconds = ttl_seconds
        self._sources: dict[str, TaintSource] = {}
        self._entities: dict[str, list[SecurityEntity]] = {}
        self._lock = threading.RLock()
        self._restore_sources()

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def mask_secret(value: str) -> str:
        clean = str(value)
        if len(clean) <= 8:
            return "[SECRET]"
        prefix = clean[:3] if clean.lower().startswith("sk-") else clean[:2]
        return f"{prefix}****{clean[-4:]}"

    @classmethod
    def mask_sensitive_text(cls, value: str) -> str:
        text = str(value)
        text = re.sub(
            r"\bsk-[A-Za-z0-9_-]{8,}\b",
            lambda match: cls.mask_secret(match.group(0)),
            text,
        )
        text = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "AK****[REDACTED]", text)
        text = re.sub(
            r"(?i)((?:api[_-]?key|access[_-]?token|token|password|secret|"
            r"private[_-]?key)\s*[:=]\s*[\"']?)([^\s\"']{8,})",
            r"\1[REDACTED]",
            text,
        )
        text = re.sub(
            r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}",
            r"\1[REDACTED]",
            text,
        )
        text = re.sub(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            "[PRIVATE KEY REDACTED]",
            text,
        )
        for pattern in cls.SECRET_RES[2:8]:
            text = pattern.sub("[SECRET]", text)
        return text

    def register_source(
        self,
        content: str,
        source_type: SourceType,
        origin: str,
        trace_id: str | None = None,
        tool_call_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TaintSource:
        trust, authority = SOURCE_DEFAULTS[source_type]
        source = TaintSource(
            source_id=f"src-{uuid.uuid4().hex[:16]}",
            source_type=source_type,
            trust_level=trust,
            authority_level=authority,
            origin=str(origin),
            content_hash=self._hash(str(content)),
            created_at=time.time(),
            trace_id=trace_id,
            tool_call_id=tool_call_id,
            metadata=metadata or {},
        )
        with self._lock:
            self._purge()
            self._sources[source.source_id] = source
            if len(self._sources) > self.max_sources:
                oldest = min(
                    self._sources.values(),
                    key=lambda item: item.created_at,
                )
                self._sources.pop(oldest.source_id, None)
                self._entities.pop(oldest.source_id, None)
        self.provenance.add_node(
            source.source_id,
            node_type="source",
            trace_id=trace_id,
            label=source.origin,
            metadata={
                "source_type": source.source_type.value,
                "trust_level": source.trust_level.value,
                "authority_level": source.authority_level.value,
            },
        )
        return source

    def extract_entities(
        self,
        source: TaintSource,
        content: str,
    ) -> list[SecurityEntity]:
        text = str(content)
        entities: list[SecurityEntity] = []
        seen: set[tuple[EntityType, str]] = set()

        def add(
            entity_type: EntityType,
            raw: str,
            normalized: str,
            confidence: float,
            *,
            instructional: bool = False,
            action_hint: str | None = None,
            sensitivity: str = "none",
            metadata: dict[str, Any] | None = None,
        ) -> None:
            key = (entity_type, normalized)
            if not normalized or key in seen:
                return
            seen.add(key)
            safe_raw = (
                self.mask_sensitive_text(raw)
                if entity_type in {
                    EntityType.URL,
                    EntityType.COMMAND,
                    EntityType.INSTRUCTION,
                }
                else raw
            )
            entity = SecurityEntity(
                entity_id=f"ent-{uuid.uuid4().hex[:16]}",
                entity_type=entity_type,
                raw_value=safe_raw,
                normalized_value=normalized,
                source_id=source.source_id,
                confidence=confidence,
                is_instructional=instructional,
                action_hint=action_hint,
                sensitivity=sensitivity,
                metadata=metadata or {},
            )
            entities.append(entity)
            self.provenance.add_node(
                entity.entity_id,
                node_type="entity",
                trace_id=source.trace_id,
                label=f"{entity_type.value}:{safe_raw}",
                metadata={
                    "entity_type": entity_type.value,
                    "sensitivity": sensitivity,
                },
            )
            self.provenance.add_edge(
                from_node_id=source.source_id,
                to_node_id=entity.entity_id,
                relation="contains",
                trace_id=source.trace_id,
                confidence=confidence,
                reason="source_contains_entity",
                entity_type=entity_type.value,
            )

        secret_spans: list[tuple[int, int]] = []
        for pattern in self.SECRET_RES:
            for match in pattern.finditer(text):
                value = match.group(1) if match.lastindex else match.group(0)
                secret_spans.append(match.span())
                add(
                    EntityType.SECRET,
                    self.mask_secret(value),
                    f"sha256:{self._hash(value)}",
                    0.99,
                    sensitivity="critical",
                    metadata={"masked": True, "secret_hash": self._hash(value)},
                )

        url_values: list[str] = []
        for match in self.URL_RE.finditer(text):
            raw = match.group(0).rstrip(".,;:")
            url_values.append(raw)
            normalized, metadata = self.normalize_url(raw)
            add(
                EntityType.URL, raw, normalized, 0.98,
                sensitivity=(
                    "critical" if metadata.get("private_or_metadata") else "none"
                ),
                metadata=metadata,
            )
            host = metadata.get("host")
            if host:
                add(EntityType.DOMAIN, host, host, 0.97, metadata=metadata)
                try:
                    ipaddress.ip_address(host.strip("[]"))
                except ValueError:
                    pass
                else:
                    add(
                        EntityType.IP_ADDRESS,
                        host,
                        host.strip("[]"),
                        0.99,
                        metadata=metadata,
                    )

        for match in self.EMAIL_RE.finditer(text):
            raw = match.group(0)
            normalized, metadata = self.normalize_email(raw)
            add(
                EntityType.EMAIL,
                raw,
                normalized,
                0.99,
                sensitivity="medium" if metadata["spoof_suspected"] else "none",
                metadata=metadata,
            )

        path_candidates = []
        path_candidates.extend(match.group(0) for match in self.WINDOWS_PATH_RE.finditer(text))
        path_candidates.extend(match.group(0) for match in self.UNIX_PATH_RE.finditer(text))
        path_candidates.extend(
            match.group(0)
            for match in re.finditer(
                r"(?i)(?:^|[\s'\"`(])("
                r"(?:fake_home|fake_root|workspace)[/\\][^\s'\"`),;]+|"
                r"(?:\.[A-Za-z0-9_.-]+[/\\])[^\s'\"`),;]+|"
                r"(?:\.env(?:\.\w+)?|id_rsa|id_ed25519|"
                r"[\w.-]+\.(?:pem|key|p12|pfx)))",
                text,
            )
        )
        for raw in path_candidates:
            clean = raw.strip(" \t\r\n'\"`()[]{}.,;:")
            if "://" in clean or any(clean in url for url in url_values):
                continue
            normalized, metadata = self.normalize_path(clean)
            sensitivity = (
                "critical" if self.is_sensitive_path(normalized) else "none"
            )
            add(
                EntityType.PATH,
                clean,
                normalized,
                0.93,
                sensitivity=sensitivity,
                metadata=metadata,
            )
            suffix = Path(clean.replace("\\", "/")).suffix.lower()
            if suffix:
                add(
                    EntityType.FILE_EXTENSION,
                    suffix,
                    suffix,
                    0.95,
                    metadata={"path": normalized},
                )

        for match in self.COMMAND_RE.finditer(text):
            raw = match.group(1).strip()
            add(
                EntityType.COMMAND,
                raw,
                self.normalize_command(raw),
                0.9,
                instructional=True,
                action_hint="execute",
                sensitivity=(
                    "critical" if self.command_is_dangerous(raw) else "medium"
                ),
            )

        lowered = text.lower()
        for word, action in self.INSTRUCTION_WORDS.items():
            if word.lower() in lowered:
                add(
                    EntityType.INSTRUCTION,
                    word,
                    word.lower(),
                    0.75,
                    instructional=True,
                    action_hint=action,
                )

        with self._lock:
            self._entities[source.source_id] = entities
        return entities

    def register_context(
        self,
        content: str,
        source_type: SourceType,
        origin: str,
        trace_id: str | None = None,
        tool_call_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[TaintSource, list[SecurityEntity]]:
        source = self.register_source(
            content,
            source_type,
            origin,
            trace_id,
            tool_call_id,
            metadata,
        )
        entities = self.extract_entities(source, content)
        if self.state_store is not None:
            self.state_store.save_taint_source(
                self._source_dict(source),
                [self._entity_dict(entity) for entity in entities],
                ttl_seconds=self.ttl_seconds,
            )
        return source, entities

    def extract_entities_from_tool_args(
        self,
        tool_name: str,
        args: dict,
    ) -> list[SecurityEntity]:
        source = TaintSource(
            source_id=f"arg-{uuid.uuid4().hex[:16]}",
            source_type=SourceType.LLM_PLAN,
            trust_level=TrustLevel.MEDIUM,
            authority_level=AuthorityLevel.LOW,
            origin=f"{tool_name}.arguments",
            content_hash=self._hash(json.dumps(args, default=str, sort_keys=True)),
            created_at=time.time(),
            metadata={"tool": tool_name, "argument_source": True},
        )
        entities: list[SecurityEntity] = []
        for name, value in self._flatten_args(args):
            if name.startswith("_"):
                continue
            text = str(value)
            if name in {"path", "source", "destination", "file", "file_path"}:
                normalized, metadata = self.normalize_path(text)
                entities.append(self._argument_entity(
                    source, EntityType.PATH, text, normalized, name,
                    sensitivity=(
                        "critical" if self.is_sensitive_path(normalized)
                        else "none"
                    ),
                    metadata=metadata,
                ))
            elif name in {"url", "uri", "redirect_url", "location"}:
                normalized, metadata = self.normalize_url(text)
                entities.append(self._argument_entity(
                    source, EntityType.URL, text, normalized, name,
                    sensitivity=(
                        "critical" if metadata.get("private_or_metadata")
                        else "none"
                    ),
                    metadata=metadata,
                ))
            elif name in {"to", "recipient", "email"}:
                normalized, metadata = self.normalize_email(text)
                entities.append(self._argument_entity(
                    source, EntityType.EMAIL, text, normalized, name,
                    metadata=metadata,
                ))
            elif name in {"cmd", "command", "script"}:
                entities.append(self._argument_entity(
                    source,
                    EntityType.COMMAND,
                    text,
                    self.normalize_command(text),
                    name,
                    sensitivity=(
                        "critical" if self.command_is_dangerous(text)
                        else "medium"
                    ),
                ))

            temp = self.register_source(
                text,
                SourceType.LLM_PLAN,
                f"{tool_name}.args.{name}",
                metadata={"temporary_argument": True},
            )
            extracted = self.extract_entities(temp, text)
            for entity in extracted:
                entity.source_id = source.source_id
                entity.metadata["argument"] = name
                if entity.entity_type == EntityType.SECRET:
                    entity.raw_value = self.mask_secret(entity.raw_value)
                entities.append(entity)
            with self._lock:
                self._sources.pop(temp.source_id, None)
                self._entities.pop(temp.source_id, None)

        unique: dict[tuple[str, str, str], SecurityEntity] = {}
        for entity in entities:
            key = (
                entity.entity_type.value,
                entity.normalized_value,
                str(entity.metadata.get("argument", "")),
            )
            unique[key] = entity
        return list(unique.values())

    def match_taint(
        self,
        tool_name: str,
        args: dict,
        trace_id: str | None = None,
        conversation_id: str | None = None,
    ) -> list[TaintMatch]:
        argument_entities = self.extract_entities_from_tool_args(tool_name, args)
        matches: list[TaintMatch] = []
        with self._lock:
            self._purge()
            sources = list(self._sources.values())
        for source in sources:
            same_scope = (
                (trace_id and source.trace_id == trace_id)
                or (
                    conversation_id
                    and source.metadata.get("conversation_id") == conversation_id
                )
            )
            if not same_scope or source.source_type == SourceType.LLM_PLAN:
                continue
            if source.trust_level not in {TrustLevel.LOW, TrustLevel.UNTRUSTED}:
                continue
            for source_entity in self._entities.get(source.source_id, ()):
                for argument_entity in argument_entities:
                    relation, confidence = self._entity_relation(
                        source_entity,
                        argument_entity,
                    )
                    if relation is None:
                        continue
                    matches.append(TaintMatch(
                        source=source,
                        source_entity=source_entity,
                        argument_entity=argument_entity,
                        relation=relation,
                        confidence=confidence,
                        reason="tainted_argument_flow",
                    ))
        return matches

    def record_edge(self, match: TaintMatch) -> ProvenanceEdge:
        trace_id = match.source.trace_id
        argument = match.argument_entity
        self.provenance.add_node(
            argument.entity_id,
            node_type="tool_argument",
            trace_id=trace_id,
            label=(
                f"{argument.metadata.get('tool', '')}."
                f"{argument.metadata.get('argument', '')}"
            ),
            metadata={
                "entity_type": argument.entity_type.value,
                "masked_value": argument.raw_value,
            },
        )
        record = self.provenance.add_edge(
            from_node_id=match.source_entity.entity_id,
            to_node_id=argument.entity_id,
            relation=match.relation,
            trace_id=trace_id,
            confidence=match.confidence,
            reason=match.reason,
            entity_type=argument.entity_type.value,
            metadata={
                "source": match.source.origin,
                "source_type": match.source.source_type.value,
                "argument": argument.metadata.get("argument"),
                "masked_value": argument.raw_value,
            },
        )
        return ProvenanceEdge(
            edge_id=record.edge_id,
            from_entity_id=record.from_node_id,
            to_entity_id=record.to_node_id,
            relation=record.relation,
            confidence=record.confidence,
            reason=record.reason,
            metadata=record.metadata,
        )

    def get_entities_for_trace(self, trace_id: str) -> list[SecurityEntity]:
        with self._lock:
            source_ids = [
                source.source_id for source in self._sources.values()
                if source.trace_id == trace_id
            ]
            return [
                entity
                for source_id in source_ids
                for entity in self._entities.get(source_id, ())
            ]

    def get_edges_for_trace(self, trace_id: str) -> list[dict]:
        return self.provenance.find_edges(trace_id)

    def get_source(self, source_id: str) -> TaintSource | None:
        with self._lock:
            return self._sources.get(source_id)

    def clear_trace(self, trace_id: str) -> None:
        with self._lock:
            stale = [
                source_id for source_id, source in self._sources.items()
                if source.trace_id == trace_id
            ]
            for source_id in stale:
                self._sources.pop(source_id, None)
                self._entities.pop(source_id, None)
        self.provenance.clear_trace(trace_id)
        if self.state_store is not None:
            self.state_store.delete_taint_trace(trace_id)

    def _restore_sources(self) -> None:
        if self.state_store is None:
            return
        for record in self.state_store.list_taint_sources():
            raw_source = record["source"]
            try:
                source = TaintSource(
                    **{
                        **raw_source,
                        "source_type": SourceType(raw_source["source_type"]),
                        "trust_level": TrustLevel(raw_source["trust_level"]),
                        "authority_level": AuthorityLevel(
                            raw_source["authority_level"]
                        ),
                    }
                )
                entities = [
                    SecurityEntity(
                        **{
                            **raw_entity,
                            "entity_type": EntityType(
                                raw_entity["entity_type"]
                            ),
                        }
                    )
                    for raw_entity in record.get("entities", ())
                ]
            except (KeyError, TypeError, ValueError):
                continue
            self._sources[source.source_id] = source
            self._entities[source.source_id] = entities
            self.provenance.add_node(
                source.source_id,
                node_type="source",
                trace_id=source.trace_id,
                label=source.origin,
                metadata={
                    "source_type": source.source_type.value,
                    "trust_level": source.trust_level.value,
                    "authority_level": source.authority_level.value,
                },
            )
            for entity in entities:
                self.provenance.add_node(
                    entity.entity_id,
                    node_type="entity",
                    trace_id=source.trace_id,
                    label=f"{entity.entity_type.value}:{entity.raw_value}",
                    metadata={
                        "entity_type": entity.entity_type.value,
                        "sensitivity": entity.sensitivity,
                    },
                )
                self.provenance.add_edge(
                    from_node_id=source.source_id,
                    to_node_id=entity.entity_id,
                    relation="contains",
                    trace_id=source.trace_id,
                    confidence=entity.confidence,
                    reason="source_contains_entity",
                    entity_type=entity.entity_type.value,
                )

    @staticmethod
    def _source_dict(source: TaintSource) -> dict:
        data = asdict(source)
        data["source_type"] = source.source_type.value
        data["trust_level"] = source.trust_level.value
        data["authority_level"] = source.authority_level.value
        return data

    @staticmethod
    def _entity_dict(entity: SecurityEntity) -> dict:
        data = asdict(entity)
        data["entity_type"] = entity.entity_type.value
        return data

    def export_matches(self, matches: list[TaintMatch]) -> list[dict]:
        return [
            {
                "source": match.source.origin,
                "source_type": match.source.source_type.value,
                "trust_level": match.source.trust_level.value,
                "entity_type": match.source_entity.entity_type.value,
                "masked_value": match.source_entity.raw_value,
                "argument": match.argument_entity.metadata.get("argument"),
                "relation": match.relation,
                "confidence": match.confidence,
                "reason": match.reason,
            }
            for match in matches
        ]

    def normalize_path(self, raw: str) -> tuple[str, dict]:
        original = str(raw).strip().strip("'\"")
        decoded = re.sub(
            r"(?i)%(?:c0%af|e0%80%af|f0%80%80%af)",
            "/",
            original,
        )
        decoded = re.sub(
            r"(?i)%(?:c1%9c|e0%81%9c|f0%80%81%9c)",
            "\\\\",
            decoded,
        )
        for _ in range(3):
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        decoded = decoded.translate(str.maketrans({
            "\u2044": "/",
            "\u2215": "/",
            "\u29f8": "/",
            "\uff0f": "/",
            "\uff3c": "\\",
            "\uff0e": ".",
            "\u2024": ".",
            "\ufe52": ".",
        }))
        expanded = os.path.expandvars(os.path.expanduser(decoded))
        windows = re.match(r"^([A-Za-z]):[\\/](.*)$", expanded)
        if windows:
            drive = windows.group(1).lower()
            rest = windows.group(2).replace("\\", "/")
            normalized = f"{drive}:/{posixpath.normpath(rest)}"
            path = Path(decoded)
        else:
            portable = expanded.replace("\\", "/")
            normalized = posixpath.normpath(portable)
            path = Path(expanded)
            if self.workspace is not None:
                candidate = path if path.is_absolute() else self.workspace / path
                normalized = str(Path(os.path.abspath(os.path.normpath(
                    str(candidate)
                ))))
        metadata: dict[str, Any] = {
            "url_decoded": decoded != original,
            "contains_traversal": (
                any(part == ".." for part in portable_parts(decoded))
                or bool(re.search(
                    r"(?:^|[/\\])\.{3,}(?:[/\\]|$)",
                    decoded,
                ))
            ),
        }
        if self.workspace is not None:
            candidate = path if path.is_absolute() else self.workspace / path
            lexical = Path(os.path.abspath(os.path.normpath(str(candidate))))
            metadata["absolute_path"] = str(lexical)
            metadata["within_workspace"] = self._is_within(
                lexical,
                self.workspace,
            )
            if candidate.exists() or candidate.is_symlink():
                real = Path(os.path.realpath(candidate))
                metadata["realpath"] = str(real)
                metadata["symlink"] = candidate.is_symlink() or real != lexical
                metadata["realpath_within_workspace"] = self._is_within(
                    real,
                    self.workspace,
                )
                normalized = str(real)
        metadata["sensitive"] = self.is_sensitive_path(normalized)
        return normalized, metadata

    @staticmethod
    def normalize_url(raw: str) -> tuple[str, dict]:
        value = unquote(str(raw).strip())
        try:
            parsed = urlparse(value)
            port = parsed.port
        except ValueError:
            return value, {
                "scheme": "",
                "host": "",
                "port": None,
                "path": "",
                "is_private": False,
                "is_metadata": False,
                "private_or_metadata": False,
                "invalid": True,
            }
        host = (parsed.hostname or "").lower().rstrip(".")
        parsed_ip = TaintTracker._parse_ip_host(host)
        if parsed_ip is not None:
            host = str(parsed_ip)
        scheme = parsed.scheme.lower()
        netloc = host
        if ":" in host and not host.startswith("["):
            netloc = f"[{host}]"
        if port:
            netloc = f"{netloc}:{port}"
        path = posixpath.normpath(parsed.path or "/")
        if parsed.path.endswith("/") and not path.endswith("/"):
            path += "/"
        normalized = urlunparse((
            scheme,
            netloc,
            path,
            "",
            parsed.query,
            "",
        ))
        private = False
        metadata_host = host in {
            "metadata.google.internal",
            "metadata.azure.internal",
            "instance-data.ec2.internal",
            "metadata.test",
            "100.100.100.200",
        }
        if host in {"localhost", "localhost.localdomain"}:
            private = True
        try:
            ip = parsed_ip or ipaddress.ip_address(host.strip("[]"))
            private = (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
            )
            metadata_host = metadata_host or str(ip) == "169.254.169.254"
        except ValueError:
            pass
        return normalized, {
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": path,
            "is_private": private,
            "is_metadata": metadata_host,
            "private_or_metadata": private or metadata_host,
        }

    @staticmethod
    def _parse_ip_host(host: str):
        value = str(host).strip("[]").lower()
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            pass
        if value.isdigit():
            number = int(value, 10)
            if 0 <= number <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(number)
            return None
        parts = value.split(".")
        if len(parts) != 4:
            return None
        values = []
        try:
            for part in parts:
                base = (
                    16 if part.startswith("0x")
                    else 8 if len(part) > 1 and part.startswith("0")
                    else 10
                )
                number = int(part, base)
                if number > 255:
                    return None
                values.append(number)
        except ValueError:
            return None
        return ipaddress.IPv4Address(bytes(values))

    @staticmethod
    def normalize_email(raw: str) -> tuple[str, dict]:
        value = str(raw).strip().lower()
        local, _, domain = value.rpartition("@")
        labels = [label for label in domain.split(".") if label]
        spoof = (
            domain.startswith("xn--")
            or any(label.startswith("xn--") for label in labels)
            or (
                len(labels) >= 4
                and labels[-2:] in (["evil", "test"], ["example", "test"])
            )
            or ".test." in domain
        )
        return value, {
            "local": local,
            "domain": domain,
            "spoof_suspected": spoof,
        }

    @classmethod
    def normalize_command(cls, raw: str) -> str:
        return cls.mask_sensitive_text(
            re.sub(r"\s+", " ", str(raw).strip())
        )

    @classmethod
    def command_is_dangerous(cls, command: str) -> bool:
        value = re.sub(r"\\\r?\n", "", str(command))
        if cls.command_is_safe_cleanup(value):
            value = re.sub(
                r"(?i)\brm\s+-[^\n;&|]*r[^\n;&|]*f[^\n;&|]*"
                r"\s+(?:\./)?(?:node_modules|dist|build|coverage|tmp)"
                r"(?:/)?(?=\s*(?:&&|;|$))",
                "",
                value,
            )
        patterns = (
            r"(?i)\b(?:curl|wget|fetch)\b[^\n]*(?:\||;|&&)"
            r"\s*(?:/bin/)?(?:ba)?sh\b",
            r"(?i)\bcurl\b[^\n]*(?:-d|--data(?:-binary)?)\s*"
            r"@[^ \t;&|]*(?:secret|credential|token|key)",
            r"(?i)\bcurl\b[^\n]*>\s*/(?:bin|sbin|usr/bin|usr/sbin|etc)/",
            r"(?i)\|\s*(?:/[\w?*.-]+/)?(?:ba)?sh\b",
            r"(?i)\bxargs\s+(?:-[^\s]+\s+)*(?:/bin/)?(?:ba)?sh\b",
            r"(?i)\b(?:python(?:3)?|node|ruby|perl|php)\b[^\n]*"
            r"(?:eval|exec|system|subprocess)[^\n]*"
            r"(?:https?://|urllib|requests|net::http|lwp|file_get_contents)",
            r"(?i)\bpython(?:3)?\b[^\n]*\bexec\s*\([^\n]*"
            r"(?:open\s*\(|csv\.(?:dictreader|reader))",
            r"(?i)(?:socket\.socket|use\s+socket|tcpsocket|fsockopen|new-object\s+"
            r"system\.net\.sockets\.tcpclient)[^\n]*(?:connect|open|\()"
            r"[^\n]*(?:dup2|/bin/(?:ba)?sh|iex|invoke-expression|exec)",
            r"(?i)(?:/dev/(?:tcp|udp)|openssl\s+s_client)[^\n]*"
            r"(?:bash|sh|exec|cat\s*<&|\d+<>|(?:tcp|udp)/)",
            r"(?i)\bexec\s+\d+<>/dev/(?:tcp|udp)/",
            r"(?i)(?:^|\s)/(?:[^/\s]+/)*[^/\s]*sh\s+-i[^\n]*"
            r"/dev/(?:tcp|udp)/",
            r"(?i)\b(?:nc|ncat|netcat|socat)\b[^\n]*\s-e\s",
            r"(?i)\b(?:nc|ncat|netcat)\b[^\n]*\s-l(?:v|p|\s)",
            r"(?i)base64\s+(?:-d|--decode)[^\n]*(?:\||;)"
            r"\s*(?:/bin/)?(?:ba)?sh\b",
            r"(?i)\bpowershell(?:\.exe)?\b[^\n]*(?:-enc(?:odedcommand)?\b|"
            r"invoke-expression|\biex\b)",
            r"(?i)(?:\$\([^)]*(?:curl|wget|cat|python|node|base64)[^)]*\)"
            r"|`[^`]*(?:curl|wget|cat|python|node)[^`]*`)",
            r"(?i)\b(?:ld_preload|bash_env)\s*=|"
            r"\bnode_options\s*=\s*['\"]?--require\b",
            r"(?i)\bchmod\s+(?:[ugoa,+-]*s|[4567][0-7]{3})\b",
            r"(?i)\bchmod\s+\+x\s+[^\n;&|]+\s*&&\s*"
            r"(?:\./|/|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[A-Za-z0-9_.-])",
            r"(?i)\bfind\b[^\n]*-exec\s+(?:/bin/)?(?:ba)?sh\s+-p\b",
            r"(?i)\bcat\b[^\n]*\|\s*mysql\b[^\n]*\s-p",
            r"(?i)\bmount\b[^\n]*&&[^\n]*(?:\./|(?:ba)?sh\s+)"
            r"[A-Za-z0-9_.-]+",
            r"(?i)\bapktool\b[^\n]*&&\s*(?:/bin/)?(?:ba)?sh\b",
            r"(?i)\bxargs\b[^\n]*(?:nc|ncat|netcat|umount)\b",
            r"(?i)\b(?:systemctl|service)\s+(?:stop|disable)\s+"
            r"(?:ssh|sshd|firewalld|ufw)\b|"
            r"\b(?:ufw\s+disable|iptables\s+-[fx])\b",
            r"(?i)(?::\(\)\s*\{\s*:\|:\s*&\s*\};:|"
            r"os\.fork\(\)[^\n]*(?:range\(|while\s+true))",
            r"(?i)(?::\s*>\s*/var/log/|truncate\s+-s\s*0\s+/var/log/)",
            r"(?i)\bdd\s+if=/dev/(?:sd[a-z]\d*|mem|zero)\b",
            r"(?i)\bcat\s+/dev/mem\b|"
            r"\bfind\s+/\s+[^\n]*\.(?:key|pem)\b",
            r"(?i)/(?:proc/(?:\d+/environ|self/fd|net/tcp)"
            r"|var/run/docker\.sock)",
            r"(?i)\bln\s+-s[f]?\s+(?:/|~)[^\s]*\s+[^\s]+",
            r"(?i)\b(?:pip|pip3|npm|pnpm|yarn)\b[^\n]*"
            r"(?:--extra-index-url|--registry|--install-option)"
            r"[^\n]*http://",
            r"(?i)\b(?:pip|pip3)\b[^\n]*git\+http://",
            r"(?i)\b(?:curl|wget)\b[^\n]*\|\s*"
            r"(?:make|python(?:3)?|node|ruby|perl|php)\b",
            r"(?i)\bgrep\b[^\n]*(?:api[_-]?key|token|secret|password|"
            r"credential)",
            r"(?i)\b(?:history\s+-r\s*&&\s*!!|"
            r"xargs\s+kill\s+-9)\b",
            r"(?i)\bmkfifo\b[^\n]*(?:curl|wget)[^\n]*(?:bash|sh)",
            r"(?i)(?:\$[A-Za-z_][A-Za-z0-9_]*|\$cmd)"
            r"\s*\|\s*(?:/bin/)?(?:ba)?sh\b",
            r"(?i)\bcurl\s+\$\([^)]*(?:printf|echo|cat)[^)]*\)",
            r"(?i)https?://[^\s\"']*[?&][^=\s]+="
            r"(?:\$\(|`)[^\n]*(?:/etc/passwd|\.ssh|\.env|base64)",
            r"(?i)\b(?:cu|ba)(?:`[^`]+`)+(?:rl|sh)\b",
            r"(?i)\bcurl\b[^\n#]*#[^\n]*\|[^\n]*\bbash\b",
        )
        destructive_rm = re.search(
            r"(?i)\brm\s+-[^\n]*r[^\n]*f\b",
            value,
        )
        return bool(destructive_rm or any(
            re.search(pattern, value) for pattern in patterns
        ))

    @staticmethod
    def command_is_safe_cleanup(command: str) -> bool:
        return bool(re.fullmatch(
            r"(?is)\s*rm\s+-[^\n;&|]*r[^\n;&|]*f[^\n;&|]*\s+"
            r"(?:\./)?(?:node_modules|dist|build|coverage|tmp)/?"
            r"\s*(?:&&\s*(?:npm|pnpm|yarn)\s+install\s*)?",
            str(command),
        ))

    @staticmethod
    def command_is_read_only(command: str) -> bool:
        value = re.sub(r"\s+", " ", str(command).strip())
        patterns = (
            r"pwd",
            r"(?:python(?:3)?|node|ruby|perl|php)\s+--version",
            r"python(?:3)?\s+-m\s+(?:py_compile|compileall)\b.+",
            r"(?:git\s+(?:status|log|diff|show)\b.*)",
            r"printf\s+[^|;&`$<>]+",
            r"grep\b(?!.*(?:api[_-]?key|token|secret|password|credential))"
            r".*(?:\$\{?workspace\}?|workspace[/\\]|(?:^|\s)\.).*",
            r"(?:ls|dir)\b(?!.*(?:>|--delete)).*",
            r"wc\b.*",
            r"find\s+(?:\.|workspace(?:[/\\]|\s)).*"
            r"(?<!\s-delete)(?<!\s-exec)",
            r"(?:env|printenv)(?:\s*\|\s*grep\s+"
            r"[A-Za-z_][A-Za-z0-9_]*)?",
            r"(?:ps|netstat|ss|lsof|mount|df|du|uname|whoami|id)\b.*",
            r"ssh-add\s+-l",
            r"readlink\s+/proc/(?:self|\d+)/[A-Za-z0-9_./-]+",
            r"cat\s+/proc/(?:cpuinfo|meminfo|version|uptime|"
            r"(?:self|\d+)/(?:maps|cgroup|status))"
            r"(?:\s*\|\s*grep\s+[A-Za-z0-9_.-]+)?",
            r"ls\b[^\n]*/proc/(?:self|\d+)/ns/?",
            r"(?:pytest|python(?:3)?\s+-m\s+(?:pytest|unittest)|"
            r"npm\s+test|pnpm\s+test|yarn\s+test|make\s+test|"
            r"go\s+test)\b.*",
        )
        return any(
            re.fullmatch(pattern, value, flags=re.IGNORECASE)
            for pattern in patterns
        )

    @classmethod
    def is_sensitive_path(cls, value: str) -> bool:
        normalized = str(value).replace("\\", "/").lower()
        return bool(
            cls.SENSITIVE_NAME_RE.search(normalized)
            or any(marker in normalized for marker in (
                "/.ssh/", "/.aws/", "/.gnupg/", "/etc/shadow",
                "/.kube/config", "/.docker/config.json",
                "/etc/passwd", "/etc/sudoers", "/root/",
            ))
        )

    @staticmethod
    def _flatten_args(args: dict, prefix: str = "") -> list[tuple[str, Any]]:
        values: list[tuple[str, Any]] = []
        for key, value in args.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                values.extend(TaintTracker._flatten_args(value, name))
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        values.extend(TaintTracker._flatten_args(
                            item,
                            f"{name}.{index}",
                        ))
                    else:
                        values.append((name, item))
            elif value is not None:
                values.append((name.split(".")[-1], value))
        return values

    @staticmethod
    def _argument_entity(
        source: TaintSource,
        entity_type: EntityType,
        raw: str,
        normalized: str,
        argument: str,
        *,
        sensitivity: str = "none",
        metadata: dict[str, Any] | None = None,
    ) -> SecurityEntity:
        return SecurityEntity(
            entity_id=f"arg-ent-{uuid.uuid4().hex[:16]}",
            entity_type=entity_type,
            raw_value=(
                TaintTracker.mask_secret(raw)
                if entity_type == EntityType.SECRET
                else TaintTracker.mask_sensitive_text(raw)
            ),
            normalized_value=normalized,
            source_id=source.source_id,
            confidence=0.99,
            sensitivity=sensitivity,
            metadata={
                **(metadata or {}),
                "argument": argument,
                "tool": source.metadata.get("tool"),
            },
        )

    @staticmethod
    def _entity_relation(
        source: SecurityEntity,
        argument: SecurityEntity,
    ) -> tuple[str | None, float]:
        if source.entity_type != argument.entity_type:
            if (
                source.entity_type == EntityType.INSTRUCTION
                and argument.entity_type == EntityType.COMMAND
            ):
                return None, 0
            return None, 0
        left = source.normalized_value.lower()
        right = argument.normalized_value.lower()
        if left == right:
            return "reused_in_argument", 1.0
        if len(left) >= 6 and (left in right or right in left):
            return "derived_from", 0.85
        return None, 0

    @staticmethod
    def _is_within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    def _purge(self) -> None:
        cutoff = time.time() - self.ttl_seconds
        stale = [
            source_id for source_id, source in self._sources.items()
            if source.created_at < cutoff
        ]
        for source_id in stale:
            self._sources.pop(source_id, None)
            self._entities.pop(source_id, None)


def portable_parts(value: str) -> list[str]:
    return [
        part for part in str(value).replace("\\", "/").split("/")
        if part not in {"", "."}
    ]


def source_to_dict(source: TaintSource) -> dict:
    return asdict(source)
