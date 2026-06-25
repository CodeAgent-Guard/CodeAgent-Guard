from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ProvenanceNode:
    node_id: str
    node_type: str
    trace_id: str | None
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceEdgeRecord:
    edge_id: str
    trace_id: str | None
    from_node_id: str
    to_node_id: str
    relation: str
    confidence: float
    reason: str
    entity_type: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ProvenanceGraph:
    """Small in-memory provenance graph scoped by trace identifiers."""

    def __init__(self, *, max_edges_per_trace: int = 500) -> None:
        self.max_edges_per_trace = max_edges_per_trace
        self._nodes: dict[str, ProvenanceNode] = {}
        self._edges: dict[str, list[ProvenanceEdgeRecord]] = {}
        self._lock = threading.RLock()

    def add_node(
        self,
        node_id: str,
        *,
        node_type: str,
        trace_id: str | None,
        label: str,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceNode:
        node = ProvenanceNode(
            node_id=node_id,
            node_type=node_type,
            trace_id=trace_id,
            label=label,
            metadata=metadata or {},
        )
        with self._lock:
            self._nodes[node_id] = node
        return node

    def add_edge(
        self,
        *,
        from_node_id: str,
        to_node_id: str,
        relation: str,
        trace_id: str | None,
        confidence: float,
        reason: str,
        entity_type: str | None = None,
        metadata: dict[str, Any] | None = None,
        edge_id: str | None = None,
    ) -> ProvenanceEdgeRecord:
        edge = ProvenanceEdgeRecord(
            edge_id=edge_id or f"edge-{uuid.uuid4().hex[:16]}",
            trace_id=trace_id,
            from_node_id=from_node_id,
            to_node_id=to_node_id,
            relation=relation,
            confidence=round(float(confidence), 4),
            reason=reason,
            entity_type=entity_type,
            metadata=metadata or {},
        )
        key = trace_id or "_global"
        with self._lock:
            values = self._edges.setdefault(key, [])
            values.append(edge)
            if len(values) > self.max_edges_per_trace:
                del values[:-self.max_edges_per_trace]
        return edge

    def find_edges(self, trace_id: str) -> list[dict]:
        with self._lock:
            return [asdict(edge) for edge in self._edges.get(trace_id, ())]

    def find_entity_flows(
        self,
        trace_id: str,
        entity_type: str | None = None,
    ) -> list[dict]:
        values = self.find_edges(trace_id)
        if entity_type is None:
            return values
        return [
            edge for edge in values
            if edge.get("entity_type") == entity_type
        ]

    @staticmethod
    def explain_match(match: Any) -> str:
        source = match.source
        entity = match.source_entity
        argument = match.argument_entity
        return (
            f"{source.origin} 中的 {entity.entity_type.value} 实体 "
            f"{entity.raw_value} 被复用于工具参数 {argument.metadata.get('argument', '')}"
        )

    def to_json(self, trace_id: str) -> dict:
        edges = self.find_edges(trace_id)
        node_ids = {
            value
            for edge in edges
            for value in (edge["from_node_id"], edge["to_node_id"])
        }
        with self._lock:
            nodes = [
                asdict(self._nodes[node_id])
                for node_id in node_ids
                if node_id in self._nodes
            ]
        return {"trace_id": trace_id, "nodes": nodes, "edges": edges}

    def clear_trace(self, trace_id: str) -> None:
        with self._lock:
            self._edges.pop(trace_id, None)
            stale = [
                node_id for node_id, node in self._nodes.items()
                if node.trace_id == trace_id
            ]
            for node_id in stale:
                self._nodes.pop(node_id, None)
