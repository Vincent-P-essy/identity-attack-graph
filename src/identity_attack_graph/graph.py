from __future__ import annotations

import hashlib
import heapq
import math
from collections import deque
from dataclasses import dataclass, field

from .models import AttackPath, GraphEdge, GraphNode, RiskSummary


@dataclass(order=True, slots=True)
class _PathState:
    effort: float
    node_ids: tuple[str, ...] = field(compare=True)
    edge_ids: tuple[str, ...] = field(compare=False)
    exploitability: float = field(compare=False)
    confidence: float = field(compare=False)
    techniques: tuple[str, ...] = field(compare=False)


class AttackGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, GraphEdge] = {}
        self.adjacency: dict[str, list[str]] = {}

    def add_node(self, node: GraphNode) -> None:
        existing = self.nodes.get(node.id)
        if existing is not None and existing != node:
            raise ValueError(f"conflicting node definition for {node.id}")
        self.nodes[node.id] = node
        self.adjacency.setdefault(node.id, [])

    def add_edge(
        self,
        *,
        source: str,
        target: str,
        kind: str,
        label: str,
        effort: float,
        exploitability: float,
        confidence: float,
        evidence: tuple[str, ...] = (),
        techniques: tuple[str, ...] = (),
    ) -> GraphEdge:
        if source not in self.nodes or target not in self.nodes:
            raise ValueError(f"edge references missing node: {source} -> {target}")
        digest = hashlib.sha256(
            "\0".join((source, target, kind, *sorted(evidence))).encode()
        ).hexdigest()[:20]
        edge = GraphEdge(
            id=f"edge-{digest}",
            source=source,
            target=target,
            kind=kind,
            label=label,
            effort=effort,
            exploitability=exploitability,
            confidence=confidence,
            evidence=evidence,
            techniques=techniques,
        )
        existing = self.edges.get(edge.id)
        if existing is None:
            self.edges[edge.id] = edge
            self.adjacency[source].append(edge.id)
            self.adjacency[source].sort()
        elif existing != edge:
            raise ValueError(f"edge hash collision for {edge.id}")
        return edge

    def find_paths(
        self,
        entrypoints: list[str],
        targets: list[str],
        *,
        max_depth: int = 8,
        max_paths_per_pair: int = 5,
    ) -> list[AttackPath]:
        target_set = set(targets)
        found: list[AttackPath] = []
        pair_counts: dict[tuple[str, str], int] = {}
        for entrypoint in sorted(entrypoints):
            if entrypoint not in self.nodes:
                continue
            queue = [
                _PathState(
                    effort=0,
                    node_ids=(entrypoint,),
                    edge_ids=(),
                    exploitability=1,
                    confidence=1,
                    techniques=(),
                )
            ]
            while queue:
                state = heapq.heappop(queue)
                current = state.node_ids[-1]
                if current in target_set and current != entrypoint:
                    pair = (entrypoint, current)
                    if pair_counts.get(pair, 0) < max_paths_per_pair:
                        found.append(self._materialize(state, entrypoint, current))
                        pair_counts[pair] = pair_counts.get(pair, 0) + 1
                    continue
                if len(state.edge_ids) >= max_depth:
                    continue
                for edge_id in self.adjacency.get(current, []):
                    edge = self.edges[edge_id]
                    if edge.target in state.node_ids:
                        continue
                    pair = (entrypoint, edge.target)
                    if edge.target in target_set and pair_counts.get(pair, 0) >= max_paths_per_pair:
                        continue
                    heapq.heappush(
                        queue,
                        _PathState(
                            effort=state.effort + edge.effort,
                            node_ids=(*state.node_ids, edge.target),
                            edge_ids=(*state.edge_ids, edge.id),
                            exploitability=state.exploitability * edge.exploitability,
                            confidence=state.confidence * edge.confidence,
                            techniques=tuple(sorted(set(state.techniques + edge.techniques))),
                        ),
                    )
        return sorted(found, key=lambda item: (-item.risk, item.effort, item.id))

    def centrality(self) -> dict[str, float]:
        """Exact unweighted directed betweenness centrality (Brandes)."""
        score = {node_id: 0.0 for node_id in self.nodes}
        neighbors = {
            node_id: sorted({self.edges[edge_id].target for edge_id in edge_ids})
            for node_id, edge_ids in self.adjacency.items()
        }
        for source in sorted(self.nodes):
            stack: list[str] = []
            predecessors: dict[str, list[str]] = {node_id: [] for node_id in self.nodes}
            paths = {node_id: 0.0 for node_id in self.nodes}
            paths[source] = 1.0
            distance = {node_id: -1 for node_id in self.nodes}
            distance[source] = 0
            queue: deque[str] = deque([source])
            while queue:
                vertex = queue.popleft()
                stack.append(vertex)
                for neighbor in neighbors.get(vertex, []):
                    if distance[neighbor] < 0:
                        queue.append(neighbor)
                        distance[neighbor] = distance[vertex] + 1
                    if distance[neighbor] == distance[vertex] + 1:
                        paths[neighbor] += paths[vertex]
                        predecessors[neighbor].append(vertex)
            dependency = {node_id: 0.0 for node_id in self.nodes}
            while stack:
                vertex = stack.pop()
                for predecessor in predecessors[vertex]:
                    if paths[vertex]:
                        dependency[predecessor] += (paths[predecessor] / paths[vertex]) * (
                            1 + dependency[vertex]
                        )
                if vertex != source:
                    score[vertex] += dependency[vertex]
        size = len(self.nodes)
        denominator = (size - 1) * (size - 2)
        if denominator > 0:
            score = {key: value / denominator for key, value in score.items()}
        return {key: round(value, 6) for key, value in sorted(score.items())}

    def _materialize(self, state: _PathState, entrypoint: str, target: str) -> AttackPath:
        impact = self.nodes[target].impact
        risk = min(100.0, impact * state.exploitability * state.confidence)
        digest = hashlib.sha256("\0".join((*state.node_ids, *state.edge_ids)).encode()).hexdigest()[
            :20
        ]
        return AttackPath(
            id=f"path-{digest}",
            entrypoint=entrypoint,
            target=target,
            node_ids=state.node_ids,
            edge_ids=state.edge_ids,
            effort=round(state.effort, 3),
            exploitability=round(state.exploitability, 6),
            confidence=round(state.confidence, 6),
            target_impact=impact,
            risk=round(risk, 3),
            techniques=state.techniques,
        )


def summarize_risk(paths: list[AttackPath]) -> RiskSummary:
    risks = sorted((path.risk for path in paths), reverse=True)
    aggregate = 0.0
    if risks:
        maximum = risks[0]
        aggregate = maximum + (100 - maximum) * (1 - math.exp(-sum(risks[1:]) / 500))
    return RiskSummary(
        path_count=len(paths),
        maximum_path_risk=round(max(risks, default=0.0), 3),
        aggregate_risk=round(aggregate, 3),
        crown_jewels_reachable=len({path.target for path in paths}),
    )
