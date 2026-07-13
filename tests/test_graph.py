from __future__ import annotations

import pytest

from identity_attack_graph.graph import AttackGraph, summarize_risk
from identity_attack_graph.models import GraphNode, NodeKind, Provider


def node(identifier: str, *, impact: float = 20, target: bool = False) -> GraphNode:
    return GraphNode(
        id=identifier,
        label=identifier,
        provider=Provider.AWS,
        kind=NodeKind.TARGET if target else NodeKind.IDENTITY,
        subtype="test",
        impact=impact,
        crown_jewel=target,
    )


def test_graph_finds_weighted_acyclic_paths_and_risk() -> None:
    graph = AttackGraph()
    for item in (node("a"), node("b"), node("c", impact=100, target=True)):
        graph.add_node(item)
    first = graph.add_edge(
        source="a",
        target="b",
        kind="step",
        label="step",
        effort=1,
        exploitability=0.8,
        confidence=0.9,
        techniques=("T0001",),
    )
    repeated = graph.add_edge(
        source="a",
        target="b",
        kind="step",
        label="step",
        effort=1,
        exploitability=0.8,
        confidence=0.9,
        techniques=("T0001",),
    )
    graph.add_edge(
        source="b",
        target="c",
        kind="finish",
        label="finish",
        effort=2,
        exploitability=0.5,
        confidence=1,
    )
    graph.add_edge(
        source="b",
        target="a",
        kind="cycle",
        label="cycle",
        effort=1,
        exploitability=1,
        confidence=1,
    )
    assert first == repeated and len(graph.edges) == 3
    paths = graph.find_paths(["a"], ["c"])
    assert len(paths) == 1
    assert paths[0].node_ids == ("a", "b", "c")
    assert paths[0].effort == 3
    assert paths[0].risk == 36
    assert paths[0].techniques == ("T0001",)
    assert graph.centrality()["b"] > 0
    assert summarize_risk(paths).aggregate_risk == 36


def test_graph_validates_references_and_conflicting_nodes() -> None:
    graph = AttackGraph()
    graph.add_node(node("a"))
    with pytest.raises(ValueError, match="missing node"):
        graph.add_edge(
            source="a",
            target="missing",
            kind="bad",
            label="bad",
            effort=1,
            exploitability=1,
            confidence=1,
        )
    with pytest.raises(ValueError, match="conflicting"):
        graph.add_node(node("a", impact=90))
    assert graph.find_paths(["missing"], ["a"]) == []


def test_risk_summary_is_monotonic_for_multiple_paths() -> None:
    graph = AttackGraph()
    graph.add_node(node("a"))
    graph.add_node(node("b"))
    graph.add_node(node("target", impact=90, target=True))
    graph.add_edge(
        source="a",
        target="target",
        kind="direct-a",
        label="a",
        effort=1,
        exploitability=0.5,
        confidence=1,
    )
    graph.add_edge(
        source="b",
        target="target",
        kind="direct-b",
        label="b",
        effort=1,
        exploitability=0.4,
        confidence=1,
    )
    one = graph.find_paths(["a"], ["target"])
    two = graph.find_paths(["a", "b"], ["target"])
    assert summarize_risk(two).aggregate_risk > summarize_risk(one).aggregate_risk
