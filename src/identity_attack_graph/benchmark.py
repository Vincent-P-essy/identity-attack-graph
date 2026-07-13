from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import __version__
from .analyzer import Analyzer
from .loader import load_environment
from .models import Report
from .resources import package_source_sha256, resource_text

GROUND_TRUTH_SCHEMA_VERSION = "1.1"
BENCHMARK_SCHEMA_VERSION = "1.1"
MAX_GROUND_TRUTH_BYTES = 2 * 1024 * 1024

PathSignature = tuple[str, str, tuple[str, ...], tuple[str, ...]]
EdgeSignature = tuple[str, str, str, tuple[str, ...]]


def benchmark(
    environment_path: Path,
    ground_truth_path: Path,
    output: Path,
    *,
    iterations: int = 50,
) -> dict[str, Any]:
    if iterations < 1 or iterations > 1_000:
        raise ValueError("iterations must be between 1 and 1000")
    environment = load_environment(environment_path)
    raw_truth = ground_truth_path.read_bytes()
    truth = _load_ground_truth(raw_truth)
    expected_paths, expected_edges, expected_risk = _ground_truth(truth)
    latencies: list[float] = []
    hashes: list[str] = []
    final: Report | None = None
    for _ in range(iterations):
        started = time.perf_counter()
        final = Analyzer(environment).analyze()
        latencies.append((time.perf_counter() - started) * 1_000)
        payload = final.model_dump(mode="json")
        payload.pop("elapsed_ms", None)
        hashes.append(
            hashlib.sha256(
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode()
            ).hexdigest()
        )
    if final is None:  # pragma: no cover - iterations is validated above.
        raise AssertionError("benchmark produced no report")

    actual_paths = _report_paths(final)
    actual_edges = {
        (edge.source, edge.target, edge.kind, tuple(sorted(set(edge.evidence))))
        for edge in final.edges
    }
    path_comparison = _classification(set(expected_paths), set(actual_paths))
    edge_comparison = _classification(expected_edges, actual_edges)
    path_risk_errors = [
        {
            **_path_payload(signature),
            "expected": expected_paths[signature],
            "actual": actual_paths[signature],
            "absolute_error": round(abs(expected_paths[signature] - actual_paths[signature]), 6),
        }
        for signature in sorted(set(expected_paths) & set(actual_paths))
        if not math.isclose(expected_paths[signature], actual_paths[signature], abs_tol=0.001)
    ]
    actual_risk = final.risk.model_dump(mode="json")
    risk_deltas = {
        key: round(float(actual_risk[key]) - float(expected_risk[key]), 6) for key in expected_risk
    }
    risk_summary_matches = all(
        math.isclose(float(actual_risk[key]), float(expected_risk[key]), abs_tol=0.001)
        for key in expected_risk
    )
    report: dict[str, Any] = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "ground_truth_schema_version": GROUND_TRUTH_SCHEMA_VERSION,
        "environment_sha256": hashlib.sha256(environment_path.read_bytes()).hexdigest(),
        "ground_truth_sha256": hashlib.sha256(raw_truth).hexdigest(),
        "iterations": iterations,
        "expected_paths": len(expected_paths),
        "actual_paths": len(actual_paths),
        "path_recall": path_comparison["recall"],
        "path_precision": path_comparison["precision"],
        "expected_edges": len(expected_edges),
        "actual_edges": len(actual_edges),
        "edge_recall": edge_comparison["recall"],
        "edge_precision": edge_comparison["precision"],
        "path_risk_matches": not path_risk_errors,
        "path_risk_errors": path_risk_errors,
        "risk_summary_matches": risk_summary_matches,
        "expected_risk": expected_risk,
        "actual_risk": actual_risk,
        "risk_deltas": risk_deltas,
        "false_positives": {
            "paths": [_path_payload(item) for item in sorted(path_comparison["false_positives"])],
            "edges": [_edge_payload(item) for item in sorted(edge_comparison["false_positives"])],
        },
        "false_negatives": {
            "paths": [_path_payload(item) for item in sorted(path_comparison["false_negatives"])],
            "edges": [_edge_payload(item) for item in sorted(edge_comparison["false_negatives"])],
        },
        "deterministic": len(set(hashes)) == 1,
        "report_sha256": hashes[0] if len(set(hashes)) == 1 else "",
        "latency_p50_ms": round(_percentile(latencies, 50), 3),
        "latency_p95_ms": round(_percentile(latencies, 95), 3),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "provenance": {
            "package_version": __version__,
            "analysis_source_sha256": package_source_sha256(),
            "dependency_lock_sha256": hashlib.sha256(
                resource_text("data/uv.lock").encode()
            ).hexdigest(),
            "source_revision": os.getenv(
                "IDENTITY_GRAPH_SOURCE_REVISION", "uncommitted-or-installed-artifact"
            ),
            "source_tree_state": os.getenv("IDENTITY_GRAPH_SOURCE_TREE_STATE", "unspecified"),
            "runner_python": platform.python_version(),
            "runner_platform": platform.platform(),
        },
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "benchmark.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    (output / "BENCHMARK.md").write_text(_markdown(report), encoding="utf-8")
    return report


def _load_ground_truth(raw: bytes) -> Mapping[str, Any]:
    if len(raw) > MAX_GROUND_TRUTH_BYTES:
        raise ValueError(f"ground truth exceeds {MAX_GROUND_TRUTH_BYTES} bytes")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"ground truth contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid ground truth: {error}") from error
    if not isinstance(value, Mapping):
        raise ValueError("ground truth must be a JSON object")
    return value


def _ground_truth(
    truth: Mapping[str, Any],
) -> tuple[dict[PathSignature, float], set[EdgeSignature], dict[str, float | int]]:
    if truth.get("schema_version") != GROUND_TRUTH_SCHEMA_VERSION:
        raise ValueError(f"ground truth schema_version must be {GROUND_TRUTH_SCHEMA_VERSION!r}")
    raw_paths = truth.get("paths")
    raw_edges = truth.get("edges")
    raw_risk = truth.get("risk_summary")
    if not isinstance(raw_paths, list) or not isinstance(raw_edges, list):
        raise ValueError("ground truth paths and edges must be arrays")
    if not isinstance(raw_risk, Mapping):
        raise ValueError("ground truth risk_summary must be an object")

    paths: dict[PathSignature, float] = {}
    for index, item in enumerate(raw_paths):
        if not isinstance(item, Mapping):
            raise ValueError(f"ground truth paths[{index}] must be an object")
        nodes = _non_empty_strings(item.get("nodes"), f"paths[{index}].nodes")
        kinds = _non_empty_strings(item.get("edge_kinds"), f"paths[{index}].edge_kinds")
        if len(kinds) != len(nodes) - 1:
            raise ValueError(f"ground truth paths[{index}] edge_kinds length is inconsistent")
        entrypoint = _non_empty_string(item.get("entrypoint"), f"paths[{index}].entrypoint")
        target = _non_empty_string(item.get("target"), f"paths[{index}].target")
        if nodes[0] != entrypoint or nodes[-1] != target:
            raise ValueError(f"ground truth paths[{index}] endpoints do not match nodes")
        risk = _finite_number(item.get("risk"), f"paths[{index}].risk", minimum=0, maximum=100)
        path_signature = (entrypoint, target, nodes, kinds)
        if path_signature in paths:
            raise ValueError(f"ground truth contains duplicate path at index {index}")
        paths[path_signature] = risk

    edges: set[EdgeSignature] = set()
    for index, item in enumerate(raw_edges):
        if not isinstance(item, Mapping):
            raise ValueError(f"ground truth edges[{index}] must be an object")
        edge_signature = (
            _non_empty_string(item.get("source"), f"edges[{index}].source"),
            _non_empty_string(item.get("target"), f"edges[{index}].target"),
            _non_empty_string(item.get("kind"), f"edges[{index}].kind"),
            tuple(
                sorted(set(_non_empty_strings(item.get("evidence"), f"edges[{index}].evidence")))
            ),
        )
        if edge_signature in edges:
            raise ValueError(f"ground truth contains duplicate edge at index {index}")
        edges.add(edge_signature)

    risk_keys = {
        "path_count",
        "maximum_path_risk",
        "aggregate_risk",
        "crown_jewels_reachable",
    }
    if set(raw_risk) != risk_keys:
        raise ValueError("ground truth risk_summary fields are incomplete or unsupported")
    risk_summary: dict[str, float | int] = {
        "path_count": _integer(raw_risk["path_count"], "risk_summary.path_count"),
        "maximum_path_risk": _finite_number(
            raw_risk["maximum_path_risk"],
            "risk_summary.maximum_path_risk",
            minimum=0,
            maximum=100,
        ),
        "aggregate_risk": _finite_number(
            raw_risk["aggregate_risk"],
            "risk_summary.aggregate_risk",
            minimum=0,
            maximum=100,
        ),
        "crown_jewels_reachable": _integer(
            raw_risk["crown_jewels_reachable"], "risk_summary.crown_jewels_reachable"
        ),
    }
    return paths, edges, risk_summary


def _report_paths(report: Report) -> dict[PathSignature, float]:
    edges = {edge.id: edge for edge in report.edges}
    return {
        (
            path.entrypoint,
            path.target,
            path.node_ids,
            tuple(edges[edge_id].kind for edge_id in path.edge_ids),
        ): path.risk
        for path in report.paths
    }


def _classification(expected: set[Any], actual: set[Any]) -> dict[str, Any]:
    true_positives = expected & actual
    false_positives = actual - expected
    false_negatives = expected - actual
    return {
        "precision": len(true_positives) / len(actual) if actual else float(not expected),
        "recall": len(true_positives) / len(expected) if expected else 1.0,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


def _path_payload(signature: PathSignature) -> dict[str, Any]:
    return {
        "entrypoint": signature[0],
        "target": signature[1],
        "nodes": list(signature[2]),
        "edge_kinds": list(signature[3]),
    }


def _edge_payload(signature: EdgeSignature) -> dict[str, Any]:
    return {
        "source": signature[0],
        "target": signature[1],
        "kind": signature[2],
        "evidence": list(signature[3]),
    }


def _non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"ground truth {field} must be a non-empty string")
    return value


def _non_empty_strings(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"ground truth {field} must be a non-empty string array")
    result = tuple(_non_empty_string(item, field) for item in value)
    if len(result) != len(set(result)):
        raise ValueError(f"ground truth {field} contains duplicates")
    return result


def _finite_number(value: Any, field: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"ground truth {field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError(f"ground truth {field} is outside the supported range")
    return result


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"ground truth {field} must be a non-negative integer")
    return int(value)


def _percentile(values: list[float], percentile: int) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile / 100
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _markdown(report: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Identity Attack Graph benchmark",
            "",
            f"- Expected paths: **{report['expected_paths']}**",
            f"- Actual paths: **{report['actual_paths']}**",
            f"- Path recall / precision: **{report['path_recall']:.1%} / "
            f"{report['path_precision']:.1%}**",
            f"- Expected evidence-bound edges: **{report['expected_edges']}**",
            f"- Actual evidence-bound edges: **{report['actual_edges']}**",
            f"- Edge recall / precision: **{report['edge_recall']:.1%} / "
            f"{report['edge_precision']:.1%}**",
            f"- Path risks match: **{str(report['path_risk_matches']).lower()}**",
            f"- Risk summary matches: **{str(report['risk_summary_matches']).lower()}**",
            f"- Deterministic across {report['iterations']} runs: "
            f"**{str(report['deterministic']).lower()}**",
            f"- Analysis latency p50: **{report['latency_p50_ms']:.3f} ms**",
            f"- Analysis latency p95: **{report['latency_p95_ms']:.3f} ms**",
            "",
            "## Provenance",
            "",
            f"- Package: **{report['provenance']['package_version']}**",
            f"- Analysis source SHA-256: `{report['provenance']['analysis_source_sha256']}`",
            f"- Dependency lock SHA-256: `{report['provenance']['dependency_lock_sha256']}`",
            f"- Source revision: `{report['provenance']['source_revision']}`",
            f"- Source-tree state: **{report['provenance']['source_tree_state']}**",
            f"- Runner: Python {report['provenance']['runner_python']} on "
            f"{report['provenance']['runner_platform']}",
            "",
            "The corpus is synthetic and curated. Metrics describe expected semantic paths, "
            "evidence-bound edges, and reviewed risk outputs in that fixture only.",
            "",
        ]
    )
