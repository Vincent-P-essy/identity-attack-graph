from __future__ import annotations

import hashlib
import json
import platform
import time
from pathlib import Path
from typing import Any

from .analyzer import Analyzer
from .loader import load_environment


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
    truth = json.loads(raw_truth)
    expected = {
        (item["entrypoint"], item["target"], tuple(item["nodes"])) for item in truth["paths"]
    }
    latencies: list[float] = []
    hashes: list[str] = []
    final = None
    for _ in range(iterations):
        started = time.perf_counter()
        final = Analyzer(environment).analyze()
        latencies.append((time.perf_counter() - started) * 1_000)
        payload = final.model_dump(mode="json")
        payload.pop("elapsed_ms", None)
        hashes.append(
            hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
    if final is None:  # pragma: no cover - iterations is validated above.
        raise AssertionError("benchmark produced no report")
    actual = {(item.entrypoint, item.target, item.node_ids) for item in final.paths}
    matched = expected & actual
    recall = len(matched) / len(expected) if expected else 1.0
    precision = len(matched) / len(actual) if actual else float(not expected)
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "environment_sha256": hashlib.sha256(environment_path.read_bytes()).hexdigest(),
        "ground_truth_sha256": hashlib.sha256(raw_truth).hexdigest(),
        "iterations": iterations,
        "expected_paths": len(expected),
        "actual_paths": len(actual),
        "path_recall": recall,
        "path_precision": precision,
        "deterministic": len(set(hashes)) == 1,
        "report_sha256": hashes[0],
        "latency_p50_ms": round(_percentile(latencies, 50), 3),
        "latency_p95_ms": round(_percentile(latencies, 95), 3),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "benchmark.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "BENCHMARK.md").write_text(_markdown(report), encoding="utf-8")
    return report


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
            f"- Path recall: **{report['path_recall']:.1%}**",
            f"- Path precision: **{report['path_precision']:.1%}**",
            f"- Deterministic across {report['iterations']} runs: "
            f"**{str(report['deterministic']).lower()}**",
            f"- Analysis latency p50: **{report['latency_p50_ms']:.3f} ms**",
            f"- Analysis latency p95: **{report['latency_p95_ms']:.3f} ms**",
            "",
            "The corpus is synthetic and curated. Recall/precision describe expected semantic "
            "paths in that fixture, not unknown paths in a cloud estate.",
            "",
        ]
    )
