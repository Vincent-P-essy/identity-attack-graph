from __future__ import annotations

import json
from pathlib import Path

import pytest

from identity_attack_graph.analyzer import Analyzer
from identity_attack_graph.benchmark import _percentile, benchmark
from identity_attack_graph.models import Environment, PermissionMutation, WhatIfRequest
from identity_attack_graph.reporting import write_report, write_what_if


def test_report_writers_produce_auditable_formats(environment: Environment, tmp_path: Path) -> None:
    analyzer = Analyzer(environment)
    report = analyzer.analyze()
    write_report(report, tmp_path)
    for name in ("report.json", "graph.json", "paths.csv", "REPORT.md", "graph.dot"):
        assert (tmp_path / name).is_file()
    assert "Risk is a deterministic" in (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    assert "digraph identity_attack_graph" in (tmp_path / "graph.dot").read_text(encoding="utf-8")
    simulation = analyzer.what_if(
        WhatIfRequest(
            mutations=[
                PermissionMutation(statement_id="delegator-bind-cluster-admin", action="bind")
            ]
        )
    )
    write_what_if(simulation, tmp_path / "simulation" / "what-if.json")
    assert json.loads((tmp_path / "simulation/what-if.json").read_text())["eliminated_paths"]


def test_report_writers_neutralize_active_content(environment: Environment, tmp_path: Path) -> None:
    report = Analyzer(environment).analyze()
    report.environment = "<script>alert(1)</script>|unsafe"
    report.nodes[0] = report.nodes[0].model_copy(
        update={"label": 'node"\\\\\n}; injected [label="yes"'}
    )
    report.paths[0] = report.paths[0].model_copy(update={"entrypoint": "=1+1"})
    write_report(report, tmp_path)
    markdown = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    dot = (tmp_path / "graph.dot").read_text(encoding="utf-8")
    csv_text = (tmp_path / "paths.csv").read_text(encoding="utf-8")
    assert "<script>" not in markdown and "&#124;" in markdown
    assert "\\n}; injected" in dot
    assert "'=1+1" in csv_text


def test_benchmark_matches_ground_truth(
    environment_path: Path, repository_root: Path, tmp_path: Path
) -> None:
    report = benchmark(
        environment_path,
        repository_root / "fixtures/ground-truth.json",
        tmp_path,
        iterations=3,
    )
    assert report["path_recall"] == 1
    assert report["path_precision"] == 1
    assert report["edge_recall"] == 1
    assert report["edge_precision"] == 1
    assert report["path_risk_matches"] is True
    assert report["risk_summary_matches"] is True
    assert report["deterministic"] is True
    assert report["actual_paths"] == 7
    assert (tmp_path / "BENCHMARK.md").is_file()


def test_benchmark_validates_iterations(
    environment_path: Path, repository_root: Path, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="iterations"):
        benchmark(
            environment_path,
            repository_root / "fixtures/ground-truth.json",
            tmp_path,
            iterations=0,
        )
    assert _percentile([2.0], 95) == 2
    assert _percentile([1.0, 3.0], 50) == 2


def test_benchmark_binds_edge_evidence_and_risk(
    environment_path: Path, repository_root: Path, tmp_path: Path
) -> None:
    truth = json.loads((repository_root / "fixtures/ground-truth.json").read_text(encoding="utf-8"))
    truth["edges"][0]["evidence"] = ["fabricated:evidence"]
    truth["paths"][0]["risk"] = 0
    truth_path = tmp_path / "truth.json"
    truth_path.write_text(json.dumps(truth), encoding="utf-8")
    report = benchmark(environment_path, truth_path, tmp_path / "out", iterations=1)
    assert report["edge_recall"] < 1
    assert report["edge_precision"] < 1
    assert report["path_risk_matches"] is False
    assert report["false_positives"]["edges"]
    assert report["false_negatives"]["edges"]


def test_benchmark_rejects_incomplete_ground_truth(environment_path: Path, tmp_path: Path) -> None:
    truth_path = tmp_path / "truth.json"
    truth_path.write_text('{"schema_version":"1.0"}', encoding="utf-8")
    with pytest.raises(ValueError, match="schema_version"):
        benchmark(environment_path, truth_path, tmp_path / "out", iterations=1)
