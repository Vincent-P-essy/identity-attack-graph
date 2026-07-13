from __future__ import annotations

import json
from pathlib import Path

import pytest

from identity_attack_graph import cli


def test_cli_analyze_what_if_and_benchmark(
    environment_path: Path,
    repository_root: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    base = ["--environment", str(environment_path)]
    analysis = tmp_path / "analysis"
    assert cli.main([*base, "analyze", "--out", str(analysis)]) == 0
    assert (analysis / "report.json").is_file()
    assert '"path_count": 7' in capsys.readouterr().out

    what_if = tmp_path / "what-if.json"
    assert (
        cli.main(
            [
                *base,
                "what-if",
                "--remove",
                "delegator-bind-cluster-admin=bind",
                "--out",
                str(what_if),
            ]
        )
        == 0
    )
    assert json.loads(what_if.read_text(encoding="utf-8"))["eliminated_paths"]
    capsys.readouterr()

    evidence = tmp_path / "benchmark"
    assert (
        cli.main(
            [
                *base,
                "benchmark",
                "--truth",
                str(repository_root / "fixtures/ground-truth.json"),
                "--out",
                str(evidence),
                "--iterations",
                "2",
            ]
        )
        == 0
    )
    capsys.readouterr()


def test_cli_normalize_and_serve(
    monkeypatch: pytest.MonkeyPatch,
    repository_root: Path,
    environment_path: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    normalized = tmp_path / "imported.json"
    assert (
        cli.main(
            [
                "normalize",
                "--aws",
                str(repository_root / "fixtures/aws/authorization-details.json"),
                "--kubernetes",
                str(repository_root / "fixtures/kubernetes/rbac-lab.yaml"),
                "--account-id",
                "111122223333",
                "--out",
                str(normalized),
            ]
        )
        == 0
    )
    assert json.loads(normalized.read_text(encoding="utf-8"))["identities"]
    capsys.readouterr()

    observed: dict[str, object] = {}

    def fake_run(app: object, *, host: str, port: int) -> None:
        observed.update({"app": app, "host": host, "port": port})

    monkeypatch.setattr(cli.uvicorn, "run", fake_run)
    assert (
        cli.main(
            [
                "--environment",
                str(environment_path),
                "serve",
                "--host",
                "127.0.0.2",
                "--port",
                "9090",
            ]
        )
        == 0
    )
    assert observed["host"] == "127.0.0.2" and observed["port"] == 9090


def test_cli_mutation_parser_rejects_invalid_syntax() -> None:
    with pytest.raises(ValueError, match="STATEMENT_ID=ACTION"):
        cli._parse_mutation("invalid")


def test_cli_packaged_defaults_are_working_directory_independent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "packaged-benchmark"
    assert cli.main(["benchmark", "--out", str(output), "--iterations", "1"]) == 0
    report = json.loads((output / "benchmark.json").read_text(encoding="utf-8"))
    assert report["edge_precision"] == report["edge_recall"] == 1
    capsys.readouterr()
