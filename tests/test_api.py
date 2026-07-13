from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from identity_attack_graph.api import create_app
from identity_attack_graph.loader import MAX_INPUT_BYTES
from identity_attack_graph.models import Environment


def test_api_report_views_and_security_headers(environment_path: Path) -> None:
    client = TestClient(create_app(environment_path))
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["environment"] == "banking-platform-identity-lab"
    assert health.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in health.headers["content-security-policy"]

    report = client.get("/v1/report")
    graph = client.get("/v1/graph")
    paths = client.get("/v1/paths")
    findings = client.get("/v1/findings")
    assert report.status_code == graph.status_code == paths.status_code == 200
    assert report.json()["risk"]["path_count"] == 7
    assert len(graph.json()["edges"]) == 14
    assert len(paths.json()["paths"]) == 7
    assert findings.json()["findings"]
    assert client.get("/").status_code == 200
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/../pyproject.toml").status_code == 404


def test_api_default_resources_do_not_depend_on_working_directory(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())
    assert client.get("/healthz").json()["environment"] == "banking-platform-identity-lab"
    assert client.get("/").status_code == 200


def test_api_what_if_and_submitted_environment(
    environment_path: Path, environment: Environment
) -> None:
    client = TestClient(create_app(environment_path))
    result = client.post(
        "/v1/what-if",
        json={"mutations": [{"statement_id": "delegator-bind-cluster-admin", "action": "bind"}]},
    )
    assert result.status_code == 200
    assert len(result.json()["eliminated_paths"]) == 1
    invalid = client.post(
        "/v1/what-if",
        json={"mutations": [{"statement_id": "missing", "action": "x"}]},
    )
    assert invalid.status_code == 422

    submitted = client.post("/v1/analyze", json=environment.model_dump(mode="json"))
    assert submitted.status_code == 200 and submitted.json()["risk"]["path_count"] == 7
    payload = environment.model_dump(mode="json")
    payload["entrypoints"].append("missing")
    rejected = client.post("/v1/analyze", json=payload)
    assert rejected.status_code == 422

    oversized = client.post(
        "/v1/analyze",
        content=b"{}",
        headers={"content-type": "application/json", "content-length": str(MAX_INPUT_BYTES + 1)},
    )
    assert oversized.status_code == 413
    duplicate = client.post(
        "/v1/what-if",
        content=(
            b'{"mutations":[{"statement_id":"x","action":"y"}],'
            b'"mutations":[{"statement_id":"x","action":"y"}]}'
        ),
        headers={"content-type": "application/json"},
    )
    assert duplicate.status_code == 400
    non_finite = client.post(
        "/v1/analyze",
        content=b'{"schema_version":"1.0","name":"x","metadata":{"risk":NaN}}',
        headers={"content-type": "application/json"},
    )
    assert non_finite.status_code == 400
