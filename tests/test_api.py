from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from identity_attack_graph.api import create_app
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
