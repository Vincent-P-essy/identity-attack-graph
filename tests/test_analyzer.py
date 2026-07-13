from __future__ import annotations

import pytest

from identity_attack_graph.analyzer import Analyzer
from identity_attack_graph.models import (
    Environment,
    PermissionMutation,
    WhatIfRequest,
)


def test_lab_has_reviewed_cross_cloud_paths(environment: Environment) -> None:
    report = Analyzer(environment).analyze()
    assert len(report.nodes) == 14
    assert len(report.paths) == 7
    assert report.risk.crown_jewels_reachable == 5
    assert report.risk.maximum_path_risk == 94
    assert 97 < report.risk.aggregate_risk < 98
    assert report.unsupported_semantics == []
    assert {(path.entrypoint, path.target, path.node_ids) for path in report.paths} >= {
        (
            "aws:user:developer",
            "aws:secret:admin-token",
            (
                "aws:user:developer",
                "aws:lambda:payroll-api",
                "aws:role:payroll-runtime",
                "aws:secret:admin-token",
            ),
        ),
        (
            "k8s:user:developer",
            "k8s:privilege:cluster-admin",
            ("k8s:user:developer", "k8s:privilege:cluster-admin"),
        ),
    }
    edge_kinds = {edge.kind for edge in report.edges}
    assert {
        "lambda_code_execution",
        "assume_role",
        "pass_role_via_lambda",
        "bind_cluster_admin",
        "mount_secret_via_pod",
        "exec_as_service_account",
        "privileged_pod_host_access",
    } <= edge_kinds


def test_findings_include_excessive_permissions_and_reachable_targets(
    environment: Environment,
) -> None:
    report = Analyzer(environment).analyze()
    categories = {item.category for item in report.findings}
    assert "excessive_permission" in categories
    assert "reachable_crown_jewel" in categories
    reachable = next(item for item in report.findings if item.category == "reachable_crown_jewel")
    assert len(reachable.evidence) == 7


def test_what_if_shows_security_and_business_impact(environment: Environment) -> None:
    analyzer = Analyzer(environment)
    bind = analyzer.what_if(
        WhatIfRequest(
            mutations=[
                PermissionMutation(statement_id="delegator-bind-cluster-admin", action="bind")
            ]
        )
    )
    assert len(bind.eliminated_paths) == 1
    assert bind.risk_reduction > 5
    assert bind.broken_business_operations == []
    assert bind.new_paths == []

    pods = analyzer.what_if(
        WhatIfRequest(
            mutations=[
                PermissionMutation(statement_id="payroll-developer-create-pods", action="create")
            ]
        )
    )
    assert len(pods.eliminated_paths) == 3
    assert [item.id for item in pods.broken_business_operations] == [
        "business-create-payroll-workload"
    ]


def test_what_if_validates_statement_and_action(environment: Environment) -> None:
    analyzer = Analyzer(environment)
    with pytest.raises(ValueError, match="not found"):
        analyzer.what_if(
            WhatIfRequest(mutations=[PermissionMutation(statement_id="missing", action="x")])
        )
    with pytest.raises(ValueError, match="absent"):
        analyzer.what_if(
            WhatIfRequest(
                mutations=[
                    PermissionMutation(
                        statement_id="dev-lambda-deploy", action="lambda:DeleteFunction"
                    )
                ]
            )
        )
    with pytest.raises(ValueError, match="explicit Deny"):
        analyzer.what_if(
            WhatIfRequest(
                mutations=[
                    PermissionMutation(
                        statement_id="dev-deny-secrets",
                        action="secretsmanager:GetSecretValue",
                    )
                ]
            )
        )


def test_passrole_without_service_creation_is_not_a_path(environment: Environment) -> None:
    what_if = Analyzer(environment).what_if(
        WhatIfRequest(
            mutations=[
                PermissionMutation(
                    statement_id="ci-create-function", action="lambda:CreateFunction"
                )
            ]
        )
    )
    assert any(path.entrypoint == "aws:user:ci-runner" for path in what_if.eliminated_paths)
    assert not any(path.entrypoint == "aws:user:ci-runner" for path in what_if.new_paths)


def test_unsupported_relevant_condition_removes_edge_fail_closed(
    environment: Environment,
) -> None:
    payload = environment.model_dump(mode="json")
    payload["identities"][0]["policies"].append(
        {
            "id": "unsupported-lambda-condition",
            "effect": "Allow",
            "actions": ["lambda:UpdateFunctionCode"],
            "resources": ["arn:aws:lambda:eu-west-3:111122223333:function:payroll-api"],
            "conditions": {"NumericEquals": {"custom:key": "1"}},
        }
    )
    changed = Environment.model_validate(payload)
    report = Analyzer(changed).analyze()
    assert report.unsupported_semantics
    assert not any(edge.kind == "lambda_code_execution" for edge in report.edges)
    assert any(item.category == "unsupported_semantics" for item in report.findings)
