from __future__ import annotations

from identity_attack_graph.evaluation import AwsEvaluator, KubernetesEvaluator
from identity_attack_graph.models import (
    Effect,
    Environment,
    PermissionDecision,
    PolicyStatement,
)


def test_aws_explicit_deny_overrides_other_layers(environment: Environment) -> None:
    evaluator = AwsEvaluator(environment)
    decision = evaluator.evaluate(
        "aws:user:developer",
        "secretsmanager:GetSecretValue",
        "arn:aws:secretsmanager:eu-west-3:111122223333:secret:payroll-db",
    )
    assert decision.decision is PermissionDecision.EXPLICIT_DENY
    assert decision.evidence == ("identity:dev-deny-secrets:Deny",)


def test_aws_boundary_and_scp_intersections_allow_supported_action(
    environment: Environment,
) -> None:
    evaluator = AwsEvaluator(environment)
    update = evaluator.evaluate(
        "aws:user:developer",
        "lambda:UpdateFunctionCode",
        "arn:aws:lambda:eu-west-3:111122223333:function:payroll-api",
    )
    assert update.decision is PermissionDecision.ALLOW
    assert any(item.startswith("boundary:developer-boundary") for item in update.evidence)
    assert any(item.startswith("scp:scp-full-access-lab") for item in update.evidence)

    implicit = evaluator.evaluate("aws:user:developer", "iam:DeleteUser", "*")
    assert implicit.decision is PermissionDecision.IMPLICIT_DENY


def test_group_permissions_are_inherited(environment: Environment) -> None:
    decision = AwsEvaluator(environment).evaluate("aws:user:developer", "lambda:ListFunctions", "*")
    assert decision.decision is PermissionDecision.ALLOW
    assert "identity:developers-observability:Allow" in decision.evidence


def test_passrole_condition_is_required(environment: Environment) -> None:
    evaluator = AwsEvaluator(environment)
    role = "arn:aws:iam::111122223333:role/deployment-runtime"
    missing = evaluator.evaluate("aws:user:ci-runner", "iam:PassRole", role)
    allowed = evaluator.evaluate(
        "aws:user:ci-runner",
        "iam:PassRole",
        role,
        {"iam:PassedToService": "lambda.amazonaws.com"},
    )
    wrong = evaluator.evaluate(
        "aws:user:ci-runner",
        "iam:PassRole",
        role,
        {"iam:PassedToService": "ec2.amazonaws.com"},
    )
    assert missing.decision is PermissionDecision.IMPLICIT_DENY
    assert allowed.decision is PermissionDecision.ALLOW
    assert wrong.decision is PermissionDecision.IMPLICIT_DENY


def test_assume_role_requires_permission_and_trust(environment: Environment) -> None:
    evaluator = AwsEvaluator(environment)
    developer = evaluator.identities["aws:user:developer"]
    audit = evaluator.identities["aws:role:security-audit"]
    runtime = evaluator.identities["aws:role:payroll-runtime"]
    assert evaluator.can_assume(developer, audit).decision is PermissionDecision.ALLOW
    assert evaluator.can_assume(developer, runtime).decision is not PermissionDecision.ALLOW


def test_unknown_policy_semantics_fail_closed(environment: Environment) -> None:
    payload = environment.model_dump(mode="json")
    payload["identities"][1]["policies"].append(
        {
            "id": "unsupported-condition",
            "effect": "Allow",
            "actions": ["s3:GetObject"],
            "resources": ["*"],
            "conditions": {"NumericEquals": {"custom:key": "1"}},
        }
    )
    payload["identities"][1]["policies"].append(
        {
            "id": "plain-s3-allow",
            "effect": "Allow",
            "actions": ["s3:GetObject"],
            "resources": ["*"],
        }
    )
    changed = Environment.model_validate(payload)
    decision = AwsEvaluator(changed).evaluate("aws:user:ci-runner", "s3:GetObject", "arn:x")
    assert decision.decision is PermissionDecision.UNKNOWN
    assert "condition operator NumericEquals" in decision.unknown_reasons[0]


def test_scp_explicit_deny_wins(environment: Environment) -> None:
    changed = environment.model_copy(deep=True)
    changed.service_control_policy.append(
        PolicyStatement(
            id="scp-deny-lambda",
            effect=Effect.DENY,
            actions=("lambda:UpdateFunctionCode",),
            resources=("*",),
        )
    )
    decision = AwsEvaluator(changed).evaluate(
        "aws:user:developer",
        "lambda:UpdateFunctionCode",
        "arn:aws:lambda:eu-west-3:111122223333:function:payroll-api",
    )
    assert decision.decision is PermissionDecision.EXPLICIT_DENY
    assert decision.evidence == ("scp:scp-deny-lambda:Deny",)


def test_kubernetes_scope_and_resource_names(environment: Environment) -> None:
    evaluator = KubernetesEvaluator(environment)
    create_payroll = evaluator.evaluate("k8s:user:developer", "create", "pods", namespace="payroll")
    create_other = evaluator.evaluate("k8s:user:developer", "create", "pods", namespace="other")
    bind = evaluator.evaluate(
        "k8s:user:developer",
        "bind",
        "clusterroles",
        api_group="rbac.authorization.k8s.io",
        resource_name="cluster-admin",
    )
    read_named = evaluator.evaluate(
        "k8s:sa:payroll:web",
        "get",
        "secrets",
        namespace="payroll",
        resource_name="database",
    )
    read_other = evaluator.evaluate(
        "k8s:sa:payroll:web",
        "get",
        "secrets",
        namespace="payroll",
        resource_name="other",
    )
    assert create_payroll.decision is PermissionDecision.ALLOW
    assert create_other.decision is PermissionDecision.IMPLICIT_DENY
    assert bind.decision is PermissionDecision.ALLOW
    assert read_named.decision is PermissionDecision.ALLOW
    assert read_other.decision is PermissionDecision.IMPLICIT_DENY
