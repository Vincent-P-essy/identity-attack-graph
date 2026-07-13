from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

import pytest

from identity_attack_graph.adapters import (
    _document,
    import_aws_authorization_details,
    import_kubernetes_file,
    import_kubernetes_yaml,
)
from identity_attack_graph.models import IdentityKind


def test_aws_authorization_details_adapter(repository_root: Path) -> None:
    payload = json.loads(
        (repository_root / "fixtures/aws/authorization-details.json").read_text(encoding="utf-8")
    )
    identities, groups = import_aws_authorization_details(payload, account_id="111122223333")
    assert {item.id for item in identities} == {
        "aws:user:developer",
        "aws:role:payroll-runtime",
    }
    developer = next(item for item in identities if item.kind is IdentityKind.USER)
    role = next(item for item in identities if item.kind is IdentityKind.ROLE)
    assert developer.groups == ("aws:group:developers",)
    assert developer.policies[0].actions == ("lambda:UpdateFunctionCode",)
    assert role.trust_principals == ("lambda.amazonaws.com",)
    assert groups[0].policies[0].actions == ("lambda:ListFunctions",)


def test_aws_adapter_resolves_managed_policy_and_boundary() -> None:
    document = {
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::example/*",
        }
    }
    arn = "arn:aws:iam::111122223333:policy/Boundary"
    payload = {
        "Policies": [
            {
                "Arn": arn,
                "PolicyVersionList": [
                    {
                        "IsDefaultVersion": True,
                        "Document": urllib.parse.quote(json.dumps(document)),
                    }
                ],
            }
        ],
        "UserDetailList": [
            {
                "UserName": "bounded",
                "AttachedManagedPolicies": [{"PolicyArn": arn}],
                "PermissionsBoundary": {"PermissionsBoundaryArn": arn},
            }
        ],
    }
    identities, _ = import_aws_authorization_details(payload, account_id="111122223333")
    assert identities[0].policies[0].actions == ("s3:GetObject",)
    assert identities[0].permissions_boundary[0].actions == ("s3:GetObject",)
    with pytest.raises(ValueError, match="policy document"):
        _document(42)


def test_kubernetes_yaml_adapter(repository_root: Path) -> None:
    identities, roles, bindings, resources = import_kubernetes_file(
        repository_root / "fixtures/kubernetes/rbac-lab.yaml"
    )
    assert {item.id for item in identities} == {
        "k8s:sa:payroll:web",
        "k8s:user:developer",
    }
    assert roles[0].id == "k8s:role:payroll:developer"
    assert bindings[0].subjects == ("k8s:user:developer",)
    secret = next(item for item in resources if item.kind == "k8s_secret")
    pod = next(item for item in resources if item.kind == "pod")
    assert secret.crown_jewel is True and secret.impact == 90
    assert pod.service_account == "k8s:sa:payroll:web"


def test_kubernetes_adapter_imports_cluster_binding_group_and_privileged_pod() -> None:
    source = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: wildcard}
rules:
  - apiGroups: ['*']
    resources: ['*']
    verbs: ['*']
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: everyone}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: wildcard}
subjects:
  - {kind: Group, name: engineering}
---
apiVersion: v1
kind: Pod
metadata: {name: privileged, namespace: ops}
spec:
  serviceAccountName: deployer
  containers:
    - name: shell
      image: example.invalid/safe:1
      securityContext: {privileged: true}
"""
    identities, roles, bindings, resources = import_kubernetes_yaml(source)
    assert any(item.kind is IdentityKind.GROUP for item in identities)
    assert roles[0].kind == "ClusterRole"
    assert bindings[0].kind == "ClusterRoleBinding"
    assert resources[0].privileged is True
