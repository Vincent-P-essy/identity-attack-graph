from __future__ import annotations

import json
import urllib.parse
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal

import yaml

from .models import (
    Effect,
    Identity,
    IdentityGroup,
    IdentityKind,
    KubernetesBinding,
    KubernetesRole,
    KubernetesRule,
    PolicyStatement,
    Provider,
    Resource,
    TrustStatement,
)


def import_aws_authorization_details(
    payload: dict[str, Any], *, account_id: str
) -> tuple[list[Identity], list[IdentityGroup]]:
    """Import the useful subset of IAM GetAccountAuthorizationDetails output."""
    if payload.get("IsTruncated") in {True, "true", "True"}:
        raise ValueError("IAM authorization details are truncated; collect every page first")
    managed = _managed_policy_documents(payload.get("Policies", []))
    groups: list[IdentityGroup] = []
    group_ids: dict[str, str] = {}
    for raw in payload.get("GroupDetailList", []):
        name = str(raw["GroupName"])
        group_id = f"aws:group:{name}"
        group_ids[name] = group_id
        policies, unresolved = _entity_policies(raw, managed, f"group/{name}")
        groups.append(
            IdentityGroup(
                id=group_id,
                name=name,
                policies=tuple(policies),
                unresolved_policy_references=tuple(unresolved),
                provider=Provider.AWS,
            )
        )

    identities: list[Identity] = []
    for raw in payload.get("UserDetailList", []):
        name = str(raw["UserName"])
        source = f"user/{name}"
        policies, unresolved = _entity_policies(raw, managed, source)
        boundary, unresolved_boundary = _boundary(raw, managed, source)
        identities.append(
            Identity(
                id=f"aws:user:{name}",
                provider=Provider.AWS,
                kind=IdentityKind.USER,
                name=name,
                arn=str(raw.get("Arn") or f"arn:aws:iam::{account_id}:user/{name}"),
                groups=tuple(
                    group_ids[item] for item in raw.get("GroupList", []) if item in group_ids
                ),
                policies=tuple(policies),
                permissions_boundary=tuple(boundary),
                unresolved_policy_references=tuple(unresolved),
                unresolved_boundary_reference=unresolved_boundary,
            )
        )
    for raw in payload.get("RoleDetailList", []):
        name = str(raw["RoleName"])
        source = f"role/{name}"
        trust_document = _document(raw.get("AssumeRolePolicyDocument", {}))
        trust = _trust_principals(trust_document)
        trust_policy, unresolved_trust = _trust_statements(trust_document, f"{source}/trust")
        policies, unresolved = _entity_policies(raw, managed, source)
        boundary, unresolved_boundary = _boundary(raw, managed, source)
        identities.append(
            Identity(
                id=f"aws:role:{name}",
                provider=Provider.AWS,
                kind=IdentityKind.ROLE,
                name=name,
                arn=str(raw.get("Arn") or f"arn:aws:iam::{account_id}:role/{name}"),
                policies=tuple(policies),
                permissions_boundary=tuple(boundary),
                unresolved_policy_references=tuple(unresolved),
                unresolved_boundary_reference=unresolved_boundary,
                trust_principals=tuple(trust),
                trust_policy=tuple(trust_policy),
                unresolved_trust_semantics=tuple(unresolved_trust),
            )
        )
    return identities, groups


def import_kubernetes_yaml(
    text: str,
) -> tuple[
    list[Identity],
    list[KubernetesRole],
    list[KubernetesBinding],
    list[Resource],
]:
    documents = [item for item in yaml.safe_load_all(text) if isinstance(item, dict)]
    identities: dict[str, Identity] = {}
    roles: list[KubernetesRole] = []
    bindings: list[KubernetesBinding] = []
    resources: list[Resource] = []

    for document in documents:
        kind = str(document.get("kind", ""))
        metadata = document.get("metadata") or {}
        name = str(metadata.get("name", ""))
        namespace = str(metadata.get("namespace", "default"))
        labels = {str(k): str(v) for k, v in (metadata.get("labels") or {}).items()}
        if kind == "ServiceAccount":
            identity = _kubernetes_subject("ServiceAccount", name, namespace)
            identities[identity.id] = identity
        elif kind in {"Role", "ClusterRole"}:
            role_id = _role_id(kind, name, namespace)
            role_kind: Literal["Role", "ClusterRole"] = "Role" if kind == "Role" else "ClusterRole"
            rules = []
            for index, raw_rule in enumerate(document.get("rules") or []):
                rules.append(
                    KubernetesRule(
                        id=f"{role_id}:rule:{index}",
                        verbs=tuple(str(item) for item in raw_rule.get("verbs", [])),
                        api_groups=tuple(str(item) for item in raw_rule.get("apiGroups", [""])),
                        resources=tuple(str(item) for item in raw_rule.get("resources", [])),
                        resource_names=tuple(
                            str(item) for item in raw_rule.get("resourceNames", [])
                        ),
                    )
                )
            roles.append(
                KubernetesRole(
                    id=role_id,
                    name=name,
                    kind=role_kind,
                    namespace=namespace if kind == "Role" else None,
                    rules=tuple(rules),
                )
            )
        elif kind in {"RoleBinding", "ClusterRoleBinding"}:
            binding_kind: Literal["RoleBinding", "ClusterRoleBinding"] = (
                "RoleBinding" if kind == "RoleBinding" else "ClusterRoleBinding"
            )
            binding_id = (
                f"k8s:binding:{namespace}:{name}"
                if kind == "RoleBinding"
                else f"k8s:cluster-binding:{name}"
            )
            subject_ids = []
            for raw_subject in document.get("subjects") or []:
                subject_kind = str(raw_subject.get("kind", ""))
                if subject_kind not in {"User", "Group", "ServiceAccount"}:
                    raise ValueError(
                        f"unsupported Kubernetes binding subject kind: {subject_kind!r}"
                    )
                subject = _kubernetes_subject(
                    subject_kind,
                    str(raw_subject["name"]),
                    str(raw_subject.get("namespace", namespace)),
                )
                identities.setdefault(subject.id, subject)
                subject_ids.append(subject.id)
            role_ref = document.get("roleRef") or {}
            ref_kind = str(role_ref.get("kind", ""))
            if ref_kind not in {"Role", "ClusterRole"}:
                raise ValueError(f"unsupported Kubernetes roleRef kind: {ref_kind!r}")
            if role_ref.get("apiGroup") != "rbac.authorization.k8s.io":
                raise ValueError("Kubernetes roleRef apiGroup must be rbac.authorization.k8s.io")
            bindings.append(
                KubernetesBinding(
                    id=binding_id,
                    name=name,
                    kind=binding_kind,
                    role_ref=_role_id(ref_kind, str(role_ref["name"]), namespace),
                    subjects=tuple(subject_ids),
                    namespace=namespace if kind == "RoleBinding" else None,
                )
            )
        elif kind == "Secret":
            crown = labels.get("identity-attack-graph.io/crown-jewel") == "true"
            resources.append(
                Resource(
                    id=f"k8s:secret:{namespace}:{name}",
                    provider=Provider.KUBERNETES,
                    kind="k8s_secret",
                    name=name,
                    namespace=namespace,
                    impact=float(labels.get("identity-attack-graph.io/impact", 80)),
                    crown_jewel=crown,
                    labels=labels,
                )
            )
        elif kind == "Pod":
            spec = document.get("spec") or {}
            service_account_name = str(spec.get("serviceAccountName", "default"))
            service_account = _kubernetes_subject("ServiceAccount", service_account_name, namespace)
            identities.setdefault(service_account.id, service_account)
            resources.append(
                Resource(
                    id=f"k8s:pod:{namespace}:{name}",
                    provider=Provider.KUBERNETES,
                    kind="pod",
                    name=name,
                    namespace=namespace,
                    service_account=service_account.id,
                    privileged=any(
                        bool((container.get("securityContext") or {}).get("privileged"))
                        for container in spec.get("containers", [])
                    ),
                    impact=45,
                    labels=labels,
                )
            )
    _validate_imported_binding_scopes(roles, bindings)
    return list(identities.values()), roles, bindings, resources


def import_kubernetes_file(
    path: Path,
) -> tuple[
    list[Identity],
    list[KubernetesRole],
    list[KubernetesBinding],
    list[Resource],
]:
    return import_kubernetes_yaml(path.read_text(encoding="utf-8"))


def _entity_policies(
    raw: dict[str, Any], managed: dict[str, dict[str, Any]], source: str
) -> tuple[list[PolicyStatement], list[str]]:
    statements: list[PolicyStatement] = []
    unresolved: list[str] = []
    inline = (
        raw.get("UserPolicyList") or raw.get("RolePolicyList") or raw.get("GroupPolicyList") or []
    )
    for policy in inline:
        name = str(policy.get("PolicyName", "inline"))
        statements.extend(
            _statements(_document(policy.get("PolicyDocument", {})), f"{source}/{name}")
        )
    for attached in raw.get("AttachedManagedPolicies", []):
        arn = str(attached.get("PolicyArn", ""))
        if arn in managed:
            statements.extend(_statements(managed[arn], f"{source}/{arn}"))
        else:
            unresolved.append(f"{source}:attached-managed-policy:{arn or '<missing-arn>'}")
    return statements, sorted(set(unresolved))


def _boundary(
    raw: dict[str, Any], managed: dict[str, dict[str, Any]], source: str
) -> tuple[list[PolicyStatement], str | None]:
    boundary = raw.get("PermissionsBoundary") or {}
    if not boundary:
        return [], None
    arn = str(boundary.get("PermissionsBoundaryArn", ""))
    if arn not in managed:
        return [], f"{source}:permissions-boundary:{arn or '<missing-arn>'}"
    return _statements(managed[arn], f"{source}/boundary/{arn}"), None


def _managed_policy_documents(policies: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    for policy in policies:
        arn = str(policy.get("Arn", ""))
        versions = policy.get("PolicyVersionList") or []
        default = next((item for item in versions if item.get("IsDefaultVersion")), None)
        if arn and default:
            documents[arn] = _document(default.get("Document", {}))
    return documents


def _document(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        decoded = urllib.parse.unquote(raw)
        parsed = json.loads(decoded)
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("IAM policy document must be an object or URL-encoded object")


def _statements(document: dict[str, Any], source: str) -> list[PolicyStatement]:
    raw_statements = document.get("Statement", [])
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    statements = []
    for index, raw in enumerate(raw_statements):
        statements.append(
            PolicyStatement(
                id=f"{source}:statement:{index}",
                effect=Effect(str(raw["Effect"])),
                actions=_tuple(raw.get("Action", [])),
                resources=_tuple(raw.get("Resource", "*")),
                conditions=raw.get("Condition") or {},
                not_actions=_tuple(raw.get("NotAction", [])),
                not_resources=_tuple(raw.get("NotResource", [])),
                source=source,
            )
        )
    return statements


def _trust_principals(document: dict[str, Any]) -> list[str]:
    result: list[str] = []
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        actions = _tuple(statement.get("Action", []))
        if not any(action in {"sts:AssumeRole", "sts:*", "*"} for action in actions):
            continue
        principal = statement.get("Principal") or {}
        if isinstance(principal, str):
            result.append(principal)
        elif isinstance(principal, dict):
            for value in principal.values():
                result.extend(_tuple(value))
    return sorted(set(result))


def _trust_statements(
    document: dict[str, Any], source: str
) -> tuple[list[TrustStatement], list[str]]:
    raw_statements = document.get("Statement", [])
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    statements: list[TrustStatement] = []
    unresolved: list[str] = []
    for index, raw in enumerate(raw_statements):
        statement_id = f"{source}:statement:{index}"
        if not isinstance(raw, dict):
            unresolved.append(f"{statement_id}: statement is not an object")
            continue
        if raw.get("NotPrincipal") is not None or raw.get("NotAction") is not None:
            unresolved.append(f"{statement_id}: NotPrincipal/NotAction is unsupported")
            continue
        principal = raw.get("Principal")
        principals: list[str] = []
        if isinstance(principal, str):
            principals.append(principal)
        elif isinstance(principal, dict):
            for value in principal.values():
                principals.extend(_tuple(value))
        if not principals:
            unresolved.append(f"{statement_id}: Principal is missing or unsupported")
            continue
        statements.append(
            TrustStatement(
                id=statement_id,
                effect=Effect(str(raw["Effect"])),
                actions=_tuple(raw.get("Action", [])),
                principals=tuple(principals),
                conditions=raw.get("Condition") or {},
                source=source,
            )
        )
    return statements, sorted(set(unresolved))


def _tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return (str(value),)


def _kubernetes_subject(kind: str, name: str, namespace: str) -> Identity:
    if kind == "ServiceAccount":
        return Identity(
            id=f"k8s:sa:{namespace}:{name}",
            provider=Provider.KUBERNETES,
            kind=IdentityKind.SERVICE_ACCOUNT,
            name=name,
            namespace=namespace,
        )
    prefix = "group" if kind == "Group" else "user"
    return Identity(
        id=f"k8s:{prefix}:{name}",
        provider=Provider.KUBERNETES,
        kind=IdentityKind.GROUP if kind == "Group" else IdentityKind.USER,
        name=name,
    )


def _role_id(kind: str, name: str, namespace: str) -> str:
    return f"k8s:role:{namespace}:{name}" if kind == "Role" else f"k8s:cluster-role:{name}"


def _validate_imported_binding_scopes(
    roles: list[KubernetesRole], bindings: list[KubernetesBinding]
) -> None:
    by_id = {role.id: role for role in roles}
    for binding in bindings:
        role = by_id.get(binding.role_ref)
        if role is None:
            raise ValueError(f"Kubernetes binding {binding.id} references an unavailable role")
        if binding.kind == "ClusterRoleBinding" and role.kind != "ClusterRole":
            raise ValueError(f"ClusterRoleBinding {binding.id} must reference a ClusterRole")
        if (
            binding.kind == "RoleBinding"
            and role.kind == "Role"
            and role.namespace != binding.namespace
        ):
            raise ValueError(f"RoleBinding {binding.id} must reference a Role in its namespace")
