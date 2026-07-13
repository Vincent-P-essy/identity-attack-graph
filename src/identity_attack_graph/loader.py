from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Environment

MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_ANALYSIS_RELATION_CHECKS = 2_000_000


def load_environment(path: Path) -> Environment:
    if not path.is_file():
        raise ValueError(f"environment file does not exist: {path}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"environment exceeds {MAX_INPUT_BYTES} bytes")
    try:
        payload = strict_json_object(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ValueError(f"cannot load environment {path}: {error}") from error
    environment = Environment.model_validate(payload)
    validate_references(environment)
    return environment


def strict_json_object(text: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    value = json.loads(
        text,
        object_pairs_hook=unique_object,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON number {token}")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError("environment must be a JSON object")
    return value


def validate_references(environment: Environment) -> None:
    estimated_checks = len(environment.identities) * (
        len(environment.identities)
        + 2 * len(environment.resources)
        + len(environment.kubernetes_bindings)
    )
    if estimated_checks > MAX_ANALYSIS_RELATION_CHECKS:
        raise ValueError(
            "environment exceeds the bounded analysis complexity "
            f"of {MAX_ANALYSIS_RELATION_CHECKS} relation checks"
        )
    identity_ids = {item.id for item in environment.identities}
    group_ids = {item.id for item in environment.groups}
    resource_ids = {item.id for item in environment.resources}
    roles = {item.id: item for item in environment.kubernetes_roles}
    role_ids = set(roles)
    node_ids = identity_ids | resource_ids | {"k8s:privilege:cluster-admin"}
    failures: list[str] = []
    for identity in environment.identities:
        for group in identity.groups:
            if group not in group_ids:
                failures.append(f"{identity.id} references unknown group {group}")
    for resource in environment.resources:
        if resource.execution_role and resource.execution_role not in identity_ids:
            failures.append(
                f"{resource.id} references unknown execution role {resource.execution_role}"
            )
        if resource.service_account and resource.service_account not in identity_ids:
            failures.append(
                f"{resource.id} references unknown service account {resource.service_account}"
            )
    for binding in environment.kubernetes_bindings:
        if binding.role_ref not in role_ids:
            failures.append(f"{binding.id} references unknown role {binding.role_ref}")
        else:
            role = roles[binding.role_ref]
            if binding.kind == "ClusterRoleBinding" and role.kind != "ClusterRole":
                failures.append(f"{binding.id} must reference a ClusterRole")
            if (
                binding.kind == "RoleBinding"
                and role.kind == "Role"
                and role.namespace != binding.namespace
            ):
                failures.append(f"{binding.id} references a Role in another namespace")
        for subject in binding.subjects:
            if subject not in identity_ids:
                failures.append(f"{binding.id} references unknown subject {subject}")
    for entrypoint in environment.entrypoints:
        if entrypoint not in identity_ids:
            failures.append(f"unknown entrypoint {entrypoint}")
    for target in environment.targets:
        if target not in node_ids:
            failures.append(f"unknown target {target}")
    for requirement in environment.business_requirements:
        if requirement.principal not in identity_ids:
            failures.append(f"{requirement.id} references unknown principal")
        if requirement.resource not in resource_ids and requirement.resource != "*":
            failures.append(f"{requirement.id} references unknown resource")
    if failures:
        raise ValueError("invalid environment references: " + "; ".join(sorted(failures)))
