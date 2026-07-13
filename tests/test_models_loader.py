from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

from identity_attack_graph.loader import MAX_INPUT_BYTES, load_environment, validate_references
from identity_attack_graph.models import (
    Environment,
    KubernetesBinding,
    KubernetesRole,
    PolicyStatement,
)


def test_environment_loads_and_references_are_valid(
    environment: Environment, environment_path: Path
) -> None:
    assert environment.name == "banking-platform-identity-lab"
    assert len(environment.identities) == 7
    assert load_environment(environment_path).model_dump() == environment.model_dump()


def test_duplicate_ids_are_rejected(environment: Environment) -> None:
    payload = environment.model_dump(mode="json")
    payload["resources"][0]["id"] = payload["identities"][0]["id"]
    with pytest.raises(ValidationError, match="unique"):
        Environment.model_validate(payload)


def test_duplicate_semantic_ids_are_rejected(environment: Environment) -> None:
    payload = environment.model_dump(mode="json")
    payload["identities"][1]["policies"][0]["id"] = payload["identities"][0]["policies"][0]["id"]
    with pytest.raises(ValidationError, match=r"statement.*unique"):
        Environment.model_validate(payload)


@pytest.mark.parametrize(
    "mutator, expected",
    [
        (lambda p: p["entrypoints"].append("missing"), "unknown entrypoint"),
        (lambda p: p["targets"].append("missing"), "unknown target"),
        (
            lambda p: p["resources"][0].update({"execution_role": "missing"}),
            "unknown execution role",
        ),
        (
            lambda p: p["kubernetes_bindings"][0]["subjects"].append("missing"),
            "unknown subject",
        ),
        (
            lambda p: p["kubernetes_bindings"][0].update({"role_ref": "missing"}),
            "unknown role",
        ),
    ],
)
def test_reference_validation_fails_closed(
    environment: Environment, mutator: Callable[[dict[str, object]], None], expected: str
) -> None:
    payload = environment.model_dump(mode="json")
    mutator(payload)
    invalid = Environment.model_validate(payload)
    with pytest.raises(ValueError, match=expected):
        validate_references(invalid)


def test_loader_rejects_missing_bad_and_oversize_files(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        load_environment(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot load"):
        load_environment(bad)
    large = tmp_path / "large.json"
    large.write_bytes(b"x" * (MAX_INPUT_BYTES + 1))
    with pytest.raises(ValueError, match="exceeds"):
        load_environment(large)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"name":"one","name":"two"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_environment(duplicate)

    non_finite = tmp_path / "non-finite.json"
    non_finite.write_text('{"name":"x","metadata":{"risk":NaN}}', encoding="utf-8")
    with pytest.raises(ValueError, match="non-finite"):
        load_environment(non_finite)


def test_scope_models_reject_inconsistent_namespace() -> None:
    with pytest.raises(ValidationError, match="requires a namespace"):
        KubernetesRole(id="r", name="r", kind="Role", rules=())
    with pytest.raises(ValidationError, match="must not have"):
        KubernetesBinding(
            id="b",
            name="b",
            kind="ClusterRoleBinding",
            namespace="default",
            role_ref="r",
            subjects=("s",),
        )


def test_reference_validation_rejects_invalid_binding_role_scope(
    environment: Environment,
) -> None:
    payload = environment.model_dump(mode="json")
    payload["kubernetes_bindings"].append(
        {
            "id": "invalid-cluster-binding",
            "name": "invalid",
            "kind": "ClusterRoleBinding",
            "role_ref": "k8s:role:payroll:developer",
            "subjects": ["k8s:user:developer"],
        }
    )
    invalid_cluster = Environment.model_validate(payload)
    with pytest.raises(ValueError, match="must reference a ClusterRole"):
        validate_references(invalid_cluster)

    payload = environment.model_dump(mode="json")
    payload["kubernetes_bindings"][0]["namespace"] = "other"
    invalid_namespace = Environment.model_validate(payload)
    with pytest.raises(ValueError, match="another namespace"):
        validate_references(invalid_namespace)


def test_policy_patterns_cannot_be_blank() -> None:
    with pytest.raises(ValidationError, match="blank"):
        PolicyStatement(id="bad", effect="Allow", actions=("",), resources=("*",))
