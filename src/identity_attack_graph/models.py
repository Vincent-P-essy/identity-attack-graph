from __future__ import annotations

from enum import StrEnum
from typing import Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Scalar: TypeAlias = str | int | float | bool | None


class Provider(StrEnum):
    AWS = "aws"
    KUBERNETES = "kubernetes"


class IdentityKind(StrEnum):
    USER = "user"
    ROLE = "role"
    GROUP = "group"
    SERVICE_ACCOUNT = "service_account"


class Effect(StrEnum):
    ALLOW = "Allow"
    DENY = "Deny"


class PermissionDecision(StrEnum):
    ALLOW = "allow"
    EXPLICIT_DENY = "explicit_deny"
    IMPLICIT_DENY = "implicit_deny"
    UNKNOWN = "unknown"


class NodeKind(StrEnum):
    IDENTITY = "identity"
    WORKLOAD = "workload"
    RESOURCE = "resource"
    PRIVILEGE = "privilege"
    TARGET = "target"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


ConditionValue: TypeAlias = str | list[str]
Conditions: TypeAlias = dict[str, dict[str, ConditionValue]]


class PolicyStatement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[A-Za-z0-9_.:/-]+$", min_length=1, max_length=160)
    effect: Effect
    actions: tuple[str, ...] = Field(min_length=1)
    resources: tuple[str, ...] = ("*",)
    conditions: Conditions = Field(default_factory=dict)
    not_actions: tuple[str, ...] = ()
    not_resources: tuple[str, ...] = ()
    source: str = "identity-policy"

    @field_validator("actions", "resources", "not_actions", "not_resources")
    @classmethod
    def reject_blank_patterns(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value.strip() for value in values):
            raise ValueError("policy patterns cannot be blank")
        return values


class Identity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[A-Za-z0-9_.:/-]+$", min_length=1, max_length=200)
    provider: Provider
    kind: IdentityKind
    name: str
    arn: str | None = None
    namespace: str | None = None
    groups: tuple[str, ...] = ()
    policies: tuple[PolicyStatement, ...] = ()
    permissions_boundary: tuple[PolicyStatement, ...] = ()
    trust_principals: tuple[str, ...] = ()
    labels: dict[str, str] = Field(default_factory=dict)


class IdentityGroup(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    provider: Provider = Provider.AWS
    name: str
    policies: tuple[PolicyStatement, ...] = ()


class Resource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[A-Za-z0-9_.:/-]+$", min_length=1, max_length=240)
    provider: Provider
    kind: str
    name: str
    arn: str | None = None
    namespace: str | None = None
    execution_role: str | None = None
    service_account: str | None = None
    auto_trigger: bool = False
    privileged: bool = False
    impact: float = Field(default=25, ge=0, le=100)
    crown_jewel: bool = False
    labels: dict[str, str] = Field(default_factory=dict)


class KubernetesRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    verbs: tuple[str, ...] = Field(min_length=1)
    api_groups: tuple[str, ...] = ("",)
    resources: tuple[str, ...] = Field(min_length=1)
    resource_names: tuple[str, ...] = ()


class KubernetesRole(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    name: str
    kind: Literal["Role", "ClusterRole"]
    namespace: str | None = None
    rules: tuple[KubernetesRule, ...] = ()

    @model_validator(mode="after")
    def role_scope_is_consistent(self) -> KubernetesRole:
        if self.kind == "Role" and self.namespace is None:
            raise ValueError("Role requires a namespace")
        if self.kind == "ClusterRole" and self.namespace is not None:
            raise ValueError("ClusterRole must not have a namespace")
        return self


class KubernetesBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    name: str
    kind: Literal["RoleBinding", "ClusterRoleBinding"]
    role_ref: str
    subjects: tuple[str, ...] = Field(min_length=1)
    namespace: str | None = None

    @model_validator(mode="after")
    def binding_scope_is_consistent(self) -> KubernetesBinding:
        if self.kind == "RoleBinding" and self.namespace is None:
            raise ValueError("RoleBinding requires a namespace")
        if self.kind == "ClusterRoleBinding" and self.namespace is not None:
            raise ValueError("ClusterRoleBinding must not have a namespace")
        return self


class BusinessRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    operation: str
    principal: str
    action: str
    resource: str
    context: dict[str, str] = Field(default_factory=dict)


class Environment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    name: str
    identities: list[Identity] = Field(default_factory=list)
    groups: list[IdentityGroup] = Field(default_factory=list)
    resources: list[Resource] = Field(default_factory=list)
    kubernetes_roles: list[KubernetesRole] = Field(default_factory=list)
    kubernetes_bindings: list[KubernetesBinding] = Field(default_factory=list)
    service_control_policy: list[PolicyStatement] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    business_requirements: list[BusinessRequirement] = Field(default_factory=list)
    metadata: dict[str, Scalar] = Field(default_factory=dict)

    @model_validator(mode="after")
    def identifiers_are_unique(self) -> Environment:
        ids = [item.id for item in self.identities]
        ids += [item.id for item in self.groups]
        ids += [item.id for item in self.resources]
        ids += [item.id for item in self.kubernetes_roles]
        ids += [item.id for item in self.kubernetes_bindings]
        if len(ids) != len(set(ids)):
            raise ValueError("all environment identifiers must be unique")
        return self


class PermissionEvaluation(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: PermissionDecision
    action: str
    resource: str
    evidence: tuple[str, ...] = ()
    unknown_reasons: tuple[str, ...] = ()


class GraphNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    label: str
    provider: Provider
    kind: NodeKind
    subtype: str
    impact: float = Field(ge=0, le=100)
    crown_jewel: bool = False
    metadata: dict[str, Scalar] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    source: str
    target: str
    kind: str
    label: str
    effort: float = Field(ge=0.01, le=100)
    exploitability: float = Field(gt=0, le=1)
    confidence: float = Field(gt=0, le=1)
    evidence: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()


class AttackPath(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    entrypoint: str
    target: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    effort: float
    exploitability: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    target_impact: float = Field(ge=0, le=100)
    risk: float = Field(ge=0, le=100)
    techniques: tuple[str, ...] = ()


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    category: str
    severity: Severity
    title: str
    subject: str
    evidence: tuple[str, ...] = ()
    recommendation: str


class RiskSummary(BaseModel):
    path_count: int
    maximum_path_risk: float
    aggregate_risk: float
    crown_jewels_reachable: int


class Report(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    environment: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    paths: list[AttackPath]
    findings: list[Finding]
    centrality: dict[str, float]
    risk: RiskSummary
    unsupported_semantics: list[str] = Field(default_factory=list)
    elapsed_ms: float


class PermissionMutation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: Literal["remove"] = "remove"
    statement_id: str
    action: str


class WhatIfRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mutations: list[PermissionMutation] = Field(min_length=1, max_length=20)


class WhatIfReport(BaseModel):
    baseline_risk: RiskSummary
    simulated_risk: RiskSummary
    risk_reduction: float
    eliminated_paths: list[AttackPath]
    new_paths: list[AttackPath]
    surviving_paths: int
    broken_business_operations: list[BusinessRequirement]
    applied_mutations: list[PermissionMutation]


class ErrorResponse(BaseModel):
    detail: str
    code: str
