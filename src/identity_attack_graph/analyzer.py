from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable

from .evaluation import AwsEvaluator, KubernetesEvaluator
from .graph import AttackGraph, summarize_risk
from .loader import validate_references
from .models import (
    AttackPath,
    BusinessRequirement,
    Effect,
    Environment,
    Finding,
    GraphNode,
    Identity,
    IdentityKind,
    NodeKind,
    PermissionDecision,
    PermissionEvaluation,
    PermissionMutation,
    PolicyStatement,
    Provider,
    Report,
    Resource,
    Severity,
    WhatIfReport,
    WhatIfRequest,
)

_SENSITIVE_AWS_ACTIONS = {
    "*",
    "iam:*",
    "iam:PassRole",
    "iam:PutRolePolicy",
    "iam:AttachRolePolicy",
    "iam:CreateAccessKey",
    "sts:AssumeRole",
    "lambda:UpdateFunctionCode",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
}


class Analyzer:
    def __init__(self, environment: Environment) -> None:
        validate_references(environment)
        self.environment = environment
        self.aws = AwsEvaluator(environment)
        self.kubernetes = KubernetesEvaluator(environment)
        self.unsupported: set[str] = set()

    def analyze(self) -> Report:
        started = time.perf_counter()
        self.unsupported.clear()
        graph = AttackGraph()
        self._add_nodes(graph)
        self._add_aws_edges(graph)
        self._add_kubernetes_edges(graph)
        paths = graph.find_paths(self.environment.entrypoints, self.environment.targets)
        findings = self._findings(paths, graph)
        return Report(
            environment=self.environment.name,
            nodes=sorted(graph.nodes.values(), key=lambda item: item.id),
            edges=sorted(graph.edges.values(), key=lambda item: item.id),
            paths=paths,
            findings=findings,
            centrality=graph.centrality(),
            risk=summarize_risk(paths),
            unsupported_semantics=sorted(self.unsupported),
            elapsed_ms=round((time.perf_counter() - started) * 1_000, 3),
        )

    def what_if(self, request: WhatIfRequest) -> WhatIfReport:
        baseline = self.analyze()
        simulated_environment = _apply_mutations(self.environment, request.mutations)
        simulated = Analyzer(simulated_environment).analyze()
        baseline_paths = _semantic_paths(baseline)
        simulated_paths = _semantic_paths(simulated)
        eliminated = sorted(
            (path for key, path in baseline_paths.items() if key not in simulated_paths),
            key=lambda item: (-item.risk, item.id),
        )
        new = sorted(
            (path for key, path in simulated_paths.items() if key not in baseline_paths),
            key=lambda item: (-item.risk, item.id),
        )
        broken = [
            requirement
            for requirement in self.environment.business_requirements
            if self._requirement_allowed(self.environment, requirement)
            and not self._requirement_allowed(simulated_environment, requirement)
        ]
        return WhatIfReport(
            baseline_risk=baseline.risk,
            simulated_risk=simulated.risk,
            risk_reduction=round(
                max(0.0, baseline.risk.aggregate_risk - simulated.risk.aggregate_risk), 3
            ),
            eliminated_paths=eliminated,
            new_paths=new,
            surviving_paths=len(simulated.paths),
            broken_business_operations=broken,
            applied_mutations=request.mutations,
        )

    def _add_nodes(self, graph: AttackGraph) -> None:
        targets = set(self.environment.targets)
        for identity in self.environment.identities:
            privileged = identity.labels.get("privileged", "false").lower() == "true"
            impact = 90 if privileged else (65 if identity.kind is IdentityKind.ROLE else 20)
            graph.add_node(
                GraphNode(
                    id=identity.id,
                    label=identity.name,
                    provider=identity.provider,
                    kind=NodeKind.TARGET if identity.id in targets else NodeKind.IDENTITY,
                    subtype=identity.kind.value,
                    impact=impact,
                    crown_jewel=identity.id in targets,
                    metadata={
                        "arn": identity.arn,
                        "namespace": identity.namespace,
                        "privileged": privileged,
                    },
                )
            )
        for resource in self.environment.resources:
            kind = NodeKind.RESOURCE
            if resource.kind in {"lambda_function", "pod", "workload"}:
                kind = NodeKind.WORKLOAD
            if resource.id in targets or resource.crown_jewel:
                kind = NodeKind.TARGET
            graph.add_node(
                GraphNode(
                    id=resource.id,
                    label=resource.name,
                    provider=resource.provider,
                    kind=kind,
                    subtype=resource.kind,
                    impact=resource.impact,
                    crown_jewel=resource.id in targets or resource.crown_jewel,
                    metadata={
                        "arn": resource.arn,
                        "namespace": resource.namespace,
                        "privileged": resource.privileged,
                    },
                )
            )
        if "k8s:privilege:cluster-admin" not in graph.nodes:
            graph.add_node(
                GraphNode(
                    id="k8s:privilege:cluster-admin",
                    label="Kubernetes cluster-admin",
                    provider=Provider.KUBERNETES,
                    kind=(
                        NodeKind.TARGET
                        if "k8s:privilege:cluster-admin" in targets
                        else NodeKind.PRIVILEGE
                    ),
                    subtype="cluster_admin",
                    impact=100,
                    crown_jewel="k8s:privilege:cluster-admin" in targets,
                )
            )

    def _add_aws_edges(self, graph: AttackGraph) -> None:
        identities = [
            identity
            for identity in self.environment.identities
            if identity.provider is Provider.AWS
        ]
        roles = [identity for identity in identities if identity.kind is IdentityKind.ROLE]
        resources = [
            resource for resource in self.environment.resources if resource.provider is Provider.AWS
        ]

        for principal in identities:
            for role in roles:
                if principal.id == role.id:
                    continue
                assume = self.aws.can_assume(principal, role)
                if self._allowed(assume):
                    graph.add_edge(
                        source=principal.id,
                        target=role.id,
                        kind="assume_role",
                        label=f"Assume {role.name}",
                        effort=1.5,
                        exploitability=0.92,
                        confidence=1,
                        evidence=assume.evidence,
                        techniques=("T1078",),
                    )
                self._add_pass_role_edge(graph, principal, role)
                self._add_policy_takeover_edge(graph, principal, role)

            for resource in resources:
                if resource.kind == "lambda_function":
                    self._add_lambda_edges(graph, principal, resource)
                self._add_direct_aws_access(graph, principal, resource)

        for resource in resources:
            if resource.kind == "lambda_function" and resource.execution_role in graph.nodes:
                graph.add_edge(
                    source=resource.id,
                    target=resource.execution_role or "",
                    kind="executes_as",
                    label="Function executes with role",
                    effort=0.1,
                    exploitability=1,
                    confidence=1,
                    evidence=(f"resource:{resource.id}:execution_role",),
                )

    def _add_direct_aws_access(
        self, graph: AttackGraph, principal: Identity, resource: Resource
    ) -> None:
        action: str | None = None
        kind = ""
        technique = ""
        target_resource = resource.arn or resource.id
        if resource.kind == "secret":
            service = resource.labels.get("service", "secretsmanager")
            action = "ssm:GetParameter" if service == "ssm" else "secretsmanager:GetSecretValue"
            kind, technique = "read_secret", "T1555"
        elif resource.kind == "s3_bucket":
            action = "s3:GetObject"
            target_resource = f"{target_resource.rstrip('/')}/*"
            kind, technique = "read_sensitive_object", "T1530"
        elif resource.kind == "iam_user" and resource.labels.get("admin", "false") == "true":
            action = "iam:CreateAccessKey"
            kind, technique = "create_access_key", "T1098.001"
        if action is None:
            return
        decision = self.aws.evaluate(principal.id, action, target_resource)
        if self._allowed(decision):
            graph.add_edge(
                source=principal.id,
                target=resource.id,
                kind=kind,
                label=f"{action} on {resource.name}",
                effort=1,
                exploitability=0.96,
                confidence=1,
                evidence=decision.evidence,
                techniques=(technique,),
            )

    def _add_lambda_edges(
        self, graph: AttackGraph, principal: Identity, function: Resource
    ) -> None:
        target = function.arn or function.id
        update = self.aws.evaluate(principal.id, "lambda:UpdateFunctionCode", target)
        invoke = self.aws.evaluate(principal.id, "lambda:InvokeFunction", target)
        if not self._allowed(update):
            return
        if self._allowed(invoke):
            evidence = (*update.evidence, *invoke.evidence)
            exploitability = 0.9
            effort = 2.0
            label = "Modify and invoke function code"
        elif function.auto_trigger:
            evidence = (*update.evidence, f"resource:{function.id}:auto_trigger")
            exploitability = 0.65
            effort = 3.5
            label = "Modify code and await configured trigger"
        else:
            return
        graph.add_edge(
            source=principal.id,
            target=function.id,
            kind="lambda_code_execution",
            label=label,
            effort=effort,
            exploitability=exploitability,
            confidence=0.98,
            evidence=tuple(sorted(set(evidence))),
            techniques=("T1648",),
        )

    def _add_pass_role_edge(self, graph: AttackGraph, principal: Identity, role: Identity) -> None:
        service_trust = self.aws.trusts_service(role, "lambda.amazonaws.com")
        if not self._allowed(service_trust):
            return
        role_resource = role.arn or role.id
        pass_role = self.aws.evaluate(
            principal.id,
            "iam:PassRole",
            role_resource,
            {"iam:PassedToService": "lambda.amazonaws.com"},
        )
        create = self.aws.evaluate(principal.id, "lambda:CreateFunction", "*")
        invoke = self.aws.evaluate(principal.id, "lambda:InvokeFunction", "*")
        if all(self._allowed(item) for item in (pass_role, create, invoke)):
            graph.add_edge(
                source=principal.id,
                target=role.id,
                kind="pass_role_via_lambda",
                label="Create and invoke a function with passed role",
                effort=3,
                exploitability=0.78,
                confidence=0.97,
                evidence=tuple(
                    sorted(
                        set(
                            service_trust.evidence
                            + pass_role.evidence
                            + create.evidence
                            + invoke.evidence
                        )
                    )
                ),
                techniques=("T1548",),
            )

    def _add_policy_takeover_edge(
        self, graph: AttackGraph, principal: Identity, role: Identity
    ) -> None:
        role_resource = role.arn or role.id
        modify = self.aws.evaluate(principal.id, "iam:PutRolePolicy", role_resource)
        assume = self.aws.can_assume(principal, role)
        if self._allowed(modify) and self._allowed(assume):
            graph.add_edge(
                source=principal.id,
                target=role.id,
                kind="modify_and_assume_role",
                label="Modify inline role policy and assume role",
                effort=2.5,
                exploitability=0.86,
                confidence=0.98,
                evidence=tuple(sorted(set(modify.evidence + assume.evidence))),
                techniques=("T1098",),
            )

    def _add_kubernetes_edges(self, graph: AttackGraph) -> None:
        identities = [
            identity
            for identity in self.environment.identities
            if identity.provider is Provider.KUBERNETES
        ]
        resources = [
            resource
            for resource in self.environment.resources
            if resource.provider is Provider.KUBERNETES
        ]
        targets = [resource for resource in resources if resource.id in self.environment.targets]
        for principal in identities:
            for resource in resources:
                if resource.kind == "k8s_secret":
                    self._add_kubernetes_secret_edges(graph, principal, resource)
                elif resource.kind == "pod":
                    self._add_pod_edges(graph, principal, resource)
            self._add_kubernetes_privilege_edges(graph, principal, resources)

        for target in targets:
            if target.id == "k8s:privilege:cluster-admin":
                continue
            graph.add_edge(
                source="k8s:privilege:cluster-admin",
                target=target.id,
                kind="cluster_admin_access",
                label=f"Cluster-admin access to {target.name}",
                effort=0.1,
                exploitability=1,
                confidence=1,
                evidence=("kubernetes:cluster-admin",),
            )

    def _add_kubernetes_secret_edges(
        self, graph: AttackGraph, principal: Identity, secret: Resource
    ) -> None:
        for verb in ("get", "list", "watch"):
            decision = self.kubernetes.evaluate(
                principal.id,
                verb,
                "secrets",
                namespace=secret.namespace,
                resource_name=secret.name if verb == "get" else None,
            )
            if self._allowed(decision):
                graph.add_edge(
                    source=principal.id,
                    target=secret.id,
                    kind="read_kubernetes_secret",
                    label=f"{verb} Secret {secret.name}",
                    effort=1,
                    exploitability=0.98,
                    confidence=1,
                    evidence=decision.evidence,
                    techniques=("T1552.007",),
                )
                break
        create_pod = self.kubernetes.evaluate(
            principal.id, "create", "pods", namespace=secret.namespace
        )
        if self._allowed(create_pod):
            graph.add_edge(
                source=principal.id,
                target=secret.id,
                kind="mount_secret_via_pod",
                label="Create workload that mounts namespace Secret",
                effort=2.5,
                exploitability=0.84,
                confidence=0.95,
                evidence=create_pod.evidence,
                techniques=("T1610", "T1552.007"),
            )

    def _add_pod_edges(self, graph: AttackGraph, principal: Identity, pod: Resource) -> None:
        execute = self.kubernetes.evaluate(
            principal.id,
            "create",
            "pods/exec",
            namespace=pod.namespace,
            resource_name=pod.name,
        )
        if self._allowed(execute) and pod.service_account in graph.nodes:
            graph.add_edge(
                source=principal.id,
                target=pod.service_account or "",
                kind="exec_as_service_account",
                label=f"Exec into {pod.name} and use its service account",
                effort=2,
                exploitability=0.8,
                confidence=0.9,
                evidence=execute.evidence,
                techniques=("T1609.004",),
            )

    def _add_kubernetes_privilege_edges(
        self, graph: AttackGraph, principal: Identity, resources: list[Resource]
    ) -> None:
        cluster_admin = "k8s:privilege:cluster-admin"
        bind = self.kubernetes.evaluate(
            principal.id,
            "bind",
            "clusterroles",
            api_group="rbac.authorization.k8s.io",
            resource_name="cluster-admin",
        )
        create_binding = self.kubernetes.evaluate(
            principal.id,
            "create",
            "clusterrolebindings",
            api_group="rbac.authorization.k8s.io",
        )
        impersonate = self.kubernetes.evaluate(
            principal.id,
            "impersonate",
            "groups",
            api_group="",
            resource_name="system:masters",
        )
        if self._allowed(bind) and self._allowed(create_binding):
            graph.add_edge(
                source=principal.id,
                target=cluster_admin,
                kind="bind_cluster_admin",
                label="Bind self to cluster-admin",
                effort=1.8,
                exploitability=0.94,
                confidence=1,
                evidence=tuple(sorted(set(bind.evidence + create_binding.evidence))),
                techniques=("T1098",),
            )
        if self._allowed(impersonate):
            graph.add_edge(
                source=principal.id,
                target=cluster_admin,
                kind="impersonate_system_masters",
                label="Impersonate system:masters",
                effort=1.2,
                exploitability=0.96,
                confidence=1,
                evidence=impersonate.evidence,
                techniques=("T1134",),
            )

        roles = {item.id: item for item in self.environment.kubernetes_roles}
        for binding in self.environment.kubernetes_bindings:
            if binding.kind != "ClusterRoleBinding" or principal.id not in binding.subjects:
                continue
            role = roles[binding.role_ref]
            update_role = self.kubernetes.evaluate(
                principal.id,
                "update",
                "clusterroles",
                api_group="rbac.authorization.k8s.io",
                resource_name=role.name,
            )
            escalate_role = self.kubernetes.evaluate(
                principal.id,
                "escalate",
                "clusterroles",
                api_group="rbac.authorization.k8s.io",
                resource_name=role.name,
            )
            if self._allowed(update_role) and self._allowed(escalate_role):
                graph.add_edge(
                    source=principal.id,
                    target=cluster_admin,
                    kind="escalate_bound_cluster_role",
                    label=f"Escalate bound ClusterRole {role.name}",
                    effort=2.2,
                    exploitability=0.9,
                    confidence=1,
                    evidence=tuple(sorted(set(update_role.evidence + escalate_role.evidence))),
                    techniques=("T1098",),
                )

        privileged_allowed = bool(
            self.environment.metadata.get("kubernetes_privileged_admission", False)
        )
        if privileged_allowed:
            for namespace in sorted({item.namespace for item in resources if item.namespace}):
                create_pod = self.kubernetes.evaluate(
                    principal.id, "create", "pods", namespace=namespace
                )
                if not self._allowed(create_pod):
                    continue
                for host in (item for item in resources if item.kind == "k8s_host"):
                    graph.add_edge(
                        source=principal.id,
                        target=host.id,
                        kind="privileged_pod_host_access",
                        label="Create privileged pod with host access",
                        effort=3,
                        exploitability=0.72,
                        confidence=0.75,
                        evidence=(*create_pod.evidence, "admission:privileged-pods-allowed"),
                        techniques=("T1611",),
                    )

        nodes_proxy = self.kubernetes.evaluate(principal.id, "get", "nodes/proxy")
        if self._allowed(nodes_proxy):
            for host in (item for item in resources if item.kind == "k8s_host"):
                graph.add_edge(
                    source=principal.id,
                    target=host.id,
                    kind="kubelet_proxy_access",
                    label="Reach privileged kubelet API through nodes/proxy",
                    effort=2,
                    exploitability=0.83,
                    confidence=0.95,
                    evidence=nodes_proxy.evidence,
                    techniques=("T1609",),
                )

    def _findings(self, paths: list[AttackPath], graph: AttackGraph) -> list[Finding]:
        findings: list[Finding] = []
        requirements = {
            (item.principal, item.action) for item in self.environment.business_requirements
        }
        for identity in self.environment.identities:
            statements = list(identity.policies) + list(identity.permissions_boundary)
            for statement in statements:
                if statement.effect is not Effect.ALLOW:
                    continue
                wildcard = (
                    any("*" in action for action in statement.actions) or "*" in statement.resources
                )
                sensitive_unused = [
                    action
                    for action in statement.actions
                    if action in _SENSITIVE_AWS_ACTIONS
                    and (identity.id, action) not in requirements
                ]
                if wildcard or sensitive_unused:
                    evidence = [f"statement:{statement.id}"]
                    evidence.extend(f"unused:{action}" for action in sensitive_unused)
                    findings.append(
                        _finding(
                            category="excessive_permission",
                            severity=Severity.HIGH if wildcard else Severity.MEDIUM,
                            title=f"Potentially excessive permissions on {identity.name}",
                            subject=identity.id,
                            evidence=tuple(evidence),
                            recommendation=(
                                "Narrow actions/resources and validate against recorded "
                                "business requirements."
                            ),
                        )
                    )
        for role in self.environment.kubernetes_roles:
            for rule in role.rules:
                if "*" in rule.verbs or "*" in rule.resources or "*" in rule.api_groups:
                    findings.append(
                        _finding(
                            category="rbac_wildcard",
                            severity=Severity.HIGH,
                            title=f"Wildcard Kubernetes RBAC rule in {role.name}",
                            subject=role.id,
                            evidence=(f"rule:{rule.id}",),
                            recommendation=(
                                "Replace wildcards with the smallest required verbs and resources."
                            ),
                        )
                    )
        centrality = graph.centrality()
        for node_id, value in centrality.items():
            if value >= 0.08:
                findings.append(
                    _finding(
                        category="choke_point",
                        severity=Severity.MEDIUM,
                        title=f"High-centrality identity or resource: {graph.nodes[node_id].label}",
                        subject=node_id,
                        evidence=(f"betweenness:{value:.6f}",),
                        recommendation=(
                            "Prioritize hardening and monitoring of this graph choke point."
                        ),
                    )
                )
        if paths:
            findings.append(
                _finding(
                    category="reachable_crown_jewel",
                    severity=Severity.CRITICAL,
                    title=f"{len(paths)} attack paths reach configured targets",
                    subject="environment",
                    evidence=tuple(path.id for path in paths),
                    recommendation=(
                        "Remove the highest-leverage permission shown by what-if analysis."
                    ),
                )
            )
        for reason in sorted(self.unsupported):
            findings.append(
                _finding(
                    category="unsupported_semantics",
                    severity=Severity.MEDIUM,
                    title="Policy semantics were evaluated fail-closed",
                    subject="environment",
                    evidence=(reason,),
                    recommendation=(
                        "Normalize or add tested support before relying on this permission path."
                    ),
                )
            )
        unique = {finding.id: finding for finding in findings}
        return sorted(unique.values(), key=lambda item: (item.severity.value, item.id))

    def _allowed(self, evaluation: PermissionEvaluation) -> bool:
        self.unsupported.update(evaluation.unknown_reasons)
        return evaluation.decision is PermissionDecision.ALLOW

    @staticmethod
    def _requirement_allowed(environment: Environment, requirement: BusinessRequirement) -> bool:
        principal = next(
            (item for item in environment.identities if item.id == requirement.principal), None
        )
        if principal is None:
            return False
        if principal.provider is Provider.AWS:
            resource = next(
                (item for item in environment.resources if item.id == requirement.resource), None
            )
            target = (resource.arn or resource.id) if resource else requirement.resource
            return (
                AwsEvaluator(environment)
                .evaluate(principal.id, requirement.action, target, requirement.context)
                .decision
                is PermissionDecision.ALLOW
            )
        resource_type = requirement.context.get("resource_type", requirement.resource)
        return (
            KubernetesEvaluator(environment)
            .evaluate(
                principal.id,
                requirement.action,
                resource_type,
                api_group=requirement.context.get("api_group", ""),
                namespace=requirement.context.get("namespace"),
                resource_name=requirement.context.get("resource_name"),
            )
            .decision
            is PermissionDecision.ALLOW
        )


def _finding(
    *,
    category: str,
    severity: Severity,
    title: str,
    subject: str,
    evidence: tuple[str, ...],
    recommendation: str,
) -> Finding:
    digest = hashlib.sha256("\0".join((category, subject, *sorted(evidence))).encode()).hexdigest()[
        :16
    ]
    return Finding(
        id=f"finding-{digest}",
        category=category,
        severity=severity,
        title=title,
        subject=subject,
        evidence=evidence,
        recommendation=recommendation,
    )


def _semantic_paths(report: Report) -> dict[tuple[object, ...], AttackPath]:
    edges = {edge.id: edge for edge in report.edges}
    return {
        (
            path.entrypoint,
            path.target,
            path.node_ids,
            tuple(edges[edge_id].kind for edge_id in path.edge_ids),
        ): path
        for path in report.paths
    }


def _apply_mutations(
    environment: Environment, mutations: Iterable[PermissionMutation]
) -> Environment:
    result = environment.model_copy(deep=True)
    for mutation in mutations:
        found = False
        identities = []
        for identity in result.identities:
            policies, changed = _remove_action(identity.policies, mutation)
            boundaries, boundary_changed = _remove_action(identity.permissions_boundary, mutation)
            if changed or boundary_changed:
                found = True
                identities.append(
                    identity.model_copy(
                        update={"policies": policies, "permissions_boundary": boundaries}
                    )
                )
            else:
                identities.append(identity)
        result.identities = identities

        groups = []
        for group in result.groups:
            policies, changed = _remove_action(group.policies, mutation)
            found = found or changed
            groups.append(group.model_copy(update={"policies": policies}) if changed else group)
        result.groups = groups

        scp, changed = _remove_action(tuple(result.service_control_policy), mutation)
        if changed:
            found = True
            result.service_control_policy = list(scp)

        roles = []
        for role in result.kubernetes_roles:
            rules = []
            role_changed = False
            for rule in role.rules:
                if rule.id != mutation.statement_id:
                    rules.append(rule)
                    continue
                if mutation.action not in rule.verbs:
                    raise ValueError(
                        f"action {mutation.action} is absent from rule {mutation.statement_id}"
                    )
                remaining = tuple(item for item in rule.verbs if item != mutation.action)
                if remaining:
                    rules.append(rule.model_copy(update={"verbs": remaining}))
                role_changed = True
                found = True
            roles.append(role.model_copy(update={"rules": tuple(rules)}) if role_changed else role)
        result.kubernetes_roles = roles
        if not found:
            raise ValueError(f"statement or rule not found: {mutation.statement_id}")
    return result


def _remove_action(
    statements: tuple[PolicyStatement, ...], mutation: PermissionMutation
) -> tuple[tuple[PolicyStatement, ...], bool]:
    updated: list[PolicyStatement] = []
    changed = False
    for item in statements:
        if item.id != mutation.statement_id:
            updated.append(item)
            continue
        if item.effect is Effect.DENY:
            raise ValueError("what-if removal of explicit Deny statements is not supported")
        actions = item.actions
        if mutation.action not in actions:
            raise ValueError(
                f"action {mutation.action} is absent from statement {mutation.statement_id}"
            )
        remaining = tuple(action for action in actions if action != mutation.action)
        if remaining:
            updated.append(item.model_copy(update={"actions": remaining}))
        changed = True
    return tuple(updated), changed
