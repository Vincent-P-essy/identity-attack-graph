from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from .models import (
    Effect,
    Environment,
    Identity,
    KubernetesRule,
    PermissionDecision,
    PermissionEvaluation,
    PolicyStatement,
    Provider,
    TrustStatement,
)


def _action_matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def _resource_matches(pattern: str, resource: str) -> bool:
    return fnmatch.fnmatchcase(resource, pattern)


@dataclass(frozen=True, slots=True)
class StatementMatch:
    applies: bool
    unknown: str | None = None


class AwsEvaluator:
    """Conservative single-account identity-policy evaluator for the supported subset."""

    def __init__(self, environment: Environment) -> None:
        self.environment = environment
        self.identities = {item.id: item for item in environment.identities}
        self.groups = {item.id: item for item in environment.groups}

    def evaluate(
        self,
        principal_id: str,
        action: str,
        resource: str,
        context: dict[str, str] | None = None,
    ) -> PermissionEvaluation:
        principal = self.identities.get(principal_id)
        if principal is None or principal.provider is not Provider.AWS:
            return PermissionEvaluation(
                decision=PermissionDecision.IMPLICIT_DENY,
                action=action,
                resource=resource,
                evidence=(),
                unknown_reasons=("principal is not an AWS identity",),
            )
        request_context = context or {}
        identity_statements = list(principal.policies)
        unresolved = list(principal.unresolved_policy_references)
        if principal.unresolved_boundary_reference:
            unresolved.append(principal.unresolved_boundary_reference)
        for group_id in principal.groups:
            group = self.groups.get(group_id)
            if group is not None:
                identity_statements.extend(group.policies)
                unresolved.extend(group.unresolved_policy_references)

        layers = [
            ("identity", identity_statements, False),
            ("boundary", list(principal.permissions_boundary), True),
            ("scp", list(self.environment.service_control_policy), True),
        ]
        evidence: list[str] = []
        unknown = [f"unresolved policy reference: {item}" for item in unresolved]

        for layer_name, statements, _intersection in layers:
            for statement in statements:
                matched = self._statement_matches(statement, action, resource, request_context)
                if matched.unknown:
                    unknown.append(f"{statement.id}: {matched.unknown}")
                if matched.applies and statement.effect is Effect.DENY:
                    return PermissionEvaluation(
                        decision=PermissionDecision.EXPLICIT_DENY,
                        action=action,
                        resource=resource,
                        evidence=(f"{layer_name}:{statement.id}:Deny",),
                        unknown_reasons=tuple(sorted(set(unknown))),
                    )

        identity_allows = self._allows(
            identity_statements, action, resource, request_context, evidence, unknown, "identity"
        )
        if not identity_allows:
            decision = PermissionDecision.UNKNOWN if unknown else PermissionDecision.IMPLICIT_DENY
            return PermissionEvaluation(
                decision=decision,
                action=action,
                resource=resource,
                evidence=tuple(evidence),
                unknown_reasons=tuple(sorted(set(unknown))),
            )

        for layer_name, statements, intersection in layers[1:]:
            if (
                intersection
                and statements
                and not self._allows(
                    statements,
                    action,
                    resource,
                    request_context,
                    evidence,
                    unknown,
                    layer_name,
                )
            ):
                decision = (
                    PermissionDecision.UNKNOWN if unknown else PermissionDecision.IMPLICIT_DENY
                )
                return PermissionEvaluation(
                    decision=decision,
                    action=action,
                    resource=resource,
                    evidence=tuple(evidence),
                    unknown_reasons=tuple(sorted(set(unknown))),
                )
        if unknown:
            return PermissionEvaluation(
                decision=PermissionDecision.UNKNOWN,
                action=action,
                resource=resource,
                evidence=tuple(evidence),
                unknown_reasons=tuple(sorted(set(unknown))),
            )
        return PermissionEvaluation(
            decision=PermissionDecision.ALLOW,
            action=action,
            resource=resource,
            evidence=tuple(evidence),
        )

    def can_assume(
        self, principal: Identity, role: Identity, context: dict[str, str] | None = None
    ) -> PermissionEvaluation:
        target = role.arn or role.id
        permission = self.evaluate(principal.id, "sts:AssumeRole", target, context)
        if permission.decision is not PermissionDecision.ALLOW:
            return permission
        trust_context = dict(context or {})
        if principal.arn:
            trust_context.setdefault("aws:PrincipalArn", principal.arn)
            account_id = _arn_account(principal.arn)
            if account_id:
                trust_context.setdefault("aws:PrincipalAccount", account_id)
        trust = self._evaluate_trust(
            role,
            "sts:AssumeRole",
            (principal.id, principal.arn or ""),
            trust_context,
        )
        if trust.decision is not PermissionDecision.ALLOW:
            return trust.model_copy(update={"evidence": (*permission.evidence, *trust.evidence)})
        return PermissionEvaluation(
            decision=PermissionDecision.ALLOW,
            action="sts:AssumeRole",
            resource=target,
            evidence=(*permission.evidence, *trust.evidence),
        )

    def trusts_service(
        self, role: Identity, service: str, context: dict[str, str] | None = None
    ) -> PermissionEvaluation:
        return self._evaluate_trust(
            role,
            "sts:AssumeRole",
            (service,),
            dict(context or {}),
        )

    def _evaluate_trust(
        self,
        role: Identity,
        action: str,
        candidates: tuple[str, ...],
        context: dict[str, str],
    ) -> PermissionEvaluation:
        target = role.arn or role.id
        if not role.trust_policy:
            trusted = any(
                candidate
                and any(
                    fnmatch.fnmatchcase(candidate, pattern) for pattern in role.trust_principals
                )
                for candidate in candidates
            )
            decision = (
                PermissionDecision.UNKNOWN
                if role.unresolved_trust_semantics
                else (PermissionDecision.ALLOW if trusted else PermissionDecision.IMPLICIT_DENY)
            )
            return PermissionEvaluation(
                decision=decision,
                action=action,
                resource=target,
                evidence=(f"trust:{role.id}",) if trusted else (),
                unknown_reasons=tuple(sorted(set(role.unresolved_trust_semantics))),
            )

        unknown = list(role.unresolved_trust_semantics)
        allows: list[str] = []
        for statement in role.trust_policy:
            matched = self._trust_statement_matches(statement, action, candidates, context)
            if matched.unknown:
                unknown.append(f"{statement.id}: {matched.unknown}")
            if not matched.applies:
                continue
            evidence = f"trust:{statement.id}:{statement.effect.value}"
            if statement.effect is Effect.DENY:
                return PermissionEvaluation(
                    decision=PermissionDecision.EXPLICIT_DENY,
                    action=action,
                    resource=target,
                    evidence=(evidence,),
                    unknown_reasons=tuple(sorted(set(unknown))),
                )
            allows.append(evidence)
        if unknown:
            decision = PermissionDecision.UNKNOWN
        elif allows:
            decision = PermissionDecision.ALLOW
        else:
            decision = PermissionDecision.IMPLICIT_DENY
        return PermissionEvaluation(
            decision=decision,
            action=action,
            resource=target,
            evidence=tuple(allows),
            unknown_reasons=tuple(sorted(set(unknown))),
        )

    def _trust_statement_matches(
        self,
        statement: TrustStatement,
        action: str,
        candidates: tuple[str, ...],
        context: dict[str, str],
    ) -> StatementMatch:
        if not any(_action_matches(pattern, action) for pattern in statement.actions):
            return StatementMatch(False)
        if not any(
            _trust_principal_matches(pattern, candidate)
            for pattern in statement.principals
            for candidate in candidates
            if candidate
        ):
            return StatementMatch(False)
        return _conditions_match(statement.conditions, context)

    def _allows(
        self,
        statements: list[PolicyStatement],
        action: str,
        resource: str,
        context: dict[str, str],
        evidence: list[str],
        unknown: list[str],
        layer: str,
    ) -> bool:
        allowed = False
        for statement in statements:
            matched = self._statement_matches(statement, action, resource, context)
            if matched.unknown:
                unknown.append(f"{statement.id}: {matched.unknown}")
            if matched.applies and statement.effect is Effect.ALLOW:
                allowed = True
                evidence.append(f"{layer}:{statement.id}:Allow")
        return allowed

    def _statement_matches(
        self,
        statement: PolicyStatement,
        action: str,
        resource: str,
        context: dict[str, str],
    ) -> StatementMatch:
        if statement.not_actions or statement.not_resources:
            return StatementMatch(False, "NotAction/NotResource is outside the supported subset")
        if not any(_action_matches(pattern, action) for pattern in statement.actions):
            return StatementMatch(False)
        if not any(_resource_matches(pattern, resource) for pattern in statement.resources):
            return StatementMatch(False)
        return _conditions_match(statement.conditions, context)


@dataclass(frozen=True, slots=True)
class EffectiveKubernetesRule:
    rule: KubernetesRule
    binding_id: str
    role_id: str
    namespace: str | None


class KubernetesEvaluator:
    def __init__(self, environment: Environment) -> None:
        self.environment = environment
        self.roles = {item.id: item for item in environment.kubernetes_roles}
        self.rules: dict[str, list[EffectiveKubernetesRule]] = {}
        for binding in environment.kubernetes_bindings:
            role = self.roles.get(binding.role_ref)
            if role is None:
                continue
            namespace = binding.namespace if binding.kind == "RoleBinding" else None
            for subject in binding.subjects:
                self.rules.setdefault(subject, []).extend(
                    EffectiveKubernetesRule(rule, binding.id, role.id, namespace)
                    for rule in role.rules
                )

    def evaluate(
        self,
        principal_id: str,
        verb: str,
        resource: str,
        *,
        api_group: str = "",
        namespace: str | None = None,
        resource_name: str | None = None,
    ) -> PermissionEvaluation:
        evidence: list[str] = []
        for grant in self.rules.get(principal_id, []):
            if grant.namespace is not None and grant.namespace != namespace:
                continue
            rule = grant.rule
            if not _k8s_matches(rule.verbs, verb):
                continue
            if not _k8s_matches(rule.api_groups, api_group):
                continue
            if not _k8s_matches(rule.resources, resource):
                continue
            if rule.resource_names and (
                resource_name is None or resource_name not in rule.resource_names
            ):
                continue
            evidence.append(f"binding:{grant.binding_id}/role:{grant.role_id}/rule:{rule.id}")
        decision = PermissionDecision.ALLOW if evidence else PermissionDecision.IMPLICIT_DENY
        return PermissionEvaluation(
            decision=decision,
            action=f"{verb}:{api_group}:{resource}",
            resource=f"{namespace or '*'}:{resource_name or '*'}",
            evidence=tuple(evidence),
        )


def _k8s_matches(patterns: tuple[str, ...], value: str) -> bool:
    return "*" in patterns or value in patterns


def _conditions_match(
    conditions: dict[str, dict[str, str | list[str]]], context: dict[str, str]
) -> StatementMatch:
    for operator, entries in conditions.items():
        if operator not in {"StringEquals", "StringLike"}:
            return StatementMatch(False, f"condition operator {operator} is unsupported")
        for key, expected_raw in entries.items():
            actual = context.get(key)
            expected = [expected_raw] if isinstance(expected_raw, str) else expected_raw
            if actual is None:
                return StatementMatch(False)
            if operator == "StringEquals" and actual not in expected:
                return StatementMatch(False)
            if operator == "StringLike" and not any(
                fnmatch.fnmatchcase(actual, pattern) for pattern in expected
            ):
                return StatementMatch(False)
    return StatementMatch(True)


def _arn_account(value: str) -> str:
    parts = value.split(":", 5)
    return parts[4] if len(parts) == 6 and parts[0] == "arn" else ""


def _trust_principal_matches(pattern: str, candidate: str) -> bool:
    if pattern == "*" or pattern == candidate:
        return True
    if pattern.endswith(":root"):
        return bool(_arn_account(pattern)) and _arn_account(pattern) == _arn_account(candidate)
    return False
