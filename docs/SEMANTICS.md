# Supported permission semantics

## AWS IAM

| Construct | Status | Behavior |
|---|---|---|
| identity inline/managed policy document | supported | union of matching allows; explicit deny wins |
| group policy | supported | inherited by listed users |
| permissions boundary | supported subset | intersection; explicit deny wins |
| unresolved managed policy / boundary | fail closed | evaluation is `unknown`; no edge is emitted |
| SCP | supported subset | intersection when a complete effective statement set is supplied; explicit deny wins |
| action wildcard | supported | case-insensitive glob matching |
| resource wildcard | supported | case-sensitive glob matching |
| `StringEquals`, `StringLike` | supported | context must satisfy every configured key |
| role trust policy | supported subset | Allow/Deny, action, principal and supported conditions; explicit deny wins |
| legacy normalized trust principal | supported | principal ID/ARN or service pattern without conditions |
| resource policy | role trust only | other policies are outside v1 |
| `NotAction`, `NotResource` | fail closed | relevant evaluation becomes unknown |
| other condition operators | fail closed | relevant evaluation becomes unknown |
| session policy, RCP, cross-account | unsupported | do not rely on v1 for those decisions |

No resource-based implicit-deny exception is approximated. Environments that
depend on such semantics must be normalized into an explicit reviewed grant or
left unsupported.

The AWS snapshot importer rejects truncated `GetAccountAuthorizationDetails`
responses. An attached policy or permissions-boundary ARN whose document is
absent is retained as an unresolved reference, never treated as if the policy did
not exist. Imported role-trust conditions use the same `StringEquals` /
`StringLike` subset; another relevant operator produces `unknown`. AWS account
root principals are matched to identities in that account. The Organizations
SCP set must be supplied separately in normalized input.

## Kubernetes RBAC

| Construct | Status | Behavior |
|---|---|---|
| Role / RoleBinding | supported | permissions limited to binding namespace |
| ClusterRole / ClusterRoleBinding | supported | cluster-scoped grant |
| ClusterRole in RoleBinding | supported | rules limited to binding namespace |
| `resourceNames` | supported | named-resource match required |
| `*` verb/group/resource | supported and flagged | additive wildcard grant |
| special `bind` | compound path | requires create on the corresponding binding object |
| special `escalate` | compound path | requires update on a ClusterRole already cluster-bound to the principal |
| group `impersonate` | direct privilege path | evaluated on `groups` in the core API group |
| Secret `get/list/watch` | direct path | all three can reveal Secret data |
| workload creation | potential path | can mount namespace resources |
| aggregated ClusterRole | unsupported | no label-selector aggregation |
| admission / custom authorizer | declared metadata only | no live admission decision |

Reference validation enforces the Kubernetes API roleRef contract:
`ClusterRoleBinding` can reference only a `ClusterRole`; a `RoleBinding` can
reference a `ClusterRole` or a `Role` in the binding namespace. Invalid
normalized relationships are rejected before evaluation.
