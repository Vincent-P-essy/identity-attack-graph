# Supported permission semantics

## AWS IAM

| Construct | Status | Behavior |
|---|---|---|
| identity inline/managed policy document | supported | union of matching allows; explicit deny wins |
| group policy | supported | inherited by listed users |
| permissions boundary | supported subset | intersection; explicit deny wins |
| SCP | supported subset | intersection when supplied; explicit deny wins |
| action wildcard | supported | case-insensitive glob matching |
| resource wildcard | supported | case-sensitive glob matching |
| `StringEquals`, `StringLike` | supported | context must satisfy every configured key |
| role trust principal | supported subset | principal ID/ARN or service pattern |
| resource policy | role trust only | other policies are outside v1 |
| `NotAction`, `NotResource` | fail closed | relevant evaluation becomes unknown |
| other condition operators | fail closed | relevant evaluation becomes unknown |
| session policy, RCP, cross-account | unsupported | do not rely on v1 for those decisions |

No resource-based implicit-deny exception is approximated. Environments that
depend on such semantics must be normalized into an explicit reviewed grant or
left unsupported.

## Kubernetes RBAC

| Construct | Status | Behavior |
|---|---|---|
| Role / RoleBinding | supported | permissions limited to binding namespace |
| ClusterRole / ClusterRoleBinding | supported | cluster-scoped grant |
| ClusterRole in RoleBinding | supported | rules limited to binding namespace |
| `resourceNames` | supported | named-resource match required |
| `*` verb/group/resource | supported and flagged | additive wildcard grant |
| special `bind` / `impersonate` | compound paths | requires the complementary operation where applicable |
| Secret `get/list/watch` | direct path | all three can reveal Secret data |
| workload creation | potential path | can mount namespace resources |
| aggregated ClusterRole | unsupported | no label-selector aggregation |
| admission / custom authorizer | declared metadata only | no live admission decision |
