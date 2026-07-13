# Threat model

## Assets and actors

Protected assets include effective-permission conclusions, crown-jewel
classification, business requirements, policy evidence, graph integrity, and
the source snapshots. The primary adversarial inputs are malicious or malformed
export files and an operator attempting to overstate what the prototype proves.

## Threats and controls

| Threat | Controls | Residual risk |
|---|---|---|
| false allow from unsupported policy | explicit semantics matrix; relevant unknown suppresses edge | an incorrectly implemented supported construct can still be wrong |
| false escalation from one permission | compound edges require every complementary grant | service-specific prerequisites may remain incomplete |
| explicit deny ignored | deny pass precedes all allow layers | only supported request context is evaluated |
| dangling reference changes graph | semantic reference validation | stale but syntactically valid snapshots are possible |
| parser/resource exhaustion | 10 MiB normalized input limit; strict schema; bounded path depth/count | API body limit and request admission need a reverse proxy |
| path explosion | simple paths, depth 8, five paths per entrypoint/target | large estates require indexed/streamed analysis |
| malicious YAML object construction | `yaml.safe_load_all`; no tags or execution | large raw YAML should be size-limited by collection pipeline |
| HTML/graph injection | browser uses `textContent`; CSP; no CDN or inline script | DOT consumers must apply their own safe-rendering policy |
| fabricated probability claim | score named prioritization heuristic; methodology and UI disclaimers | readers can still misinterpret numeric output |
| what-if hides business outage | each declared operation re-evaluated before/after | undeclared operations cannot be reported |

## Trust boundaries

- Collection credentials and cloud APIs are outside the process.
- Normalized JSON and Kubernetes YAML are untrusted inputs.
- The versioned analysis code and semantics configuration are trusted.
- The local dashboard is an unauthenticated loopback demonstrator.
- Docker isolation assumes a trusted host/runtime.

The project never deploys resources, changes IAM/RBAC, retrieves Secret values,
or sends data to a model or external service.
