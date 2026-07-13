# Architecture

## Analysis contract

The input contract separates collection from reasoning. `Environment 1.0`
contains identities, policy statements, roles, bindings, resources,
entrypoints, crown-jewel targets, and optional business requirements. Importers
produce this contract but never select entrypoints or targets automatically.

## Pipeline

1. Pydantic rejects unknown fields, invalid scope, duplicate identifiers, and
   malformed action/resource patterns.
2. Reference validation checks groups, execution roles, service accounts,
   bindings, entrypoints, targets, and business requirements.
3. Provider evaluators calculate effective permission decisions. AWS can return
   allow, explicit deny, implicit deny, or unknown; Kubernetes returns additive
   allow/implicit deny.
4. The capability builder asks narrowly scoped questions about known resources
   and emits only complete primitives. Every edge contains evidence IDs.
5. A directed multigraph enumerates bounded simple paths ordered by cumulative
   effort. Exploitability and confidence multiply along each path.
6. Findings and exact directed betweenness centrality identify wildcards,
   potentially unused high-risk grants, and graph choke points.
7. JSON, CSV, Markdown, DOT, API, and dashboard views serialize the same report.

## Edge examples

```text
developer
  --[UpdateFunctionCode + InvokeFunction]--> payroll Lambda
  --[configured execution role]-----------> runtime role
  --[GetSecretValue]----------------------> admin token
```

```text
Kubernetes user
  --[create pods in payroll]--------------> namespace Secret
```

The second edge represents the documented ability of a workload creator to
mount namespace resources. Confidence is lower than a direct Secret `get`
grant, and the evidence states exactly which binding allowed pod creation.

## What-if transaction

Permission removals operate on policy statement or RBAC rule IDs. The simulator:

1. deep-copies the validated source environment;
2. removes exactly one named action/verb from each requested allow;
3. drops a statement/rule if it becomes empty;
4. rebuilds permission evaluators, compound edges, and all paths;
5. compares stable path IDs;
6. re-evaluates declared business operations against both environments.

Explicit deny removal is rejected because weakening a guardrail is a different
risk operation. Permission addition is intentionally absent from v1.

## Determinism

Node, edge, finding, and path IDs are SHA-256-derived from semantic fields and
evidence, then truncated for display. Input iteration is sorted before output.
The benchmark removes only measured elapsed time before hashing the complete
report; 100 reviewed executions produced one hash.

## Deployment

The image is built from a locked environment and runs as UID/GID 10001 with a
read-only root filesystem, all Linux capabilities dropped, no-new-privileges,
bounded memory/PIDs/CPU, and a small noexec `/tmp`. Analysis reads only the
committed fixture by default and persists nothing.
