# Security policy

Report vulnerabilities through GitHub private vulnerability reporting. Include
the affected commit, input fixture, expected permission decision, observed
decision, and minimal reproduction. Do not publish cloud credentials, real
policy exports, account IDs, tokens, or Secret values in an issue.

This project analyzes offline snapshots and must not be granted cloud
credentials. Run the dashboard on loopback. Treat imported authorization data
as sensitive even when it contains no secret values: it exposes defensive
structure and privilege relationships.

Input JSON is size-limited and rejects duplicate keys and non-finite numbers;
Kubernetes YAML uses the safe loader. Missing authorization documents and
unsupported semantics fail closed. These controls reduce parser and
over-granting risk but do not make the unauthenticated local API suitable for
direct Internet exposure.

The committed account number, addresses, names, and credentials are synthetic.
Never replace them with production data in a public fork.
