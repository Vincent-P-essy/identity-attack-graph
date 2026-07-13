# Security policy

Report vulnerabilities through GitHub private vulnerability reporting. Include
the affected commit, input fixture, expected permission decision, observed
decision, and minimal reproduction. Do not publish cloud credentials, real
policy exports, account IDs, tokens, or Secret values in an issue.

This project analyzes offline snapshots and must not be granted cloud
credentials. Run the dashboard on loopback. Treat imported authorization data
as sensitive even when it contains no secret values: it exposes defensive
structure and privilege relationships.

The committed account number, addresses, names, and credentials are synthetic.
Never replace them with production data in a public fork.
