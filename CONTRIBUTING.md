# Contributing

Every permission-semantic change needs:

1. a positive evaluation test;
2. an explicit-deny or fail-closed negative test;
3. a compound-edge test when escalation requires multiple actions;
4. a ground-truth review if public paths, edge evidence, or risk output changes;
5. an update to `docs/SEMANTICS.md` and the threat model.

Managed-policy, boundary, trust, and RBAC binding references must remain
fail-closed when incomplete or invalid. Do not flatten conditional trust or
compare what-if paths using mutable evidence-derived identifiers.

Run before submitting:

```bash
uv sync --frozen --all-extras
make lint
make test
make benchmark
sha256sum --check benchmarks/reference/inputs.sha256
docker compose config --quiet
docker build -t identity-attack-graph:test .
```

Do not add real authorization exports, credentials, or generated co-author
trailers. Keep risk claims tied to reproducible evidence and document false
positive/negative boundaries.
