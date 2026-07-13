# Contributing

Every permission-semantic change needs:

1. a positive evaluation test;
2. an explicit-deny or fail-closed negative test;
3. a compound-edge test when escalation requires multiple actions;
4. a ground-truth review if public path output changes;
5. an update to `docs/SEMANTICS.md` and the threat model.

Run before submitting:

```bash
uv sync --frozen --all-extras
make lint
make test
make benchmark
docker compose config --quiet
docker build -t identity-attack-graph:test .
```

Do not add real authorization exports, credentials, or generated co-author
trailers. Keep risk claims tied to reproducible evidence and document false
positive/negative boundaries.
