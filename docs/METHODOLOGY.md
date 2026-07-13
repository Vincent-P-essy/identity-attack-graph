# Experimental methodology

## Ground truth

The synthetic banking-platform fixture contains three entrypoints and five
targets across AWS and Kubernetes. Seven semantic paths were reviewed manually
before benchmarking, together with fourteen graph edges. Ground truth stores
each path's entrypoint, target, complete node sequence, ordered edge kinds, and
expected risk. Each graph edge binds source, target, kind, and exact evidence
IDs. The expected risk summary is versioned alongside them.

Recall and precision are:

```text
recall    = reviewed paths emitted / reviewed paths
precision = reviewed paths emitted / all emitted paths
```

The same calculation is applied to evidence-bound edges. The quality gate also
requires matched path risks and all risk-summary fields to agree within 0.001.
False-positive and false-negative paths and edges are serialized explicitly.

These metrics describe one curated fixture. They are neither population
estimates nor evidence that unknown production paths are absent.

## Determinism

Each benchmark iteration loads the same input, creates new evaluators and graph,
and serializes the full report. `elapsed_ms` is removed because it is measured,
then canonical JSON is SHA-256 hashed. A run is deterministic only if every hash
is identical.

## Latency

Wall-clock latency surrounds the complete in-process call to `Analyzer.analyze`.
It includes permission evaluation, graph edges, path search, centrality,
findings, and scoring. It excludes file loading, cloud export, HTTP, browser
rendering, and what-if analysis. p50/p95 use linear interpolation over sorted
measurements and are never CI performance thresholds.

## Risk heuristic

Path risk is target impact multiplied by every edge's exploitability and
confidence. Aggregate score is:

```text
max_path + (100 - max_path) × (1 - exp(-sum(other_paths) / 500))
```

This monotonic saturation keeps the dominant path visible while alternatives
increase priority with diminishing influence. Constants are reviewed fixture
choices, not fitted probabilities.

## Reproduction

```bash
uv sync --frozen --all-extras
make lint
make test
make benchmark
sha256sum --check benchmarks/reference/inputs.sha256
```

The reference snapshot records Python, kernel/platform, fixture hashes,
iterations, deterministic report hash, and latency percentiles. It also records
a SHA-256 digest over the analyzed Python sources, the exact `uv.lock` digest,
package version, source revision/tree-state labels supplied by the runner, and
the Python/platform runner identity. The committed input checksum file binds the
environment, ground truth, and dependency lock.
