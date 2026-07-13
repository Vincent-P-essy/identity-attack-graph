# Reviewed reference run

This snapshot preserves a measured analysis of the synthetic lab and binds the
result to the analyzed package source, dependency lock, and runner. It was
generated before commit from the dirty working tree based on the revision below;
CI regenerates the same functional checks from a clean checkout.

- Date: 2026-07-13
- Python: 3.12.13
- Platform: Linux 5.15.0-185-generic x86_64, glibc 2.35
- Iterations: 100 fresh analyzers
- Expected/actual semantic paths: 7/7
- Expected/actual evidence-bound edges: 14/14
- False-positive/false-negative paths and edges: 0/0
- Reviewed path risks and aggregate risk: all match within 0.001
- Deterministic report SHA-256:
  `0ceb66541579ae73769b58cb57c467a0f63df5e0c5767f643b540ad5c749b2be`
- Package source SHA-256:
  `a5ab973793a0507204c6a98571a53281e12bc3eab49dec763ca211457ed32051`
- Dependency lock SHA-256:
  `440cfd0d81352bdb979fde8679fcd924fae418a0e698e661453a7d90d0081648`
- Base source revision:
  `949b2c752d45b97956e55ff355e32ca1a295de50`
- Source-tree state: `dirty-working-tree`

The environment, ground-truth, and dependency-lock hashes are pinned in
`inputs.sha256`. The benchmark JSON records the package source hash and runner.
Functional path results should reproduce; timing is machine-specific and is not
a CI performance gate.
