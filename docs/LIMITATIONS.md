# Limitations

- The AWS evaluator is intentionally smaller than AWS enforcement. Cross-account
  flows, session policies, RCPs, most resource policies, service-specific
  conditions, and many policy-language constructs require more context.
- Unknown semantics are fail-closed, which prevents false allows but can produce
  false negatives.
- Trust-policy conditions are limited to `StringEquals` and `StringLike` plus
  automatically supplied principal ARN/account context. External IDs must be
  supplied explicitly; other relevant operators fail closed.
- The AWS importer does not collect Organizations SCPs. A complete effective SCP
  statement set must be supplied in the normalized environment when applicable.
- Kubernetes workload creation edges model documented potential. The engine
  cannot know whether an admission webhook, Pod Security Admission, image policy,
  quota, or runtime control blocks the concrete exploit.
- Only JSON normalized environments and selected AWS/Kubernetes export shapes
  are accepted. Azure, GCP, identity providers, CI platforms, and SaaS roles are
  future adapters.
- Path enumeration is bounded to eight edges and five paths per entrypoint/target.
  A larger graph needs scalable k-shortest-path algorithms and persistence.
- Centrality is exact unweighted directed betweenness; it ignores edge effort.
- Excessive-permission findings compare grants to manually declared operations,
  not CloudTrail or Kubernetes audit-log usage.
- What-if v1 removes uniquely identified Allow actions/verbs only. It does not
  add permissions, rewrite trust policies, or model propagation delay. New paths
  can appear when bounded top-k enumeration exposes a previously hidden
  alternative; this does not mean permission removal granted a capability.
- The dashboard/API are local demonstrations without authentication, TLS,
  multi-tenancy, rate limits, or durable report storage.
