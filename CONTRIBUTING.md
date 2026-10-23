# Contributing

Small, factual patches: fingerprint additions that cite a fetched, dated
source; threshold tuning with its documented observation; backend field
mappings for Sigma.

- Rules: fingerprints must be copied exactly as published — zero invented
  strings; every rule keeps its source + date + CVE mapping in comments.
- Tests: every new fingerprint or threshold gets a corpus line and a test;
  `pytest -q` must stay green.
- Commits: factual, technical subjects. No marketing.

IONSEC internal contributions: branch from `main`, keep the subject line
plain, and explain the provenance in the body when adding fingerprints.
