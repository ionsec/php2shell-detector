"""php2shell-detector — local host/posture, log-scan and drift checks for the
PHP2Shell vulnerabilities (CVE-2026-109618, CVE-2026-109619).

Every fingerprint, CVE fact and version constant in this package is copied from
the IONSEC research briefs (compiled 2026-10-23 from fetched primary sources):

  ~/.hermes/cache/scratch/php2shell/research/technique.md
  ~/.hermes/cache/scratch/php2shell/research/tracker.md

No fingerprint, IOC or config flag is invented by this tool.
"""

__version__ = "0.1.0"
TOOL_NAME = "php2shell-detector"