# PHP2Shell — Curated Sources & References
**Package:** `php2shell-detector` (IONSEC) · **Compiled:** 2026-10-23 · **CVEs:** CVE-2026-109618, CVE-2026-109619 · **Total sources: 28**

Every URL below corresponds to a source fetched during the IONSEC research compilation (2026-10-23; every listed vendor page returned HTTP 200 and its text was verified — see the citation ledger and page archive in `/Users/ruji/.hermes/cache/scratch/php2shell/`). Curated, not exhaustive: the full catalogue (60+ confirmed publications) lives in the research briefs; the 28 strongest for detection/DFIR work are kept here, grouped. Dates are the publishers' own.

---

## A. Primary disclosure & advisories (the record)

| # | Publisher | Title (as published) | Date | URL |
|---|---|---|---|---|
| 1 | PHP project (php-src) | "RCE via OOM corruption" — **GHSA-w8hw-w9fx-j79w** → CVE-2026-109618 | 2026-10-21 | https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w |
| 2 | PHP project (php-src) | "RCE via stale global state" — **GHSA-6wmf-4rv5-p3rp** → CVE-2026-109619 | 2026-10-21 | https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp |
| 3 | PHP project (php.net) | 2026 news archive: pre-announcement (#2026-10-20-1), security release + advisory (#2026-10-21), informational advisory CVE-2026-115560 | 2026-10-20/21/23 | https://www.php.net/archive/2026.php |
| 4 | PHP Foundation | "Today's PHP security release and how we're strengthening PHP security" (discovery/reporting history, leak timeline) | 2026-10-21 | https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/ |
| 5 | Wiz Research | "PHP2Shell: AI uncovers critical RCE vulnerabilities affecting 70% of the Internet" | 2026-10-21 | https://www.wiz.io/blog/php2shell-php-rce |
| 6 | Calif | "php2shell: A tale of two PHP remote vulnerabilities" (LCFR research write-up) | 2026-10-21 | https://calif.io/blog/php2shell |
| 7 | Corelight (B. Reardon) | "Building 'php2shell' detections before coordinated disclosure" | 2026-10-21 | https://corelight.com/blog/php2shell-detection-before-disclosure |

## B. Government CERT / agency advisories

| # | Body | Title | Date | URL |
|---|---|---|---|---|
| 8 | CISA (US) | "Critical Vulnerabilities in PHP Require Immediate Patching" | 2026-10-21 | https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching |
| 9 | NSA (US) | "NSA Advisory: Critical Patches Recommended for PHP Vulnerabilities" | 2026-10-21 | https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4630238/nsa-advisory-critical-patches-recommended-for-php-vulnerabilities/ |
| 10 | CERT-EU | SA 2026-018 (v1.0–v1.2) | 2026-10-20 → 23 | https://cert.europa.eu/publications/security-advisories/2026-018/ |
| 11 | NCSC (UK) | "Critical security issue affecting PHP" | 2026-10-21 | https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php |

## C. Cloud / WAF / network-layer mitigations (managed-rule landscape our rules complement)

| # | Publisher | Title | Date | URL |
|---|---|---|---|---|
| 12 | Cloudflare | "Cloudflare deploys protections against php2shell vulnerability" (14 'Anomalous Execution' rules, request+response, default-on 03:02 UTC 21 Oct; 23 Oct CVE-2026-115560 update) | 2026-10-21 (upd 23) | https://blog.cloudflare.com/php-vulnerabilities-waf-protection/ |
| 13 | AWS (C.J. Moses) | "Amazon Threat Intelligence identifies PHP2Shell exploitation prior to public disclosure in MadPot" (17 Oct pre-disclosure attempt; IOC table) | 2026-10-21 | https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/ |
| 14 | AWS | "Using AWS WAF to apply mitigations for PHP2Shell RCE vulnerabilities…" (PHP2Shell_BODY v2.3 → PHP2Shell_BODY_Extended v2.4; coverage matrix + WAF-reach limits) | 2026-10-22/23 | https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/ |
| 15 | Microsoft | "Addressing PHP2Shell (CVE-2026-109618 and CVE-2026-109619): upgrade guidance and Azure WAF mitigations" (FD/AEG rule 99006001 — disabled by default) | 2026-10-22 | https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/addressing-php2shell-cve-2026-109618-and-cve-2026-109619-upgrade-guidance-and-az/4566623 |
| 16 | Google Cloud | "Responding to core PHP vulnerabilities CVE-2026-109618 and CVE-2026-109619" (Cloud Armor managed rules; SecOps hunt id GLOBAL.26.015) | 2026-10-21 (upd 22) | https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619 |
| 17 | Akamai | "Understanding PHP2Shell: Everything You Need to Know" | 2026-10-22 | https://www.akamai.com/blog/security-research/understanding-php2shell-everything-you-need-to-know |
| 18 | Fortinet FortiGuard Labs | Threat Signal report #6551 — PHP2Shell RCE (FortiGate IPS SIDs 62657/62658, defs 37.317; FortiWeb signatures 0.00438) | 2026-10-22/23 | https://www.fortiguard.com/threat-signal-report/6551/php2shell-remote-code-execution-vulnerabilities |

## D. Sensor / telemetry observations (fingerprint provenance for our rules)

| # | Publisher | Title | Date | URL |
|---|---|---|---|---|
| 19 | ELLIO | "PHP2Shell: what we observed and what to do" (deception-network timeline 08:36 UTC 21 Oct; payload internals; Potassium loader IOCs; published indicator list used verbatim in our rules) | 2026-10-21 (upd 22) | https://ellio.tech/en/blog/php2shell-what-we-observed-and-what-to-do/ |
| 20 | F5 Labs | "PHP2Shell exploitation attempts observed" (Patterns 1–3 verbatim request shapes; ~100-entry UA appendix) | 2026-10-22 | https://www.f5.com/labs/articles/php2shell-exploitation-attempts-observed |
| 21 | VulnCheck | "PHP2Shell Vulnerabilities: Analysis, Exploit Availability, and Mitigation Guidance" (Canary IOC table incl. boundary `------p2s9rdme2st6guc9g0rafic`, PHPSESSID `xqsuvwz3n97wu8j3emz1axuo5y`, planted webshell `PWNED::` payload, uploaded-part SHA-256s) | 2026-10-21 (upd 22) | https://www.vulncheck.com/blog/php2shell-vulnerabilities |
| 22 | watchTowr | Rapid Reaction: "PHP Remote Code Execution — php2shell" (+ FAQ; leak confirmation; Attacker Eye exploitation of both CVEs) | 2026-10-20/21 | https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/ |
| 23 | Datadog Security Labs | "PHP2Shell — critical vulnerabilities in PHP" (independent repro: `_zend_hash_str_add_or_update_i` OOM window, 8.5.11 ARM64 mod_php, 3-stage chain) | 2026-10-21 (upd 22) | https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/ |

## E. Community detection (adaptation sources; license recorded per item)

| # | Publisher | Title | Date | URL | License |
|---|---|---|---|---|---|
| 24 | NCSC-NL (NL gov) | php2shell operational repository (status tracker, mitigation/detection material) | 2026-10-21 (upd 23) | https://github.com/NCSC-NL/php2shell | (repo per-file; see LICENSE) |
| 25 | Corelight | php2shell-detect — Zeek package + Suricata SIDs 3000650-52 (built pre-disclosure) | 2026-10-21 | https://github.com/corelight/php2shell-detect | BSD 3-Clause (fetched 2026-10-23) |
| 26 | Lexsah | php2shell-detection (Sigma/Suricata/YARA/ModSecurity/Falco) | 2026-10-21+ | https://github.com/Lexsah/php2shell-detection | MIT (Copyright (c) 2026 Lexsah and contributors) |
| 27 | BartoszGarba | php2shell-sigma-rules (post-exploitation process Sigma, win+linux) | 2026-10-21+ | https://github.com/BartoszGarba/php2shell-sigma-rules | Unlicense / public domain |
| 28 | php2shell.eu | Vendor-by-vendor detection matrix (source of the verified "CRS has no PHP2Shell rule" gap statement; community ModSecurity example id:1026109618 convention) | 2026-10-21+ (checked 23 Oct) | https://php2shell.eu/ | (site content; no claim made) |

---

## Provenance discipline

- **Fingerprints:** every fingerprint string used in `rules/sigma/`, `rules/suricata/`, `rules/modsecurity/` is copied exactly from one of the fetched sources above (grouped: D for sensor shapes, C+D for rule-landscape names, E for adapted community logic). Defanged strings (`hxxp://92.118.112[.]100`) used in detection are marked with their publish form + the uncloaking note in the rule comments.
- **No invented fingerprints.** Tuning thresholds (empty-file counts, nesting depth ≥18, part-header count ≥256, PHPSESSID cookie ≥120 chars) are labelled as tuning parameters in the rule comments and in the open-decisions notes.
- **Adaptations** are attributed per-rule (source + license + delta). Corelight-adapted Suricata SIDs are renumbered out of their space into the IONSEC private block (1006500-1006502 ↔ 3000650-52, documented in-file).
- **Attribution hygiene:** no vendor is claimed to endorse or have contributed to these rules. The upstream landscape (Talos 67359/60/75 Community Ruleset, FortiGate 62657/62658, FortiWeb 0.00438, Cloudflare managed rules #1-14, AWS v2.3/v2.4, Azure 99006001, GCP GLOBAL.26.015, Palo Alto Threat ID 543004, CrowdSec vpatch, Check Point CPAI-2026-15172, Sophos 231318x/213184x) is documented in the research briefs for situational awareness, but those vendors' SIDs are not reproduced here.