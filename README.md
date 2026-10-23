<div align="center">

<!-- ══════════════════════════════════════════════════════════════════ -->
<!--  php2shell-detector — hero banner (brand: crimson / dark)           -->
<!-- ══════════════════════════════════════════════════════════════════ -->

# php2shell-detector

**Local + network detections for PHP2Shell (CVE-2026-109618 / CVE-2026-109619)**

> *One pass, three checks: host posture, access-log fingerprints, binary drift.*

Two unauthenticated RCE bug classes in the PHP core, both reachable while PHP parses
the request — before application code runs. Disclosed 2026-10-21; fixed releases
**8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**. This package answers the on-shift question
three ways and ships the network coverage beside it.

```bash
# 1) all three checks with defaults (posture auto-discovers php/php8.x + package managers +
#    apache/fpm config; drift hashes /tmp /var/tmp /dev/shm; log scan waits for --log)
python3 -m php2shell_detector

# 2) point at the SERVED runtime (not just CLI php) + webroot
python3 -m php2shell_detector --php-bin /usr/bin/php8.4 --webroot /var/www/html

# 3) scan logs: access log + php-fpm error log (repeatable --log; .gz supported)
python3 -m php2shell_detector --log /var/log/nginx/access.log --log /var/log/php8.4-fpm.log

# 4) machine-readable report
python3 -m php2shell_detector --webroot /var/www/html --php-bin php --json | jq .
```

<!-- Hero buttons -->
[![Quick Start](https://img.shields.io/badge/Quick_Start-Get_Started-e63946?style=for-the-badge&logo=terminal&logoColor=white&labelColor=0a0a0f)](https://github.com/ionsec/php2shell-detector#host-tool)
[![CISA Alert](https://img.shields.io/badge/CISA-Alert_2026--10--21-0a0a0f?style=for-the-badge&labelColor=1a1a2e)](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
[![License](https://img.shields.io/badge/License-AGPL--3.0-e63946?style=for-the-badge&labelColor=0a0a0f)](LICENSE)

---

**Developed by [IONSEC](https://github.com/ionsec)**

</div>

---

Every fingerprint, CVE fact, fixed version and threshold in this package comes from
the IONSEC research briefs (compiled 2026-10-23 from fetched primary sources —
php.net/GHSA advisories, ELLIO, F5 Labs, VulnCheck, Sophos, AWS MadPot, Wiz,
Corelight). **No fingerprint is invented.** Rules carry provenance in comments and
output: `VERBATIM` = exact documented string/shape; `DERIVED` = detection threshold
grounded in a documented observation, stated inline. Related advisory:
**CVE-2026-115560** (session upload-progress RCE on patched releases,
informational 2026-10-23).

# Host tool

## What it checks — and what a finding can actually tell you

| Check | What it does | What a finding means |
|---|---|---|
| **HOST POSTURE** | PHP runtime inventory (`php -v`, and dpkg/rpm/apk/brew package queries), SAPI exposure (mod_php / php-FPM / php-cgi / FrankenPHP/LiteSpeed markers), enabling settings (`session.upload_progress.enabled`, `session.upload_progress.cleanup`, `fatal_error_backtraces` on 8.5, `memory_limit`, `post_max_size`, `upload_max_filesize`, `max_file_uploads`), webroot `.htaccess`/`.user.ini` files, edge multipart-block presence | Exposure. Not an incident. |
| **LOG SCAN** | Access logs + PHP/php-fpm error logs against the documented PHP2Shell fingerprints: scanner UAs, marker strings (JACKALPOC, P2SMARK, boundaries…), `PHP_SESSION_UPLOAD_PROGRESS` field, `php://filter` session-file reads, hardcoded session ids, OOM body-size cluster, unusable/contradicted Content-Length, worker crashes, `Allowed memory size` fatals, `Maximum execution time exceeded`, 500 bursts, rotating-session heap-grooming cadence — plus the structural multipart amplification shapes when bodies are logged | **Attempt evidence, not execution.** All brief telemetry describes attempts; no public source reported a confirmed compromise as of 2026-10-23. |
| **DRIFT CHECK** | Stream-hash every regular file in `/tmp`, `/var/tmp`, `/dev/shm` (+ `--tmpdir`) and compare against the documented binary fingerprints (Potassium Mirai-variant loader + three additional payloads ELLIO published). Local reads only. | Loader hash on disk = **suspected compromise, trigger IR**. Presence of drop *name* `nfs` without a hash match is info-only. |

### Honest limits

- **A log hit never proves execution.** It timestamps attempts and gives
  hunting context (source IPs, URIs, cadence). Correlate with the drift check,
  worker crash records and response-side anomalies (Wiz's oversized/malformed
  `PHPSESSID` response cookie; `PWNED::` / `JACKALPOC` in response bodies) —
  the last two are not visible in access logs; WAF/CDN transaction logging
  covers them.
- **Posture is point-in-time** and covers the runtime you point it at. The
  served runtime can differ from the CLI `php` binary (verify with phpinfo() /
  the package database on the host that actually serves). Containers, panels
  (cPanel/Plesk), appliances and bundled PHP each need their own inventory; this
  tool does not enumerate them.
- **Version strings lie on backported distro builds.** RHSA-2026:87080 ships a
  patched build keeping the old `7.4.33` version string; RHEL9's patched php
  stays `8.0.30` (RHSA-2026:87151). Vendor LTS backports for EOL branches keep
  the version number, too. A version reading can false-flag AND false-clear —
  confirm via changelog:
  - Debian/Ubuntu: `zgrep CVE-2026-109618 /usr/share/doc/php8.1-common/changelog.Debian.gz`
  - RHEL/Alma/Rocky (Remi uses `php81-…` names): `rpm -q --changelog php-common | grep CVE-2026-109618`
- **EOL honesty:** PHP ≤8.1 has **no official fixed release**; advisories cover
  PHP 5.4–8.5. Source backports exist for 7.4/8.0/8.1; **nothing for ≤7.3**.
  Ubuntu ESM and other vendor-LTS ecosystems extend coverage with unchanged
  version strings. The tool reports version verdicts but cannot know the
  changelog — it says so in the finding text.
- **`fatal_error_backtraces` (PHP 8.5):** the briefs do not state its default,
  so the tool does not assume one — absent directives get an "unknown, verify
  with php -i" row instead of a guessed verdict.
- **After patching, restart every worker** (Apache, php-fpm, long-running PHP
  processes) — the patched runtime is not loaded into running processes. The
  tool cannot observe worker age; re-run posture after restarting.
- **The edge is covered by the separate rules package** — host tooling
  complements, not replaces, network/WAF coverage. IONSEC's Suricata /
  ModSecurity / Sigma rules live in `rules/` (see `README.md` in this
  directory); external managed coverage: Cloudflare (default-on 21 Oct), AWS WAF
  `PHP2Shell_BODY` (v2.3, 109619) / `PHP2Shell_BODY_Extended` (v2.4, 109618),
  Azure Front Door 99006001 (off by default — enable), Talos Snort SIDs
  67359/67360/67375, FortiGate 62657/62658, open-source Corelight
  Zeek/Suricata: github.com/corelight/php2shell-detect.
- **Deliberately NOT checked:** `AllowEncodedSlashes` or any other httpd
  directive not documented by the briefs (no speculation beyond the research).
- **php-cgi nuance:** listed "at risk" by php.net without separate published
  validation; FPM's 109618 exposure is source-analysis only (failed startup
  kills the child) — the tool's rating table reflects exactly this.

### Networked / not networked

Nothing in this tool opens a socket. Posture shells out to **local** commands
(`php -v/-i`, `dpkg-query`, `rpm`, `apk info`, `brew list`, `apachectl -M`,
`pgrep`), reads local config files; logs are read locally; the drift check
hashes local files only. The tool has no update/IOC-feed fetching feature — IOC
freshness is your intel process's job.

---

## Run

From this directory (`python3` = 3.10+):

```
python3 -m php2shell_detector
```

## CLI

| Flag | Meaning |
|---|---|
| `--webroot PATH` | webroot scan for `.htaccess`/`.user.ini` (posture) |
| `--log PATH` | log file(s); repeatable; plain or `.gz` |
| `--php-bin PATH` | PHP binary to interrogate (default probes PATH for `php`/`php8.x`) |
| `--ini PATH` | extra php.ini file to parse (repeatable) |
| `--apache-conf PATH` | explicit apache config file (default: standard dirs if present) |
| `--fpm-conf PATH` | explicit php-fpm pool/master conf (default: standard paths if present) |
| `--tmpdir PATH` | extra drift tmpdir (repeatable; replaces defaults) |
| `--check NAME` | run only this check: `posture` / `logs` / `drift` (repeatable) |
| `--log-format FMT` | `auto` (default) / `combined` / `common` / `ltsv` |
| `--max-lines N` | lines scanned per file (default 200,000) |
| `--json` | JSON report (same content as text mode) |
| `--quiet` | text mode: only warn/critical finding lines |
| `--version`, `-h` | metadata / help |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | checks ran; no warn/critical finding |
| `1` | at least one warn/critical finding — inspect the report |
| `2` | invocation/resource problem (bad flag values, missing explicit paths) |

### Reading the output

- Severities: `critical` (act now: mod_php exposure, unpatched web-serving
  runtime, loader hash on disk), `warn` (real exposure surface or attempt
  evidence), `info` (context), `ok` (verified mitigation, e.g. upload-progress
  disabled in a pool's `php_admin_flag`).
- Every finding carries `basis` (rule provenance) and, for log findings, the
  file, line and a **defanged** evidence excerpt (IPs are `[.]`-mangled).
- Per rule, up to the first 8 line hits are shown with `repeat_count` showing
  the real volume; the report list is capped at 60 entries severity-first.
  `finding_count` per file is the untruncated total. Full detail: `--json`.

## Log formats & body visibility

Per line auto-detect: **combined**, **common** (Apache/nginx) and **LTSV**.
LTSV keys used: `req|request`, `ua|user_agent`, `status`, `size`, `host`,
`time`, `cookie`, `body`, `content_length`, `request_length`,
`body_bytes_received`.

Standard access logs do **not** contain request bodies; the structural rules
therefore fire only when you log them:

- LTSV with an escaped `body:` field (`\n`, `\r`, `\t`, `\x00` escapes — nginx
  `$request_body`, escaped). Bodies are deep-scanned up to 2 MiB; anything
  bigger is judged via the size-cluster rule instead.
- Request-length fields (`request_length`, `body_bytes_received`,
  `content_length`) enable the **documented OOM body-size cluster** rule (exact
  values only: 62,929 / 8,388,608 / 9,437,183 / 12,655,437 / 15,657,436 /
  25,281,929 bytes — ELLIO/F5 clusters).
- `content_length: -` (logged-but-unusable) on a POST with a body → unusable
  Content-Length shape. When the field is simply not logged, the tool does not
  guess (no false positives from log-config differences).

PHP/php-fpm **error logs** (detected by filename or content) are scanned for
the documented server-side signatures (§10.3 of the technique brief):
`Allowed memory size … exhausted` fatals, `Maximum execution time exceeded`,
worker crash records (SIGSEGV/SIGABRT, FPM children `exited on signal`),
`PHP Startup` INI diagnostics and `Deprecated:` noise (109619 consumer
touchpoints, info), plus any documented marker string (critically, if marker
strings reach a PHP log).

## Derived thresholds (documented shapes, conservative cut-offs)

Tune in `php2shell_detector/fingerprints.py` (`BODY_THRESHOLDS`):

| Rule | Threshold | Documented observation |
|---|---|---|
| EMPTY_FILE_PART_FLOOD | ≥100 | "hundreds of empty file fields" (ELLIO) |
| FIELD_NESTING_DEEP | depth ≥12 | "field names nested dozens of levels deep" |
| PART_HEADER_FLOOD | ≥1000/part | "X: a" × 230,000–1,872,936 (ELLIO) |
| PADDING_FLOOD | ≥30,000 B single-char run | F5 62,929×'A'; ELLIO 24 MiB×'B' |
| IDENTICAL_SMALL_PARTS | ≥64 equal-length parts ≤512 B | 149 identical 288-byte parts (ELLIO/PoC) |
| NULL_FILE_PART | all-NUL value ≤4 B | 2 literal NUL bytes file parts (F5) |
| ROTATING_SESSION_CADENCE | ≥5 distinct PHPSESSID same endpoint | F5 pattern-2 cadence |
| REPEATED_5XX | ≥5 per path | documented 500-burst side effect |

## Drift fingerprints (exactly as published in the briefs)

| Label | Hashes | Size / drop path |
|---|---|---|
| Potassium Mirai-variant loader | MD5 `b61a098fc62a2c2696e196dca78da71a` · SHA1 `c472dab4ff7c16782a8037f988d4daa6d4bdb343` · SHA256 `0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486` | 179,632 B ELF x86-64 static; `/tmp/nfs`, run `./nfs php` (Sophos + ELLIO identical values) |
| DDoS booter `bot.x86_64` | SHA256 `7133612558a5d0f257ca6bdb4f765453af9465bc5298acdcf33b5761b8c59aac` | ELLIO sensor payload |
| Chinese IIS web shell `1.aspx` | SHA256 `17758cf05e3376f8448dff926564e038b763b4a46668455e2ccb5ac0839e629c` | ELLIO sensor payload |
| Go remote-access agent | SHA256 `dd98bf48899aa385035352688357742c73ddc5e47ec4ecc7d7b74c53c2e3ca3d` | ELLIO sensor payload |

Hash hits report "documented payload fingerprint … see references; no
attribution implied by this tool" — the briefs record that **no actor
attribution exists** and Potassium is a commodity botnet family; do not upgrade
that wording in your own reporting without vendor attribution.

## Tests

```
pytest -q        # from this directory
```

- Synthetic benign + exploit corpora live in `php2shell_detector/corpora.py`
  (exploit lines built ONLY from documented fingerprints, each with its basis;
  benign traffic designed to trip nothing).
- One test back-audits the zero-invented-fingerprints property: every UA string
  published in the briefs must be caught by the matcher; benign UAs (curl,
  Chrome, Firefox, python-requests) must produce nothing.
- Drift machinery tests use a synthetic fingerprint (clearly labelled "not a
  real-world IOC") because the real hashes cannot be tested against a
  fabricated binary; the shipped constants are format-checked and tested to
  match the brief values.
- Static example corpora for manual smoke runs: `examples/logs/`
  (regenerate: `python3 examples/make_examples.py`). Fixtures:
  `examples/fixture_php.sh` (clearly-labelled stub, do not deploy),
  `examples/fixture_webroot/`, `examples/fixture_apache.conf`,
  `examples/fixture_tmp/`.

## Known gaps

- No Windows SAPI inventory (php-cgi.exe/bundled php.exe) — out of scope.
- Apache config scanning does not chase `Include` recursion — pass
  `--apache-conf` for non-standard layouts.
- No container/volume traversal — run the tool inside if needed.
- Response-side checks (cookie canaries, response bodies) are out of scope for
  a log-file tool; see the network rules package for those layers.
- The tool is attempt-oriented: it does not (and cannot) verify a runtime was
  actually exploited from logs alone.

# Network / WAF rules package

## Rule coverage matrix

| Rule family | CVE path | Layer | Key published basis |
|---|---|---|---|
| Upload-progress trigger (body) | 109619 (also in 109618-labelled tooling) | WAF/IDS/body logs | PHP field name + F5 Pattern 1/2, ELLIO 743-request telemetry, Zafran lab sigs, Corelight/Talos/FortiGate coverage pattern |
| Heap-grooming cadence | 109619 | WAF/edge logs | F5 Pattern 2 (rotating 16-hex PHPSESSID + replayed trigger + x.txt) |
| OOM amplification shapes | 109618 | WAF/ModSec audit logs | GHSA-w8hw-w9fx-j79w advisory vectors (missing/untrusted Content-Length, empty file controls, deep nesting, unbounded part headers); exact ELLIO body sizes/field shapes |
| Boundary/hardcoded/canary IOCs | both | web logs/WAF/IDS/Suricata/ModSec | F5, ELLIO, VulnCheck, Sophos, Flare, KELA, Arctic Wolf published strings — copied verbatim |
| Loader-drift (file/process event) | both (delivered Potassium) | host (auditd/Sysmon-class) | ELLIO + Sophos (`/tmp/nfs`, SHA-256 0c5486f0…, `./nfs php`) |
| Disclosure canary (response) | 109618 | full-transaction logs/WAF | Wiz "unexpectedly large or malformed PHPSESSID response cookies" |
| Version inventory (response header/phpinfo) | both | Suricata response side | Corelight SIDs 3000651/52 — adapted (BSD-3) |

## Deployment notes

- **Suricata:** add `rules/suricata/ionsec-php2shell.rules` to `rule-files` in `suricata.yaml`; validate with `suricata -T`. Body-inspection depth must cover the 8 MiB+ OOM payloads. SIDs live in the documented private/local block **1000000-1999999**; our allocation **1006500-1006519** (Base 1006500-1006502 mirrors Corelight's 3000650-52 — see in-file attribution: their logic is BSD-3-Clause (c) 2026 Corelight, Inc., adapted here with the SID renumber + msg/delta documented in comments).
- **ModSecurity (CRS environments):** include `rules/modsecurity/ionsec-php2shell-dropin.conf` after your CRS include. Requires `SecRequestBodyAccess On` (CRS-recommended default). Ships detection-only (`pass,log`); blocking toggle and rationale are documented in the file header. **The OWASP CRS (3.x/4.x) has no PHP2Shell rule** (verified 2026-10-23 via php2shell.eu's vendor matrix) — this drop-in fills that gap without touching CRS rule IDs.
- **Sigma:** designed for webserver access logs, WAF/proxy logs (body-aware fields documented per rule), Linux file/process events, and response-phase transaction logs. Field-name mapping per backend (e.g., nginx `$http_cookie` → `cs-cookie`, `http.request.body.bytes` → `request_body_size`) is in each rule description. Not every field exists in vanilla NCSA combined logs — the body rules require WAF/ModSec-audit/CDN-style logging.

## Provenance & attribution

- **No invented fingerprints.** Every fingerprint string is copied exactly from a fetched vendor publication; each rule's YAML comments state the source, the fetch date (2026-10-23), and the CVE mapping. Defanged strings published by vendors (`hxxp://92.118.112[.]100/nfs-setup`) are marked with their publish form and the uncloak used for matching.
- **Adapted rules cite source + license + delta** (Corelight BSD-3-Clause; Lexsah MIT; BartoszGarba Unlicense/community; Zafran lab signatures). No community rule is copied silently.
- **No attribution claims in rule text:** vendor names appear only in comments/references, never as claims of endorsement or contribution.
- Tuning thresholds (counts ≥100/256, nesting ≥18, PHPSESSID ≥120 chars) are explicitly labelled as **tuning parameters**, not fingerprints.

## Provenance & attribution

- **No invented fingerprints.** Every fingerprint string is copied exactly from a fetched vendor publication; each rule's YAML comments state the source, the fetch date (2026-10-23), and the CVE mapping. Defanged strings published by vendors (`hxxp://92.118.112[.]100/nfs-setup`) are marked with their publish form and the uncloak used for matching.
- **Adapted rules cite source + license + delta** (Corelight BSD-3-Clause; Lexsah MIT; BartoszGarba Unlicense; Zafran lab sigs). No community rule is copied silently.
- **No attribution claims in rule text.**
- Tuning thresholds (counts ≥100/256, nesting ≥18, PHPSESSID ≥120 chars) are labelled tuning parameters, not fingerprints.

# Validation

## Validation

- **Sigma:** sigma-cli / sigtool / sigmac are **not installed** in this environment (checked 2026-10-23) — no heavy tooling was installed per build policy. All 10 YAML files validate as parseable YAML (PyYAML 6.0.3; see Validation section below for the check transcript). Rules follow the Sigma 2.x schema (standard keys; custom body fields documented in-file). For strict schema/UUID4 validation, install `sigma-cli` and run `sigma check rules/sigma/*.yml`.
- **Suricata:** no Suricata binary available in this environment — syntax was written in the Suricata 8.0.6 keyword set used by the Corelight-validated rules (`http.method`, `http.request_body`, `http.response_header`, `http.response_body`, `http.cookie`, `http.user_agent`, `threshold`), each rule was parsed/checked for balanced rule delimiters, and the Corelight-adapted rules carry logic verbatim from their 8.0.6-validated file. Run `suricata -T -c your/suricata.yaml` before enforcing in production.
- **ModSecurity:** no modsec engine available here; rules use documented v2.x-compatible syntax (chain, ARGS_POST_NAMES, MULTIPART_PART_HEADERS) consistent with CRS 4.x conventions. Load-test in a preproduction vhost before enforcing.

Host tool: run `pytest -q` from this directory (see Tests in the Host tool section above).

## References

Curated top-28 publication list (all previously fetched and verified, grouped: primary disclosure, agency advisories, cloud/WAF mitigations, sensor observations, community detection): see **[`rules/references/php2shell-sources.md`](rules/references/php2shell-sources.md)**.

Landscape snapshot (2026-10-23) for orientation — vendor SIDs live in their feeds, not in this package: ModSecurity CRS **has no PHP2Shell rule** (our documented gap); Talos Snort SIDs 67359/67360/67375 (free Community Ruleset); FortiGate IPS 62657/62658 (defs 37.317) + FortiWeb 0.00438; Corelight SIDs 3000650-52 (open source, pre-disclosure); Cloudflare 14 "Anomalous Execution" managed rules; AWS WAF `PHP2Shell_BODY` (v2.3, 109619) + `PHP2Shell_BODY_Extended` (v2.4, 109618); Azure Front Door 99006001 (disabled by default); Google Cloud Armor GLOBAL.26.015; Palo Alto Threat ID 543004; Community Sigma repos: NCSC-NL/php2shell (operational repo; no Sigma rules upstream yet), Lexsah/php2shell-detection (MIT), BartoszGarba/php2shell-sigma-rules (Unlicense).

## Open decisions

- ModSec drop-in denies nothing by default (`pass,log`); near-zero-false-positive canary rules are the candidates for early deny mode.
- Thresholds marked as tuning parameters (empty-file ≥100, nesting ≥18, part-headers ≥256, PHPSESSID ≥120/≥20).
- Private-range registry: Suricata block 1006500–1006519 and ModSec community-convention IDs 1026xxxx sit in an internal IONSEC ledger.
- sigma-cli/sigtool and Suricata engines are not installed in the build environment; lint (`sigma check rules/sigma/*.yml`) and `suricata -T` belong in a policy container before enforcing in production.
- CVE-2026-115560 kept out of rule scope; revisit exploit shape.
- Track php-src #24488 GC regression caution on 8.4.27/8.5.12 before advising exact fixed-version pins.
