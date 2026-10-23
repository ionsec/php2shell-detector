"""Static, documented fingerprints and CVE facts for PHP2Shell.

CVE-2026-109618 ("RCE via OOM corruption", GHSA-w8hw-w9fx-j79w) and
CVE-2026-109619 ("RCE via stale global state", GHSA-6wmf-4rv5-p3rp).

Everything in this module is copied verbatim from the two research briefs:

  technique.md  (technical brief; [S#] tags resolve to its section-12 source table)
  tracker.md    (timeline / in-the-wild tracker; sources listed inline)

Source tags in comments refer to those two documents. Anything marked DERIVED
is a detection *threshold* or *heuristic* grounded in a documented observation,
not a fabricated IOC; its basis is stated on the spot.
"""

import re

# ---------------------------------------------------------------------------
# CVE / version facts (technique.md section 3, php.net + GHSA)
# ---------------------------------------------------------------------------

# Fixed releases 2026-10-21 (~14:00-14:07 UTC). [S5, S7, S16]
FIXED_VERSIONS = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
# Branches that have NO official fixed release [S24, S10, S16]: <= 8.1.
# Source backports exist for 7.4 / 8.0 / 8.1 [S12, S5]; nothing for <= 7.3 [S17].
# Vendor backports keep the old version string (e.g. "8.1.34", RHEL "7.4.33"
# module build) -> version-string scanners false-flag / false-clear. [S24, S28, S30]
EOL_LAST_SUPPORTED = (8, 1)
BACKPORTABLE_BRANCHES = {(7, 4), (8, 0), (8, 1)}
# Advisory coverage: "every unpatched PHP since 5.4" [S24, S8, S29, S30].
AFFECTED_SINCE = (5, 4)

# ---------------------------------------------------------------------------
# Binary fingerprints — drift check (tracker.md section 4.4; technique.md 10.1)
# All values published identically by Sophos and ELLIO IOC tables.
# Never claim attribution in output: this is a commodity Mirai-variant loader
# fingerprint; research briefs: no actor attribution exists (tracker.md section 7).
# ---------------------------------------------------------------------------

POTASSIUM_LOADER = {
    "label": "Mirai-variant loader fingerprint ('Potassium' PHP2Shell-delivered sample)",
    "md5": "b61a098fc62a2c2696e196dca78da71a",
    "sha1": "c472dab4ff7c16782a8037f988d4daa6d4bdb343",
    "sha256": "0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486",
    "size_bytes": 179632,  # ELF x86-64, statically linked (ELLIO)
    "drop_paths": ["/tmp/nfs"],  # documented drop path, run as "./nfs php" [Sophos]
    "source": "tracker.md 4.4 / technique.md 10.1 (Sophos + ELLIO, fetched 2026-10-23)",
}

# Additional payload hashes ELLIO published from its own sensors (tracker.md 4.4).
# Neutral labels only ("documented payload fingerprint"); the IIS-webshell and
# Go-agent files are unrelated operators' payload, not the PHP2Shell bot per se.
ELLIIO_EXTRA_PAYLOADS = [
    {
        "label": "documented DDoS-booter payload fingerprint",
        "sha256": "7133612558a5d0f257ca6bdb4f765453af9465bc5298acdcf33b5761b8c59aac",
        "size_bytes": None,
        "drop_paths": ["bot.x86_64"],
        "source": "tracker.md 4.4 (ELLIO IOC table)",
    },
    {
        "label": "documented IIS web-shell payload fingerprint",
        "sha256": "17758cf05e3376f8448dff926564e038b763b4a46668455e2ccb5ac0839e629c",
        "size_bytes": None,
        "drop_paths": ["1.aspx"],
        "source": "tracker.md 4.4 (ELLIO IOC table)",
    },
    {
        "label": "documented Go remote-access agent payload fingerprint",
        "sha256": "dd98bf48899aa385035352688357742c73ddc5e47ec4ecc7d7b74c53c2e3ca3d",
        "size_bytes": None,
        "drop_paths": [],
        "source": "tracker.md 4.4 (ELLIO IOC table)",
    },
]

# Filesystem probe paths documented in the briefs (existence only -> info).
PROBE_PATHS = [
    ("/dev/shm/.cache.so", "documented probe path [technique.md 10.1 - ELLIO]"),
]

# Drift scan does local file reads only. Never any network access.
DEFAULT_TMPDIRS = ("/tmp", "/var/tmp", "/dev/shm")

# ---------------------------------------------------------------------------
# User-Agent fingerprints (technique.md 10.1; tracker.md 4.3)
# VERBATIM strings as published by the cited telemetry. Detection tokens are
# deliberately coarse (the "php2shell" token covers ~30 published UA variants
# and will also catch tomorrow's variant); they can never false-flag an
# operator's own tooling that does not self-identify... except if an operator's
# scanner self-identifies as "php2shell-*", which the published scanners below
# (Vilnius SOC, VulnCheck, Imperva, CERT-In...) literally do. That is a
# documented property of this IOC set, noted in README.
# ---------------------------------------------------------------------------

VERBATIM_USER_AGENTS = [
    "php2shell-scan/109618",                                        # S22, S16, S23
    "php2shell-scan/1.3 (eigen-oppervlak controle; CVE-2026-109618/109619)",  # S16
    "php2shell-verify/1.0",                                         # S16, S22
    "Mozilla/5.0 (php2shell-poc)",                                  # S16
    "php2shell-poc/1.0 (authorized-staging-test; marker=cryptographer-php-poc-here)",  # S16, S22
    "php2shell-109618",                                             # S22
    "php2shell-109619",                                             # S22
    "php2shell-version-check/1.0 (safe, no exploitation)",          # S16
    "PHP2Shell-Batch-Verifier/1.0",                                 # S16
    "shellflow-php2shell/1.0",                                      # S16
    "php2shell-scan/1.0 (+https://github.com/0xrsydn/php2shell-scan)",        # S16, S22
    "php-upload-progress-scan/1.0 (internal, authorized-use-only)", # S16
    "php2shell-scanner/0.1 (+@ofjaaah)",                            # S16
    "php-fingerprint/1.0 (security triage; PHP2Shell exposure check)",        # S16
    "Mozilla/5.0 (compatible; php2shell-exposure-scan/1.0)",        # S16
    "Vilnius-SOC-PHP2Shell-Check/1.1 (+read-only fingerprint; no exploit; contact: soc@vilnius.lt)",  # S16
    "php2shell-check/0.0.0-20261022111727-d9c486a664e7",            # S16
    "php2shell-pasif-tarayici/2.0 (passive fingerprint; only on authorized sites)",  # S16
    "php2shell-validate/1.0 (+detection-only; no exploitation)",    # S16
    "php2shell-exposure-bash/3.0.0",                                # S16
    "php2shell-hunter-fingerprint/1.0",                             # S16
    "php2shell-mass/9.0",                                           # S16
    "php2shell-profile-inventory/1.0",                              # S16
    "php2shell-scope-fingerprint/1.0",                              # S16
    "php2shell-universal",                                          # S16
    "Mozilla/5.0 (php2shell-test/2.0.0)",                           # S23
    "Mozilla/5.0 (php-session-start-rce-poc)",                      # S23
    "PHP2Shell-VulnCheck/2.0 (responsible-disclosure)",             # S22
    "SOCRadarLabs/v4 (php2shell-checker)",                          # S22
    "sudo3rs-PHP2Shell-Checker/1.4.0",                              # S22
    "Mozilla/5.0 (CERT-In PHP2Shell Assessment)",                   # S22
    "HexStrike-PHP2Shell-Scanner/1.0",                              # S22
    "Mozilla/5.0 (compatible; ImpervaPHP2ShellChecker/1.0; +https://www.imperva.com/)",  # S22
    "php2shell-scanner/1.0",                                        # S22
    # one UA embeds live PHP code (F5 appendix, technique.md 10.1):
    "php2shellLP<?php echo 'php2shell_out_start';system('id');echo 'php2shell_out_end';?>",
]
# Detection tokens (ci substring) — derived family rule grounded in the set above.
UA_TOKENS_CI = ("php2shell", "php-session-start-rce-poc", "php-upload-progress-scan")
# Live-code / execution-marker tokens inside any UA (ci) [technique.md 10.1].
UA_CODE_TOKENS_CI = ("<?php", "system(", "php2shell_out_start", "php2shell_out_end")

# ---------------------------------------------------------------------------
# Marker tokens with documented occurrences (VERBATIM strings; ci match)
# technique.md 10.1/10.4; tracker.md 4.3
# ---------------------------------------------------------------------------

MARKER_TOKENS_CI = (
    "b7kpoc618",                                  # F5 boundary [S22]
    "b7kpoc619",                                  # F5/PoC default boundary [S22]
    "----php2shelld656557dacfa4fbc",              # F5 boundary [S22]
    "p2sprobec982a06c",                           # ELLIO/F5 progress value [S22, S23]
    "jackalpoc",                                  # public PoC canary [S16, S23]
    "p2smark",                                    # ELLIO canary [tracker.md 4.3]
    "p2smk",                                      # ELLIO canary [tracker.md 4.3]
    "php2shell_ok",                               # ELLIO canary [tracker.md 4.3]
    "php2shell_out_start",                        # response-echo wrapper [S23]/F5
    "php2shell_out_end",                          # response-echo wrapper [S23]/F5
    "poc_79fe5e4f",                               # ELLIO canary [tracker.md 4.3]
    "------atk",                                  # ELLIO boundary [tracker.md 4.3]
    "nucleiboundary",                             # ELLIO boundary [tracker.md 4.3]
    "pwned::",                                    # VulnCheck webshell response marker [S16]
    "php2shelllp<?php",                           # live-code UA stem [S22]
)
MARKER_REGEXES = (
    re.compile(r"-{2,}p2s[0-9a-fA-F]{8}"),        # "------p2s" + 8 hex digits [tracker 4.3]
)
# Hardcoded PHPSESSID values documented by F5 / VulnCheck. [S22, S16]
HARDCODED_SESSION_IDS_CI = (
    "a1b2c3d4e5f6a7b8c9d0e1f2a3",   # F5 pattern-3 hardcoded cookie [S22]
    "xqsuvwz3n97wu8j3emz1axuo5y",   # VulnCheck canary session file "sess_..." [S16]
)
# Progress-field values documented by ELLIO/F5 (only meaningful with the
# PHP_SESSION_UPLOAD_PROGRESS field present). [S22, S23]
PROGRESS_VALUES = ("pwn", "p2sprobec982a06c", "p2smark", "p2smk")
# One documented progress value embedded a live command (ELLIO, technique 10.1):
PROGRESS_COMMAND_TOKEN = "system('curl http://15.235.206.16:8443')"  # defanged in output

# ---------------------------------------------------------------------------
# Request-shape facts (multipart amplification, technique.md section 2.1/10.2)
# VERBATIM shapes from the advisories + ELLIO/F5 telemetry; thresholds are
# DERIVED and deliberately conservative (see comments).
# ---------------------------------------------------------------------------

# Documented OOM request-body sizes seen in the wild (ELLIO cluster) and the
# F5 62,929-byte OOM body. Exact matches only. [S23, S22; tracker.md 4.3]
OOM_BODY_SIZE_CLUSTER = (62929, 8388608, 9437183, 12655437, 15657436, 25281929)

# Thresholds (DERIVED, conservative, documented basis):
BODY_THRESHOLDS = {
    # ELLIO: "hundreds of empty file fields" -> >= 100 (VERBATIM shape)
    "empty_file_parts_min": 100,
    # ELLIO: "field names nested dozens of levels deep" -> depth >= 12
    "nested_depth_min": 12,
    # ELLIO: "X: a" x 230,000+ within one part -> >= 1000 (well under the
    # observed minimum, but far above any legitimate part header count)
    "part_header_flood_min": 1000,
    # F5: single 62,929-byte body of repeated 'A'; ELLIO: 24 MiB run of 'B'
    # -> identical-char run >= 30,000 bytes
    "padding_run_min": 30000,
    # ELLIO weaponized PoC: 149 identical 288-byte parts; PoC default: 149
    # identical 288-byte parts -> >= 64 equal-length parts <= 512 bytes
    "identical_battery_min": 64,
    "identical_battery_len_max": 512,
    # documented 2-byte NUL file content (heap-grooming), files "f" / "f=x.txt"
    "null_file_part_max_len": 4,
    # bodies are not scanned above this size (1 MiB cap for the run-scan pass;
    # large-body presence is judged via the size-cluster rule instead)
    "scan_text_cap": 2 * 1024 * 1024,
}

# php-session-file read shape (DERIVED rule on a VERBATIM technique):
# "php://filter ... /sess_xqsuvwz..." reads [S16]; "sess_<26>" generic session
# files are a documented older technique ELLIO tags separately [S23].
RE_PHP_FILTER = re.compile(r"php://filter", re.IGNORECASE)
RE_SESS_REF = re.compile(r"sess_[A-Za-z0-9_]{8,}")