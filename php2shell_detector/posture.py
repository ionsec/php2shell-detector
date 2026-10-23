"""HOST POSTURE check: PHP runtime inventory, SAPI exposure, enabling settings.

Facts enforced here (sources = research briefs; do not extend beyond these):

- Fixed releases 2026-10-21: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or higher patches
  of the same branch). [technique.md section 3.1]
- PHP 8.1 and older: EOL, no official fixed binaries. Source backports exist for
  7.4 / 8.0 / 8.1; nothing for <= 7.3. [technique.md 3.2]
  Vendor backports keep the old version string -> version strings alone can
  false-flag/clear; package changelog checks are the ground truth.
- Affected: every unpatched PHP since 5.4. [technique.md 3.4]
- SAPI risk table [technique.md section 2.1/2.2/4]:
    mod_php   - CRITICAL: 109618 RCE validated over HTTP with default input AND
                memory limits (prefork, multi-worker); fires before application
                code. 109619 RCE validated (8.5 backtrace path + session path).
    php-fpm   - WARN: 109619 session-lifecycle RCE validated on FPM (needs an
                app-side fatal + a follow-up request on the same worker);
                109618 source-analysis only, no complete exploit demonstrated.
    php-cgi   - WARN: listed at-risk by php.net; no separate validation published.
    other (FrankenPHP/LiteSpeed/unknown) - WARN per advisory "all deployments
                serving web requests are at risk".
- Enabling settings (109619):
    session.upload_progress.enabled is DEFAULT ON and requires no session_start()
    anywhere. [technique.md 2.2] php.net informational advisory 2026-10-23
    (CVE-2026-115560) recommends keeping it 0 until the next regular bugfix
    release - so enabled stays a finding even on fully patched PHP.
    fatal_error_backtraces = an 8.5 feature; enabled -> the "strongest
    demonstrated case" for 109619 mod_php RCE. [technique.md 2.2]
    The tool does NOT assume a default for fatal_error_backtraces when the
    directive is absent from scanned configs (briefs do not state one); it
    reports the runtime value when `php -i` is runnable.
- Mitigations recognized (technique.md 8.3; reported as context, not findings
  when absent): session.upload_progress.enabled=0 set in pool/server config,
  php_admin_value memory_limit=-1 (or equivalent), FPM pm.max_requests=1,
  edge multipart blocking (nginx if/$http_content_type, Apache RewriteCond).

Deliberately NOT checked (not supported by the briefs): AllowEncodedSlashes or
any other httpd directive the briefs do not mention - no speculation.
"""

import glob
import os
import re
import shutil
import subprocess
from typing import Optional

from . import fingerprints
from .report import finding, severity_max

# ---------------------------------------------------------------------------

_PHP_BIN_NAMES = [
    "php", "php8.5", "php8.4", "php8.3", "php8.2", "php8.1", "php8.0", "php7.4",
    "php85", "php84", "php83", "php82", "php81", "php74",
]

_RE_PHPV = re.compile(r"PHP (\d+)\.(\d+)\.(\d+)")

APACHE_SCAN_DIRS = [
    "/etc/apache2", "/etc/httpd",
    "/usr/local/etc/httpd", "/opt/homebrew/etc/httpd",
    "/opt/homebrew/opt/httpd/etc/httpd",
]

FPM_POOL_GLOBS = [
    "/etc/php/*/fpm/pool.d/*.conf",
    "/etc/php/*/fpm/php-fpm.conf",          # Debian/Ubuntu master
    "/etc/php/*/fpm/php.ini",
    "/etc/php-fpm.d/*.conf",                # RHEL/Alma/Rocky
    "/etc/php-fpm.conf",
    "/usr/local/etc/php-fpm.d/*.conf",      # macOS Homebrew (surý builds)
    "/opt/homebrew/etc/php/*/php-fpm.d/*.conf",
    "/opt/homebrew/etc/php/*/php.ini",
    "/usr/local/etc/php.ini", "/etc/php.ini",
]

# settings we report; (key, severity when enabled)
_SETTINGS_OF_INTEREST = [
    "session.upload_progress.enabled",
    "session.upload_progress.cleanup",
    "fatal_error_backtraces",
    "memory_limit",
    "post_max_size",
    "upload_max_filesize",
    "max_file_uploads",
]


def _run(cmd, timeout: int = 20):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": proc.returncode, "out": proc.stdout or "", "err": proc.stderr or ""}
    except OSError:  # FileNotFound / Permission denied: command not available here
        return None
    except subprocess.TimeoutExpired:
        return {"rc": -1, "out": "", "err": "timeout"}


# ---------------------------------------------------------------------------
# version evaluation
# ---------------------------------------------------------------------------

def parse_php_version(text: str) -> Optional[tuple]:
    m = _RE_PHPV.search(text)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def eval_version(major: int, minor: int, patch: int) -> dict:
    """Severity/status for a version per the fixed-version list and EOL table."""
    branch = (major, minor)
    ver = f"{major}.{minor}.{patch}"
    cve = "CVE-2026-109618/109619"
    if (major, minor) < fingerprints.AFFECTED_SINCE:
        return {
            "status": "pre_5_4",
            "severity": "info",
            "detail": f"{ver} - older than PHP 5.4; the advisories cover PHP 5.4+ but the "
                      f"runtime is far out of support. Upgrade regardless.",
        }
    if branch in {tuple(map(int, b.split("."))) for b in fingerprints.FIXED_VERSIONS}:
        fixed = fingerprints.FIXED_VERSIONS[f"{major}.{minor}"]
        if patch >= fixed:
            return {
                "status": "patched",
                "severity": "ok",
                "detail": f"{ver} >= branch fix {major}.{minor}.{fixed} "
                          f"({cve} fixed 2026-10-21). Restart all workers after any patch.",
            }
        return {
            "status": "vulnerable_unpatched",
            "severity": "warn",
            "detail": f"{ver} < branch fix {major}.{minor}.{fixed} "
                      f"({cve} fixed 2026-10-21). Actual risk depends on SAPI - see exposure rating.",
        }
    if branch > (8, 5):
        return {
            "status": "unknown_future_branch",
            "severity": "info",
            "detail": f"{ver} - branch not in the 2026-10-21 fixed-version table; "
                      f"verify separately (newer PHP releases should contain the fix).",
        }
    if branch <= fingerprints.EOL_LAST_SUPPORTED:
        if branch in fingerprints.BACKPORTABLE_BRANCHES:
            return {
                "status": "eol_backportable",
                "severity": "warn",
                "detail": f"{ver} - EOL branch, no official fixed release (source backports exist "
                          f"for 7.4/8.0/8.1; vendor LTS may backport while keeping this version "
                          f"string). Verify the package changelog: e.g. "
                          f"zgrep CVE-2026-109618 /usr/share/doc/<pkg>/changelog.Debian.gz "
                          f"or rpm -q --changelog <pkg> | grep CVE-2026-109618.",
            }
        return {
            "status": "eol_no_fix",
            "severity": "warn",
            "detail": f"{ver} - EOL and no fix exists for this branch (<=7.3 gets nothing; "
                      f"PHP 5.4+ affected). Upgrade to a supported branch is the only option.",
        }
    return {
        "status": "unknown_not_in_list",
        "severity": "info",
        "detail": f"{ver} - branch not covered by the 2026-10-21 fixed-version table; verify separately.",
    }


# ---------------------------------------------------------------------------
# runtime discovery
# ---------------------------------------------------------------------------

def discover_php_runtimes(php_bin: Optional[str]) -> list:
    """Inventory PHP runtimes via explicit --php-bin and PATH probing."""
    runtimes, seen = [], set()
    candidates = []
    if php_bin:
        candidates.append(php_bin)
    else:
        for name in _PHP_BIN_NAMES:
            which = shutil.which(name)
            if which:
                candidates.append(which)
    for binp in candidates:
        if binp in seen:
            continue
        seen.add(binp)
        res = _run([binp, "-v"])
        if not res or res["rc"] != 0:
            continue
        ver = parse_php_version(res["out"])
        if ver is None:
            continue
        ev = eval_version(*ver)
        runtimes.append({
            "bin": binp,
            "version": ".".join(map(str, ver)),
            "major": ver[0], "minor": ver[1], "patch": ver[2],
            "eval": ev,
            "source": f"{binp} -v",
        })
    return runtimes


def query_packages() -> dict:
    """Best-effort package-manager inventories. Local commands only."""
    out = {"managers": [], "entries": []}
    # Debian/Ubuntu (and surý builds)
    res = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
    if res and res["rc"] == 0:
        out["managers"].append("dpkg")
        for line in res["out"].splitlines():
            parts = line.split("\t")
            if len(parts) != 2 or not parts[0].startswith("php"):
                continue
            name, version = parts
            base = version.split("-")[0].split("+")[0]
            m = re.match(r"(\d+)\.(\d+)\.(\d+)", base)
            ev = eval_version(*map(int, m.groups())) if m else {
                "status": "unparseable", "severity": "info",
                "detail": f"version string '{version}' could not be parsed -> check changelog:"}
            out["entries"].append({"package": name, "version": base, "raw_version": version, "eval": ev})
    # RHEL/Alma/Rocky/Fedora (+ Remi parallel installs use php81- style names)
    res = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
    if res and res["rc"] == 0:
        out["managers"].append("rpm")
        for line in res["out"].splitlines():
            parts = line.split("\t")
            if len(parts) != 2 or "php" not in parts[0]:
                continue
            name, version = parts
            base = version.split("-")[0].split(".")[0] if 0 else version
            m = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
            ev = eval_version(*map(int, m.groups())) if m else {
                "status": "unparseable", "severity": "info",
                "detail": f"version string '{version}' could not be parsed -> check changelog:"}
            # BACKPORT CAVEAT (briefs): RHSA-2026:87080 keeps the 7.4.33 version
            # string while being patched; RHSA-2026:87151 keeps RHEL9 8.0.30 while
            # being patched. Version-based verdicts below can be wrong in BOTH
            # directions; the operator must confirm via the changelog.
            out["entries"].append({"package": name, "version": version.split("-")[0],
                                   "raw_version": version, "eval": dict(ev,
                                   detail=(ev.get("detail", "") + " | backported distro builds may keep this old version string - confirm via changelog:"
                                           " rpm -q --changelog " + name + " | grep CVE-2026-109618")).strip()})
    # Alpine
    res = _run(["sh", "-c", "apk info -v | grep -i '^php'"])
    if res and res["rc"] == 0:
        out["managers"].append("apk")
        for line in res["out"].splitlines():
            if not line.strip():
                continue
            m = re.match(r"^(php[0-9\-]*.*?)-(\d+\.\d+\.\d+)", line)
            if not m:
                continue
            name, ver = m.group(1), m.group(2)
            ev = eval_version(*map(int, ver.split(".")))
            out["entries"].append({"package": name, "version": ver, "raw_version": line, "eval": ev})
    # Homebrew (macOS/dev hosts)
    res = _run(["sh", "-c", "brew list --versions 2>/dev/null | grep -E '^(php|php@)'"])
    if res and res["rc"] == 0:
        out["managers"].append("brew")
        for line in res["out"].splitlines():
            parts = line.split()
            if len(parts) < 2 or not parts[0].startswith("php"):
                continue
            name, ver = parts[0], parts[1]
            m = re.match(r"(\d+)\.(\d+)\.(\d+)", ver)
            ev = eval_version(*map(int, m.groups())) if m else {
                "status": "unparseable", "severity": "info", "detail": f"version '{ver}' unparseable"}
            out["entries"].append({"package": name, "version": ver, "raw_version": ver, "eval": ev})
    return out


# ---------------------------------------------------------------------------
# SAPI detection
# ---------------------------------------------------------------------------

def scan_sapi(apache_conf_override=None, fpm_conf_override=None) -> dict:
    sapi = {
        "mod_php": {"installed": False, "evidence": []},
        "fpm": {"installed": False, "evidence": []},
        "cgi": {"installed": False, "evidence": []},
        "other": {"installed": False, "evidence": []},
    }

    # 1) running processes / binaries (local command execution only)
    res = _run(["sh", "-c", "pgrep -l -f 'php-fpm' 2>/dev/null; true; pgrep -x php-fpm 2>/dev/null; true"])
    pgrep_lines = [l for l in (res or {}).get("out", "").splitlines() if l.strip()]
    if pgrep_lines:
        sapi["fpm"]["installed"] = True
        sapi["fpm"]["evidence"].append("php-fpm processes running: " + ", ".join(pgrep_lines[:5]))

    for name in ("php-fpm",):
        path = shutil.which(name)
        if path:
            sapi["fpm"]["installed"] = True
            sapi["fpm"]["evidence"].append(f"binary {path} on PATH")
    if shutil.which("php-cgi"):
        sapi["cgi"]["installed"] = True
        sapi["cgi"]["evidence"].append("php-cgi binary on PATH: " + shutil.which("php-cgi"))
    # php-cgi under common package-managed paths
    for p in ("/usr/bin/php-cgi", "/usr/sbin/php-cgi"):
        if os.path.exists(p) and p not in (" ".join(sapi["cgi"]["evidence"])):
            sapi["cgi"]["installed"] = True
            sapi["cgi"]["evidence"].append(f"installed {p}")

    res = _run(["sh", "-c", "command -v apachectl >/dev/null && (apachectl -M 2>/dev/null || apachectl -t -D DUMP_MODULES 2>/dev/null) | grep -i php; true"])
    if (res or {}).get("out", "").strip():
        sapi["mod_php"]["installed"] = True
        sapi["mod_php"]["evidence"].append("apachectl module dump lists PHP module: " +
                                           (res or {}).get("out", "").strip().splitlines()[0])
    if shutil.which("php-fpm") is None and not pgrep_lines and not sapi["fpm"]["evidence"]:
        # leave fpm uninstalled=False
        pass

    # 2) apache config scan (LoadModule phpX_module ... libphpX.so / php_value)
    if apache_conf_override:
        apache_res = _scan_apache_paths([apache_conf_override], from_file=True)
    else:
        dirs = [d for d in APACHE_SCAN_DIRS if os.path.isdir(d)]
        apache_res = _scan_apache_paths(dirs)
    if apache_res["mod_php_loads"]:
        sapi["mod_php"]["installed"] = True
        for load in apache_res["mod_php_loads"]:
            sapi["mod_php"]["evidence"].append(load)
    sapi["apache_scan"] = apache_res

    # 3) fpm pool configs
    fpm_files = []
    if fpm_conf_override:
        fpm_files = [fpm_conf_override]
    else:
        for g in FPM_POOL_GLOBS:
            fpm_files.extend(sorted(glob.glob(g)))
    pools = []
    for path in fpm_files:
        pools.extend(_parse_fpm_file(path))
    if pools:
        sapi["fpm"]["installed"] = True
        sapi["fpm"]["evidence"].append(f"FPM pool/master configs found: {len(pools)} file(s)")
    sapi["fpm_pools"] = pools

    # 4) FrankenPHP / LiteSpeed markers installed (binary presence only)
    for fw in ("frankenphp", "lsws", "litespeed"):
        w = shutil.which(fw)
        if w:
            sapi["other"]["installed"] = True
            sapi["other"]["evidence"].append(f"binary {w} on PATH ({fw})")

    # rating per the brief SAPI table
    sapi["rating"], sapi["rationale"] = rate_sapi(
        sapi["mod_php"]["installed"], sapi["fpm"]["installed"],
        sapi["cgi"]["installed"], sapi["other"]["installed"])
    row_sev = {"mod_php": "critical", "fpm": "warn", "cgi": "warn", "other": "warn"}
    for name, sev in row_sev.items():
        if sapi[name]["installed"]:
            sapi[name]["severity"] = sev
    return sapi


def rate_sapi(mod_php_installed: bool, fpm_installed: bool, cgi_installed: bool,
              other_installed: bool):
    if mod_php_installed:
        return ("critical", "mod_php loaded - CVE-2026-109618 RCE validated over HTTP on mod_php "
            "with default input AND memory limits, and it fires BEFORE application code; "
            "CVE-2026-109619 RCE validated on mod_php (8.5 backtrace path + session path). "
            "[technique.md 2.1/2.2/4]")
    if fpm_installed:
        return ("warn", "PHP-FPM present - CVE-2026-109619 session-upload-progress RCE validated "
            "on FPM (fatal-error producer during app execution + follow-up request on the same "
            "worker); CVE-2026-109618 has no complete FPM exploit demonstrated (startup failure "
            "kills the child; source-analysis only). Still exposed - patch. [technique.md 2.1/2.2/4]")
    if cgi_installed or other_installed:
        return ("warn", "php-cgi or other serving SAPI present - php.net lists php-cgi (and other "
            "serving SAPIs) as at risk; no separate published validation. [technique.md 4]")
    return ("info", "no serving SAPI found on this host (CLI/cron PHP only, or the serving "
        "runtime is on another host/container). Verify the runtime that actually serves web "
        "requests separately (phpinfo() / packages on the runtime host). [technique.md 8.1]")


def _scan_apache_paths(paths, from_file=False) -> dict:
    """Scan apache config trees/files for mod_php + mitigation-relevant directives.

    Scope is deliberately limited to what the research briefs support:
    mod_php LoadModule evidence, php_value/php_admin_value|flag per-directory
    directives (they apply before request startup - a 109619 consumer), and
    edge multipart blocking. AllowEncodedSlashes etc. are NOT checked (not in
    the briefs).
    """
    res = {"scanned": [], "mod_php_loads": [], "php_directives": [],
           "multipart_block": None, "errors": []}
    files = []
    if from_file:
        files = [p for p in paths if os.path.isfile(p)]
        res["scanned"].extend(files)
    else:
        for d in paths:
            for root, sub, fnames in os.walk(d):
                depth = root[len(d):].count(os.sep)
                if depth > 2:
                    sub[:] = []
                    continue
                for fn in fnames:
                    if fn.endswith((".conf", ".load", ".conf~", "")) or fn.startswith("php"):
                        p = os.path.join(root, fn)
                        if os.path.isfile(p) and os.path.getsize(p) < 2 * 1024 * 1024:
                            files.append(p)
                res["scanned"].append(root)
    texts = []
    for p in sorted(set(files)):
        try:
            with open(p, "r", errors="replace") as fh:
                texts.append((p, fh.read()))
        except OSError as e:
            res["errors"].append(f"{p}: {e}")
    re_load = re.compile(r"(?mi)^\s*LoadModule\s+php[\w]*?module\s+(\S+)")
    re_directive = re.compile(
        r"(?mi)^\s*php_(?:admin_)?(?:value|flag)\s+([A-Za-z0-9_.\-]+)\s+([^\n]+?)\s*$")
    re_multiblock = re.compile(
        r"(?mi)^(?:.*RewriteCond.*%\{HTTP:Content-Type\}.*multipart/form-data.*"
        r"|.*\$http_content_type.*multipart/form-data.*return 403.*)$")
    for p, text in texts:
        for m in re_load.finditer(text):
            res["mod_php_loads"].append(f"{p}: LoadModule -> {m.group(1)}")
        for m in re_directive.finditer(text):
            res["php_directives"].append({
                "file": p, "key": (m.group(1) or "").lower(),
                "value": (m.group(2) or "").strip()})
        for m in re_multiblock.finditer(text):
            res["multipart_block"] = f"{p}: {m.group(0).strip()[:120]}"
    return res


def _parse_fpm_file(path) -> list:
    """Parse an FPM pool/master file into pool records with settings of interest."""
    try:
        with open(path, "r", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    re_admin_kv = re.compile(r"(?m)^\s*php_(admin_)?(value|flag)\s*\[([^\]]+)\]\s*=\s*(.+?)\s*$")
    pm_max = re.search(r"(?m)^\s*pm\.max_requests\s*=\s*(\d+)\s*$", text)
    pool = {"file": path, "pool": os.path.basename(path), "admin": {}, "values": {},
            "pm_max_requests": int(pm_max.group(1)) if pm_max else None}
    for m in re_admin_kv.finditer(text):
        key = m.group(3).lower()
        val = m.group(4).strip().strip('"') if m.group(4) else None
        if val == "":  # php_admin_value[x] = (empty -> PHP default)
            continue
        if m.group(1):  # admin flag/value is binding for that key
            pool["admin"][key] = val
        else:
            pool["values"][key] = val
    return [pool]


# ---------------------------------------------------------------------------
# ini / webroot
# ---------------------------------------------------------------------------

def runtime_settings_from_php_i(php_bin: str) -> Optional[dict]:
    """Parse `php -i` for the settings of interest. CLI-SAPI view (caveat)."""
    res = _run([php_bin, "-i"], timeout=30)
    if not res or res["rc"] != 0:
        return None
    settings = {}
    for line in res["out"].splitlines():
        if " => " not in line:
            continue
        key, _, _val = line.partition(" => ")
        key = key.strip()
        if key in _SETTINGS_OF_INTEREST:
            # php -i prints "key => local_value"; master ini view is the 3rd column
            cols = line.split(" => ")
            settings[key] = {
                "local": cols[1] if len(cols) > 1 else None,
                "master": cols[2] if len(cols) > 2 else None,
            }
    return settings or None


def parse_ini_file(path) -> Optional[dict]:
    """Simple php.ini parse for the settings of interest (section-agnostic)."""
    try:
        with open(path, "r", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    found = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*=\s*([^;\n\r]+)", line)
        if m and m.group(1) in _SETTINGS_OF_INTEREST:
            found[m.group(1)] = m.group(2).strip().strip('"')
    return found or None


def scan_webroot(webroot: str) -> dict:
    """Scan a webroot for .htaccess / .user.ini (brief-supported files only)."""
    out = {"root": webroot, "files": [], "findings": [], "notes": []}
    if not os.path.isdir(webroot):
        out["notes"].append(f"webroot does not exist / is not a directory: {webroot}")
        return out
    names = [".htaccess", ".user.ini"]
    # .user.ini note per briefs: in FPM it applies TOO LATE for the 109619
    # consumer (pool/server-level settings are the mitigation path).
    for root, _dirs, files in os.walk(webroot):
        rel_root = os.path.relpath(root, webroot)
        for fn in files:
            if fn in names:
                out["files"].append(os.path.normpath(os.path.join(rel_root, fn)))
        # keep the walk shallow-ish: 2 levels deep is plenty for posture
        if rel_root != "." and rel_root.count(os.sep) >= 2:
            _dirs[:] = []
    for rel in out["files"]:
        path = os.path.join(webroot, rel)
        try:
            with open(path, "r", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)$", rel)
        if rel == ".htaccess":
            for dm in re.finditer(r"(?mi)^\s*php_(?:admin_)?(?:value|flag)\s+([A-Za-z0-9_.\-]+)\s+(.+?)\s*$", text):
                key, val = dm.group(1).lower(), dm.group(2)
                out["findings"].append(finding(
                    "HTACCESS_PHP_DIRECTIVE", "info",
                    f".htaccess sets {key}={val} - per-directory config applies BEFORE "
                    f"php_request_startup(); memory_limit/php_flags here are part of the "
                    f"109618/109619 exposure surface (evidence only)",
                    check="posture", file=path, evidence=f"{key} = {val}",
                    basis="VERBATIM: technique.md 2.2 (per-directory config applies before request startup)",
                    related=["109619", "109618"]))
        elif rel == ".user.ini":
            for key, val in (parse_ini_file(path) or {}).items():
                out["findings"].append(finding(
                    "USER_INI_DIRECTIVE", "info", f".user.ini sets {key}={val} - .user.ini changes "
                    f"apply too late in FPM to matter for the 109619 consumer path (evidence only)",
                    check="posture", file=path, evidence=f"{key} = {val}",
                    basis="VERBATIM: technique.md 2.2 / 8.2 ('.user.ini applies too late')",
                    related=["109619"]))
    return out


def collect_settings(posture: dict, php_bin: Optional[str], extra_inis) -> list:
    """Emit setting rows (with why/severity) from every source we can read."""
    rows = []
    has_serving_sapi = (posture["sapi"]["mod_php"]["installed"]
                        or posture["sapi"]["fpm"]["installed"]
                        or posture["sapi"]["cgi"]["installed"]
                        or posture["sapi"]["other"]["installed"])

    def add(key, value, source, why, severity):
        rows.append({"key": key, "value": value, "source": source,
                     "why": why, "severity": severity})

    seen_rows = set()

    def add_once(key, value, source, why, severity):
        k = (key, str(value), severity, source)
        if k in seen_rows:
            return
        seen_rows.add(k)
        add(key, value, source, why, severity)

    # 1) php -i (runtime, CLI-SAPI view) or configured ini files
    if php_bin:
        rt = runtime_settings_from_php_i(php_bin)
        if rt:
            for key, vals in rt.items():
                v = vals["local"]
                if key == "session.upload_progress.enabled":
                    if _truthy(v):
                        add_once(key, v, f"php -i ({php_bin}, CLI-SAPI view)",
                                 _why_upload_progress() + (" (no serving SAPI detected on this "
                                 "host - applies when this runtime serves web requests)"
                                 if not has_serving_sapi else ""), "warn")
                    else:
                        add_once(key, v, f"php -i ({php_bin}, CLI-SAPI view)",
                                 "enabled=0 - blocks the validated 109619 upload-progress consumer "
                                 "paths; keep off per the 2026-10-23 informational advisory", "ok")
                elif key == "fatal_error_backtraces":
                    if _truthy(v):
                        add_once(key, v, f"php -i ({php_bin}, CLI-SAPI view)",
                                 _why_backtraces("warn") + (" (no serving SAPI detected on this "
                                 "host - applies when this runtime serves web requests)"
                                 if not has_serving_sapi else ""), "warn")
                    else:
                        add_once(key, v, f"php -i ({php_bin}, CLI-SAPI view)",
                                 "fatal_error_backtraces=0 - backtrace producer blocked", "ok")
                elif key == "memory_limit":
                    if str(v).strip() in ("-1", "-1m") or str(v).strip().upper().startswith("-1"):
                        add_once(key, v, f"php -i ({php_bin}, CLI-SAPI view)",
                                 "memory_limit=-1 - advisory mitigation for 109618 (removes the "
                                 "controllable per-request OOM trigger; allocation failures can "
                                 "still reach the path)", "ok")
                    else:
                        add_once(key, v, f"php -i ({php_bin}, CLI-SAPI view)",
                                 _why_context(key, v), "info")
                else:
                    add_once(key, v, f"php -i ({php_bin}, CLI-SAPI view)",
                             _why_context(key, v), "info")
    for ini in extra_inis or []:
        vals = parse_ini_file(ini)
        if vals is None:
            continue
        for key, v in vals.items():
            if key == "session.upload_progress.enabled":
                if _truthy(v):
                    add_once(key, v, f"ini file {ini}", _why_upload_progress(), "warn")
                else:
                    add_once(key, v, f"ini file {ini}",
                             "enabled=0 - validated 109619 session paths blocked", "ok")
            elif key == "fatal_error_backtraces":
                if _truthy(v):
                    add_once(key, v, f"ini file {ini}", _why_backtraces("warn"), "warn")
                else:
                    add_once(key, v, f"ini file {ini}",
                             "fatal_error_backtraces=0 - backtrace producer blocked", "ok")
            else:
                if key == "memory_limit" and str(v).strip().startswith("-1"):
                    add_once(key, v, f"ini file {ini}",
                             "memory_limit=-1 - advisory mitigation for 109618", "ok")
                else:
                    add_once(key, v, f"ini file {ini}", _why_context(key, v), "info")

    # 2) FPM pools (php_admin_* are binding for the pool)
    for pool in posture["sapi"].get("fpm_pools", []):
        combined = dict(pool.get("values") or {})
        combined.update(pool.get("admin") or {})
        for key, v in combined.items():
            if key == "session.upload_progress.enabled":
                if not _truthy(v):
                    add_once(key, v, f"FPM pool {pool['file']} (php_admin - binding)",
                             "enabled=0 (php_admin binding) - mitigation present per briefs; blocks "
                             "the validated 109619 session paths; set it in pool/server config and "
                             "restart, not via ini_set()/.user.ini", "ok")
                else:
                    add_once(key, v, f"FPM pool {pool['file']} (php_admin - binding)",
                             _why_upload_progress(), "warn")
            elif key == "fatal_error_backtraces":
                if _truthy(v):
                    add_once(key, v, f"FPM pool {pool['file']} (php_admin - binding)",
                             _why_backtraces("warn"), "warn")
                else:
                    add_once(key, v, f"FPM pool {pool['file']} (php_admin - binding)",
                             "fatal_error_backtraces=0 - backtrace producer blocked", "ok")
            elif key == "memory_limit":
                finite = _parse_bytes(v) if v not in (None, "-1") else -1
                if finite == -1:
                    add_once(key, v, f"FPM pool {pool['file']} (php_admin - binding)",
                             "memory_limit=-1 - advisory mitigation for 109618 (removes the "
                             "controllable per-request OOM trigger; allocation failures can still "
                             "reach the path)", "ok"
                             if pool.get("admin") else "ok")
                else:
                    add_once(key, v, f"FPM pool {pool['file']}",
                             f"finite memory_limit ({v}) - the OOM-abort trigger primitive for "
                             f"109618 stays reachable while on an unpatched build",
                             "info")
            if key not in ("session.upload_progress.enabled", "fatal_error_backtraces", "memory_limit") \
                    and key in ("post_max_size", "upload_max_filesize", "max_file_uploads",
                                "session.upload_progress.cleanup"):
                add_once(key, v, f"FPM pool {pool['file']}", _why_context(key, v), "info")

    # 3) apache php_* directives
    for d in (posture["sapi"].get("apache_scan") or {}).get("php_directives", []):
        key, v = d["key"], d["value"]
        if key == "memory_limit":
            finite = _parse_bytes(v) if v not in (None, "-1") else -1
            if finite == -1:
                add_once(key, v, f"apache config {d['file']}",
                         "memory_limit=-1 - advisory mitigation for 109618", "ok")
            else:
                add_once(key, v, f"apache config {d['file']}",
                         f"finite memory_limit ({v}) in web-server config - per-directory "
                         f"config applies before request startup (109619 consumer surface); "
                         f"finite limit keeps the 109618 OOM-abort trigger reachable", "info")
        elif key == "session.upload_progress.enabled":
            sev = "ok" if not _truthy(v) else "warn"
            add_once(key, v, f"apache config {d['file']}",
                     (_why_upload_progress() if sev == "warn"
                      else "enabled=0 in apache per-directory config - blocks the validated 109619 "
                           "session paths")
                     + " (per-directory config applies before request startup)", sev)
        else:
            add_once(key, v, f"apache config {d['file']}", _why_context(key, v), "info")

    # 4) if a serving SAPI exists but the tool could not read ANY setting source:
    if has_serving_sapi and not any(r["key"] == "session.upload_progress.enabled" for r in rows):
        add("session.upload_progress.enabled", "unknown",
            "no readable source (php -i / ini files / pool confs)",
            "the briefs state this is enabled by default and is the validated 109619 path; "
            "verify with the serving SAPI's own config (php -i on the runtime, fpm pool conf) - "
            "the tool did not silently assume the default here", "warn")
    if has_serving_sapi and not any(r["key"] == "fatal_error_backtraces" for r in rows):
        add("fatal_error_backtraces", "unknown",
            "no readable source (php -i / ini files / pool confs)",
            "PHP 8.5 feature; enabled -> strongest demonstrated 109619 mod_php case. The briefs "
            "do not state the default so the tool does not claim one - read the runtime value "
            "(php -i) or your php.ini on hosts that matter", "info")
    return rows


def _truthy(v) -> bool:
    if v is None:
        return False
    s = str(v).strip().lower()
    return s in ("1", "on", "true", "yes")


def _parse_bytes(v) -> int:
    """Parse shorthand byte values like 128M / 2G / 16m -> bytes; -1 -> -1."""
    if v is None:
        return -1
    m = re.match(r"^\s*(-?\d+)\s*([KMGkmg]?)", str(v))
    if not m:
        return -1
    num = int(m.group(1))
    mult = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}.get(m.group(2).lower(), 1)
    return num * mult


def _why_upload_progress() -> str:
    return ("enabled=1 - session.upload_progress is DEFAULT ON and reachable with no "
            "session_start() anywhere; validated 109619 producer/consumer path (also the "
            "session-file read / webshell-planting shape seen 2026-10-21). php.net informational "
            "advisory 2026-10-23 recommends keeping it 0 until the next regular bugfix release "
            "(session.upload_progress.enabled must be set in php.ini/pool/server config, then "
            "workers restarted - not via ini_set()/.user.ini). "
            "Basis: technique.md 2.2/8.3, tracker.md 2026-10-23 section")


def _why_backtraces(sev: str) -> str:
    if sev == "warn":
        return ("enabled - the strongest demonstrated 109619 mod_php case "
                "(EG(last_fatal_error_backtrace) survives shutdown; mitigation: set "
                "fatal_error_backtraces=0 + restart every worker). technique.md 2.2/8.3")
    return ("report-only row (not asserted when the directive is absent; the briefs do not state "
            "its default). technique.md 2.2")


def _why_context(key: str, v) -> str:
    if key == "session.upload_progress.cleanup":
        if str(v).strip().lower() in ("0", "off", "false"):
            return "cleanup=0 - upload-progress records persist after read (larger exposure window)"
        return "report-only row; upload-progress cleanup setting (context)"
    if key == "memory_limit":
        return "report-only row: memory_limit context (finite limits keep the 109618 OOM trigger reachable)"
    if key == "post_max_size":
        return ("report-only row: post_max_size is the first wire-size cap; header amplification "
                "can still exceed it (adv: 'Sizes cap misses header-amplification within limits')")
    if key == "upload_max_filesize":
        return "report-only row: upload_max_filesize context (adv: keep it below post_max_size)"
    if key == "max_file_uploads":
        return "report-only row: empty file controls do not count toward this but still build " \
               "file-metadata arrays (109618 amplification)"
    return "report-only row"


# ---------------------------------------------------------------------------
# entry
# ---------------------------------------------------------------------------

def run_posture(php_bin: Optional[str] = None, extra_inis=None,
                apache_conf: Optional[str] = None, fpm_conf: Optional[str] = None,
                webroot: Optional[str] = None) -> dict:
    posture = {"runtimes": [], "packages": None, "sapi": {}, "settings": [],
               "webroot": {}, "findings": [], "notes": []}
    posture["runtimes"] = discover_php_runtimes(php_bin)
    posture["packages"] = query_packages()

    sapi = scan_sapi(apache_conf, fpm_conf)
    posture["sapi"] = sapi

    # runtime findings
    for rt in posture["runtimes"]:
        ev = rt["eval"]
        sev = ev["severity"]
        # if the runtime serves web requests, an unpatched version escalates to critical
        if sev == "warn" and sapi["rating"] == "critical":
            sev = "critical"
        postfix = ""
        if sapi["rating"] == "critical":
            postfix = " mod_php exposure elevates this to critical (validated multi-path RCE, pre-application)."
        posture["findings"].append(finding(
            "PHP_RUNTIME_VERSION", sev,
            f"{rt['bin']} reports PHP {rt['version']} -> {ev['status']}.{postfix}",
            check="posture", evidence=rt["source"],
            basis="VERBATIM: fixed versions 8.2.35/8.3.36/8.4.27/8.5.12 - "
                  "technique.md section 3 (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp)",
            related=["109618", "109619"]))
    # package findings (best-effort; version-string caveat is in the message)
    for p in ((posture["packages"] or {}).get("entries") or []):
        ev = p["eval"]
        if ev["severity"] == "warn":
            posture["findings"].append(finding(
                "PHP_PACKAGE_VERSION", "warn",
                f"package {p['package']} {p['raw_version']} -> {ev['status']}. {ev.get('detail', '')}",
                check="posture", evidence=f"{p['package']} {p['raw_version']}",
                basis="VERBATIM: distro fixes keep old version strings (RHSA-2026:87080 7.4.33, "
                      "RHSA-2026:87151 8.0.30) - technique.md 3.2/3.3",
                related=["109618", "109619"]))

    # explicit --php-bin that failed to yield a version is an operator problem
    if php_bin and not posture["runtimes"]:
        posture["findings"].append(finding(
            "PHP_BIN_UNREADABLE", "warn",
            f"--php-bin {php_bin}: no 'PHP x.y.z' line in -v output (or the binary failed) - "
            f"version posture unknown",
            check="posture"))

    # sapi exposure finding
    if sapi["rating"] == "critical":
        posture["findings"].append(finding(
            "SAPI_MOD_PHP_EXPOSED", "critical",
            f"{sapi['rationale']}", check="posture",
            basis="VERBATIM: technique.md 2.1/2.2/4 - 'mod_php runs request shutdown "
                  "unconditionally - even when request startup failed'",
            related=["109618", "109619"]))
    elif sapi["rating"] == "warn":
        posture["findings"].append(finding(
            "SAPI_WEB_EXPOSED", "warn", f"{sapi['rationale']}", check="posture",
            basis="VERBATIM: technique.md 2.2 (FPM session-lifecycle RCE validated) "
                  "and 2.1 (source analysis for 109619)",
            related=["109618", "109619"]))

    # settings rows -> findings for warn-level ones
    posture["settings"] = collect_settings(posture, php_bin, extra_inis)
    for row in posture["settings"]:
        if row["severity"] in ("warn", "critical"):
            posture["findings"].append(finding(
                f"SETTING_{row['key'].upper().replace('.', '_')}", row["severity"],
                f"{row['key']} = {row['value']} (source: {row['source']}) - {row['why']}",
                check="posture", evidence=f"{row['source']}: {row['key']} = {row['value']}",
                basis="VERBATIM (enabling condition): technique.md 2.2 / 8.3 / php.net informational "
                      "advisory 2026-10-23 (CVE-2026-115560)",
                related=["109619"]))
        # also surface multipart-block mitigation info once:
    ab = (sapi.get("apache_scan") or {}).get("multipart_block")
    if ab:
        posture["findings"].append(finding(
            "APACHE_MULTIPART_BLOCK", "info",
            f"edge multipart block present in scanned apache config (advisory mitigation, "
            f"temporary; breaks legit uploads) - {ab}", check="posture",
            basis="VERBATIM: technique.md 8.3 (RewriteCond %{HTTP:Content-Type} multipart/form-data -> [F])"))

    if webroot:
        posture["webroot"] = scan_webroot(webroot)
        posture["findings"].extend(posture["webroot"].get("findings", []))

    if not posture["runtimes"] and not php_bin:
        posture["findings"].append(finding(
            "NO_PHP_RUNTIME_FOUND", "info",
            "no PHP binary discovered in PATH on this host - posture must be taken on the host "
            "(or container) that actually serves web requests", check="posture"))
    return posture