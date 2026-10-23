"""Reporting helpers: severity model, IP defanging, text + JSON renderers."""

import json
import re
from datetime import datetime, timezone
from typing import Optional

from . import __version__, TOOL_NAME

SEV_ORDER = {"ok": 0, "info": 1, "warn": 2, "critical": 3}
SEV_ORDER["crit"] = 3

TOOL_EXIT_CLEAN = 0      # ran fine, no warn/critical finding
TOOL_EXIT_FINDINGS = 1   # at least one warn/critical finding
TOOL_EXIT_ERROR = 2      # invocation/resource problem (bad args, missing files)

SECTION_ORDER = ("critical", "warn", "info", "ok")


def severity_max(*severities: str) -> str:
    best = "ok"
    for s in severities:
        if s in SEV_ORDER and SEV_ORDER[s] > SEV_ORDER.get(best, 0):
            best = s
    return best


def defang(value: str) -> str:
    """Defang dotted-quad IPs in evidence strings so copied output is inert."""
    return re.sub(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", lambda m: m.group(1).replace(".", "[.]"), value)


def clean_evidence(text: str, limit: int = 240) -> str:
    """Sanitize a raw log excerpt for the report: defang, strip control bytes."""
    txt = text.replace("\r", "\\r").replace("\n", " ")
    txt = "".join(c if (c.isprintable() and c != "\x7f") else "\\x%02x" % (ord(c) & 0xFF) for c in txt)
    return defang(txt[:limit]).rstrip()


def finding(rule: str, severity: str, message: str, *, check: str = "",
            file: Optional[str] = None, line: Optional[int] = None,
            evidence: Optional[str] = None, basis: str = "",
            related: Optional[list] = None) -> dict:
    return {
        "rule": rule,
        "severity": severity,
        "check": check,
        "message": message,
        "file": file,
        "line": line,
        "evidence": clean_evidence(evidence) if evidence else None,
        "basis": basis,
        "related": related or [],
    }


def new_report(argv) -> dict:
    return {
        "tool": TOOL_NAME,
        "version": __version__,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "argv": list(argv),
        "posture": None,
        "logs": None,
        "drift": None,
        "errors": [],
        "summary": {},
    }


def finalize(report: dict) -> dict:
    counts = {"critical": 0, "warn": 0, "info": 0, "ok": 0}
    for section in ("posture", "logs", "drift"):
        body = report.get(section) or {}
        for f in body.get("findings", []):
            sev = f.get("severity", "info")
            if sev in counts:
                counts[sev] += 1
    report["summary"] = {
        "counts": counts,
        "exit_code": _exit_code(report, counts),
    }
    return report


def _exit_code(report: dict, counts: dict) -> int:
    if report.get("errors"):
        return TOOL_EXIT_ERROR
    if counts["critical"] or counts["warn"]:
        return TOOL_EXIT_FINDINGS
    return TOOL_EXIT_CLEAN


def render_text(report: dict) -> str:
    out = []
    gen = report.get("generated_utc", "?")
    out.append(f"{TOOL_NAME} v{__version__} - local checks for PHP2Shell "
               f"(CVE-2026-109618 / CVE-2026-109619)")
    out.append(f"generated {gen} | basis: IONSEC research briefs (technique.md, tracker.md, 2026-10-23)")
    out.append("attempts/indicator hits never prove execution; posture is point-in-time")
    out.append("")

    if report.get("errors"):
        out.append(f"== ERRORS ({len(report['errors'])}) ==")
        for err in report["errors"]:
            out.append(f"[error]   {err}")
        out.append("")

    post = report.get("posture")
    if post is not None:
        out.append(f"== HOST POSTURE ==")
        for line in _render_posture(post):
            out.append(line)
        out.append("")

    logs = report.get("logs")
    if logs is not None:
        out.append("== LOG SCAN ==")
        for fline in _render_logs(logs):
            out.append(fline)
        out.append("")

    drift = report.get("drift")
    if drift is not None:
        out.append("== DRIFT CHECK (local files only; no network) ==")
        for dline in _render_drift(drift):
            out.append(dline)
        out.append("")

    summary = report.get("summary") or {}
    counts = summary.get("counts") or report.get("counts") or {}
    ec = summary.get("exit_code")
    if ec is None:
        ec = summary.get("exit", 0)
    out.append("== SUMMARY ==")
    out.append(f"findings: critical={counts.get('critical', 0)} warn={counts.get('warn', 0)} "
               f"info={counts.get('info', 0)} ok={counts.get('ok', 0)} | exit_code={ec}")
    if report.get("errors"):
        out.append("(errors present: check invocation / file paths)")

    # findings listing
    findings = []
    for section in ("posture", "logs", "drift"):
        body = report.get(section) or {}
        findings.extend(body.get("findings", []))
    if findings:
        order = {"critical": 0, "warn": 1, "info": 2, "ok": 3}
        findings.sort(key=lambda f: (order.get(f.get("severity"), 9), f.get("check", ""), f.get("rule", "")))
        shown = 0
        for f in findings:
            if shown >= 200:
                rest = len(findings) - shown
                out.append(f"  ... {rest} more finding(s) truncated - see --json")
                break
            shown += 1
            out.append(_format_finding(f))
    return "\n".join(out) + "\n"


def _sev_tag(sev: str) -> str:
    return {"critical": "critical", "warn": "warning", "info": "   info", "ok": "     ok"}.get(sev, "  " + sev)


def _format_finding(f: dict) -> str:
    loc = ""
    if f.get("file"):
        loc = f" {f['file']}" + (f":{f['line']}" if f.get("line") else "")
    line = f"[{_sev_tag(f.get('severity', 'info'))}] {f.get('rule', '?'):<28} {f.get('message', '')}"
    if loc:
        line += f"  ({loc})"
    if f.get("evidence"):
        line += f"\n            evidence: {f['evidence']}"
    if f.get("basis"):
        line += f"\n            basis: {f['basis']}"
    return line


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, default=str, sort_keys=False)


# ---------------------------------------------------------------------------
# section renderers
# ---------------------------------------------------------------------------

def _render_posture(post: dict) -> list:
    out = []
    for rt in post.get("runtimes", []):
        ev = rt.get("eval") or {}
        out.append(f"[{_sev_tag(ev.get('severity', 'ok'))}] PHP runtime: {rt.get('bin', '?')}"
                   f" -> PHP {rt.get('version') or '?'} : {ev.get('status', '?')}"
                   + (f" - {ev['detail']}" if ev.get("detail") else ""))
    pkgs = post.get("packages")
    if pkgs:
        for p in pkgs.get("entries", []):
            ev = p.get("eval") or {}
            out.append(f"[{_sev_tag(ev.get('severity', 'ok'))}] package: {p['package']} {p['version']} "
                       f"-> {ev.get('status', '?')}" + (f" - {ev['detail']}" if ev.get("detail") else ""))
        if not pkgs.get("entries"):
            out.append("[   info] packages: no dpkg/rpm/apk/brew PHP packages found/queryable")
    sapi = post.get("sapi") or {}
    for name, row in sapi.items():
        if name not in ("mod_php", "fpm", "cgi", "other"):
            continue
        if row.get("installed"):
            out.append(f"[{ _sev_tag(row.get('severity', 'info'))}] SAPI {name}: "
                       + "; ".join(row.get("evidence", []))[:400])
        else:
            out.append(f"[   info] SAPI {name}: not found on this host")
    out.append(f"exposure rating: {sapi.get('rating', 'n/a')} - {sapi.get('rationale', '')}")
    for row in post.get("settings", []):
        out.append(f"[{_sev_tag(row.get('severity', 'info'))}] setting {row['key']}"
                   f" (source: {row.get('source', '?')}): {row.get('value', '?')} - {row.get('why', '')}")
    web = post.get("webroot") or {}
    if web:
        for fname in web.get("files", []):
            out.append(f"[   info] webroot file: {fname}")
        for f in web.get("findings", []):
            out.append(f"[{_sev_tag(f['severity'])}] {f['rule']}: {f['message']}")
            if f.get("evidence"):
                out.append(f"            evidence: {f['evidence']}")
    for f in post.get("findings", []):
        out.append(_format_finding(f))
    return out


def _render_logs(logs: dict) -> list:
    out = []
    for fs in logs.get("files", []):
        out.append(f"  {fs.get('path')}: format={fs.get('format')} lines_scanned={fs.get('lines_scanned')} "
                   f"parsed={fs.get('parsed')} findings={fs.get('finding_count')}")
    for f in logs.get("findings", []):
        out.append(_format_finding(f))
    return out


def _render_drift(drift: dict) -> list:
    out = []
    if drift.get("paths_used"):
        out.append(f"  paths scanned: {', '.join(drift['paths_used'])}")
    if drift.get("paths_missing"):
        out.append(f"  paths absent (skipped): {', '.join(drift['paths_missing'])}")
    out.append(f"  files hashed: {drift.get('files_hashed', 0)}"
               f" | skipped large: {drift.get('skipped_large', 0)} | fs errors: {drift.get('fs_errors', 0)}")
    for f in drift.get("findings", []):
        out.append(_format_finding(f))
    return out