"""php2shell-detector CLI — orchestrates the three checks:

  posture : PHP runtime inventory + SAPI exposure + enabling settings (local commands/config reads)
  logs    : access / PHP error log scan against documented PHP2Shell fingerprints
  drift   : tmpdir file-hash triage vs the documented binary fingerprints (local reads only)

Exit codes:
  0 - checks ran, no warn/critical finding
  1 - at least one warn/critical finding (inspect the report)
  2 - invocation/resource problem (bad flag values, missing explicit paths)

Local operations only: posture shells out to local tools (php -v/-i, dpkg-query,
rpm, apk, brew list, apachectl -M, pgrep); drift reads files; nothing
networked. See README.md for the honest limits section.
"""

import argparse
import os
import sys
import traceback
from typing import Optional

from . import TOOL_NAME, __version__, drift, logs, posture, report as rp


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(f"{TOOL_NAME} v{__version__} — local checks for PHP2Shell "
                     "(CVE-2026-109618 / CVE-2026-109619). Host posture, log scan "
                     "and tmpdir drift triage. Local operations only; fingerprints "
                     "come from the 2026-10-23 research briefs."),
        epilog=("exit codes: 0 = clean, 1 = findings, 2 = invocation/resource error. "
                "A log hit is an ATTEMPT indicator, never proof of execution; "
                "posture is point-in-time and version-strings lie on backported "
                "distro builds — see README limits."),
    )
    p.add_argument("--webroot", metavar="PATH",
                   help="webroot to scan for .htaccess/.user.ini (posture check)")
    p.add_argument("--log", metavar="PATH", action="append", default=[],
                   help="log file to scan (repeatable; access log or PHP/php-fpm "
                        "error log; .gz supported)")
    p.add_argument("--php-bin", metavar="PATH",
                   help="php binary to interrogate (default: probe PATH for php/php8.x)")
    p.add_argument("--ini", metavar="PATH", action="append", default=[],
                   help="extra php.ini file to parse for settings (repeatable)")
    p.add_argument("--apache-conf", metavar="PATH",
                   help="explicit apache config file to scan (default: scan standard config dirs if present)")
    p.add_argument("--fpm-conf", metavar="PATH",
                   help="explicit php-fpm pool/master conf to parse (default: scan standard paths if present)")
    p.add_argument("--tmpdir", metavar="PATH", action="append", default=[],
                   help="extra tmp directory for the drift hash check (default: /tmp, /var/tmp, /dev/shm when present)")
    p.add_argument("--check", metavar="NAME", action="append", default=[],
                   choices=("posture", "logs", "drift"),
                   help="run only this check (repeatable; default: all three)")
    p.add_argument("--log-format", metavar="FMT", default="auto",
                   choices=("auto", "combined", "common", "ltsv"),
                   help="force an access-log format (default: auto-detect per line)")
    p.add_argument("--max-lines", metavar="N", type=int, default=200000,
                   help="cap log lines scanned per file (default 200000)")
    p.add_argument("--json", action="store_true", help="JSON report instead of text")
    p.add_argument("--quiet", action="store_true", help="only findings (no summary lines) in text mode")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    rep = rp.new_report(sys.argv if argv is None else argv)

    want = set(args.check or ("posture", "logs", "drift"))

    # --- validate explicit paths first (exit 2 on missing)
    for path in list(args.log):
        if not os.path.exists(path):
            rep["errors"].append(f"--log {path}: file not found")
        elif not os.path.isfile(path):
            rep["errors"].append(f"--log {path}: not a regular file")
    if args.php_bin and not os.path.exists(args.php_bin):
        rep["errors"].append(f"--php-bin {args.php_bin}: not found")
    for ini in args.ini:
        if not os.path.isfile(ini):
            rep["errors"].append(f"--ini {ini}: not found")
    for extra in args.tmpdir:
        if not os.path.isdir(extra):
            rep["errors"].append(f"--tmpdir {extra}: not a directory")
    if args.apache_conf and not os.path.isfile(args.apache_conf):
        rep["errors"].append(f"--apache-conf {args.apache_conf}: not found")
    if args.fpm_conf and not os.path.isfile(args.fpm_conf):
        rep["errors"].append(f"--fpm-conf {args.fpm_conf}: not found")
    if args.webroot and not os.path.isdir(args.webroot):
        rep["errors"].append(f"--webroot {args.webroot}: not a directory")

    if rep["errors"]:
        rep = rp.finalize(rep)
        _emit(rep, args)
        return rp.TOOL_EXIT_ERROR

    # --- posture
    if "posture" in want:
        try:
            rep["posture"] = posture.run_posture(
                php_bin=args.php_bin, extra_inis=list(args.ini),
                apache_conf=args.apache_conf, fpm_conf=args.fpm_conf,
                webroot=args.webroot)
        except Exception as e:  # never die on a partial result
            rep["errors"].append(f"posture check failed: {e.__class__.__name__}: {e}")
            if os.environ.get("PHP2SHELL_DEBUG"):
                rep["errors"].append(traceback.format_exc())

    # --- logs
    if "logs" in want and args.log:
        file_reports = []
        ok_files = [p for p in args.log if os.path.isfile(p)]
        for path in ok_files:
            try:
                res = logs.scan_log_file(path, fmt=args.log_format,
                                         max_lines=args.max_lines)
                file_reports.append(res)
            except OSError as e:
                rep["errors"].append(f"log scan failed for {path}: {e}")
        rep["logs"] = {
            "files": file_reports,
            "findings": [f for fr in file_reports for f in fr.get("findings", [])],
            "body_visibility_note": (
                "multipart-amplification shapes need the request body in the log "
                "(LTSV body: field / nginx $request_body); UA/probe/size rules run on standard formats"),
        }
    elif "logs" in want and not args.log:
        rep["logs"] = {"files": [], "findings": [], "body_visibility_note":
                       "no --log given: log scan skipped (pass an access log and/or PHP error log)"}

    # --- drift
    if "drift" in want:
        try:
            paths = None
            if args.tmpdir:
                paths = list(args.tmpdir)
            else:
                paths = [p for p in drift.DEFAULT_TMPDIRS if os.path.isdir(p)] \
                    or None  # keep defaults for the "missing" note
            rep["drift"] = drift.scan(paths=paths)
            if args.tmpdir:
                pass
        except Exception as e:
            rep["errors"].append(f"drift check failed: {e.__class__.__name__}: {e}")

    rep = rp.finalize(rep)

    if args.quiet and not args.json:
        text = _quiet_text(rep)
        sys.stdout.write(text)
    else:
        _emit(rep, args)
    return rep["summary"]["exit_code"]


def _emit(rep: dict, args):
    if args.json:
        sys.stdout.write(rp.render_json(rep) + "\n")
    else:
        sys.stdout.write(rp.render_text(rep))


def _quiet_text(rep: dict) -> str:
    lines = []
    for section in ("posture", "logs", "drift"):
        for f in (rep.get(section) or {}).get("findings", []):
            sev = f.get("severity", "info")
            if sev in ("warn", "critical"):
                lines.append(f"[{sev}] {f.get('rule')}: {f.get('message')}"
                             + (f" :: {f.get('evidence')}" if f.get('evidence') else ""))
    for err in rep.get("errors", []):
        lines.append(f"[error] {err}")
    return "\n".join(lines) + ("\n" if lines else "")


if __name__ == "__main__":
    sys.exit(main())