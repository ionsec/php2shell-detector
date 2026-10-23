#!/usr/bin/env python3
"""Regenerate the static example corpora (examples/logs/*) used for smoke runs.

The content is produced by php2shell_detector.corpora — the SAME builders the
pytest suite uses — so shipped examples and tests cannot drift. Exploit lines
are built exclusively from fingerprints documented in the 2026-10-23 research
briefs (technique.md / tracker.md).

Usage: python3 examples/make_examples.py
"""

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL_ROOT = HERE.parent
sys.path.insert(0, str(TOOL_ROOT))

from php2shell_detector import corpora  # noqa: E402

OUT = HERE / "logs"

FILES = {
    "access_benign.log": corpora.benign_access_combined() + corpora.benign_access_ltsv(),
    "access_exploit.log": corpora.exploit_access_combined() + corpora.exploit_access_ltsv(),
    "php_error_benign.log": corpora.benign_php_error(),
    "php_error_exploit.log": corpora.exploit_php_error(),
}


def fixture_webroot() -> None:
    root = HERE / "fixture_webroot"
    sub = root / "cms" / "admin"
    sub.mkdir(parents=True, exist_ok=True)
    (root / ".htaccess").write_text(
        "# fixture webroot for smoke run (synthetic)\n"
        "php_value memory_limit 16M\n")
    (root / ".user.ini").write_text("upload_max_filesize=2M\n")
    (sub / ".htaccess").write_text("# per-directory override fixture\nphp_value upload_max_filesize 8M\n")


def fixture_tmpdir() -> None:
    d = HERE / "fixture_tmp"
    d.mkdir(exist_ok=True)
    # a benign file: name matches nothing, hash matches nothing
    (d / "notes.txt").write_text("fixture scratch file; drift check: no match expected here\n")


def fixture_php(version: str = "8.4.26") -> None:
    script = HERE / "fixture_php.sh"
    script.write_text(
        "#!/bin/sh\n"
        "# TEST FIXTURE - synthetic PHP binary stub for the tool smoke run; do not deploy.\n"
        'case "$1" in\n'
        '  -v) echo "PHP %s (cli) (built: Oct  2 2026 00:00:00) (NTS)";;\n'
        '  -i) echo "session.upload_progress.enabled => 1 => 1"\n'
        '      echo "session.upload_progress.cleanup => 1 => 1"\n'
        '      echo "memory_limit => 16M => 16M"\n'
        '      echo "post_max_size => 8M => 8M"\n'
        '      echo "upload_max_filesize => 2M => 2M"\n'
        '      echo "max_file_uploads => 20 => 20";;\n'
        '  *) : ;;\n'
        "esac\n" % version)
    script.chmod(0o755)


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, lines in FILES.items():
        (OUT / name).write_text("\n".join(lines) + "\n")
        print(f"wrote {OUT / name} ({len(lines)} lines)")
    fixture_webroot()
    fixture_tmpdir()
    fixture_php()
    (HERE / "fixture_tmp" / "nfs").write_text(
        "fixture: file NAMED like the documented loader drop path (content does not "
        "match any documented hash) - demonstrates the info-only drift naming check\n")
    print("wrote fixture_webroot/, fixture_tmp/ (incl. nfs name check), fixture_php.sh")


if __name__ == "__main__":
    main()