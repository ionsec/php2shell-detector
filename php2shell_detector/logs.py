"""LOG SCAN: access logs (nginx/Apache common, combined, LTSV) + PHP/php-fpm
error logs, matched against PHP2Shell fingerprints documented in the research
briefs. No fingerprint is invented; rule IDs state their basis (VERBATIM =
exact documented string/shape; DERIVED = threshold/heuristic grounded in a
documented observation).

Honest limits (also in README):
- Log-based hit never proves execution. All briefs' telemetry describes
  ATTEMPTS; no vendor has reported a confirmed public compromise (as of the
  brief compile date 2026-10-23).
- Access logs normally do NOT carry request bodies: the multipart-amplification
  shapes (empty-file part floods, nesting depth, per-part header floods,
  padding runs) only fire when the body is visible (LTSV `body:` field,
  escaped \\n/\\x00 - see README) or via the documented body-size cluster on
  request-size fields. The string/space tokens (UA, boundaries, progress
  field, php://filter, hardcoded session ids) fire on ordinary logs.
- User-agents rotate trivially (briefs); the structural/behavioral rules are
  the more durable layer. Benign UAs (curl, Chrome, Firefox) are deliberately
  NOT flagged even though F5 noted attackers blending in with them - that
  would drown the operator.
"""

import gzip
import os
import re
from collections import Counter, defaultdict
from typing import Optional

from . import fingerprints
from .report import clean_evidence, defang, finding

# ---------------------------------------------------------------------------
# log parsing
# ---------------------------------------------------------------------------

RE_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?')
RE_COMMON = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s*$')

LTSV_INT_FIELDS = ("status", "size", "content_length", "body_bytes_received",
                   "request_length", "body_bytes_sent")


def parse_ltsv(line: str) -> Optional[dict]:
    fields = {}
    for token in line.rstrip("\r\n").split("\t"):
        if ":" not in token:
            return None
        key, _, val = token.partition(":")
        fields[key.strip()] = val
    if not fields or not any(k in fields for k in ("req", "request")):
        return None
    return fields


def parse_access_line(line: str) -> Optional[dict]:
    """Parse one access-log line in combined / common format."""
    m = RE_COMBINED.match(line.rstrip("\r\n"))
    fmt = "combined"
    if not m:
        m = RE_COMMON.match(line.rstrip("\r\n"))
        fmt = "common"
    if not m:
        ltsv = parse_ltsv(line)
        if ltsv is not None:
            return _mk_record(line, ltsv, "ltsv")
        return None
    d = m.groupdict()
    req = d.get("req") or ""
    parts = req.split()
    if len(parts) >= 3:
        method, uri, proto = parts[0], " ".join(parts[1:-1]), parts[-1]
    elif len(parts) == 2:
        method, uri, proto = parts[0], parts[1], ""
    else:
        method, uri, proto = req, "", ""
    rec = {
        "ip": d.get("ip"), "ts": d.get("ts"),
        "method": method, "uri": uri, "proto": proto,
        "status": int(d["status"]) if d.get("status", "").isdigit() else None,
        "size": d.get("size"), "ref": d.get("ref") or "", "ua": d.get("ua") or "",
        "format": fmt,
    }
    return rec


def _mk_record(line: str, ltsv: dict, fmt: str) -> dict:
    req = ltsv.get("req") or ltsv.get("request") or ""
    parts = req.split()
    if len(parts) >= 3:
        method, uri, proto = parts[0], " ".join(parts[1:-1]), parts[-1]
    elif len(parts) == 2:
        method, uri, proto = parts[0], parts[1], ""
    else:
        method, uri, proto = req, "", ""
    body = (ltsv.get("body") or "")
    body = _unescape_body(body)
    rec = {
        "ip": ltsv.get("host") or ltsv.get("ip") or ltsv.get("fwd") or ltsv.get("forwardedfor"),
        "ts": ltsv.get("time") or ltsv.get("time_local"),
        "method": method, "uri": uri, "proto": proto,
        "status": int(ltsv["status"]) if str(ltsv.get("status", "")).isdigit() else None,
        "size": ltsv.get("body_bytes_sent") or ltsv.get("size"),
        "ref": ltsv.get("referer") or "",
        "ua": ltsv.get("ua") or ltsv.get("user_agent") or "",
        "cookie": ltsv.get("cookie") or "",
        "body": body,
        # distinguish "not logged at all" (None) from "logged and unusable" ("-"/"")
        "content_length": (ltsv.get("content_length") if "content_length" in ltsv else None) or "",
        "request_length": (ltsv.get("request_length") or "").strip(),
        "body_bytes_received": (ltsv.get("body_bytes_received") or "").strip(),
        "format": fmt,
    }
    return rec


def _unescape_body(text: str) -> str:
    """Log-bodies must be escaped to stay on one line (README, LTSV field).
    Unescape \\n \\r \\t \\x00 sequences for the multipart deep-scan."""
    if "\\" not in text:
        return text
    text = text.replace("\\x00", "\x00").replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
    return text


def iter_lines(path: str, follow_symlink: bool = False):
    """Yield (line_no, line) from a plain or .gz log file."""
    op = gzip.open if (path.endswith(".gz") or _is_gzip(path)) else open
    with op(path, "rt", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            yield i, line


def _is_gzip(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"\x1f\x8b"
    except OSError:
        return False


# ---------------------------------------------------------------------------
# string rules (VERBATIM tokens)
# ---------------------------------------------------------------------------

_RE_UPLOAD_PROGRESS = re.compile(r"PHP_SESSION_UPLOAD_PROGRESS", re.IGNORECASE)
_RE_PROGRESS_TAG_VALUE = re.compile(r'name="PHP_SESSION_UPLOAD_PROGRESS"[^>]*value="([^"]*)"', re.IGNORECASE)
_RE_PROGRESS_HEADER = re.compile(r"^\s*PHP_SESSION_UPLOAD_PROGRESS:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_RE_PROGRESS_FORM = re.compile(r'name="PHP_SESSION_UPLOAD_PROGRESS"[^\n]*\r?\n\r?\n([^\r\n]*)', re.IGNORECASE)
_RE_COOKIE_PHPSESSID = re.compile(r"PHPSESSID=([A-Za-z0-9]+)")

_RULE_BASIS_UA = ("VERBATIM: UA token family from the published scanner list "
                  "(technique.md 10.1 / F5 ~100-entry appendix; tracker.md 4.3)")
_RULE_BASIS_MARKER = ("VERBATIM: marker token documented in technique.md 10.1/10.4 "
                      "(ELLIO / F5 / VulnCheck telemetry; tracker.md 4.3)")


def eval_record(record: dict, raw_line: str, line_no: int, path: str, out: list,
                cadence_state: dict) -> None:
    line_ci = (raw_line or "").lower()
    ua = record.get("ua") or ""
    line_no_str = line_no

    evidence_common = {"file": path, "line": line_no_str}

    # 1) UA scanner family — live-code/markers first (higher signal), then family token
    code = [t for t in fingerprints.UA_CODE_TOKENS_CI if t in ua.lower()]
    if ua and code and any(t in ua.lower() for t in fingerprints.UA_TOKENS_CI):
        out.append(finding(
            "UA_PHP2SHELL_TOOLING", "warn",
            "User-Agent matches the documented PHP2Shell scanner/tooling UA family "
            "and embeds live PHP code / execution markers - attempt telemetry, not proof of execution",
            evidence=ua, basis=_RULE_BASIS_UA, check="logs", related=["109618", "109619"],
            **evidence_common))
    elif ua and code:
        out.append(finding(
            "UA_LIVE_CODE_EXEC", "warn",
            "User-Agent embeds PHP code or execution markers outside the php2shell UA family "
            "(documented F5 live-code UA behaviour; technique.md 10.1) - attempt telemetry",
            evidence=ua, basis=_RULE_BASIS_UA, check="logs", related=["109619"],
            **evidence_common))
    elif ua and any(t in ua.lower() for t in fingerprints.UA_TOKENS_CI):
        out.append(finding(
            "UA_PHP2SHELL_TOOLING", "warn",
            "User-Agent matches the documented PHP2Shell scanner/tooling UA family - "
            "attempt telemetry, not proof of execution",
            evidence=ua, basis=_RULE_BASIS_UA, check="logs", related=["109618", "109619"],
            **evidence_common))

    # 3) documented marker tokens anywhere on the line
    marker_hits = [t for t in fingerprints.MARKER_TOKENS_CI if t in line_ci]
    marker_hits += [r.pattern if re.search(r, raw_line) else None for r in fingerprints.MARKER_REGEXES]
    marker_hits = [t for t in marker_hits if t]
    if marker_hits:
        out.append(finding(
            "DOCUMENTED_MARKER_TOKEN", "warn",
            "line contains documented PHP2Shell marker string(s) (" + ", ".join(sorted(set(marker_hits))[:4]) + ")",
            check="logs",
            evidence=clean_evidence(raw_line), basis=_RULE_BASIS_MARKER,
            related=["109618", "109619"], **evidence_common))

    # 4) hardcoded documented PHP session ids (cookie fields, URIs)
    sess_hard = [s for s in fingerprints.HARDCODED_SESSION_IDS_CI if s in line_ci]
    if sess_hard:
        out.append(finding(
            "HARDCODED_SESSION_ID", "warn",
            "documented hardcoded PHP session identifier in log line (F5/VulnCheck IOC)",
            check="logs",
            evidence="session id: " + ",".join(sess_hard[:2]),
            basis="VERBATIM: F5 hardcoded PHPSESSID=a1b2c3d4e5f6a7b8c9d0e1f2a3 [S22]; "
                  "VulnCheck sess_xqsuvwz3n97wu8j3emz1axuo5y [S16]",
            related=["109619"], **evidence_common))

    # 5) php://filter / session-file reads in the request line (follow-on reads)
    uri = record.get("uri") or ""
    if uri:
        if fingerprints.RE_PHP_FILTER.search(uri):
            out.append(finding(
                "PHP_FILTER_QUERY_READ", "warn",
                "php://filter stream in request line - documented follow-on read shape "
                "(session/file reads after upload-progress writes; generic technique, "
                "documented here per VulnCheck 221.14.159.x activity)",
                check="logs",
                evidence=uri[:200], basis="VERBATIM shape / DERIVED rule scope: technique.md 10.2 "
                                          "and tracker.md 4.3 ('GET /download.php?file=php://filter/...')",
                related=["109619"], **evidence_common))
        elif fingerprints.RE_SESS_REF.search(uri):
            out.append(finding(
                "SESSION_FILE_REFERENCE", "warn",
                "session file reference (sess_<id>) in request line - documented "
                "upload-progress write-then-include technique (ELLIO-tags it separately)",
                check="logs",
                evidence=uri[:200], basis="DERIVED heuristic on VERBATIM technique: tracker.md 4.3 "
                                          "( sess_<hex> file writes via upload-progress then inclusion )",
                related=["109619"], **evidence_common))

    # 6) request-size cluster / untrusted content length (needs request-side fields)
    method = (record.get("method") or "").upper()
    req_size = _first_req_size(record)
    if method == "POST" and req_size is not None:
        if req_size in fingerprints.OOM_BODY_SIZE_CLUSTER:
            out.append(finding(
                "OOM_BODY_SIZE_CLUSTER", "warn",
                f"request body size exactly matches a documented OOM-body cluster value "
                f"({req_size} bytes - ELLIO/F5 observed clusters)",
                check="logs",
                evidence=str(req_size),
                basis="VERBATIM: body sizes clustered at 8,388,608 / 9,437,183 / 15,657,436 / "
                      "12,655,437 / 25,281,929 bytes; F5 62,929-byte 'A'-pad OOM body (technique 10.1/10.2; "
                      "tracker 4.3); requires body/request_length logging",
                related=["109618"], **evidence_common))
    cl = str(record.get("content_length") or "").strip()
    has_body = bool(record.get("body"))
    if method == "POST" and has_body:
        # only judge what the log actually recorded: "-" / unusable value, or a
        # numeric CL contradicted by the logged body. When the field is simply
        # not logged we cannot infer a missing wire-level CL (not a finding).
        if cl == "-":
            out.append(finding(
                "UNTRUSTED_CONTENT_LENGTH", "warn",
                "POST with visible body but logged-unusable Content-Length - the advisory "
                "names bodies 'with no usable declared Content-Length' as an initial 109618 pass",
                evidence="content_length=-; body present", basis="VERBATIM shape: technique.md 2.1 "
                             "(bodies with no usable declared Content-Length) - visibility needs "
                             "request-body logging", check="logs", related=["109618"],
                **evidence_common))
        else:
            body_len = len(record.get("body") or "")
            try:
                cl_n = int(cl)
                if body_len and cl_n and body_len > cl_n * 4 and body_len > 1024:
                    out.append(finding(
                        "UNTRUSTED_CONTENT_LENGTH", "warn",
                        f"declared Content-Length ({cl_n}) far smaller than logged body "
                        f"({body_len} bytes) - the advisory names 'untrusted' CL as 109618 pass-through",
                        evidence=f"cl={cl_n} body={body_len}", basis="VERBATIM shape: technique.md 2.1 "
                        "(missing/unusable/untrusted Content-Length)",
                        related=["109618"], **evidence_common))
            except ValueError:
                pass

    # 7) body deep-scan (only when body visible in log)
    body = record.get("body") or ""
    if body and len(body) <= fingerprints.BODY_THRESHOLDS["scan_text_cap"]:
        body_res = scan_multipart_body(body)
        for bf in body_res["findings"]:
            bf["file"] = path
            bf["line"] = line_no
            bf["check"] = "logs"
            out.append(bf)
        if body_res["stats"].get("progress_field"):
            vals = body_res["stats"].get("progress_values") or []
            val_note = ""
            if vals:
                interesting = sorted(set(vals) & set(fingerprints.PROGRESS_VALUES))
                if interesting:
                    val_note = " (documented values: " + ", ".join(interesting[:3]) + ")"
            out.append(finding(
                "UPLOAD_PROGRESS_FIELD", "warn",
                "PHP_SESSION_UPLOAD_PROGRESS field in logged multipart body - the session-path "
                "probe field documented across ELLIO/F5/VulnCheck telemetry" + val_note,
                check="logs",
                evidence=clean_evidence("; ".join(vals)) or 'name="PHP_SESSION_UPLOAD_PROGRESS"',
                basis="VERBATIM: technique.md 10.1/10.2 (session.upload_progress probe field; "
                      "signal, not verdict)", related=["109619"], **evidence_common))

    # 8) status counters for aggregate rules
    if record.get("status") == 500 and record.get("uri"):
        path_key = record["uri"]
        cadence_state["500s"][path_key] += 1
    if method == "POST" and record.get("uri"):
        sids = _RE_COOKIE_PHPSESSID.findall(record.get("cookie") or "") or \
            _RE_COOKIE_PHPSESSID.findall(record.get("uri") or "")
        trigger = ("PHP_SESSION_UPLOAD_PROGRESS" in (body or "").upper()) or \
            any(t in ua.lower() for t in fingerprints.UA_TOKENS_CI)
        if sids and trigger:
            key = record["uri"]
            entry = cadence_state["rotation"].setdefault(key, set())
            for sid in sids:
                entry.add(sid)


def _first_req_size(record: dict):
    for key in ("body_bytes_received", "request_length", "content_length"):
        v = str(record.get(key) or "").strip().replace(",", "")
        if v.isdigit():
            return int(v)
    return None


def _finalize_cadence(cadence_state: dict, path: str, out: list) -> None:
    MIN = 5
    for uri, sids in cadence_state["rotation"].items():
        if len(sids) >= MIN:
            out.append(finding(
                "ROTATING_SESSION_CADENCE", "warn",
                f">= {MIN} distinct PHPSESSID values POSTing the same endpoint ({uri}) with "
                "upload-progress/php2shell markers - documented heap-grooming cadence "
                "(F5 pattern 2: minimal trigger, rotating fresh sessions, same endpoint)",
                check="logs",
                file=path, evidence=f"{len(sids)} distinct session ids on {defang(uri)}",
                basis="VERBATIM shape / DERIVED threshold: technique.md 10.2 (heap-grooming "
                      "cadence, rotating fresh PHPSESSID, minimal multipart triggers)",
                related=["109619"]))
    for uri, n in cadence_state["500s"].items():
        if n >= 5:
            out.append(finding(
                "REPEATED_5XX", "warn" if n >= 5 else "info",
                f"{n} HTTP-500 responses for {uri} in this log - memory-limit fatals and "
                "500 bursts are documented exploitation side effects (paired with a PHP "
                "error-log OOM fatal this is the strongest server-side log signal)",
                check="logs",
                file=path, evidence=f"{uri} x{n}",
                basis="VERBATIM shape: technique.md 10.3 (repeated HTTP 500s after "
                      "memory-limit failures)", related=["109618", "109619"]))


# ---------------------------------------------------------------------------
# multipart body deep-scan
# ---------------------------------------------------------------------------

_RE_BOUNDARY_LINE = re.compile(r"(?m)^--[^\r\n]+$")
_RE_CONTENT_DISPOSITION = re.compile(r"(?mi)^content-disposition:\s*form-data;\s*(.*)$")
_RE_PART_HEADER = re.compile(r"(?m)^[A-Za-z][A-Za-z0-9\-]*:\s")
_RE_NAME = re.compile(r'name="([^"]*)"')
_RE_FILENAME_EMPTY = re.compile(r'name="([^"]*)";\s*filename="?"?')


def scan_multipart_body(text: str) -> dict:
    """Deep-scan a logged multipart body for the documented amplification shapes.

    All thresholds are DERIVED (conservative) against documented observations:
      empty-file part flood >= 100     [VERBATIM shape: 'hundreds' - ELLIO]
      field nesting depth   >= 12      [VERBATIM shape: 'dozens of levels deep']
      part header flood     >= 1000    [VERBATIM shape: 'X: a' x 230,000+]
      identical-char run    >= 30,000  [VERBATIM shape: 62,929 x 'A' / 24 MiB 'B']
      identical small parts >= 64     [VERBATIM shape: 149 x 288-byte parts]
      all-NUL file part     <= 4 bytes [VERBATIM shape: 2-byte NUL files]
    """
    findings = []
    stats = {"body_len": len(text), "parts": 0, "empty_file_parts": 0,
             "max_nesting": 0, "max_header_lines": 0, "max_pad_run": 0,
             "null_file_parts": 0, "progress_field": False,
             "progress_values": [], "identical_battery": None}

    th = fingerprints.BODY_THRESHOLDS
    # CR-normalize so the boundary line regex works for CRLF bodies ($ anchors
    # before \n and \r is excluded from the char class otherwise)
    text = text.replace("\r\n", "\n")
    parts = _split_parts(text)
    stats["parts"] = len(parts)
    same_len = Counter()
    same_content = Counter()

    progress_vals = []
    if _RE_UPLOAD_PROGRESS.search(text):
        for m in _RE_PROGRESS_TAG_VALUE.finditer(text):
            progress_vals.append(m.group(1) or "")
        for m in _RE_PROGRESS_HEADER.finditer(text):
            progress_vals.append(m.group(1) or "")
        for m in _RE_PROGRESS_FORM.finditer(text):
            progress_vals.append(m.group(1) or "")
        stats["progress_field"] = True
        stats["progress_values"] = progress_vals
    # progress value tokens get their own finding only if documented value present
    docvals = sorted(set(stats["progress_values"]) & set(fingerprints.PROGRESS_VALUES))
    if docvals:
        findings.append(finding(
            "UPLOAD_PROGRESS_DOCUMENTED_VALUES", "warn",
            "PHP_SESSION_UPLOAD_PROGRESS value(s) match documented probe values (" + ", ".join(docvals[:4]) + ")",
            evidence=", ".join(docvals[:4]),
            basis="VERBATIM: p2sprobec982a06c/pwn/P2SMARK* (technique.md 10.1; tracker.md 4.3)",
            related=["109619"]))

    for part_body_or_chunk, cd in parts:  # parts yield (full chunk, CD line)
        m = _RE_NAME.search(cd or "")
        name = m.group(1) if m else ""
        depth = name.count("[")
        stats["max_nesting"] = max(stats["max_nesting"], depth)
        # split chunk into header section and value body
        hdr_block = _part_header_block(part_body_or_chunk)
        hdr_count = len(_RE_PART_HEADER.findall(hdr_block))
        stats["max_header_lines"] = max(stats["max_header_lines"], hdr_count)
        rest = part_body_or_chunk[len(hdr_block):]
        # multipart framing: value is between the blank header separator and the
        # boundary newline
        part_value = rest.lstrip("\n").rstrip("\n")
        fsem = re.search(r'filename=""', (part_body_or_chunk or ""), re.IGNORECASE)
        if fsem:
            stats["empty_file_parts"] += 1
        if part_value and 0 < len(part_value) <= th["null_file_part_max_len"] \
                and all(ch == "\x00" for ch in part_value):
            stats["null_file_parts"] += 1
        if part_value:
            same_len[len(part_value)] += 1
            same_content[part_value] += 1

    # empty file controls: advisory says they bypass max_file_uploads but still
    # build metadata arrays
    if stats["empty_file_parts"] >= th["empty_file_parts_min"]:
        findings.append(finding(
            "EMPTY_FILE_PART_FLOOD", "warn",
            f"{stats['empty_file_parts']} empty-file multipart controls (filename=) - documented "
            "empty-file-control amplification (they bypass max_file_uploads while still "
            "building file-metadata arrays)",
            evidence=f"{stats['empty_file_parts']} empty file parts in body",
            basis="VERBATIM shape / DERIVED threshold: technique.md 2.1 (empty file controls) "
                  "+ ELLIO 'hundreds of empty file fields' [S23]",
            related=["109618"]))
    if stats["max_nesting"] >= th["nested_depth_min"]:
        findings.append(finding(
            "FIELD_NESTING_DEEP", "warn",
            f"field-name array nesting {stats['max_nesting']} levels deep - documented "
            "'field names nested dozens of levels deep' amplification",
            evidence=f"max nesting depth {stats['max_nesting']}",
            basis="VERBATIM shape / DERIVED threshold: technique.md 2.1 (deeply nested field "
                  "names multiply parsing work) + ELLIO a0000[0]... [S23]",
            related=["109618"]))
    if stats["max_header_lines"] >= th["part_header_flood_min"]:
        findings.append(finding(
            "PART_HEADER_FLOOD", "warn",
            f"{stats['max_header_lines']} header lines inside one multipart part - documented "
            "'unbounded part headers expand far beyond wire size' amplification "
            "(ELLIO: X: a x 230,000+)",
            evidence=f"max header lines per part {stats['max_header_lines']}",
            basis="VERBATIM shape / DERIVED threshold: technique.md 2.1 (unbounded headers in "
                  "one part) + ELLIO line-flood counts [S23]",
            related=["109618"]))
    if text and len(text) > th["padding_run_min"]:
        pad = longest_run(text)
        stats["max_pad_run"] = pad
        if pad >= th["padding_run_min"]:
            findings.append(finding(
                "PADDING_FLOOD", "warn",
                f"{pad}-byte identical-character run in body - documented memory-padding "
                "flood shape (F5: 62,929-byte 'A' body; ELLIO: 24 MiB 'B' run)",
                evidence=f"single-char run of {pad} bytes",
                basis="VERBATIM shape / DERIVED threshold: technique.md 10.1/10.2 + tracker.md 4.3",
                related=["109618"]))

    # identical small-parts battery (the 149 x 288-byte weaponized PoC shape)
    for ln, cnt in same_len.items():
        if cnt >= th["identical_battery_min"] and ln <= th["identical_battery_len_max"]:
            ident_content = max(same_content.values()) if same_content else 0
            stats["identical_battery"] = {"count": cnt, "len": ln, "identical_content": bool(ident_content == cnt)}
            findings.append(finding(
                "IDENTICAL_SMALL_PARTS", "warn",
                f"{cnt} parts of identical length ({ln} bytes)"
                + (" with identical content" if ident_content == cnt else "")
                + " - documented weaponized PoC battery (ELLIO: 149 x 288-byte parts with "
                "PHP type/flag bytes, zeroed pointers)",
                evidence=f"{cnt} x {ln}-byte parts",
                basis="VERBATIM shape / DERIVED threshold: tracker.md 4.3 (149 x 288-byte parts, "
                      "PoC canary JACKALPOC defaults)",
                related=["109618"]))
            break
    if stats["null_file_parts"]:
        findings.append(finding(
            "NULL_FILE_PART", "warn",
            f"{stats['null_file_parts']} all-NUL short file part(s) - documented heap-grooming "
            "file shape (F5: file parts 'f'/'f=x.txt' containing 2 literal NUL bytes)",
            evidence=f"{stats['null_file_parts']} NUL-file parts",
            basis="VERBATIM: technique.md 10.2 (heap-grooming cadence: \\0-only 2-byte file bodies) [S22, S23]",
            related=["109619"]))

    body_len = len(text.encode("utf-8", "replace")) if text else 0
    if body_len and body_len in fingerprints.OOM_BODY_SIZE_CLUSTER:
        findings.append(finding(
            "OOM_BODY_SIZE_CLUSTER", "warn",
            f"logged request body is exactly a documented OOM-body cluster size ({body_len} bytes)",
            check="logs",
            evidence=str(body_len),
            basis="VERBATIM: ELLIO cluster 8,388,608/9,437,183/15,657,436/12,655,437/25,281,929; "
                  "F5 62,929 (technique.md 10.1/10.2; tracker.md 4.3)",
            related=["109618"]))

    return {"findings": findings, "stats": stats}


def _split_parts(text: str):
    """Split a multipart body into (part_body, content_disposition_line) pairs."""
    bndry_lines = _RE_BOUNDARY_LINE.findall(text)
    if len(bndry_lines) < 2:
        return []
    boundary = bndry_lines[0]
    chunks = text.split(boundary)
    out = []
    for chunk in chunks[1:]:
        if chunk.startswith("--"):
            continue  # final --boundary--
        chunk = chunk.lstrip("\r\n")
        disp = _RE_CONTENT_DISPOSITION.search(chunk)
        disp_line = (disp.group(0) if disp else "") or ""
        out.append((chunk, disp_line))
    return out


def _part_header_block(chunk: str) -> str:
    idx = chunk.find("\n\n")
    idxr = chunk.find("\r\n\r\n")
    if idxr != -1 and (idx == -1 or idxr < idx):
        idx = idxr
    return chunk[:idx] if idx != -1 else chunk[:512]


def longest_run(text: str) -> int:
    best, cur, prev = 0, 0, None
    for ch in text:
        if ch == prev:
            cur += 1
        else:
            cur, prev = 1, ch
        if cur > best:
            best = cur
    return best


# ---------------------------------------------------------------------------
# PHP / php-fpm error log rules (technique.md 10.3 server-side signatures)
# ---------------------------------------------------------------------------

RE_OOM_FATAL = re.compile(r"Fatal error:\s+Allowed memory size of\s+\S+\s+bytes exhausted", re.IGNORECASE)
RE_MAX_EXEC = re.compile(r"(?:Fatal error|Warning):\s*Maximum execution time of\s+\S+\s+seconds exceeded", re.IGNORECASE)
RE_WORKER_CRASH = re.compile(r"(exited on signal\s+\d+|\(SIG(?:SEGV|ABRT|BUS|PIPE|ILL|SYS|FPE)\))", re.IGNORECASE)
RE_STARTUP_DIAG = re.compile(r"PHP\s+(?:Warning:\s+)?PHP Startup:", re.IGNORECASE)
RE_DEPRECATED = re.compile(r"^(?:\[)?[^\]]*?\bDeprecated\b", re.IGNORECASE)


def scan_php_error_log(path: str, out: list, max_lines: int) -> dict:
    stats = {"lines_scanned": 0, "oom_fatal": 0, "max_exec": 0, "worker_crash": 0,
             "startup_diagnostic": 0, "deprecated": 0, "marker": 0}
    crash_lines = []
    try:
        for i, line in iter_lines(path):
            if i > max_lines:
                break
            stats["lines_scanned"] += 1
            if RE_OOM_FATAL.search(line):
                stats["oom_fatal"] += 1
                out.append(finding(
                    "PHP_OOM_FATAL", "warn",
                    "PHP 'Allowed memory size ... exhausted' fatal in error log - documented "
                    "109618/109619 producer + exploitation side effect (Wiz memory-limit errors; "
                    "paired with multipart POSTs on the access side this is the strongest signal)",
                    check="logs",
                    file=path, line=i, evidence=line.strip()[:200],
                    basis="VERBATIM: technique.md 10.3 (memory-limit fatal after multipart requests; "
                          "109619 producer includes 'Maximum execution time exceeded' & fatal errors) "
                          "[S8, S24, S2]", related=["109618", "109619"]))
            if RE_MAX_EXEC.search(line):
                stats["max_exec"] += 1
                out.append(finding(
                    "PHP_MAX_EXEC_TIME", "warn",
                    "'Maximum execution time exceeded' in PHP error log - an attacker-reachable "
                    "109619 producer (any fatal during the operation abandons state reset)",
                    check="logs",
                    file=path, line=i, evidence=line.strip()[:200],
                    basis="VERBATIM: technique.md 2.2/10.3 ('Maximum execution time exceeded' is a "
                          "109619 producer) [S2, S28]", related=["109619"]))
            if RE_WORKER_CRASH.search(line):
                stats["worker_crash"] += 1
                crash_lines.append((i, line))
            if RE_STARTUP_DIAG.search(line):
                stats["startup_diagnostic"] += 1
                out.append(finding(
                    "PHP_STARTUP_DIAGNOSTIC", "info",
                    "'PHP Startup' warning in PHP error log - the exact class of pre-request "
                    "INI diagnostics that touch stale error state (109619 consumer touchpoint); "
                    "context only, not attack evidence",
                    check="logs",
                    file=path, line=i, evidence=line.strip()[:200],
                    basis="VERBATIM: technique.md 2.2/10.3 (warnings not deprecations during "
                          "config apply touch stale state; 'diagnostics during extension/server "
                          "cleanup')", related=["109619"]))
            if RE_DEPRECATED.search(line) and not RE_STARTUP_DIAG.search(line):
                stats["deprecated"] += 1
                # do one finding total for deprecated noise
            if any(t in line.lower() for t in fingerprints.MARKER_TOKENS_CI):
                stats["marker"] += 1
                out.append(finding(
                    "DOCUMENTED_MARKER_TOKEN", "warn",
                    "documented PHP2Shell marker string in PHP error log",
                    check="logs",
                    file=path, line=i, evidence=clean_evidence(line),
                    basis=_RULE_BASIS_MARKER, related=["109618", "109619"]))
    except OSError as e:
        raise
    if stats["worker_crash"]:
        sev = "warn" if stats["worker_crash"] >= 3 else "info"
        first = crash_lines[0]
        out.append(finding(
            "WORKER_CRASH", sev,
            f"{stats['worker_crash']} PHP worker crash record(s) in this log (SIGSEGV/child exited on "
            "signal) - documented exploitation side effects (mod_php segfaults, FPM worker churn)",
            check="logs",
            file=path, line=first[0], evidence=first[1].strip()[:200],
            basis="VERBATIM: technique.md 10.3 (worker crashes/segfaults/FPM children killed) [S8, S19, S23]",
            related=["109618", "109619"]))
    if stats["deprecated"]:
        out.append(finding(
            "LOG_DEPRECATED_NOISE", "info",
            f"{stats['deprecated']} deprecated-feature line(s) in PHP error log - pre-application "
            "diagnostic touchpoints (109619 consumer class). Context only; review whether these "
            "come from config/extension apply rather than app code.",
            check="logs",
            file=path, evidence=f"{stats['deprecated']} lines",
            basis="VERBATIM: technique.md 2.2 (INI diagnostics before request initialization "
                  "touch stale error state)", related=["109619"]))
    return stats


# ---------------------------------------------------------------------------
# file scanning entry
# ---------------------------------------------------------------------------

def scan_access_log(path: str, fmt: str = "auto", max_lines: int = 200000,
                    finding_cap: int = 50) -> dict:
    out = []
    stats = {"lines_scanned": 0, "parsed": 0, "unparsed": 0, "findings": 0}
    cadence_state = {"rotation": defaultdict(set), "500s": defaultdict(int)}
    fmt_seen = set()
    try:
        for i, line in iter_lines(path):
            if i > max_lines:
                break
            stats["lines_scanned"] += 1
            if not line.strip():
                continue
            rec = parse_access_line(line)
            if rec is None:
                stats["unparsed"] += 1
                continue
            stats["parsed"] += 1
            fmt_seen.add(rec.get("format", "?"))
            eval_record(rec, line, i, path, out, cadence_state)
    except OSError as e:
        raise
    _finalize_cadence(cadence_state, path, out)

    detected_fmt = ",".join(sorted(fmt_seen)) if fmt_seen else "auto"
    findings = out
    compact = _compact_findings(findings)
    return stats | {
        "format": detected_fmt,
        "path": path,
        "findings": compact,
        "finding_count": len(findings),
        "finding_cap": 60,
    }


def _compact_findings(out: list, per_rule_display: int = 8, cap: int = 60) -> list:
    """Compaction for the report: per rule show the first N line hits with a
    repeat_count, then cap the whole list severity-first ("critical" first).
    Keeps aggregated rules (cadence / 5xx, appended late) from being cut by
    sheer per-line duplicate volume."""
    per_rule = defaultdict(list)
    for f in out:
        per_rule[f["rule"]].append(f)
    final = []
    for rule, fs in per_rule.items():
        fs.sort(key=lambda f: (f.get("line") or 0))
        kept = list(fs[:per_rule_display])
        if len(fs) > per_rule_display and kept:
            kept[0]["repeat_count"] = len(fs)
        final.extend(kept)
    sev_rank = {"critical": 0, "warn": 1, "info": 2, "ok": 3}
    final.sort(key=lambda f: (sev_rank.get(f.get("severity"), 9), f.get("line") or 0))
    return final[:cap]


def scan_log_file(path: str, fmt: str = "auto", max_lines: int = 200000,
                  finding_cap: int = 50, force_format: Optional[str] = None) -> dict:
    """Uniform single-file scanner: access formats + error-log heuristics in one."""

    is_error_log = _looks_like_error_log(path)
    out = []
    if is_error_log:
        stats = scan_php_error_log(path, out, max_lines)
        return {
            "path": path,
            "kind": "php_error_log",
            "lines_scanned": stats["lines_scanned"],
            "parsed": stats["lines_scanned"],
            "unparsed": 0,
            "format": "php/error",
            "findings": _compact_findings(out),
            "finding_count": len(out),
            "finding_cap": 60,
            "stats": stats,
        }
    res = scan_access_log(path, fmt=fmt, max_lines=max_lines, finding_cap=finding_cap)
    res["kind"] = "access_log"
    return res


def _looks_like_error_log(path) -> bool:
    if "error" in os.path.basename(path).lower():
        return True
    try:
        n = 0
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                n += 1
                if re.search(r"\b(php|fpm)\b.*(fatal|warning|notice|deprecated|exited on signal)", line, re.IGNORECASE) \
                        or "PHP" in line and "Fatal" in line:
                    return True
                if n >= 40:
                    break
    except OSError:
        pass
    return False