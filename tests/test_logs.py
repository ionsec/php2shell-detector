import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from php2shell_detector import corpora, logs  # noqa: E402


def _rules_for(path, fmt="auto"):
    res = logs.scan_log_file(str(path), fmt=fmt, max_lines=5000)
    return res, [f["rule"] for f in res["findings"]]


def _write(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n")
    return p


def test_benign_access_log_no_findings(tmp_path):
    p = _write(tmp_path, "access_benign.log",
               corpora.benign_access_combined() + corpora.benign_access_ltsv())
    res, rules = _rules_for(p)
    assert res["finding_count"] == 0, f"unexpected findings: {res['findings']}"
    assert res["unparsed"] == 0


def test_exploit_combined_log_rules(tmp_path):
    p = _write(tmp_path, "access_exploit.log", corpora.exploit_access_combined())
    res, rules = _rules_for(p)
    assert "UA_PHP2SHELL_TOOLING" in rules
    # the corpus live-code UA carries the php2shellLP stem -> family rule (with
    # embedded-code wording); a code-token-only UA is covered in test_ua_code_without_family
    assert "PHP_FILTER_QUERY_READ" in rules
    assert "HARDCODED_SESSION_ID" in rules
    assert "REPEATED_5XX" in rules


def test_ua_code_without_family(tmp_path):
    # code-token UA with no php2shell token -> dedicated rule
    ua = "<?php system('id'); ?> probe"
    line = f'1.2.3.4 - - [21/Oct/2026:08:37:01 +0000] "GET / HTTP/1.1" 200 10 "-" "{ua}"'
    p = tmp_path / "access_livecode.log"
    p.write_text(line + "\n")
    res = logs.scan_log_file(str(p))
    lrules = [f["rule"] for f in res["findings"]]
    assert "UA_LIVE_CODE_EXEC" in lrules, lrules


def test_exploit_ltsv_body_shapes(tmp_path):
    p = _write(tmp_path, "access_exploit_ltsv.log", corpora.exploit_access_ltsv())
    res, rules = _rules_for(p)
    for expected in (
        "UPLOAD_PROGRESS_FIELD",
        "UPLOAD_PROGRESS_DOCUMENTED_VALUES",
        "EMPTY_FILE_PART_FLOOD",
        "FIELD_NESTING_DEEP",
        "PART_HEADER_FLOOD",
        "PADDING_FLOOD",
        "IDENTICAL_SMALL_PARTS",
        "NULL_FILE_PART",
        "UNTRUSTED_CONTENT_LENGTH",
        "OOM_BODY_SIZE_CLUSTER",
        "ROTATING_SESSION_CADENCE",
        "HARDCODED_SESSION_ID",
    ):
        assert expected in rules, f"missing rule {expected}; got {sorted(set(rules))}"


def test_php_error_log_rules(tmp_path):
    p = _write(tmp_path, "php_error_exploit.log", corpora.exploit_php_error())
    res, rules = _rules_for(p)
    assert res["kind"] == "php_error_log"
    for expected in ("PHP_OOM_FATAL", "PHP_MAX_EXEC_TIME", "WORKER_CRASH",
                     "PHP_STARTUP_DIAGNOSTIC", "DOCUMENTED_MARKER_TOKEN"):
        assert expected in rules, f"missing {expected}; got {sorted(set(rules))}"
    # 3+ crash records -> warn
    wc = [f for f in res["findings"] if f["rule"] == "WORKER_CRASH"]
    assert all(f["severity"] == "warn" for f in wc)


def test_benign_php_error_log_no_warn(tmp_path):
    p = _write(tmp_path, "php_error_benign.log", corpora.benign_php_error())
    res, rules = _rules_for(p)
    sevs = [f["severity"] for f in res["findings"]]
    assert not [s for s in sevs if s in ("warn", "critical")], f"unexpected: {res['findings']}"


def test_multipart_shape_isolation(tmp_path):
    """Each shape triggers in isolation and produces exactly its rule."""
    shapes = []
    b = corpora.BOUNDARY_ATK
    shapes.append(("empty", corpora.multipart(b, [corpora.form_part(f"f{i:03d}", "", filename="")
                                                  for i in range(120)]), "EMPTY_FILE_PART_FLOOD"))
    shapes.append(("nest", corpora.multipart(b, [corpora.form_part("a" + "[9]" * 13, "x")]),
                   "FIELD_NESTING_DEEP"))
    shapes.append(("hdr", corpora.multipart(b, [corpora.form_part("big", "x", extra_headers=1100)]),
                   "PART_HEADER_FLOOD"))
    shapes.append(("pad", corpora.multipart(b, [corpora.form_part("pad", "A" * 30001)]),
                   "PADDING_FLOOD"))
    shapes.append(("battery", corpora.multipart(b, [corpora.form_part("p1", "Q" * 288)
                                                    for _ in range(65)]), "IDENTICAL_SMALL_PARTS"))
    shapes.append(("nul", corpora.multipart(b, [corpora.form_part("f", "\x00\x00", filename="x.txt")]),
                   "NULL_FILE_PART"))
    for name, body, rule in shapes:
        single = corpora.ltsv({"host": "10.9.9.9", "time": "21/Oct/2026:16:00:00",
                               "req": "POST /probe HTTP/1.1", "status": "200", "size": "0",
                               "ua": corpora.CHROME_UA, "body": corpora.esc(body)})
        p = _write(tmp_path, f"shape_{name}.log", [single])
        res, rules = _rules_for(p)
        assert rule in rules, f"{name}: {rule} not fired; got {sorted(set(rules))}"


def test_gzip_log_file_scanned(tmp_path):
    import gzip as gz
    body = corpora.multipart(corpora.BOUNDARY_ATK, [corpora.form_part("PHP_SESSION_UPLOAD_PROGRESS",
                                                                     corpora.PROGRESS_VALUE_P2S)])
    line = corpora.ltsv({"host": "10.9.9.1", "time": "21/Oct/2026:16:05:01",
                         "req": "POST /upload.php HTTP/1.1", "status": "200", "size": "98",
                         "ua": "php2shell-scan/109618", "body": corpora.esc(body)})
    p = tmp_path / "access_rotated.gz"
    with gz.open(p, "wt") as fh:
        fh.write(line + "\n")
    res, rules = _rules_for(p)
    assert "UA_PHP2SHELL_TOOLING" in rules and "UPLOAD_PROGRESS_FIELD" in rules


def test_untrusted_content_length_shapes(tmp_path):
    body = corpora.multipart(corpora.BOUNDARY_B7K618, [corpora.form_part("blob", "B" * 5000)])
    fields = {"host": "10.9.9.6", "time": "21/Oct/2026:16:10:00",
              "req": "POST /import.php HTTP/1.1", "status": "200", "size": "0",
              "ua": corpora.CHROME_UA, "content_length": "1000", "body": corpora.esc(body)}
    p = _write(tmp_path, "access_cl.log", [corpora.ltsv(fields)])
    res, rules = _rules_for(p)
    assert "UNTRUSTED_CONTENT_LENGTH" in rules
    # same body but honest Content-Length -> no finding
    fields["content_length"] = str(len(body) + 40)
    p2 = _write(tmp_path, "access_cl_ok.log", [corpora.ltsv(fields)])
    res2, rules2 = _rules_for(p2)
    assert "UNTRUSTED_CONTENT_LENGTH" not in rules2