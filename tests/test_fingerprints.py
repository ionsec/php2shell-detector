"""Corpus + fingerprint consistency tests (the zero-invented-fingerprints audit)."""

import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from php2shell_detector import corpora, fingerprints, logs  # noqa: E402


def clean_state():
    return {"rotation": defaultdict(set), "500s": defaultdict(int)}


def test_fixed_versions_match_briefs():
    # technique.md section 3.1: fixes released 2026-10-21 for exactly these branches
    assert fingerprints.FIXED_VERSIONS == {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
    assert fingerprints.EOL_LAST_SUPPORTED == (8, 1)
    assert fingerprints.BACKPORTABLE_BRANCHES == {(7, 4), (8, 0), (8, 1)}
    assert fingerprints.AFFECTED_SINCE == (5, 4)


def test_potassium_hashes_match_briefs():
    p = fingerprints.POTASSIUM_LOADER
    assert p["md5"] == "b61a098fc62a2c2696e196dca78da71a"
    assert p["sha1"] == "c472dab4ff7c16782a8037f988d4daa6d4bdb343"
    assert p["sha256"] == "0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486"
    assert p["size_bytes"] == 179632
    assert p["drop_paths"] == ["/tmp/nfs"]


def test_hash_format_sanity():
    for fp in [fingerprints.POTASSIUM_LOADER, *fingerprints.ELLIIO_EXTRA_PAYLOADS]:
        sha = fp.get("sha256", "")
        assert len(sha) == 64 and all(c in "0123456789abcdef" for c in sha.lower())
        md5 = fp.get("md5", "")
        assert len(md5) in (0, 32) and all(c in "0123456789abcdef" for c in md5.lower())


def test_every_verbatim_ua_is_caught():
    """Forward audit: each exact UA published in the briefs must fire at least one rule."""
    for ua in fingerprints.VERBATIM_USER_AGENTS:
        rec = {"method": "GET", "uri": "/", "status": 200, "ua": ua,
               "cookie": "", "body": "", "content_length": ""}
        out = []
        line = f'1.2.3.4 - - [21/Oct/2026:08:37:01 +0000] "GET / HTTP/1.1" 200 10 "-" "{ua}"'
        logs.eval_record(rec, line, 1, "test.log", out, clean_state())
        rules = [f["rule"] for f in out]
        assert "UA_PHP2SHELL_TOOLING" in rules or "UA_LIVE_CODE_EXEC" in rules, (
            f"UA not detected: {ua!r} -> {rules}")


def test_verbatim_ua_uses_only_basically_the_php2shell_family():
    # sanity: the token family is narrow (php2shell + the two documented
    # non-"php2shell" tool UAs) and case-insensitive
    assert "php2shell" in [t.lower() for t in fingerprints.UA_TOKENS_CI]
    assert any("upload-progress-scan" in t for t in fingerprints.UA_TOKENS_CI)
    assert any("session-start-rce-poc" in t for t in fingerprints.UA_TOKENS_CI)


def test_benign_uas_are_not_flagged():
    benign = {
        "curl": "curl/8.5.0",
        "plain": "Mozilla/5.0",
        "chrome": corpora.CHROME_UA,
        "firefox": corpora.FIREFOX_UA,
        "requests": "python-requests/2.31.0",
    }
    for label, ua in benign.items():
        rec = {"method": "POST", "uri": "/upload.php", "status": 200, "ua": ua,
               "cookie": "", "body": "", "content_length": ""}
        out = []
        line = f'1.2.3.4 - - [21/Oct/2026:08:37:01 +0000] "POST /upload.php HTTP/1.1" 200 10 "-" "{ua}"'
        logs.eval_record(rec, line, 1, "test.log", out, clean_state())
        assert not out, f"benign UA {label} produced findings: {out}"


def test_benign_corpora_are_clean():
    out = []
    state = clean_state()
    for i, line in enumerate(corpora.all_benign_lines(), 1):
        rec = logs.parse_access_line(line)
        assert rec is not None, f"benign line failed to parse: {line[:100]!r}"
        logs.eval_record(rec, line, i, "benign.log", out, state)
    assert not out, f"benign corpus produced findings: {[f['rule'] for f in out]}"


def test_exploit_corpus_lines_parse():
    exploit = corpora.exploit_access_combined() + corpora.exploit_access_ltsv()
    for line in exploit:
        rec = logs.parse_access_line(line)
        assert rec is not None, f"exploit line failed to parse: {line[:80]!r}"