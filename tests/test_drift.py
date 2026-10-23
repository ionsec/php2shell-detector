import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from php2shell_detector import drift  # noqa: E402


def test_builtin_fingerpints_loaded():
    fps = drift.all_fingerprints()
    assert any("loader" in f["label"] for f in fps)
    assert all(f.get("sha256") or f.get("md5") for f in fps)


def test_synthetic_hash_match(tmp_path):
    """Machinery test with a synthetic fingerprint (NOT a real-world IOC)."""
    payload = b"SYNTHETIC-TEST-PAYLOAD-NOT-A-REAL-IOC\n" * 7
    p = tmp_path / "dropped.bin"
    p.write_bytes(payload)
    fps = [{
        "label": "synthetic test fingerprint (tests only)",
        "md5": hashlib.md5(payload).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
        "drop_paths": [],
        "source": "test fixture",
    }]
    res = drift.scan(paths=[str(tmp_path)], fps=fps)
    hits = [f for f in res["findings"] if f["rule"] == "DRIFT_HASH_MATCH"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "critical"
    assert hits[0]["file"] == str(p)
    assert "no attribution" in hits[0]["message"]
    assert res["files_hashed"] >= 1
    assert res["networked"] is False


def test_no_match_is_clean(tmp_path):
    (tmp_path / "harmless.txt").write_bytes(b"nothing suspicious here\n")
    res = drift.scan(paths=[str(tmp_path)])
    assert res["files_hashed"] == 1
    assert [f for f in res["findings"] if f["severity"] == "critical"] == []


def test_drop_name_presence_is_info_only(tmp_path):
    (tmp_path / "nfs").write_bytes(b"unrelated content - only the name matches the IOC\n")
    res = drift.scan(paths=[str(tmp_path)])
    rules = [f["rule"] for f in res["findings"]]
    assert rules == ["DRIFT_DROP_PATH_PRESENT"]
    f = res["findings"][0]
    assert f["severity"] == "info"
    assert "verify by hashing" in f["message"]


def test_hash_match_suppresses_name_info(tmp_path):
    payload = b"loader-bytes\n" * 3
    p = tmp_path / "nfs"
    p.write_bytes(payload)
    fps = [{
        "label": "synthetic loader fingerprint (tests only)",
        "md5": hashlib.md5(payload).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
        "drop_paths": ["/tmp/nfs"],
        "source": "test fixture",
    }]
    res = drift.scan(paths=[str(tmp_path)], fps=fps)
    rules = [f["rule"] for f in res["findings"]]
    assert "DRIFT_HASH_MATCH" in rules
    assert "DRIFT_DROP_PATH_PRESENT" not in rules  # hash verdict replaces name info


def test_skips_oversized_files(tmp_path, monkeypatch):
    monkeypatch.setattr(drift, "SKIP_SIZE", 16)
    (tmp_path / "big.bin").write_bytes(b"x" * 32)
    (tmp_path / "small.bin").write_bytes(b"small")
    res = drift.scan(paths=[str(tmp_path)])
    assert res["skipped_large"] == 1
    assert res["files_hashed"] == 1


def test_missing_path_noted(tmp_path):
    res = drift.scan(paths=[str(tmp_path), "/nonexistent-tmp-probe"])
    assert "/nonexistent-tmp-probe" in res["paths_missing"]


def test_symlinks_not_followed(tmp_path):
    real = tmp_path / "realdir"
    real.mkdir()
    (real / "inner.txt").write_bytes(b"data\n")
    link = tmp_path / "link.txt"
    os.symlink(real / "inner.txt", link)
    res = drift.scan(paths=[str(tmp_path)])
    assert res["files_hashed"] >= 1  # inner.txt hashed directly, symlink skipped