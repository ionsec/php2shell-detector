import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from php2shell_detector import corpora  # noqa: E402
import conftest  # noqa: E402

TOOL_ROOT = Path(__file__).resolve().parents[1]


def run_cli(args, cwd=TOOL_ROOT):
    return subprocess.run([sys.executable, "-m", "php2shell_detector", *args],
                          capture_output=True, text=True, cwd=cwd, timeout=120)


def test_cli_clean_run_exit0(tmp_path):
    # benign logs + patched/mostly-mitigated fixture php + empty tmpdir, posture+logs+drift skipped
    log = tmp_path / "access_benign.log"
    log.write_text("\n".join(corpora.benign_access_combined() + corpora.benign_access_ltsv()) + "\n")
    errlog = tmp_path / "php_error_benign.log"  # name keeps error-log detection on the benign path
    errlog.write_text("\n".join(corpora.benign_php_error()) + "\n")
    empty_tmp = tmp_path / "tmp"
    empty_tmp.mkdir()
    fixed_php = conftest.make_fixed_php(tmp_path, "8.4.27")
    r = run_cli(["--check", "logs", "--check", "drift",
                 "--log", str(log), "--log", str(errlog),
                 "--tmpdir", str(empty_tmp), "--json"])
    assert r.returncode == 0, r.stdout[:2000]
    doc = json.loads(r.stdout)
    assert doc["summary"]["exit_code"] == 0
    assert doc["summary"]["counts"]["critical"] == 0
    assert doc["summary"]["counts"]["warn"] == 0
    assert doc["drift"]["files_hashed"] == 0


def test_cli_findings_run_exit1(tmp_path):
    log = tmp_path / "access_exploit.log"
    log.write_text("\n".join(corpora.exploit_access_combined() + corpora.exploit_access_ltsv()) + "\n")
    vulnerable_php = conftest.make_fake_php(tmp_path, "8.4.26", with_85_ini=False)
    empty_tmp = tmp_path / "tmp"
    empty_tmp.mkdir()
    r = run_cli(["--php-bin", vulnerable_php, "--log", str(log),
                 "--tmpdir", str(empty_tmp), "--json"])
    assert r.returncode == 1, r.stdout[:3000]
    doc = json.loads(r.stdout)
    assert doc["summary"]["exit_code"] == 1
    counts = doc["summary"]["counts"]
    assert counts["warn"] + counts["critical"] >= 2
    rules = {f["rule"] for f in doc["logs"]["findings"]}
    assert "UA_PHP2SHELL_TOOLING" in rules
    assert any(rt["version"] == "8.4.26" and rt["eval"]["status"] == "vulnerable_unpatched"
               for rt in doc["posture"]["runtimes"])
    # evidence is defanged (no raw dotted-quad IP in report output)
    blob = json.dumps(doc)
    assert "15.235.206.16" not in blob


def test_cli_text_mode_sections(tmp_path):
    log = tmp_path / "access_exploit.log"
    log.write_text("\n".join(corpora.exploit_access_combined()) + "\n")
    php = conftest.make_fake_php(tmp_path, "7.4.33", with_85_ini=False)
    empty_tmp = tmp_path / "tmp"
    empty_tmp.mkdir()
    r = run_cli(["--php-bin", php, "--log", str(log), "--tmpdir", str(empty_tmp)])
    assert r.returncode == 1
    assert "== HOST POSTURE ==" in r.stdout
    assert "== LOG SCAN ==" in r.stdout
    assert "== DRIFT CHECK" in r.stdout
    assert "eol_backportable" in r.stdout  # 7.4.33 EOL branch wording


def test_cli_missing_log_exit2(tmp_path):
    r = run_cli(["--log", str(tmp_path / "does_not_exist.log")])
    assert r.returncode == 2


def test_cli_quiet_mode(tmp_path):
    log = tmp_path / "access_exploit.log"
    log.write_text("\n".join(corpora.exploit_access_combined()) + "\n")
    r = run_cli(["--check", "logs", "--log", str(log), "--quiet"])
    assert r.returncode == 1
    # --quiet shows only warn/critical finding lines
    for line in r.stdout.splitlines():
        assert line.startswith("[warn") or line.startswith("[critical]") or line.strip() == ""
    assert "[warn]" in r.stdout or "[critical]" in r.stdout
    assert "== SUMMARY" not in r.stdout


def test_cli_no_args_exit_info(tmp_path):
    """Default run on this host: should not crash and not fail-with-findings spuriously."""
    r = run_cli(["--json"])
    assert r.returncode in (0, 1)
    doc = json.loads(r.stdout)
    assert doc["tool"] == "php2shell-detector"
    assert "posture" in doc and "drift" in doc