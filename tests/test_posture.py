import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from php2shell_detector import posture  # noqa: E402
import conftest  # noqa: E402


def test_eval_version_table():
    cases = [
        ((8, 4, 26), "vulnerable_unpatched", "warn"),
        ((8, 4, 27), "patched", "ok"),
        ((8, 4, 30), "patched", "ok"),
        ((8, 5, 11), "vulnerable_unpatched", "warn"),
        ((8, 5, 12), "patched", "ok"),
        ((8, 3, 35), "vulnerable_unpatched", "warn"),
        ((8, 3, 36), "patched", "ok"),
        ((8, 2, 34), "vulnerable_unpatched", "warn"),
        ((8, 2, 35), "patched", "ok"),
        ((8, 1, 34), "eol_backportable", "warn"),
        ((8, 0, 30), "eol_backportable", "warn"),
        ((7, 4, 33), "eol_backportable", "warn"),
        ((7, 3, 14), "eol_no_fix", "warn"),
        ((5, 6, 40), "eol_no_fix", "warn"),
        ((5, 2, 17), "pre_5_4", "info"),
        ((8, 6, 1), "unknown_future_branch", "info"),
        ((9, 0, 0), "unknown_future_branch", "info"),
    ]
    for (maj, mi, pa), status, sev in cases:
        ev = posture.eval_version(maj, mi, pa)
        assert ev["status"] == status, f"{maj}.{mi}.{pa} -> {ev['status']} (want {status})"
        assert ev["severity"] == sev, f"{maj}.{mi}.{pa} -> {ev['severity']} (want {sev})"
        assert ev.get("detail")


def test_rate_sapi_table():
    assert posture.rate_sapi(True, False, False, False)[0] == "critical"
    assert posture.rate_sapi(False, True, False, False)[0] == "warn"
    assert posture.rate_sapi(False, False, True, False)[0] == "warn"
    assert posture.rate_sapi(False, True, False, True)[0] == "warn"
    assert posture.rate_sapi(False, False, False, False)[0] == "info"


def test_fake_php_unpatched(tmp_path):
    php = conftest.make_fake_php(tmp_path, "8.4.26", with_85_ini=False)
    res = posture.run_posture(php_bin=php)
    rt = res["runtimes"][0]
    assert rt["version"] == "8.4.26"
    assert rt["eval"]["status"] == "vulnerable_unpatched"
    rules = [f["rule"] for f in res["findings"]]
    assert "PHP_RUNTIME_VERSION" in rules
    rows = {r["key"]: r for r in res["settings"]}
    assert rows["session.upload_progress.enabled"]["severity"] == "warn"
    assert rows["memory_limit"]["value"] == "16M"


def test_fake_php_patched_clean(tmp_path):
    php = conftest.make_fixed_php(tmp_path, "8.4.27")
    res = posture.run_posture(php_bin=php)
    up = [r for r in res["settings"] if r["key"] == "session.upload_progress.enabled"]
    assert up and up[0]["severity"] == "ok"
    ml = [r for r in res["settings"] if r["key"] == "memory_limit"]
    assert ml and ml[0]["severity"] == "ok"
    rt_sev = {f["severity"] for f in res["findings"] if f["rule"] == "PHP_RUNTIME_VERSION"}
    assert rt_sev == {"ok"}


def test_fake_php_85_backtraces_flag(tmp_path):
    # PHP 8.5 fixture exposes fatal_error_backtraces in -i; enabled -> warn (109619 producer)
    php = conftest.make_fake_php(tmp_path, "8.5.11", with_85_ini=True)
    res = posture.run_posture(php_bin=php)
    rows = {r["key"]: r for r in res["settings"]}
    assert rows["fatal_error_backtraces"]["severity"] == "warn"
    assert rows["fatal_error_backtraces"]["value"] == "1"


def test_mod_php_conf_is_critical(tmp_path):
    php = conftest.make_fake_php(tmp_path, "8.4.26", with_85_ini=False)
    conf = tmp_path / "apache2.conf.load"
    conf.write_text(
        "# test fixture apache config\n"
        "LoadModule php_module /usr/lib/apache2/modules/libphp8.4.so\n"
        "php_admin_value memory_limit 16M\n")
    res = posture.run_posture(php_bin=php, apache_conf=str(conf))
    assert res["sapi"]["rating"] == "critical"
    assert res["sapi"]["mod_php"]["installed"] is True
    sev = {f["severity"] for f in res["findings"] if f["rule"] == "SAPI_MOD_PHP_EXPOSED"}
    assert sev == {"critical"}
    rt_sev = {f["severity"] for f in res["findings"] if f["rule"] == "PHP_RUNTIME_VERSION"}
    # unpatched runtime + mod_php exposure -> escalated to critical
    assert rt_sev == {"critical"}
    ml = [r for r in res["settings"] if r["key"] == "memory_limit" and "apache" in r["source"]]
    assert ml and ml[0]["value"] == "16M"


def test_fpm_pool_conf(tmp_path):
    php = conftest.make_fake_php(tmp_path, "8.4.26", with_85_ini=False)
    pool = tmp_path / "www.conf"
    pool.write_text(
        "[www]\n"
        "pm = dynamic\n"
        "php_admin_flag[session.upload_progress.enabled] = off\n"
        "php_admin_value[memory_limit] = -1\n"
        "php_admin_value[fatal_error_backtraces] = 0\n"
        "pm.max_requests = 1\n")
    res = posture.run_posture(php_bin=php, fpm_conf=str(pool))
    assert res["sapi"]["fpm"]["installed"] is True
    assert res["sapi"]["rating"] == "warn"  # FPM still exposed via 109619
    rows = {r["key"]: r for r in res["settings"]}
    up = rows.get("session.upload_progress.enabled")
    assert up and up["severity"] == "ok" and "binding" in up["source"]
    ml = rows.get("memory_limit")
    assert ml and ml["value"] == "-1"
    # unpatched runtime + FPM (warn) does NOT escalate to critical
    assert {f["severity"] for f in res["findings"] if f["rule"] == "PHP_RUNTIME_VERSION"} == {"warn"}


def test_webroot_htaccess_and_user_ini(tmp_path):
    webroot = tmp_path / "www"
    webroot.mkdir()
    (webroot / ".htaccess").write_text(
        "php_value memory_limit 16M\n"
        "php_flag session.upload_progress.enabled 0\n")
    (webroot / ".user.ini").write_text("upload_max_filesize=2M\n")
    sub = webroot / "cms" / "admin"
    sub.mkdir(parents=True)
    (sub / ".htaccess").write_text("php_value memory_limit -1\n")
    res = posture.scan_webroot(str(webroot))
    names = [n.replace(os.sep, "/") for n in res["files"]]
    assert ".htaccess" in names and ".user.ini" in names and "cms/admin/.htaccess" in names
    rules = [f["rule"] for f in res["findings"]]
    assert "HTACCESS_PHP_DIRECTIVE" in rules
    assert "USER_INI_DIRECTIVE" in rules


def test_no_php_found_is_graceful():
    res = posture.run_posture(php_bin="/nonexistent/php")  # explicit bin never found
    rules = [f["rule"] for f in res["findings"]]
    assert res["runtimes"] == []
    assert "PHP_BIN_UNREADABLE" in rules


def test_ini_file_parse(tmp_path):
    ini = tmp_path / "php.ini"
    ini.write_text(
        "; comment\n"
        "session.upload_progress.enabled = 1\n"
        "session.upload_progress.cleanup = 0\n"
        "memory_limit = 128M\n"
        "fatal_error_backtraces = 1\n")
    res = posture.run_posture(extra_inis=[str(ini)])
    rows = {r["key"]: r for r in res["settings"]}
    assert rows["session.upload_progress.enabled"]["severity"] == "warn"
    assert rows["fatal_error_backtraces"]["severity"] == "warn"
    assert rows["memory_limit"]["value"] == "128M"
    # cleanup value reported as context, not a finding
    assert rows["session.upload_progress.cleanup"]["severity"] == "info"