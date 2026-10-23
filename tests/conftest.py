import os
import stat
import sys
from pathlib import Path

TOOL_ROOT = Path(__file__).resolve().parents[1]

# make the package importable no matter where pytest is invoked from
sys.path.insert(0, str(TOOL_ROOT))


def make_fake_php(tmp_path, version: str, with_85_ini: bool = True) -> str:
    """Create a TEST-FIXTURE fake `php` binary that emulates -v / -i output."""
    path = tmp_path / f"php_{version.replace('.', '_')}"
    ini_lines = [
        "session.upload_progress.enabled => 1 => 1",
        "session.upload_progress.cleanup => 1 => 1",
        "memory_limit => 16M => 16M",
        "post_max_size => 8M => 8M",
        "upload_max_filesize => 2M => 2M",
        "max_file_uploads => 20 => 20",
    ]
    if with_85_ini:
        ini_lines.append("fatal_error_backtraces => 1 => 1")
    ini_cmds = "\n".join(f'      echo "{line}"' for line in ini_lines)
    script = (
        "#!/bin/sh\n"
        "# TEST FIXTURE (php2shell-detector tests): emulates a PHP binary; do not deploy.\n"
        'case "$1" in\n'
        '  -v) echo "PHP %s (cli) (built: Oct 2 2026 00:00:00) (NTS)"\n'
        '      echo "  Zend Engine v4.4";;\n'
        '  -i)\n' + ini_cmds + "\n      ;;\n"
        "  *) : ;;\n"
        "esac\n"
    ) % version
    path.write_text(script)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


def make_fixed_php(tmp_path, version: str) -> str:
    """Same fixture, but with upload progress disabled (a mitigated runtime)."""
    path = tmp_path / f"php_fixed_{version.replace('.', '_')}"
    script = (
        "#!/bin/sh\n"
        "# TEST FIXTURE (php2shell-detector tests): emulates a PHP binary; do not deploy.\n"
        'case "$1" in\n'
        '  -v) echo "PHP %s (cli) (built: Oct 2 2026 00:00:00) (NTS)";;\n'
        "  -i) echo \"session.upload_progress.enabled => 0 => 0\"\n"
        "      echo \"memory_limit => -1 => -1\"\n"
        "      echo \"post_max_size => 32M => 32M\";;\n"
        "  *) : ;;\n"
        "esac\n"
    ) % version
    path.write_text(script)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)