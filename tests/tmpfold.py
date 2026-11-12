# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""One temporary root per test run, removed when the run ends.

Why: the tests made a fresh folder with tempfile.mkdtemp() in hundreds of places and never removed them. On a host whose /tmp is RAM-backed tmpfs that
is cleared only of entries untouched for 10 days, one day of test runs left 12,747 folders (26k entries) in memory. Importing this module points
tempfile and child processes (TMPDIR) at a single root and removes it at exit, read-only folders included. Use mkdtemp()/mktemp() from here; a test
(test_tmp_hygiene) refuses tempfile.mkdtemp/mktemp anywhere else in tests/.
"""
import atexit, os, shutil, stat, tempfile

ROOT = tempfile.mkdtemp(prefix="lattice-scan-tests-")
os.environ["TMPDIR"] = ROOT            # child processes (the CLI run as a subprocess) create their temp files inside it too
tempfile.tempdir = ROOT                 # and so does everything in this process that asks tempfile


def _force(func, path, _exc):
    try:
        os.chmod(path, stat.S_IRWXU)
        os.chmod(os.path.dirname(path), stat.S_IRWXU)
        func(path)
    except OSError:
        pass


@atexit.register
def _cleanup() -> None:
    for dirpath, dirnames, _ in os.walk(ROOT):          # tests make read-only homes (0o555); open them before removing
        for d in dirnames:
            try:
                os.chmod(os.path.join(dirpath, d), stat.S_IRWXU)
            except OSError:
                pass
    shutil.rmtree(ROOT, onerror=_force)


def mkdtemp(**kw) -> str:
    return tempfile.mkdtemp(dir=ROOT, **kw)


def mktemp(**kw) -> str:
    return tempfile.mktemp(dir=ROOT, **kw)
