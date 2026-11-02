#!/usr/bin/env python3
"""Build every distributable of lattice-scan into dist/: the wheel, the single-file .pyz and the .deb. Local only: nothing is uploaded or signed here.

  python3 packaging/build.py            wheel + pyz + deb
The .deb installs the module under /usr/lib/python3/dist-packages and a /usr/bin/lattice-scan wrapper, depends on python3 (>= 3.9), and is arch 'all'.
"""
from __future__ import annotations
import gzip, os, shutil, subprocess, sys, tempfile, zipapp
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
SRC = HERE / "src" / "lattice_scan"
DIST = HERE / "dist"
sys.path.insert(0, str(HERE / "src"))
from lattice_scan import __version__ as VERSION  # noqa: E402

MAINTAINER = "NamiQ LLC <contact@namiq.io>"  # the contact Lattice itself gives in its answers
MODULES = ("__init__.py", "__main__.py", "cli.py", "manifests.py", "report.py")


def wheel() -> None:
    with tempfile.TemporaryDirectory() as t:
        shutil.copytree(HERE, t + "/src", ignore=shutil.ignore_patterns("dist", "__pycache__", "*.egg-info", "build"))
        subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-build-isolation", "--no-deps", "-q", "-w", str(DIST), t + "/src"], check=True)


def pyz() -> None:
    with tempfile.TemporaryDirectory() as t:
        (Path(t) / "lattice_scan").mkdir()
        for m in MODULES:
            shutil.copy(SRC / m, Path(t) / "lattice_scan" / m)
        for lic in ("LICENSE", "NOTICE"):  # Apache-2.0 asks that a redistributed copy carry the licence and notice
            shutil.copy(HERE / lic, Path(t) / lic)
        (Path(t) / "__main__.py").write_text("import sys\nfrom lattice_scan.cli import main\nsys.exit(main())\n")
        out = DIST / "lattice-scan.pyz"
        zipapp.create_archive(t, out, interpreter="/usr/bin/env python3")
        out.chmod(0o755)


def bundle() -> None:
    """Copy the .pyz into the skill, so the plugin runs it with nothing else installed. tests/test_skill.py fails if this copy is stale."""
    dest = HERE / "skills/lattice-scan/scripts"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy(DIST / "lattice-scan.pyz", dest / "lattice-scan.pyz")


def deb() -> None:
    with tempfile.TemporaryDirectory() as t:
        root = Path(t) / "pkg"
        lib = root / "usr/lib/python3/dist-packages/lattice_scan"
        lib.mkdir(parents=True)
        for m in MODULES:
            shutil.copy(SRC / m, lib / m)
        (root / "usr/bin").mkdir(parents=True)
        wrap = root / "usr/bin/lattice-scan"
        wrap.write_text("#!/usr/bin/python3\nimport sys\nfrom lattice_scan.cli import main\nsys.exit(main())\n")
        wrap.chmod(0o755)
        doc = root / "usr/share/doc/lattice-scan"
        doc.mkdir(parents=True)
        shutil.copy(HERE / "README.md", doc / "README.md")
        with gzip.open(doc / "changelog.Debian.gz", "wt") as f:
            f.write(f"lattice-scan ({VERSION}) stable; urgency=low\n\n  * First packaged release.\n\n -- {MAINTAINER}  Mon, 02 Nov 2026 00:00:00 +0000\n")
        # DEP-5 copyright file. The licence text is the one Debian already ships in /usr/share/common-licenses, which a .deb should reference, not repeat.
        (doc / "copyright").write_text(
            "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n"
            "Upstream-Name: lattice-scan\nUpstream-Contact: contact@namiq.io\nSource: https://github.com/namiq-ai/lattice-scan\n\n"
            "Files: *\nCopyright: 2026 NamiQ LLC\nLicense: Apache-2.0\n\n"
            "License: Apache-2.0\n On Debian systems the full text of the Apache License, Version 2.0 is in /usr/share/common-licenses/Apache-2.0.\n"
            " The names NamiQ and Lattice are not licensed for use; see the NOTICE file.\n")
        shutil.copy(HERE / "NOTICE", doc / "NOTICE")
        man = root / "usr/share/man/man1"
        man.mkdir(parents=True)
        # The manual page is a real file (man/lattice-scan.1); tests/test_docs.py keeps it in step with the options the tool has.
        text = (HERE / "man" / "lattice-scan.1").read_text().replace("lattice-scan 0.2.0", f"lattice-scan {VERSION}")
        with gzip.open(man / "lattice-scan.1.gz", "wt") as f:
            f.write(text)
        for q in root.rglob("*"):  # copies keep the source mode: set what a package should have
            q.chmod(0o755 if q.is_dir() or q == wrap else 0o644)
        size = sum(p.stat().st_size for p in root.rglob("*") if p.is_file()) // 1024 + 1
        ctl = root / "DEBIAN"
        ctl.mkdir()
        (ctl / "control").write_text(
            f"Package: lattice-scan\nVersion: {VERSION}\nSection: admin\nPriority: optional\nArchitecture: all\nDepends: python3 (>= 3.9)\n"
            f"Installed-Size: {size}\nMaintainer: {MAINTAINER}\nHomepage: https://namiq.io/lattice\n"
            "Description: match CISA-exploited CVEs against this host, through Lattice\n"
            " Looks up CVEs that CISA lists as exploited and compares each with the packages,\n"
            " kernel and container images installed here. Prints evidence for a person to read;\n"
            " it decides nothing. Only CVE ids leave the machine.\n")
        out = DIST / f"lattice-scan_{VERSION}_all.deb"
        subprocess.run(["fakeroot", "dpkg-deb", "--build", "-Zxz", str(root), str(out)], check=True, capture_output=True)


if __name__ == "__main__":
    os.umask(0o022)  # packaged files must be 0644 and dirs 0755 whatever the builder's umask
    shutil.rmtree(DIST, ignore_errors=True)
    DIST.mkdir()
    wheel(); pyz(); bundle(); deb()
    for p in sorted(DIST.iterdir()):
        print(f"{p.stat().st_size:>8}  {p.relative_to(HERE)}")
