#!/usr/bin/env python3
"""Build a small signed apt repository from the .deb in dist/. It signs with a key YOU name; it never creates one and never uploads anything.

  python3 packaging/build_apt_repo.py --key KEYID [--gnupghome DIR] [--out repo/]

Result (static files, serve them from any web server):
  pool/main/l/lattice-scan/lattice-scan_<v>_all.deb
  dists/stable/main/binary-all/Packages{,.gz}
  dists/stable/{Release,InRelease,Release.gpg}     InRelease is the clear-signed Release apt prefers
  lattice-scan.gpg                                  the public key, binary, for  signed-by=
Keep the private key off the web server: build and sign on one machine, copy only the output.
"""
from __future__ import annotations
import argparse, datetime as dt, gzip, hashlib, os, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def digests(p: Path) -> dict:
    b = p.read_bytes()
    return {"md5": hashlib.md5(b).hexdigest(), "sha1": hashlib.sha1(b).hexdigest(), "sha256": hashlib.sha256(b).hexdigest(), "size": len(b)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True, help="key id or fingerprint of the signing key")
    ap.add_argument("--gnupghome", help="GnuPG home holding that key")
    ap.add_argument("--out", default=str(HERE / "repo"))
    ap.add_argument("--dist", default=str(HERE / "dist"))
    a = ap.parse_args()
    env = dict(os.environ, **({"GNUPGHOME": a.gnupghome} if a.gnupghome else {}))
    out, debs = Path(a.out), sorted(Path(a.dist).glob("*.deb"))
    if not debs:
        print("no .deb in dist/: run packaging/build.py first", file=sys.stderr); return 2
    shutil.rmtree(out, ignore_errors=True)
    stanzas = []
    for deb in debs:
        name = deb.name.split("_")[0]
        pool = out / "pool/main" / name[0] / name
        pool.mkdir(parents=True, exist_ok=True)
        shutil.copy(deb, pool / deb.name)
        ctl = subprocess.run(["dpkg-deb", "-f", str(deb)], capture_output=True, text=True, check=True).stdout.strip()
        d = digests(deb)
        stanzas.append(f"{ctl}\nFilename: pool/main/{name[0]}/{name}/{deb.name}\nSize: {d['size']}\nMD5sum: {d['md5']}\nSHA1: {d['sha1']}\nSHA256: {d['sha256']}\n")
    idx = out / "dists/stable/main/binary-all"
    idx.mkdir(parents=True)
    pk = "\n".join(stanzas).encode()
    (idx / "Packages").write_bytes(pk)
    with gzip.GzipFile(idx / "Packages.gz", "wb", mtime=0) as f:
        f.write(pk)
    rel = out / "dists/stable"
    files = [p for p in sorted(idx.iterdir())]
    lines = ["Origin: NamiQ", "Label: lattice-scan", "Suite: stable", "Codename: stable", "Architectures: all", "Components: main",
             "Description: lattice-scan packages", f"Date: {dt.datetime.now(dt.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S UTC')}"]
    for algo, key in (("MD5Sum", "md5"), ("SHA1", "sha1"), ("SHA256", "sha256")):
        lines.append(f"{algo}:")
        lines += [f" {digests(p)[key]} {digests(p)['size']:>8} {p.relative_to(rel)}" for p in files]
    (rel / "Release").write_text("\n".join(lines) + "\n")
    g = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--local-user", a.key]
    subprocess.run(g + ["--clearsign", "-o", str(rel / "InRelease"), str(rel / "Release")], check=True, env=env)
    subprocess.run(g + ["--armor", "--detach-sign", "-o", str(rel / "Release.gpg"), str(rel / "Release")], check=True, env=env)
    pub = subprocess.run(["gpg", "--export", a.key], capture_output=True, check=True, env=env).stdout
    (out / "lattice-scan.gpg").write_bytes(pub)
    print(f"repository in {out}\nkey fingerprint: " + subprocess.run(["gpg", "--with-colons", "--fingerprint", a.key], capture_output=True, text=True, env=env).stdout.split("fpr:::::::::")[1].split(":")[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
