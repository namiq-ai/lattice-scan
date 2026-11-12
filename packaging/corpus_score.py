#!/usr/bin/env python3
"""Precision and recall of the host matcher on the synthetic corpus (tests/corpus/hosts.json), and the release check that the notes carry them.

A case is a Candidate when the matcher returns a match that is not a lead and whose version verdict is not outside-range: what a person would be asked
to act on. Each case's `truth` was written by hand with its reason. Two modes are scored, so a release states both what it does and what it replaced:

  identity   the signed identity list's rows are used (this release)
  names      no list: matching by names only (the behaviour before the identity join, 0.9.0 and earlier)

Local only: no network, no Lattice, no file outside the repository is written (the changelog reader looks for /usr/share/doc files named after the
invented packages and finds none).

  python3 packaging/corpus_score.py                      print the figures
  python3 packaging/corpus_score.py --json               the same as JSON
  python3 packaging/corpus_score.py --check-notes FILE   exit 1 unless FILE states this build's identity-mode precision and recall
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from lattice_scan import cli, lattice_identity as li  # noqa: E402

CORPUS = ROOT / "tests" / "corpus" / "hosts.json"
BASE_INV = {"kernel": "6.1.0-1-example", "os": "Example Linux", "manager": "dpkg", "node": "", "restartRequired": False, "hash": "corpus", "host": {},
            "packages": {}, "sources": {}, "snaps": {}, "images": [], "imageDetails": {}}


def cases() -> list:
    return json.loads(CORPUS.read_text())["cases"]


def predict(case: dict, mode: str) -> tuple:
    """(is a Candidate, why) for one case in one mode."""
    rows = {}
    for c in cases():
        r = c.get("row")
        if r and mode == "identity":
            comp = r.get("component")
            rows[c["entry"]["cve"]] = li.Row(c["entry"]["cve"], tuple(r["pids"]), li.Component(comp["role"], tuple(comp["binaries"])) if comp else None, "corpus")
    saved = cli.IDENTITY
    cli.IDENTITY = {"rows": rows if mode == "identity" else None, "aliases": {}, "note": "corpus"}
    try:
        inv = {**BASE_INV, **case["inventory"]}
        e = {"title": "", "added": "2099-01-02", "due": "2099-01-23", "action": "", "affected": [], **case["entry"]}
        m = cli.candidate(e, inv)
        if not m:
            return False, e.get("matchBasis") or "no match"
        if e.get("matchBasis") == "lead":
            return False, "lead"
        verdict = cli.impact(e, inv, m[1], m[2])["versionCheck"]["verdict"]
        return verdict != "outside-range", f"{e.get('matchBasis')}, {verdict}"
    finally:
        cli.IDENTITY = saved


def score(mode: str) -> dict:
    tp = fp = fn = tn = 0
    detail = []
    for c in cases():
        got, why = predict(c, mode)
        kind = ("TP" if c["truth"] else "FP") if got else ("FN" if c["truth"] else "TN")
        tp, fp, fn, tn = tp + (kind == "TP"), fp + (kind == "FP"), fn + (kind == "FN"), tn + (kind == "TN")
        detail.append({"id": c["id"], "result": kind, "why": why, "mirrors": c["mirrors"]})
    precision = round(tp / (tp + fp), 2) if tp + fp else 1.0
    recall = round(tp / (tp + fn), 2) if tp + fn else 1.0
    return {"mode": mode, "cases": len(detail), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "detail": detail}


def notes_line(s: dict) -> str:
    """The sentence the release notes must carry, exactly."""
    return f"Corpus: precision {s['precision']:.2f}, recall {s['recall']:.2f} on {s['cases']} synthetic host cases"


def main(argv: list) -> int:
    ident, names = score("identity"), score("names")
    if "--json" in argv:
        print(json.dumps({"identity": ident, "names": names}, indent=1))
        return 0
    if "--check-notes" in argv:
        f = Path(argv[argv.index("--check-notes") + 1])
        want = notes_line(ident)
        if want not in f.read_text():
            print(f"{f} must state the corpus figures of this build, exactly: {want!r}", file=sys.stderr)
            return 1
        print(f"release notes carry: {want}")
        return 0
    for s in (names, ident):
        print(f"{s['mode']:9} precision {s['precision']:.2f}  recall {s['recall']:.2f}  (TP {s['tp']} FP {s['fp']} FN {s['fn']} TN {s['tn']})")
    print()
    for a, b in zip(names["detail"], ident["detail"]):
        print(f"  {a['id']:4} names {a['result']} -> identity {b['result']:2}  {b['why']:<34} {a['mirrors']}")
    print("\n" + notes_line(ident))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
