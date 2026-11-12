#!/usr/bin/env python3
"""Precision and recall of the host matcher on the synthetic corpus (tests/corpus/hosts.json), and the release check that the notes carry them.

A case is a Candidate when the matcher returns a match that is not a lead and whose version verdict is not outside-range: what a person would be asked
to act on. Each case's `truth` was written by hand with its reason. Two modes are scored, so a release states both what it does and what it replaced:

  verdict    identity, then the consented distribution verdict: the client's real step (cli.distribution_verdicts) against a stand-in for graph_affects
             that answers from each case's `fixes` by the server's rule (graph-mcp affects.fix_verdict, OCO-6106). What a person who says yes gets.
  identity   the signed identity list's rows are used, the version compared as upstream numbers (what a person who says no gets)
  names      no list: matching by names only (the behaviour before the identity join, 0.9.0 and earlier)

Local only: no network, no Lattice, no file outside the repository is written (the changelog reader looks for /usr/share/doc files named after the
invented packages and finds none).

  python3 packaging/corpus_score.py                      print the figures
  python3 packaging/corpus_score.py --json               the same as JSON
  python3 packaging/corpus_score.py --check-notes FILE   exit 1 unless FILE states this build's identity-mode precision and recall
"""
from __future__ import annotations

import io
import json
import re
import sys
import tempfile
import types
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from lattice_scan import cli, lattice_identity as li, lattice_version as lv  # noqa: E402

CORPUS = ROOT / "tests" / "corpus" / "hosts.json"
BASE_INV = {"kernel": "6.1.0-1-example", "os": "Example Linux", "osRelease": "Debian 13", "manager": "dpkg", "node": "", "restartRequired": False, "hash": "corpus", "host": {},
            "packages": {}, "sources": {}, "snaps": {}, "images": [], "imageDetails": {}}


def cases() -> list:
    return json.loads(CORPUS.read_text())["cases"]


def _release(item: dict):
    """The server's release_of(): "Debian 13" -> "13", "Alpine 3.21" -> "v3.21", "" for a registry, None when unknown."""
    if item.get("ecosystem") in ("pypi", "npm", "maven", "cargo"):
        return ""
    m = re.fullmatch(r"\s*([A-Za-z]+)[ _-]*v?([0-9][0-9.]*)?\s*", item.get("os", ""))
    if not m or not m.group(2):
        return None
    fam, ver = m.group(1).lower(), m.group(2)
    if item["ecosystem"] == "deb" and fam == "debian":
        return ver.split(".")[0]
    if item["ecosystem"] == "apk" and fam == "alpine":
        return "v" + ".".join(ver.split(".")[:2])
    return None


class StandInServer:
    """Answers graph_affects from one case's `fixes` by the server's rule (graph-mcp affects.fix_verdict). The server's own tests pin that rule;
    this copy only lets the corpus see what the client does with the answer."""
    def __init__(self, cve: str, fixes: list):
        self.cve, self.fixes, self.sent = cve, fixes, []

    def call(self, tool: str, **it) -> dict:
        self.sent.append(it)
        pid = f"{it['ecosystem']}:{lv.normalise_product(it['product'], it['ecosystem'])}"
        mine = [f for f in self.fixes if f["pid"] == pid]
        if not mine:
            return {"results": []}
        rel = _release(it)
        basis = "registry" if rel == "" else "distribution"
        here = [f for f in mine if f.get("release", "") == rel] if rel is not None else []
        if not here:
            v = "undetermined"
        elif any(not (f.get("introduced") or f.get("fixed") or f.get("lastAffected")) for f in here):
            v = "in-range"
        else:
            rs = [{"scheme": f["scheme"], **({"start_including": f["introduced"]} if f.get("introduced") else {}),
                   **({"end_excluding": f["fixed"]} if f.get("fixed") else {"end_including": f["lastAffected"]} if f.get("lastAffected") else {})} for f in here]
            v = lv.verdict(it["version"], here[0]["scheme"], rs)
        return {"results": [{"cve": self.cve, "verdict": v, "why": f"stand-in: {v}", "basis": basis}]}


def predict(case: dict, mode: str) -> tuple:
    """(is a Candidate, why) for one case in one mode."""
    rows = {}
    for c in cases():
        r = c.get("row")
        if r and mode in ("identity", "verdict"):
            comp = r.get("component")
            rows[c["entry"]["cve"]] = li.Row(c["entry"]["cve"], tuple(r["pids"]), li.Component(comp["role"], tuple(comp["binaries"])) if comp else None, "corpus")
    saved = cli.IDENTITY
    cli.IDENTITY = {"rows": rows if mode in ("identity", "verdict") else None, "aliases": {}, "note": "corpus"}
    try:
        inv = {**BASE_INV, **case["inventory"]}
        e = {"title": "", "added": "2099-01-02", "due": "2099-01-23", "action": "", "affected": [], **case["entry"]}
        m = cli.candidate(e, inv)
        if not m:
            return False, e.get("matchBasis") or "no match"
        if e.get("matchBasis") == "lead":
            return False, "lead"
        imp = cli.impact(e, inv, m[1], m[2])
        if mode == "verdict" and e.get("matchBasis") == "identity":
            row = [e["cve"], "", "", "", "", "", "", "CANDIDATE", m[0]]
            with mock.patch.object(cli, "OUT", Path(tempfile.mkdtemp())), redirect_stderr(io.StringIO()):
                cli.distribution_verdicts(types.SimpleNamespace(yes=True), StandInServer(e["cve"], case.get("fixes") or []), inv, [(e, m[0], imp)], [row])
        verdict = imp["versionCheck"]["verdict"]
        return verdict != "outside-range", f"{e.get('matchBasis')}, {verdict}" + (f" ({imp['versionCheck']['basis']})" if imp["versionCheck"].get("basis") else "")
    finally:
        cli.IDENTITY = saved


def score(mode: str) -> dict:
    cli.JOINED.clear()
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
    """The sentence the release notes must carry, exactly: the figures with the distribution verdict (a person who says yes), and without it."""
    without = score("identity")
    return (f"Corpus: precision {s['precision']:.2f}, recall {s['recall']:.2f} on {s['cases']} synthetic host cases "
            f"(without the distribution verdict: {without['precision']:.2f}, {without['recall']:.2f})")


def main(argv: list) -> int:
    ident, names, verd = score("identity"), score("names"), score("verdict")
    if "--json" in argv:
        print(json.dumps({"identity": ident, "names": names, "verdict": verd}, indent=1))
        return 0
    if "--check-notes" in argv:
        f = Path(argv[argv.index("--check-notes") + 1])
        want = notes_line(verd)
        if want not in f.read_text():
            print(f"{f} must state the corpus figures of this build, exactly: {want!r}", file=sys.stderr)
            return 1
        print(f"release notes carry: {want}")
        return 0
    for s in (names, ident, verd):
        print(f"{s['mode']:9} precision {s['precision']:.2f}  recall {s['recall']:.2f}  (TP {s['tp']} FP {s['fp']} FN {s['fn']} TN {s['tn']})")
    print()
    for a, b, c in zip(names["detail"], ident["detail"], verd["detail"]):
        print(f"  {a['id']:4} names {a['result']} -> identity {b['result']} -> verdict {c['result']:2}  {c['why']:<44} {a['mirrors']}")
    print("\n" + notes_line(verd))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
