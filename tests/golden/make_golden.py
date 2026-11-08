"""Regenerates tests/golden/version_<scheme>.json: the cases lattice_version must reproduce. Not run by the tests (they only read the JSON).

Oracles: dpkg uses `dpkg --compare-versions`; pep440 uses the `packaging` library; the other schemes use ordered ladders written from each scheme's own
specification (semver 2.0.0 section 11, rpmvercmp, apk-tools version rules, Maven ComparableVersion), where every earlier entry is strictly below every later one.
Run: python3 tests/golden/make_golden.py   (needs dpkg and `packaging` for those two tables)
"""
import itertools, json, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "src"))
from lattice_scan import lattice_version as lv  # noqa: E402

DPKG = ["1.0", "1.0-1", "1.0-2", "1.0~rc1", "1.0~rc1-1", "1.0~~", "1.0~", "1.0+b1", "1.0a", "1.0.1", "1.1", "1:0.5", "1:1.0", "2.0", "2.0-1ubuntu3", "2.0-1ubuntu3.1",
        "2.0-1ubuntu10", "0.9.9+dfsg-2", "1.2.3-4~bpo11+1", "1.2.3-4", "1.2.3-4+deb12u1", "1.2.3-4+deb12u10", "1.02", "1.2", "10.0", "9.9", "1.0.0", "1.0-0",
        "7.0.0-41-cix", "3.0~beta1+really2.9"]
PEP440 = ["1.0", "1.0.0", "1.0a1", "1.0.a1", "1.0alpha1", "1.0b2", "1.0rc1", "1.0c1", "1.0.dev1", "1.0a1.dev3", "1.0.post1", "1.0-1", "1.0.post1.dev2", "1.0+local",
          "1.0+abc.5", "1.0+abc.10", "1!0.5", "2.0", "1.10", "1.9", "1.0.1", "0.9", "1.0rc1.post1", "1.0pre1", "1.0preview2", "1.0r1", "1.0.rev3", "1.0a", "1.0.0.0", "v1.0", "1.0b1+x"]
LADDERS = {
    "semver": ["0.0.1", "0.1.0", "0.9.9", "1.0.0-0", "1.0.0-1", "1.0.0-2", "1.0.0-10", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
               "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "1.10.0", "2.0.0-rc.1", "2.0.0", "10.0.0", "10.20.30"],
    "rpm": ["0.9", "1.0~rc1", "1.0~rc2", "1.0~rc10", "1.0", "1.0^git1", "1.0^git2", "1.0.1", "1.0.2", "1.0.10", "1.1", "1.2~beta", "1.2", "1.2a", "1.2b", "1.10", "2.0", "2.0.0",
            "10.0", "1:0.1", "1:0.2"],
    "apk": ["1.0_alpha", "1.0_alpha1", "1.0_alpha2", "1.0_beta", "1.0_beta1", "1.0_pre1", "1.0_rc1", "1.0_rc2", "1.0", "1.0-r1", "1.0-r2", "1.0-r10", "1.0_p1", "1.0_p1-r1", "1.0_p2",
            "1.0a", "1.0a-r1", "1.0b", "1.0.0", "1.0.1_rc1", "1.0.1", "1.1", "1.10", "2.0_rc1", "2.0"],
    "maven": ["1.0-alpha-1", "1.0-alpha-2", "1.0-beta-1", "1.0-milestone-1", "1.0-rc-1", "1.0-rc-2", "1.0-SNAPSHOT", "1.0", "1.0-sp-1", "1.0.1-alpha", "1.0.1", "1.1", "1.10",
              "2.0-rc-1", "2.0", "10.0"],
}
EQUAL = {  # pairs the scheme says are the same version
    "semver": [("1.0.0+build1", "1.0.0+build2"), ("1.0.0", "1.0.0+x"), ("v1.2.3", "1.2.3"), ("1.0.0-rc.1+a", "1.0.0-rc.1")],
    "rpm": [("1.0", "1.0"), ("1.0-1", "1.0-1"), ("0:1.0", "1.0"), ("1.01", "1.1"), ("1.0.", "1.0")],
    "apk": [("1.0", "1.0"), ("1.0-r0", "1.0"), ("1.0_rc1", "1.0_rc1"), ("1.0_p0", "1.0_p")],
    "maven": [("1.0", "1"), ("1.0", "1.0.0"), ("1.0-ga", "1.0"), ("1.0-final", "1.0"), ("1.0-release", "1"), ("1.0-cr-1", "1.0-rc-1")],
}
INVALID = {  # a string the scheme cannot read: the answer is None (undetermined), never a wrong order
    "semver": ["1.0", "1.0.0.0", "01.0.0", "abc", "", "1.0.0-"],
    "rpm": ["", "!!", "1 0"],
    "apk": ["abc", "", "1.0_unknown", "1..0"],
    "maven": ["", "!!", "-"],
    "pep440": ["", "abc", "1.0.0-foo!", "!1.0"],
    "dpkg": ["", "abc", "1.0 2", "!!"],
    "generic": ["", "abc", "x1.0"],
}


def dpkg_cmp(a, b):
    for op, r in (("lt", -1), ("eq", 0), ("gt", 1)):
        if subprocess.run(["dpkg", "--compare-versions", a, op, b]).returncode == 0:
            return r


def write(scheme, oracle, cases, probe=None):
    cases += [[a, "1.0", None] for a in INVALID[scheme]] + [["1.0", a, None] for a in INVALID[scheme]]
    (HERE / f"version_{scheme}.json").write_text(json.dumps({"scheme": scheme, "oracle": oracle, "cases": cases}, indent=0) + "\n")
    print(scheme, len(cases))


def main():
    cases = [[a, b, dpkg_cmp(a, b)] for a, b in itertools.product(DPKG, DPKG)]
    write("dpkg", subprocess.run(["dpkg", "--version"], capture_output=True, text=True).stdout.splitlines()[0], cases)
    from packaging.version import Version
    import packaging
    cases = [[a, b, (Version(a) > Version(b)) - (Version(a) < Version(b))] for a, b in itertools.product(PEP440, PEP440)]
    write("pep440", f"packaging {packaging.__version__}", cases)
    notes = {"semver": "semver 2.0.0 section 11 precedence", "rpm": "rpmvercmp (rpm/rpmio/rpmvercmp.c) rules", "apk": "apk-tools version rules",
             "maven": "Maven ComparableVersion rules"}
    for s, ladder in LADDERS.items():
        cases = []
        for i, j in itertools.combinations(range(len(ladder)), 2):
            cases += [[ladder[i], ladder[j], -1], [ladder[j], ladder[i], 1]]
        cases += [[a, b, 0] for a, b in EQUAL[s]] + [[b, a, 0] for a, b in EQUAL[s]]
        write(s, "ladder from the scheme specification: " + notes[s], cases)
    nums = [(a, b, c) for a in (0, 1, 2, 10) for b in (0, 1, 9) for c in (0, 1)]
    gen = sorted({".".join(map(str, n)) for n in nums}, key=lambda s: tuple(int(x) for x in s.split(".")))
    cases = []
    for i, j in itertools.combinations(range(len(gen)), 2):
        cases += [[gen[i], gen[j], -1], [gen[j], gen[i], 1]]
    cases += [["1", "1.0", 0], ["1.0.0", "1", 0], ["v1.2", "1.2", 0], ["1:2.0-1", "2.0", 0], ["7.0.0-41-cix", "7.0.0", 0], ["1.10", "1.9", 1], ["1.9", "1.10", -1], ["2.0.0-rc1", "2.0.0", 0]]
    write("generic", "dotted upstream numbers (the pre-existing lattice-scan behaviour); order by integer tuple", cases)


main()
