# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The one implementation of version comparison, product identity and the verdict ladder.

Every consumer (the lattice-scan CLI, the index build, the MCP item tools, the report service) imports THIS file, so the same package and version never
get two different answers. It is copied unchanged into a consumer that cannot import lattice_scan; `VENDORED.sha256` beside it holds its hash and a test (and
the consumer's CI) fails when a copy differs. Standard library only; Python 3.9 and later.

Schemes: semver, pep440, dpkg, apk, rpm, maven, generic.
    generic  dotted upstream numbers (1.2.3); anything after the number is dropped. What NVD's CPE bounds are (they carry no scheme) and what a distro
             version becomes once its epoch and revision are removed. A distribution can fix a CVE under an unchanged upstream number, so a result from
             this scheme is a lead for a person to read, never a verdict.

Range bounds follow NVD exactly: startIncluding and endIncluding are inclusive, startExcluding and endExcluding are exclusive.

A version in a scheme different from the range's, or one the scheme cannot parse, gives None (undetermined), never "outside-range". The one exception is a
range whose scheme is `generic`: both sides are reduced to their dotted upstream numbers and compared, because that is all an NVD bound says.
"""
from __future__ import annotations

import re

SCHEMES = ("semver", "pep440", "dpkg", "apk", "rpm", "maven", "generic")

# ---------------------------------------------------------------- the verdict ladder (AD-5)
# Strongest evidence first for reading order; `unmatch` is below the ladder (nothing linked the product).
VERDICTS = ("in-range", "undetermined", "outside-range", "lead", "unmatch")
VERDICT_RANK = {v: i for i, v in enumerate(VERDICTS)}   # a lead ranks below every real comparison


def strongest(verdicts):
    """The most pressing verdict of several components: a lead or an undetermined must never hide an in-range one, or the other way round."""
    return min(verdicts, key=lambda v: VERDICT_RANK[v]) if verdicts else "unmatch"


# ---------------------------------------------------------------- generic
def generic_key(version):
    """(2, 17, 1) for '1:2.17.1-1ubuntu3', 'v22.22.1' or '7.0.0-41-cix'; None when there is no leading dotted number."""
    v = re.sub(r"^\d+:", "", str(version).strip().lstrip("vV"))
    m = re.match(r"\d+(\.\d+)*", v)
    return tuple(int(x) for x in m.group(0).split(".")) if m else None


def _cmp_seq(a, b):
    return (a > b) - (a < b)


def _cmp_padded(a, b):
    n = max(len(a), len(b))
    return _cmp_seq(tuple(a) + (0,) * (n - len(a)), tuple(b) + (0,) * (n - len(b)))


def cmp_generic(a, b):
    ka, kb = generic_key(a), generic_key(b)
    return None if ka is None or kb is None else _cmp_padded(ka, kb)


# ---------------------------------------------------------------- semver 2.0.0
_SEMVER = re.compile(r"^[vV]?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")


def _semver_parse(v):
    m = _SEMVER.match(str(v).strip())
    if not m:
        return None
    pre = m.group(4)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))), (pre.split(".") if pre else None)


def cmp_semver(a, b):
    pa, pb = _semver_parse(a), _semver_parse(b)
    if pa is None or pb is None:
        return None
    if pa[0] != pb[0]:
        return _cmp_seq(pa[0], pb[0])
    ra, rb = pa[1], pb[1]
    if ra is None and rb is None:
        return 0
    if ra is None:
        return 1          # a release is above any of its pre-releases
    if rb is None:
        return -1
    for x, y in zip(ra, rb):
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            if int(x) != int(y):
                return _cmp_seq(int(x), int(y))
        elif xn != yn:
            return -1 if xn else 1       # numeric identifiers are below alphanumeric ones
        elif x != y:
            return _cmp_seq(x, y)        # ASCII order
    return _cmp_seq(len(ra), len(rb))


# ---------------------------------------------------------------- PEP 440
_PEP440 = re.compile(r"""^\s*v?(?:(?P<epoch>\d+)!)?(?P<rel>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pl>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pn>\d+)?)?
    (?:(?:-(?P<post1>\d+))|(?:[-_.]?(?P<postl>post|rev|r)[-_.]?(?P<post2>\d+)?))?
    (?:[-_.]?(?P<devl>dev)[-_.]?(?P<devn>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$""", re.X | re.I)
_NEG, _POS = (-1,), (1 << 60,)


def _pep440_key(v):
    m = _PEP440.match(str(v))
    if not m:
        return None
    epoch = int(m.group("epoch") or 0)
    rel = [int(x) for x in m.group("rel").split(".")]
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    pre = None
    if m.group("pl"):
        tag = {"alpha": "a", "a": "a", "beta": "b", "b": "b", "c": "rc", "rc": "rc", "pre": "rc", "preview": "rc"}[m.group("pl").lower()]
        pre = (tag, int(m.group("pn") or 0))
    post = None
    if m.group("post1") is not None:
        post = int(m.group("post1"))
    elif m.group("postl"):
        post = int(m.group("post2") or 0)
    dev = int(m.group("devn") or 0) if m.group("devl") else None
    local = None
    if m.group("local"):
        local = tuple((1, int(p), "") if p.isdigit() else (0, 0, p.lower()) for p in re.split(r"[-_.]", m.group("local")))
    # ordering of the missing parts follows PEP 440: x.dev < x.a < x.b < x.rc < x < x.post
    if pre is None and post is None and dev is not None:
        k_pre = (-1, "", 0)
    elif pre is None:
        k_pre = (1 << 60, "", 0)
    else:
        k_pre = (0, pre[0], pre[1])
    k_post = (-1,) if post is None else (0, post)
    k_dev = (1 << 60,) if dev is None else (0, dev)
    k_local = (-1,) if local is None else (0, local)
    return epoch, tuple(rel), k_pre, k_post, k_dev, k_local


def cmp_pep440(a, b):
    ka, kb = _pep440_key(a), _pep440_key(b)
    return None if ka is None or kb is None else _cmp_seq(ka, kb)


# ---------------------------------------------------------------- dpkg (Debian policy 5.6.12)
def _dpkg_order(c):
    if c == "~":
        return -1
    if c == "":
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_part(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        first = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return _cmp_seq(ac, bc)
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first:
                first = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first:
            return _cmp_seq(first, 0)
    return 0


def _dpkg_split(v):
    v = str(v).strip()
    if not v or not re.match(r"^(\d+:)?[0-9][A-Za-z0-9.+~:-]*$", v):
        return None
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e)
    rev = "0"
    if "-" in v:
        v, rev = v.rsplit("-", 1)
    return epoch, v, rev


def cmp_dpkg(a, b):
    pa, pb = _dpkg_split(a), _dpkg_split(b)
    if pa is None or pb is None:
        return None
    if pa[0] != pb[0]:
        return _cmp_seq(pa[0], pb[0])
    return _dpkg_part(pa[1], pb[1]) or _dpkg_part(pa[2], pb[2])


# ---------------------------------------------------------------- rpm (rpmvercmp)
def _rpm_vercmp(a, b):
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not a[i].isalnum() and a[i] not in "~^":
            i += 1
        while j < len(b) and not b[j].isalnum() and b[j] not in "~^":
            j += 1
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if not (i < len(a) and a[i] == "~"):
                return 1
            if not (j < len(b) and b[j] == "~"):
                return -1
            i += 1
            j += 1
            continue
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if not (a[i] == "^"):
                return 1
            if not (b[j] == "^"):
                return -1
            i += 1
            j += 1
            continue
        if not (i < len(a) and j < len(b)):
            break
        si, sj = i, j
        if a[i].isdigit():
            while i < len(a) and a[i].isdigit():
                i += 1
            while j < len(b) and b[j].isdigit():
                j += 1
            isnum = True
        else:
            while i < len(a) and a[i].isalpha():
                i += 1
            while j < len(b) and b[j].isalpha():
                j += 1
            isnum = False
        x, y = a[si:i], b[sj:j]
        if not y:
            return 1 if isnum else -1
        if isnum:
            x, y = x.lstrip("0"), y.lstrip("0")
            if len(x) != len(y):
                return 1 if len(x) > len(y) else -1
        if x != y:
            return 1 if x > y else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def _rpm_split(v):
    v = str(v).strip()
    if not v or not re.match(r"^(\d+:)?[A-Za-z0-9._+~^-]+$", v):
        return None
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e)
    rel = ""
    if "-" in v:
        v, rel = v.rsplit("-", 1)
    return epoch, v, rel


def cmp_rpm(a, b):
    pa, pb = _rpm_split(a), _rpm_split(b)
    if pa is None or pb is None:
        return None
    if pa[0] != pb[0]:
        return _cmp_seq(pa[0], pb[0])
    return _rpm_vercmp(pa[1], pb[1]) or _rpm_vercmp(pa[2], pb[2])


# ---------------------------------------------------------------- apk (Alpine apk-tools)
_APK_SUFFIX = {"alpha": 0, "beta": 1, "pre": 2, "rc": 3, "": 4, "cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9}
_APK = re.compile(r"^(?P<num>\d+(?:\.\d+)*)(?P<letter>[a-z])?(?P<suf>(?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(?P<rev>\d+))?$")


def _apk_key(v):
    m = _APK.match(str(v).strip())
    if not m:
        return None
    nums = tuple(int(x) for x in m.group("num").split("."))
    sufs = tuple((_APK_SUFFIX[s], int(n or 0)) for s, n in re.findall(r"_([a-z]+)(\d*)", m.group("suf") or ""))
    return nums, m.group("letter") or "", sufs, int(m.group("rev") or 0)


def cmp_apk(a, b):
    ka, kb = _apk_key(a), _apk_key(b)
    if ka is None or kb is None:
        return None
    if ka[0] != kb[0]:
        return _cmp_seq(ka[0], kb[0])                # not padded: apk puts 1.0 below 1.0.0
    if ka[1] != kb[1]:
        return _cmp_seq(ka[1], kb[1])
    sa, sb = ka[2], kb[2]
    for i in range(max(len(sa), len(sb))):
        x = sa[i] if i < len(sa) else (_APK_SUFFIX[""], 0)
        y = sb[i] if i < len(sb) else (_APK_SUFFIX[""], 0)
        if x != y:
            return _cmp_seq(x, y)
    return _cmp_seq(ka[3], kb[3])


# ---------------------------------------------------------------- maven (ComparableVersion rules)
_MAVEN_Q = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "milestone": 2, "m": 2, "rc": 3, "cr": 3, "snapshot": 4, "": 5, "ga": 5, "final": 5, "release": 5, "sp": 6}


def _maven_items(v):
    v = str(v).strip().lower()
    if not v or not re.match(r"^[0-9a-z][0-9a-z._-]*$", v):
        return None
    items, cur, kind = [], "", None
    for ch in v + ".":
        k = "d" if ch.isdigit() else ("a" if ch.isalpha() else "s")
        if k == "s" or (cur and k != kind):
            if cur:
                items.append((kind, cur))
            cur, kind = ("" if k == "s" else ch), (None if k == "s" else k)
        else:
            cur, kind = cur + ch, k
    # a digit directly after a qualifier, or a qualifier directly after a number, starts a sub-list in Maven; flattening keeps the order for real versions
    out = []
    for kind, tok in items:
        out.append(("n", int(tok)) if kind == "d" else ("q", tok))
    while out and ((out[-1][0] == "n" and out[-1][1] == 0) or (out[-1][0] == "q" and _MAVEN_Q.get(out[-1][1]) == 5)):
        out.pop()
    return out


def _maven_item_cmp(x, y):
    """Maven's ComparableVersion: a number is above any qualifier; a missing item equals 0 or the release qualifier."""
    if x is None and y is None:
        return 0
    if x is None:
        return -_maven_item_cmp(y, None)
    if y is None:
        if x[0] == "n":
            return 0 if x[1] == 0 else 1
        r = _MAVEN_Q.get(x[1], 7)
        return 0 if r == 5 else (-1 if r < 5 else 1)
    if x[0] == "n" and y[0] == "n":
        return _cmp_seq(x[1], y[1])
    if x[0] == "n":
        return 1
    if y[0] == "n":
        return -1
    qx, qy = _MAVEN_Q.get(x[1], 7), _MAVEN_Q.get(y[1], 7)
    if qx != qy:
        return _cmp_seq(qx, qy)
    return _cmp_seq(x[1], y[1]) if qx == 7 else 0


def cmp_maven(a, b):
    ia, ib = _maven_items(a), _maven_items(b)
    if ia is None or ib is None:
        return None
    for i in range(max(len(ia), len(ib))):
        c = _maven_item_cmp(ia[i] if i < len(ia) else None, ib[i] if i < len(ib) else None)
        if c:
            return c
    return 0


_CMP = {"semver": cmp_semver, "pep440": cmp_pep440, "dpkg": cmp_dpkg, "apk": cmp_apk, "rpm": cmp_rpm, "maven": cmp_maven, "generic": cmp_generic}


def compare(a, b, scheme):
    """-1, 0 or 1; None when the scheme is unknown or either side cannot be parsed in it."""
    fn = _CMP.get(scheme)
    return fn(a, b) if fn else None


# ---------------------------------------------------------------- ranges
BOUNDS = ("start_including", "start_excluding", "end_including", "end_excluding")
_CAMEL = {"startIncluding": "start_including", "startExcluding": "start_excluding", "endIncluding": "end_including", "endExcluding": "end_excluding"}


def in_range(version, version_scheme, rng):
    """True or False when the range can judge the version, None (undetermined) when it cannot.

    rng holds NVD's fields (start_including, start_excluding, end_including, end_excluding; camelCase accepted) and an optional `scheme` (default generic).
    """
    r = {_CAMEL.get(k, k): v for k, v in rng.items()}
    bounds = {k: r[k] for k in BOUNDS if r.get(k)}
    if not bounds:
        return None
    scheme = r.get("scheme") or "generic"
    if scheme not in _CMP:
        return None
    if scheme != "generic" and version_scheme != scheme:
        return None                                 # a different scheme is undetermined, never outside-range
    ok = True
    for k, bound in bounds.items():
        if scheme == "generic" and not re.fullmatch(r"\d+(\.\d+)*", str(bound)):
            return None                             # a date or build id as a bound cannot be judged
        c = compare(version, bound, scheme)
        if c is None:
            return None
        if k == "start_including":
            ok = ok and c >= 0
        elif k == "start_excluding":
            ok = ok and c > 0
        elif k == "end_including":
            ok = ok and c <= 0
        else:
            ok = ok and c < 0
    return ok


def verdict(version, version_scheme, ranges):
    """One of in-range, outside-range, undetermined for a version against all the ranges of a product. No ranges is undetermined."""
    if not ranges:
        return "undetermined"
    results = [in_range(version, version_scheme, r) for r in ranges]
    if any(x is True for x in results):
        return "in-range"
    if any(x is None for x in results):
        return "undetermined"
    return "outside-range"


# ---------------------------------------------------------------- product identity (AD-16)
ECOSYSTEMS = ("pypi", "npm", "maven", "deb", "apk", "rpm", "cargo", "docker", "generic")


def normalise_product(name, ecosystem="generic"):
    """The one normalisation of a product or package name. Lower case; per-ecosystem rules; no leading or trailing separators."""
    n = str(name or "").strip().lower()
    if ecosystem == "pypi":
        n = re.sub(r"[-_.]+", "-", n)                                  # PEP 503
    elif ecosystem == "npm":
        n = re.sub(r"\s+", "", n)                                      # @scope/name keeps its scope
    elif ecosystem == "maven":
        n = re.sub(r"\s+", "", n).replace("/", ":")                    # group:artifact
    elif ecosystem in ("deb", "apk", "rpm", "cargo", "docker"):
        n = re.sub(r"\s+", "-", n)
        n = n.replace("_", "-") if ecosystem == "cargo" else n         # crates treat - and _ alike
    else:
        n = re.sub(r"[^a-z0-9@:/.+]+", "-", n)
    return n.strip("-_.")


def pid(name, ecosystem="generic"):
    """`<ecosystem>:<normalised-name>`: the key a component, an index row and a corpus pair share."""
    eco = ecosystem if ecosystem in ECOSYSTEMS else "generic"
    return f"{eco}:{normalise_product(name, eco)}"


# ---------------------------------------------------------------- windows (AD-17)
def window_days(anchor, name):
    """(first_day, last_day) as ISO dates for a window anchored on the index's exploitedAsOf (UTC calendar days, both inclusive).

    daily = anchor-1 to anchor; weekly = anchor-6 to anchor; monthly = anchor-29 to anchor. `open` and `all` have no first day here.
    """
    import datetime as dt
    d = dt.date.fromisoformat(str(anchor)[:10])
    back = {"daily": 1, "weekly": 6, "monthly": 29}.get(name)
    if back is None:
        return None
    return (d - dt.timedelta(days=back)).isoformat(), d.isoformat()
