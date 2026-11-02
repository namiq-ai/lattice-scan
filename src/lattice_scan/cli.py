# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Standalone host check against Lattice: exploited CVEs against what THIS machine has installed.

Install it (pip, the lattice-scan.pyz file, or the .deb) on any Linux host. It needs Python 3.9+ and nothing else (standard library only): no repo, no CISA file.
It asks the Lattice MCP server (https://lattice.namiq.io/mcp) which CVEs CISA lists as exploited, takes the host's own inventory, and flags an entry as a
CANDIDATE when a product word in the entry matches an installed package, snap, container image or the kernel. A candidate is not a finding about the
host: a person reads the affected range against the installed version, then records the outcome with `resolve`.

What leaves the machine: CVE ids, and the key if you have one. The inventory (package names, versions) is never sent; matching happens here.
Records live in ~/.lattice-scan (or LATTICE_SCAN_DIR), mode 0700, because they name the host's packages. Never commit or publish them.

  lattice-scan --cve CVE-2026-1234 --cve-file ids.txt   check these ids (works keyless; ~1 lookup per id)
  lattice-scan --discover                               needs a key: list exploited CVEs added in the window (graph_search + graph_node)
  lattice-scan --debug --cve CVE-...                detailed execution log: every request, response, timing and match decision (stderr + debug.log; never the key)
  lattice-scan inventory [-n 20]                    inventory.log: what was found on each run and what changed since the last one
  lattice-scan --refresh                            collect the inventory again from scratch and print all of it (no Lattice call)
  lattice-scan impact CVE-...                       the recorded impact detail: installed versions, listed/due/overdue, required action
  lattice-scan list | stats | log [-n 20]          log = scan.log, one line per run (also records runs that stopped on an error)
  lattice-scan resolve CVE-2026-1 --status fixed --proof "changelog line names the CVE"
                                    status: verified (affects us, fix not applied yet) | fixed | not-applicable (a wrong match)
  lattice-scan add --ref HOST-1 --note "exposure, not on CISA's list"

Keyless access answers graph_lookup only (small daily limit). Since OCO-5819 option A that answer carries CISA's vendor_project, product, date_added,
due_date and required_action, and the NVD product list and affected_ranges, so the impact check works without a key. The version check compares
upstream version numbers only; a distro can fix a CVE under an unchanged number, so a person still decides, and the report shows whether an installed
package's own changelog names the CVE. --discover (listing what was added in the window)
needs a key, because graph_search is not keyless. Get a key: https://namiq.io/lattice/docs#agents. If the server says quota_exceeded the run stops and
prints its message; a person decides about any link in it, the script never opens one.

Env: LATTICE_URL (default https://lattice.namiq.io/mcp), LATTICE_API_KEY, LATTICE_SCAN_DIR, LATTICE_SCAN_INVENTORY (tests: fixed inventory JSON),
LATTICE_SCAN_TODAY (YYYY-MM-DD), LATTICE_SCAN_WINDOW (days back; default 6 = seven days counting today).
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, re, shutil, statistics, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path

from lattice_scan import __version__



def env(name: str, default: str = "") -> str:
    """LATTICE_SCAN_<name>, falling back to the HOST_SCAN_<name> of the first internal version so existing setups keep working."""
    return os.environ.get(f"LATTICE_SCAN_{name}") or os.environ.get(f"HOST_SCAN_{name}") or default


def records_dir() -> Path:
    if env("DIR"):
        return Path(env("DIR"))
    new, old = Path.home() / ".lattice-scan", Path.home() / ".host-scan"
    return old if old.exists() and not new.exists() else new  # records written before the rename stay where they are


URL = os.environ.get("LATTICE_URL", "https://lattice.namiq.io/mcp")
KEY = os.environ.get("LATTICE_API_KEY", "")
OUT = records_dir()
WINDOW = int(env("WINDOW", "6"))
TODAY = env("TODAY") or dt.date.today().isoformat()

# Words in a vendor or product name that say nothing about which package is meant.
GENERIC = set("""vulnerability vulnerabilities remote code execution server software security data access control authentication authorization
improper missing unchecked insufficient unrestricted generation predictable numbers identifiers upload file dangerous type command injection
privilege escalation cross site scripting deserialization path traversal buffer overflow out of bounds write read use after free
logging variable initialization return value enterprise community edition project foundation systems system inc corp corporation group
connect secure firewall manager console platform service services application web client network cloud management product products
online windows microsoft google apple oracle cisco adobe""".split())


DEBUG = False


def dbg(msg: str, file_only: bool = False) -> None:
    """Execution trace (--debug / LATTICE_SCAN_DEBUG=1): to stderr and to debug.log. Never writes the API key; request bodies hold only tool names and ids."""
    if not DEBUG:
        return
    line = f"{dt.datetime.now().isoformat(timespec='milliseconds')} {msg}"
    if not file_only:
        print(line, file=sys.stderr)
    private_dir()
    with open(OUT / "debug.log", "a") as fh:
        fh.write(line + "\n")


class LatticeError(Exception):
    pass


MAX_REPLY = 8 * 1024 * 1024  # a reply bigger than this is not a Lattice answer


def clean(v):
    """Text that came from the network is data, never terminal commands: replace control characters (including ESC) before it is printed or logged."""
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "?", v) if isinstance(v, str) else v


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the key is in a header, and a redirect would carry it to wherever it points."""

    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def private_dir() -> None:
    """The records directory exists and is 0700, even if an earlier run or the user created it looser: it names this host's software."""
    OUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(OUT, 0o700)


def check_url() -> None:
    """A key must not travel in clear text: refuse http:// unless it is this machine (the tests' stub server)."""
    from urllib.parse import urlparse
    u = urlparse(URL)
    if u.scheme == "https" or (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1")):
        return
    if u.scheme == "http" and not KEY:
        return  # no key to leak; the ids only
    raise LatticeError(f"refusing to use {URL}: a key is set and the address is not https")


class Lattice:
    """Minimal MCP client over streamable HTTP. The server may answer plain JSON or an SSE stream; both are read."""

    def __init__(self) -> None:
        self.session = ""
        self.n = 0
        self.last_gap = 0.0

    def _post(self, body: dict) -> dict | None:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "User-Agent": f"lattice-scan/{__version__}"}
        if KEY:
            h["X-API-Key"] = KEY
        if self.session:
            h["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(URL, json.dumps(body).encode(), h)
        t0 = time.time()
        dbg(f"-> POST {URL} {body.get('method')} {json.dumps(body.get('params', {}).get('arguments', ''))} key={'set' if KEY else 'none'} session={self.session or '-'}")
        try:
            with _OPENER.open(req, timeout=30) as r:
                self.session = r.headers.get("Mcp-Session-Id", self.session)
                raw = r.read(MAX_REPLY + 1).decode(errors="replace")
                if len(raw) > MAX_REPLY:
                    raise LatticeError("reply from Lattice is larger than 8 MB: refusing it")
                dbg(f"<- HTTP {r.status} {len(raw)} bytes in {time.time() - t0:.2f}s content-type={r.headers.get('Content-Type')}")
        except urllib.error.HTTPError as e:
            detail = e.read().decode()[:200]
            dbg(f"<- HTTP {e.code} in {time.time() - t0:.2f}s body={detail}")
            raise LatticeError(f"HTTP {e.code} from Lattice: {detail}")
        except (urllib.error.URLError, OSError) as e:
            dbg(f"<- failed in {time.time() - t0:.2f}s: {e!r}")
            raise LatticeError(f"cannot reach Lattice: {e}")
        dbg(f"   body: {raw[:300]}{' ...' if len(raw) > 300 else ''}")
        dbg(f"   full body: {raw}", file_only=True)
        if not raw.strip():
            return None
        if raw.lstrip().startswith("{"):
            return json.loads(raw)
        data = [l[5:].strip() for l in raw.splitlines() if l.startswith("data:")]  # SSE: the reply is the last data: line
        return json.loads(data[-1]) if data else None

    def start(self) -> None:
        check_url()
        self._post({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "lattice-scan", "version": __version__}}})
        try:
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        except LatticeError:
            pass  # a stateless server may refuse the notification; calls work without it

    def call(self, tool: str, **args) -> dict:
        # Keyless access allows 5 calls a minute: stay under it instead of burning the day's units on 429s.
        if not KEY:
            wait = 12.5 - (time.time() - self.last_gap)
            if wait > 0:
                dbg(f"keyless pacing: sleeping {wait:.1f}s (5 calls/minute limit)")
                time.sleep(wait)
        self.n += 1
        r = self._post({"jsonrpc": "2.0", "id": self.n, "method": "tools/call", "params": {"name": tool, "arguments": {k: v for k, v in args.items() if v is not None}}})
        self.last_gap = time.time()
        if not r or "result" not in r:
            raise LatticeError(f"{tool}: {json.dumps(r)[:200]}")
        text = "".join(c.get("text", "") for c in r["result"].get("content", []))
        try:
            data = json.loads(text)
        except ValueError:
            raise LatticeError(f"{tool}: unreadable answer: {text[:200]}")
        if DEBUG and isinstance(data, dict):
            acc = data.get("access") or {}
            dbg(f"   lattice {tool}: snapshot={data.get('snapshot', '-')} items={len(data.get('items', []))} truncated={data.get('truncated', False)} "
                f"tier={acc.get('tier', '-')} remaining_units_this_hour={acc.get('remaining_units_this_hour', '-')} limits={acc.get('limits', '-')}")
            for it in data.get("items", []):
                dbg(f"   lattice item: id={it.get('id')} source={it.get('source')} labels={it.get('labels')} uid={it.get('uid')} primary={it.get('primary')} title={it.get('title')!r}")
            if "properties" in data or "title" in data and "items" not in data:
                dbg(f"   lattice node: {json.dumps(data, sort_keys=True)[:1500]}")
            for n in data.get("notices", []):
                dbg(f"   lattice notice: {n.get('title')}: {n.get('obligation')}")
        if isinstance(data, dict) and data.get("error"):
            msg = data.get("message", data["error"])
            raise LatticeError(clean(f"{tool}: {data['error']}: {msg}"))
        return data


def run(cmd: list[str]) -> str:
    if not shutil.which(cmd[0]):
        dbg(f"collect: {' '.join(cmd[:2])}: command not installed, skipped")
        return ""
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        dbg(f"collect: {' '.join(cmd[:2])}: failed {e!r}")
        return ""
    dbg(f"collect: {' '.join(cmd[:2])}: rc={p.returncode} {len(p.stdout.splitlines())} lines in {time.time() - t0:.2f}s" + (f" stderr={p.stderr.strip()[:120]!r}" if p.returncode else ""))
    return p.stdout


def inventory() -> dict:
    fixed = env("INVENTORY")
    if fixed:
        inv = json.loads(Path(fixed).read_text())
        inv.setdefault("hash", "fixed")
        return inv
    pk: dict[str, str] = {}
    for line in run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"]).splitlines():
        n, _, v = line.partition("\t")
        if n:
            pk[n] = v
    if not pk:  # rpm and apk hosts
        for line in run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"]).splitlines():
            n, _, v = line.partition("\t")
            if n:
                pk[n] = v
    if not pk:
        for line in run(["apk", "info", "-v"]).splitlines():
            m = re.match(r"(.+?)-(\d[^-]*-r\d+)$", line)
            if m:
                pk[m.group(1)] = m.group(2)
    snaps = {f[0]: f[1] for f in (l.split() for l in run(["snap", "list"]).splitlines()[1:]) if len(f) >= 2}
    images = sorted({i for i in run(["docker", "ps", "--format", "{{.Image}}"]).splitlines() if i})
    osr = ""
    try:
        osr = next((l.split("=", 1)[1].strip('"') for l in Path("/etc/os-release").read_text().splitlines() if l.startswith("PRETTY_NAME=")), "")
    except OSError:
        pass
    inv = {"kernel": run(["uname", "-r"]).strip(), "os": osr, "packages": pk, "snaps": snaps, "images": images, "node": run(["node", "-v"]).strip(),
           "restartRequired": Path("/var/run/reboot-required").exists()}
    inv["hash"] = hashlib.sha256(json.dumps({k: inv[k] for k in ("kernel", "packages", "snaps", "images", "node")}, sort_keys=True).encode()).hexdigest()[:12]
    return inv


def stems(name: str) -> set[str]:
    """The comparable words of an installed name: 'libbrotli1' and 'python3-brotli' both give 'brotli'."""
    out = set()
    for t in re.findall(r"[a-z][a-z0-9]*", name.lower()):
        t = re.sub(r"\d+$", "", t)
        out.add(t)
        if t.startswith("lib") and len(t) > 6:
            out.add(t[3:])
    return {t for t in out if len(t) >= 4}


def words(s: str) -> set[str]:
    return {re.sub(r"\d+$", "", w) for w in re.findall(r"[a-z][a-z0-9]{3,}", s.lower()) if w not in GENERIC}


def candidate(entry: dict, inv: dict) -> tuple[str, list[str], list[str]] | None:
    """(why, what is installed that matches, their raw version strings) for an entry that might touch the host, or None. Name-level only: it never reads a version range.

    Lattice now gives CISA's vendor_project and product without a key, so every distinctive product word must be installed. The title is the fallback
    when an answer has no product (an older server): its distinctive words must all be installed, the leading vendor word dropped. The reason says which.
    """
    vendor, product = entry.get("vendor", "").lower(), entry.get("product", "").lower()
    basis = "product"
    if not product:
        product, basis = entry.get("title", "").lower(), "title"
    if vendor == "linux" and product == "kernel" or "linux kernel" in product:
        return f"kernel in use is {inv['kernel']}", [f"kernel {inv['kernel']}"], [inv["kernel"]]
    if product in ("node.js", "nodejs") and inv.get("node"):
        return f"Node.js {inv['node']} is installed", [f"node {inv['node']}"], [inv["node"]]
    if basis == "title":  # a headline leads with the vendor ("Apache Log4j2 ..."), which package names rarely carry
        first = re.findall(r"[a-z][a-z0-9]{3,}", product)[:1]
        want = {w for w in words(product) if w not in {re.sub(r"\d+$", "", f) for f in first}} or words(product)
    else:
        want = words(product)
    if not want:
        dbg(f"   match {entry['cve']} basis={basis}: no distinctive words in {product!r}, cannot match")
        return None
    have: dict[str, str] = {}
    for n in inv["packages"]:
        for w in stems(n):
            have.setdefault(w, n)
    for n in inv["snaps"]:
        have.setdefault(n.lower(), f"snap {n}")
    for im in inv["images"]:
        for w in stems(im):
            have.setdefault(w, f"container image {im.split('@')[0]}")
    dbg(f"   match {entry['cve']} basis={basis} wanted={sorted(want)} found={sorted(w for w in want if w in have)} missing={sorted(w for w in want if w not in have)}")
    if all(w in have for w in want):
        names = sorted({have[w] for w in want})
        installed = [f"{n} {inv['packages'][n]}" if n in inv["packages"] else n for n in names]
        vers = [inv["packages"][n] for n in names if n in inv["packages"]] + [inv["snaps"][n[5:]] for n in names if n.startswith("snap ") and n[5:] in inv["snaps"]]
        return f"{basis} " + " ".join(sorted(want)) + " matches " + ", ".join(names), installed, vers
    return None


def upstream(v: str) -> tuple[int, ...] | None:
    """The comparable upstream version of an installed version string, or None when it has no plain dotted number.

    '1:2.17.1-1' -> (2,17,1); '7.0.0-41-cix' -> (7,0,0); 'v22.22.1' -> (22,22,1). Distro revisions (-1ubuntu3), epochs and +suffixes are dropped, so a
    distro that backports a fix under the same upstream number looks unfixed here: the changelog check below exists for exactly that.
    """
    v = re.sub(r"^\d+:", "", v.strip().lstrip("v"))
    m = re.match(r"\d+(\.\d+)*", v)
    return tuple(int(x) for x in m.group(0).split(".")) if m else None


def cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def in_range(ver: tuple[int, ...], r: dict) -> bool | None:
    """Is ver inside one NVD range? None when a bound is not a plain dotted number (a date, a build id): that range cannot be judged."""
    bounds = {k: r[k] for k in ("start_including", "start_excluding", "end_including", "end_excluding") if r.get(k)}
    if not bounds:
        return None
    parsed = {}
    for k, v in bounds.items():
        if not re.fullmatch(r"\d+(\.\d+)*", str(v)):
            return None
        parsed[k] = tuple(int(x) for x in str(v).split("."))
    ok = True
    if "start_including" in parsed: ok &= cmp(ver, parsed["start_including"]) >= 0
    if "start_excluding" in parsed: ok &= cmp(ver, parsed["start_excluding"]) > 0
    if "end_including" in parsed: ok &= cmp(ver, parsed["end_including"]) <= 0
    if "end_excluding" in parsed: ok &= cmp(ver, parsed["end_excluding"]) < 0
    return ok


def fmt_range(r: dict) -> str:
    lo = f">= {r['start_including']}" if r.get("start_including") else f"> {r['start_excluding']}" if r.get("start_excluding") else ""
    hi = f"<= {r['end_including']}" if r.get("end_including") else f"< {r['end_excluding']}" if r.get("end_excluding") else ""
    return " and ".join(x for x in (lo, hi) if x) or "no bounds"


def version_check(entry: dict, vers: list[str]) -> dict:
    """Installed version against NVD's affected ranges for the matching product. A mechanical comparison of upstream numbers, never a verdict on the host.

    in-range      an installed version lies inside a listed range
    outside-range every usable range for the product excludes it (and none was unusable)
    undetermined  no ranges for the product, no plain version, or a range with a date or build id as its bound
    """
    # The ranges that belong to THIS entry's product: same vendor as CISA names it, and a shared product word. The host was already matched by name
    # (a kernel matches by uname, not by a package), so what is installed is not consulted here.
    kev_words = words(entry.get("product", ""))
    vendor = re.sub(r"[^a-z0-9]", "", entry.get("vendor", "").lower())
    mine = []
    for r in entry.get("ranges", []):
        sv, _, sp = r.get("product", "").partition("/")
        if words(sp.replace("_", " ")) & kev_words and (not vendor or re.sub(r"[^a-z0-9]", "", sv.lower()) in vendor):
            mine.append(r)
    if not mine:
        return {"verdict": "undetermined", "why": "Lattice listed no version range for this product name"}
    seen_unusable, hit = False, None
    checked = []
    for raw in vers:
        v = upstream(raw)
        if v is None:
            seen_unusable = True
            checked.append(f"{raw}: no plain version number")
            continue
        for r in mine:
            res = in_range(v, r)
            if res is None:
                seen_unusable = True
            elif res and hit is None:
                hit = f"{raw} (as {'.'.join(map(str, v))}) is inside {r['product']} {fmt_range(r)}"
        checked.append(f"{raw} as {'.'.join(map(str, v))}")
    if hit:
        return {"verdict": "in-range", "why": hit}
    if seen_unusable:
        return {"verdict": "undetermined", "why": "; ".join(checked) + "; some range or version could not be compared"}
    return {"verdict": "outside-range", "why": f"{'; '.join(checked)} is outside all {len(mine)} listed range(s): " + ", ".join(fmt_range(r) for r in mine[:6])}


def changelog_mentions(cve: str, installed: list[str], inv: dict) -> list[str]:
    """Installed Debian packages whose own changelog names this CVE: the local evidence that a distro backported the fix under an unchanged upstream number."""
    import gzip
    names = [i.split(" ")[0] for i in installed if i.split(" ")[0] in inv["packages"]]
    if any(i.startswith("kernel ") for i in installed):
        k = inv["kernel"]
        names += [n for n in (f"linux-image-{k}", f"linux-image-unsigned-{k}", f"linux-modules-{k}", f"linux-headers-{k}") if n in inv["packages"]]
    out = []
    for n in names:
        for f in (f"/usr/share/doc/{n}/changelog.Debian.gz", f"/usr/share/doc/{n}/changelog.gz"):
            try:
                with gzip.open(f, "rt", errors="replace") as fh:
                    if cve in fh.read():
                        out.append(n)
                        break
            except OSError:
                continue
    return sorted(set(out))


def impact(entry: dict, inv: dict, installed: list[str], vers: list[str]) -> dict:
    """What a person needs to judge this match, from what Lattice returned plus the inventory. It decides nothing.

    versionCheck compares upstream version numbers with NVD's ranges from Lattice (affected_ranges); it is evidence for a person, and 'outside-range'
    does not close a finding (only `resolve` does). The NVD product list is corroboration only (names that also appear here); it is never what makes an entry a candidate.
    """
    day = dt.date.fromisoformat(TODAY)
    have = set()
    for n in list(inv["packages"]) + list(inv["snaps"]) + list(inv["images"]):
        have |= stems(n)
    nvd = []
    for slug in entry.get("affected", []):
        prod = slug.partition("/")[2].replace("_", " ")
        w = words(prod)
        if w and all(x in have for x in w):
            nvd.append(slug)
    out = {"installed": installed, "nvdAlsoNames": nvd[:5], "versionCheck": version_check(entry, vers),
           "changelogNamesCve": changelog_mentions(entry["cve"], installed, inv),
           "action": entry.get("action", "")[:400], "listed": entry["added"], "due": entry["due"]}
    if entry["added"]:
        out["daysSinceListed"] = (day - dt.date.fromisoformat(entry["added"])).days
    if entry["due"]:
        left = (dt.date.fromisoformat(entry["due"]) - day).days
        out["dueStatus"] = f"overdue by {-left} days" if left < 0 else f"due in {left} days" if left else "due today"
    return out


def kev_entry(lat: Lattice, cve: str) -> dict | None:
    """The CISA exploited entry for one CVE, or None when the graph has no kev node (which is not 'safe', only 'not listed in this snapshot').

    The kev node of a graph_lookup carries vendor_project, product, date_added, due_date and required_action, and the nvd node carries
    affected_products as 'vendor/product; ...' (OCO-5819, option A): no key and no graph_node call needed. If an older server left them out and a key
    is set, graph_node fills them in.
    """
    items = lat.call("graph_lookup", id=cve).get("items", [])
    kev = next((i for i in items if i.get("source") == "kev"), None)
    if not kev:
        return None
    nvd = next((i for i in items if i.get("source") == "nvd"), {})
    e = {"cve": cve, "title": clean(kev.get("title", "")), "added": clean(str(kev.get("date_added", ""))), "due": clean(str(kev.get("due_date", ""))),
         "vendor": clean(kev.get("vendor_project", "")), "product": clean(kev.get("product", "")), "action": clean(kev.get("required_action", "")),
         "affected": [clean(x.strip()) for x in str(nvd.get("affected_products", "")).split(";") if x.strip()],
         "ranges": [{k: clean(v) for k, v in r.items()} for r in (nvd.get("affected_ranges") or []) if isinstance(r, dict)]}
    if not e["product"] and KEY:
        dbg(f"{cve}: lookup had no product, falling back to graph_node")
        p = lat.call("graph_node", uid=kev["uid"])
        props = p.get("properties", p)
        e.update(added=str(props.get("date_added", "")), due=str(props.get("due_date", "")), vendor=props.get("vendor_project", ""), product=props.get("product", ""))
    return e


def discover(lat: Lattice, floor: str) -> list[str]:
    """Exploited CVE ids in the window: walk the current and previous year's ids, keep kev nodes added on or after the floor."""
    ids: list[str] = []
    for year in sorted({TODAY[:4], floor[:4]}):
        cursor = None
        while True:
            r = lat.call("graph_search", id_prefix=f"CVE-{year}-", label="ExploitedCVE", limit=100, cursor=cursor)
            ids += [i["id"] for i in r.get("items", [])]
            cursor = r.get("next_cursor")
            if not r.get("truncated") or not cursor:
                break
    return sorted(set(ids))


def events() -> list[dict]:
    f = OUT / "findings.jsonl"
    return [json.loads(l) for l in f.read_text().splitlines() if l.strip()] if f.exists() else []


def append(path: str, rec: dict) -> None:
    private_dir()
    with open(OUT / path, "a") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")


def scanlog(line: str) -> None:
    """One human-readable line per run in scan.log, so 'what did the last scan see, and did it fail' is answerable without parsing the jsonl."""
    private_dir()
    with open(OUT / "scan.log", "a") as fh:
        fh.write(f"{dt.datetime.now().isoformat(timespec='seconds')} {line}\n")


def inventory_log(inv: dict, prev: dict | None, refresh: bool = False) -> None:
    """inventory.log, always on: one block per run with the counts and what changed since the previous run's inventory.

    The diff is the useful part: a CVE that appears after a package was installed or upgraded is explained by the line here, not by guessing.
    """
    def diff(old: dict, new: dict) -> str:
        add = sorted(set(new) - set(old))
        rem = sorted(set(old) - set(new))
        chg = sorted(n for n in set(old) & set(new) if old[n] != new[n])
        return f"+{len(add)} -{len(rem)} ~{len(chg)}" + "".join([f" +{n} {new[n]}" for n in add[:30]] + [f" -{n} {old[n]}" for n in rem[:30]] + [f" ~{n} {old[n]}->{new[n]}" for n in chg[:30]])
    now = dt.datetime.now().isoformat(timespec="seconds")
    lines = [f"{now} {'REFRESH ' if refresh else ''}inventory {inv['hash']} os={inv['os']!r} kernel={inv['kernel']} node={inv.get('node') or '-'} "
             f"packages={len(inv['packages'])} snaps={len(inv['snaps'])} images={len(inv['images'])} restartRequired={inv['restartRequired']}"]
    if prev is None:
        lines.append(f"{now}   first inventory on record, nothing to compare")
    elif prev.get("hash") == inv["hash"]:
        lines.append(f"{now}   unchanged since the previous run")
    else:
        lines.append(f"{now}   kernel: {prev.get('kernel')} -> {inv['kernel']}" if prev.get("kernel") != inv["kernel"] else f"{now}   kernel unchanged")
        lines.append(f"{now}   packages {diff(prev.get('packages', {}), inv['packages'])}")
        lines.append(f"{now}   snaps {diff(prev.get('snaps', {}), inv['snaps'])}")
        lines.append(f"{now}   images +{sorted(set(inv['images']) - set(prev.get('images', [])))} -{sorted(set(prev.get('images', [])) - set(inv['images']))}")
    private_dir()
    with open(OUT / "inventory.log", "a") as fh:
        fh.write("\n".join(lines) + "\n")


def state() -> dict[str, dict]:
    s: dict[str, dict] = {}
    for e in events():
        f = s.setdefault(e["ref"], {"ref": e["ref"], "status": "open"})
        if e["event"] == "found":
            f.update(listed=e.get("listed", ""), found=e["on"], why=e.get("why", ""), title=e.get("title", ""), due=e.get("due", ""), kind=e.get("kind", "kev"), impact=e.get("impact"))
        elif e["event"] == "impact":
            f["impact"] = e["impact"]
        elif e["event"] in ("verified", "fixed", "not-applicable"):
            f["status"] = e["event"]
            f["proof"] = e.get("proof", "")
            if e["event"] in ("fixed", "not-applicable"):
                f["closed"] = e["on"]
    return s


def show_inventory(inv: dict) -> None:
    print(f"inventory {inv['hash']}: {inv['os']}, kernel {inv['kernel']}, node {inv.get('node') or '-'}, restartRequired={inv['restartRequired']}")
    print(f"\nimages ({len(inv['images'])}):" + "".join(f"\n  {i}" for i in inv["images"]))
    print(f"\nsnaps ({len(inv['snaps'])}):" + "".join(f"\n  {n:<32} {v}" for n, v in sorted(inv["snaps"].items())))
    print(f"\npackages ({len(inv['packages'])}):" + "".join(f"\n  {n:<44} {v}" for n, v in sorted(inv["packages"].items())))


def cmd_run(a) -> int:
    private_dir()
    seen_f = OUT / "seen.json"
    seen = set(json.loads(seen_f.read_text())) if seen_f.exists() else set()
    ids = [c.upper() for c in (a.cve or [])]
    if a.cve_file:
        try:
            lines = Path(a.cve_file).read_text().splitlines()
        except OSError as err:
            print(f"cannot read --cve-file: {err}", file=sys.stderr)
            return 2
        ids += [l.split("#")[0].strip().upper() for l in lines if l.split("#")[0].strip()]
    named = set(ids)  # ids the user typed or listed: always read. `seen` only stops --discover re-reading what it has already read.
    if a.refresh and not ids and not a.discover:
        # Inventory only: collect again now, show all of it, log it. No Lattice call, nothing leaves the machine.
        inv = inventory()
        inv_f = OUT / "inventory.json"
        try:
            prev = json.loads(inv_f.read_text()) if inv_f.exists() else None
        except ValueError:
            prev = None
        inventory_log(inv, prev, refresh=True)
        inv_f.write_text(json.dumps(inv, indent=1, sort_keys=True))
        show_inventory(inv)
        scanlog(f"refresh inventory={inv['hash']} packages={len(inv['packages'])} snaps={len(inv['snaps'])} images={len(inv['images'])}")
        return 0
    if not ids and not a.discover:
        print("nothing to check: give --cve / --cve-file, or --discover (needs LATTICE_API_KEY)", file=sys.stderr)
        return 2
    if a.discover and not KEY:
        print("--discover needs a key (graph_search and graph_node are not keyless). Set LATTICE_API_KEY, or pass ids with --cve.", file=sys.stderr)
        return 2
    floor = (dt.date.fromisoformat(TODAY) - dt.timedelta(days=WINDOW)).isoformat()
    inv = inventory()
    dbg(f"inventory: os={inv['os']!r} kernel={inv['kernel']} packages={len(inv['packages'])} snaps={len(inv['snaps'])} images={len(inv['images'])} "
        f"node={inv.get('node') or '-'} hash={inv['hash']} restartRequired={inv['restartRequired']}")
    dbg(f"inventory kernel={inv['kernel']} node={inv.get('node') or '-'} images={inv['images']}")
    dbg("inventory snaps: " + ", ".join(f"{n} {v}" for n, v in sorted(inv["snaps"].items())), file_only=True)
    dbg("inventory packages: " + ", ".join(f"{n} {v}" for n, v in sorted(inv["packages"].items())), file_only=True)
    inv_f = OUT / "inventory.json"
    try:
        prev = json.loads(inv_f.read_text()) if inv_f.exists() else None
    except ValueError:
        prev = None
    inventory_log(inv, prev, refresh=a.refresh)
    if a.refresh:
        show_inventory(inv)
    inv_f.write_text(json.dumps(inv, indent=1, sort_keys=True))
    dbg(f"run: today={TODAY} window={WINDOW}d floor={floor} url={URL} key={'set' if KEY else 'none'} ids={len(set(ids))} discover={a.discover} again={a.again} records={OUT}")
    lat = Lattice()
    known = {e["ref"] for e in events()}
    hits, again_hits, read, not_listed = [], [], 0, []
    try:
        lat.start()
        if a.discover:
            ids += discover(lat, floor)
            dbg(f"discover: {len(set(ids))} exploited ids to read")
        for cve in sorted(set(ids)):
            if cve in seen and cve not in named and not (a.again or a.refresh):
                dbg(f"{cve}: skipped, already read (--again to re-read)")
                continue
            e = kev_entry(lat, cve)
            dbg(f"{cve}: CHECK lattice says " + ("no CISA exploited entry in this snapshot (not the same as safe)" if e is None else
                f"CISA exploited: title={e['title']!r} vendor={e['vendor'] or '-'} product={e['product'] or '-'} added={e['added'] or '-'} due={e['due'] or '-'} nvd-affected={len(e['affected'])} ranges={len(e['ranges'])}"))
            if e is None:
                not_listed.append(cve)
                continue
            if e["added"] and not (floor <= e["added"] <= TODAY) and not a.cve and not a.cve_file:
                dbg(f"{cve}: outside window {floor}..{TODAY} (added {e['added']}), skipped")
                continue  # discovery only reports the window; ids you named are always read
            read += 1
            m = candidate(e, inv)
            if m and cve in known:
                imp = impact(e, inv, m[1], m[2])
                if a.refresh or not state()[cve].get("impact"):
                    append("findings.jsonl", {"event": "impact", "ref": cve, "on": TODAY, "impact": imp})
                again_hits.append((e, m[0], imp))
            if m and cve not in known:
                why, installed, vers = m
                imp = impact(e, inv, installed, vers)
                dbg(f"{cve}: IMPACT {json.dumps(imp)}")
                append("findings.jsonl", {"event": "found", "ref": cve, "on": TODAY, "listed": e["added"], "due": e["due"], "title": e["title"], "why": why, "kind": "kev", "impact": imp})
                hits.append((e, why, imp))
            seen.add(cve)
    except LatticeError as err:
        seen_f.write_text(json.dumps(sorted(seen)))
        scanlog(f"STOPPED after {read} read, {len(hits)} candidates: {err}")
        print(f"stopped: {err}", file=sys.stderr)
        return 1
    seen_f.write_text(json.dumps(sorted(seen)))
    append("runs.jsonl", {"on": TODAY, "read": read, "candidates": len(hits), "inventory": inv["hash"], "restartRequired": inv["restartRequired"]})
    scanlog(f"ok key={'yes' if KEY else 'no'} inventory={inv['hash']} read={read} candidates={len(hits)} already-recorded={len(again_hits)}"
            + "".join(f" [{e['cve']}: {why}]" for e, why, imp in hits) + (f" not-listed={','.join(not_listed)}" if not_listed else "")
            + (" restart-required" if inv["restartRequired"] else ""))
    print(f"host scan {TODAY}: {read} exploited entries read, {len(hits)} candidates (a person must read each against the installed version)")
    for e, why, imp in hits:
        print(f"  {e['cve']}  {e['title'][:70]}\n      because: {why}")
        print_impact(imp)
    for e, why, imp in again_hits:
        print(f"  {e['cve']}  matches again ({why}); already recorded as {state()[e['cve']]['status']}, not counted as new")
        print_impact(imp)
    if not_listed:
        print(f"not in the graph's CISA list (not 'safe', only 'not listed in this snapshot'): {', '.join(not_listed)}")
    open_n = [f for f in state().values() if f["status"] in ("open", "verified")]
    if open_n:
        print(f"{len(open_n)} finding(s) not yet fixed: " + ", ".join(f["ref"] for f in open_n))
    if inv["restartRequired"]:
        print("restart required: an installed update is waiting for a reboot")
    return 0


def project_inventory(comps) -> tuple[dict, dict[str, list]]:
    """An inventory in the shape the host matcher reads, built from declared components, and where each name was declared.

    A declared range, `latest` or no tag has no version, so its value is the declaration itself (`>=1.0`, `unpinned`): version_check cannot read it as a number and
    says `undetermined`, which is the truth. Where a lockfile pins a name, the unpinned declarations of that name are dropped: the lock is what is installed.
    A name with several different versions keeps each under `name#2`, `name#3`: they all matter.
    """
    pinned_names = {c.name for c in comps if c.version}
    packages: dict[str, str] = {}
    where: dict[str, list] = {}
    for c in comps:
        if not c.version and c.name in pinned_names:
            continue
        val = c.version or c.spec or "unpinned"
        key = c.name
        k = 1
        while key in packages and packages[key] != val:
            k += 1
            key = f"{c.name}#{k}"
        packages[key] = val
        where.setdefault(key, []).append(c)
    inv = {"kernel": "", "os": "project manifests", "node": "", "restartRequired": False, "packages": packages, "snaps": {}, "images": []}
    inv["hash"] = hashlib.sha256(json.dumps(packages, sort_keys=True).encode()).hexdigest()[:12]
    return inv, where


GENERIC_PRODUCTS = {"core", "client", "server", "library", "tools", "runtime", "view", "framework", "platform", "engine", "common", "base", "utils", "api", "cli", "sdk", "web", "app"}


def _flat(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def project_candidate(entry: dict, inv: dict) -> tuple[str, list[str], list[str]] | None:
    """A declared dependency that IS this entry's product, or None. Stricter than the host's word match, on purpose.

    A host's package list is flat and a product word may sit anywhere in a name; a project's names are single identifiers, and a loose match is noise
    ('WordPress Core' is not @babel/core, 'Chromium' is not electron-to-chromium, 'BIND' is not call-bind). So: the flattened product equals the flattened
    package name, or its npm scope (@tanstack/query-core is TanStack), or one is a prefix of the other when the shorter has at least 6 characters and
    covers 70% of the longer (postgres / PostgreSQL). The title is the fallback when an answer has no product, as for the host.
    """
    product = _flat(entry.get("product", ""))
    basis = "product"
    if not product:
        product, basis = _flat(re.sub(r"^\S+\s+", "", entry.get("title", ""))), "title"
    if len(product) < 4:
        return None
    vendor = _flat(entry.get("vendor", ""))
    generic = product in GENERIC_PRODUCTS
    hit = []
    for key, val in inv["packages"].items():
        name = key.split("#")[0]
        base = _flat(name.rsplit("/", 1)[-1])
        scope = _flat(name.split("/")[0].lstrip("@")) if name.startswith("@") else ""
        # A scope that is not the product must belong to the vendor ('@babel/core' is Babel's, not WordPress's); a generic one-word product needs its vendor in the name.
        vendor_in_name = bool(vendor) and (vendor in _flat(name) or (scope and scope in vendor))
        forms = [f for f in ((base if (not scope or scope == product or vendor_in_name) else ""), scope) if f]
        for f in forms:
            short, long_ = sorted((f, product), key=len)
            same = f == product or (vendor and f == vendor + product) or (len(short) >= 6 and long_.startswith(short) and len(short) / len(long_) >= 0.7)
            if same and (not generic or vendor_in_name or f == scope or f == vendor + product):
                hit.append((key, name, val))
                break
    if not hit:
        return None
    names = sorted({n for _, n, _ in hit})
    return (f"{basis} {product} is declared as " + ", ".join(names), [f"{n} {v}" for _, n, v in hit], [v for _, _, v in hit])


def load_catalogue(path: str) -> list[dict]:
    """CISA's known_exploited_vulnerabilities.json, or one JSON object per line with source_id / vendor_project / product (the shape the OCO graph keeps)."""
    text = Path(path).read_text()
    rows = []
    if text.lstrip().startswith("{") and '"vulnerabilities"' in text[:2000]:
        for v in json.loads(text).get("vulnerabilities", []):
            rows.append({"cve": str(v.get("cveID", "")).upper(), "vendor": v.get("vendorProject", ""), "product": v.get("product", ""), "title": v.get("vulnerabilityName", "")})
    else:
        for line in text.splitlines():
            if line.strip():
                v = json.loads(line)
                rows.append({"cve": str(v.get("source_id") or v.get("cve") or "").upper(), "vendor": v.get("vendor_project", ""), "product": v.get("product", ""), "title": v.get("title", "")})
    return [r for r in rows if r["cve"].startswith("CVE-")]


def cmd_project(a) -> int:
    """Declared dependencies of one or more project folders against CISA-exploited CVEs, through Lattice. Evidence for a person; it decides nothing, writes no host records."""
    from lattice_scan import manifests
    ids = [c.upper() for c in (a.cve or [])]
    if a.cve_file:
        try:
            ids += [l.split("#")[0].strip().upper() for l in Path(a.cve_file).read_text().splitlines() if l.split("#")[0].strip()]
        except OSError as err:
            print(f"cannot read --cve-file: {err}", file=sys.stderr)
            return 2
    if not ids and not a.kev_catalogue:
        print("nothing to check: give --cve / --cve-file, or --kev-catalogue FILE (CISA's catalogue, used here only to choose which ids to read)", file=sys.stderr)
        return 2
    results = []
    lat = Lattice()
    started = False
    stopped = ""
    catalogue = load_catalogue(a.kev_catalogue) if a.kev_catalogue else []
    for root_s in a.paths:
        root = Path(root_s).resolve()
        if not root.is_dir():
            print(f"not a folder: {root_s}", file=sys.stderr)
            return 2
        comps, files, cut = manifests.read_project(root)
        inv, where = project_inventory(comps)
        pinned = sum(1 for c in comps if c.version)
        # Which ids to read: the ones named, plus catalogue entries whose product words are all declared here (a name match, nothing more).
        picked = {}
        for e in catalogue:
            if e["cve"] in ids or e["cve"] in picked:
                continue
            m = project_candidate(e, inv)
            if m:
                picked[e["cve"]] = m[0]
        todo = sorted(set(ids) | set(picked))
        unread = []
        if len(todo) > a.max_read:
            unread = todo[a.max_read:]
            todo = todo[:a.max_read]
        hits, read, not_listed = [], 0, []
        for cve in todo:
            if stopped:
                unread.append(cve)
                continue
            try:
                if not started:
                    lat.start()
                    started = True
                e = kev_entry(lat, cve)
            except LatticeError as err:
                stopped = str(err)
                unread.append(cve)
                continue
            read += 1
            if e is None:
                not_listed.append(cve)
                continue
            m = project_candidate(e, inv)
            if not m:
                continue
            why, installed, vers = m
            names = [k for k, v in inv["packages"].items() if f"{k.split('#')[0]} {v}" in installed]
            vc = version_check(e, vers)
            hits.append({"cve": cve, "title": e["title"], "why": why, "listed": e["added"], "due": e["due"], "action": e["action"][:400], "versionCheck": vc,
                         "declared": [{"name": c.name, "spec": c.spec, "version": c.version, "file": c.file, "line": c.line, "ecosystem": c.ecosystem}
                                      for n in names for c in where.get(n, [])]})
        results.append({"root": str(root), "files": files, "filesCut": cut, "components": len(comps), "pinned": pinned, "read": read, "candidates": hits,
                        "notListed": not_listed, "unread": unread, "stopped": stopped})
    if a.json:
        Path(a.json).write_text(json.dumps({"tool": f"lattice-scan {__version__}", "on": TODAY, "projects": results}, indent=1))
    for r in results:
        print(f"project scan {TODAY}: {r['root']}\n  {len(r['files'])} manifest file(s), {r['components']} declared component(s), {r['pinned']} pinned to a version"
              + (" (file search stopped at its limit: not every manifest was read)" if r["filesCut"] else ""))
        print(f"  {r['read']} exploited entries read, {len(r['candidates'])} candidate(s) (a person must read each against what is really deployed)")
        for h in r["candidates"]:
            print(f"  {h['cve']}  {h['title'][:70]}\n      because: {h['why']}")
            for d in h["declared"][:6]:
                print(f"      declared: {d['name']} {d['spec'] or '(no version)'}  [{d['file']}:{d['line']}]")
            vc = h["versionCheck"]
            print(f"      listed {h['listed'] or '-'}, due {h['due'] or '-'}\n      version check: {vc['verdict']}: {vc['why']}")
            if vc["verdict"] == "in-range":
                print("      (declared version only: what is deployed may differ, and a distribution may have backported the fix)")
        if r["unread"]:
            print(f"  NOT READ ({len(r['unread'])}): " + ", ".join(r["unread"][:12]) + (" ..." if len(r["unread"]) > 12 else "") + ("  (stopped: " + r["stopped"] + ")" if r["stopped"] else "  (over --max-read; raise it or use a key)"))
        if r["notListed"]:
            print(f"  not in the graph's CISA list (not 'safe', only 'not listed in this snapshot'): {', '.join(r['notListed'][:12])}")
    if stopped:
        print(f"stopped: {stopped}", file=sys.stderr)
    bad = [h for r in results for h in r["candidates"] if (a.fail_on == "candidate") or (a.fail_on == "in-range" and h["versionCheck"]["verdict"] == "in-range")]
    return 1 if (bad and a.fail_on != "never") else (3 if stopped else 0)


def print_impact(imp: dict) -> None:
    print(f"      installed: {'; '.join(imp['installed'])}")
    print(f"      listed {imp.get('listed') or '-'}" + (f" ({imp['daysSinceListed']} days ago)" if "daysSinceListed" in imp else "") + f", due {imp.get('due') or '-'}" + (f", {imp['dueStatus']}" if "dueStatus" in imp else ""))
    if imp.get("nvdAlsoNames"):
        print(f"      NVD also lists names found here: {', '.join(imp['nvdAlsoNames'])}")
    if imp.get("action"):
        print(f"      CISA required action: {imp['action'][:200]}")
    vc = imp.get("versionCheck")
    if vc:
        print(f"      version check: {vc['verdict']}: {vc['why']}")
        if vc["verdict"] == "in-range":
            print("      (upstream numbers only: a distro can fix this under the same number, see the changelog line)")
    cl = imp.get("changelogNamesCve")
    print("      changelog names this CVE: " + (", ".join(cl) if cl else "no installed package's changelog does (or none is readable here)"))


def cmd_impact(a) -> int:
    f = next((e for e in events() if e["ref"] == a.cve and e["event"] == "found"), None)
    if not f:
        print(f"no finding {a.cve}", file=sys.stderr); return 2
    st = state()[a.cve]
    print(f"{a.cve} [{st['status']}] {f.get('title','')}\n      because: {f.get('why','')}")
    if st.get("impact"):
        print_impact(st["impact"])
    else:
        print("      no impact record (found before the impact check existed, or added by hand)")
    return 0


def cmd_resolve(a) -> int:
    if a.cve not in state():
        print(f"no finding {a.cve}", file=sys.stderr); return 2
    if a.status in ("fixed", "verified") and not a.proof:
        print("a proof is required: the changelog line, version or command output that shows it", file=sys.stderr); return 2
    append("findings.jsonl", {"event": a.status, "ref": a.cve, "on": a.on or TODAY, "proof": a.proof or ""})
    print(f"{a.cve} -> {a.status}"); return 0


def cmd_add(a) -> int:
    if a.ref in state():
        print(f"{a.ref} already recorded", file=sys.stderr); return 2
    append("findings.jsonl", {"event": "found", "ref": a.ref, "on": a.on or TODAY, "listed": a.on or TODAY, "title": a.note, "why": "recorded by hand", "kind": "manual"})
    print(f"{a.ref} recorded"); return 0


def stats() -> dict:
    rf = OUT / "runs.jsonl"
    runs = [json.loads(l) for l in rf.read_text().splitlines()] if rf.exists() else []
    s = list(state().values())
    kev = [f for f in s if f.get("kind") == "kev"]
    real = [f for f in s if f["status"] != "not-applicable"]
    fixed = [f for f in real if f["status"] == "fixed"]
    days = sorted({r["on"] for r in runs})
    gaps = [(dt.date.fromisoformat(f["closed"]) - dt.date.fromisoformat(f["listed"])).days for f in fixed if f.get("listed") and f.get("closed")]
    return {"runs": len(runs), "daysOfRecord": len(days), "firstRun": days[0] if days else None, "lastRun": days[-1] if days else None,
            "newExploitedRead": sum(r["read"] for r in runs), "candidates": len(kev),
            "touchedHost": len([f for f in kev if f["status"] != "not-applicable"]),
            "wrongMatches": len([f for f in s if f["status"] == "not-applicable"]),
            "fixed": len(fixed), "open": len([f for f in real if f["status"] in ("open", "verified")]),
            "medianDaysListedToFixed": statistics.median(gaps) if gaps else None}


def main() -> int:
    p = argparse.ArgumentParser(prog="lattice-scan", description="Check a host against CISA-exploited CVEs through Lattice.")
    p.add_argument("--version", action="version", version=f"lattice-scan {__version__}")
    p.add_argument("--cve", action="append", help="a CVE id to check (repeatable)")
    p.add_argument("--cve-file", help="file of CVE ids, one per line, # comments allowed")
    p.add_argument("--discover", action="store_true", help="find exploited CVEs added in the window (needs LATTICE_API_KEY)")
    p.add_argument("--debug", action="store_true", help="detailed execution log to stderr and debug.log (also LATTICE_SCAN_DEBUG=1)")
    p.add_argument("--refresh", action="store_true", help="collect the inventory again now and print all of it; with ids, also re-read them. Alone it makes no Lattice call")
    p.add_argument("--again", action="store_true", help="re-read ids already read before")
    sub = p.add_subparsers(dest="c")
    r = sub.add_parser("resolve"); r.add_argument("cve"); r.add_argument("--status", required=True, choices=["verified", "fixed", "not-applicable"]); r.add_argument("--proof", default=""); r.add_argument("--on")
    im = sub.add_parser("impact", help="the recorded impact detail of one finding"); im.add_argument("cve")
    d = sub.add_parser("add"); d.add_argument("--ref", required=True); d.add_argument("--note", required=True); d.add_argument("--on")
    pj = sub.add_parser("project", help="check the dependencies a project DECLARES (requirements, pyproject, package.json and lock, Dockerfile, compose); writes no host records")
    pj.add_argument("paths", nargs="*", default=["."], help="project folders (default: the current folder)")
    pj.add_argument("--cve", action="append"); pj.add_argument("--cve-file")
    pj.add_argument("--kev-catalogue", help="CISA's known_exploited_vulnerabilities.json; used locally to choose which ids to read, nothing from it is sent")
    pj.add_argument("--max-read", type=int, default=40, help="most ids to read from Lattice per project (default 40: the keyless daily allowance is 60)")
    pj.add_argument("--json", help="also write the result to this file")
    pj.add_argument("--fail-on", choices=["never", "in-range", "candidate"], default="never", help="exit 1 when a candidate (or an in-range one) is found; default never: a person reads it")
    sub.add_parser("list"); sub.add_parser("stats")
    il = sub.add_parser("inventory", help="show inventory.log: counts and changes per run"); il.add_argument("-n", type=int, default=20)
    lg = sub.add_parser("log"); lg.add_argument("-n", type=int, default=20, help="last N lines (default 20)")
    a = p.parse_args()
    global DEBUG
    DEBUG = a.debug or env("DEBUG") == "1"
    if a.c == "project": return cmd_project(a)
    if a.c == "impact": return cmd_impact(a)
    if a.c == "resolve": return cmd_resolve(a)
    if a.c == "add": return cmd_add(a)
    if a.c == "inventory":
        f = OUT / "inventory.log"
        print("".join(f.read_text().splitlines(True)[-a.n:]) if f.exists() else "no inventory logged yet", end="")
        return 0
    if a.c == "log":
        f = OUT / "scan.log"
        print("".join(f.read_text().splitlines(True)[-a.n:]) if f.exists() else "no scans logged yet", end="")
        return 0
    if a.c == "stats": print(json.dumps(stats(), indent=1)); return 0
    if a.c == "list":
        for f in sorted(state().values(), key=lambda x: x.get("found", "")):
            print(f"{f['ref']:<18} {f['status']:<15} listed {f.get('listed','-')} found {f.get('found','-')} closed {f.get('closed','-')}  {f.get('title','')[:50]}")
        return 0
    return cmd_run(a)


if __name__ == "__main__":
    sys.exit(main())
