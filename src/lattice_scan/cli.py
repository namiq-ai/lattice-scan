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

Env: LATTICE_URL (default https://lattice.namiq.io/mcp), LATTICE_API_KEY, LATTICE_SCAN_DIR (a folder this user can write; set it for an agent in a sandbox), LATTICE_SCAN_KEEP=1, LATTICE_SCAN_INVENTORY (tests: fixed inventory JSON),
LATTICE_SCAN_TODAY (YYYY-MM-DD), LATTICE_SCAN_WINDOW (days back; default 6 = seven days counting today).
"""
from __future__ import annotations
import argparse, atexit, datetime as dt, hashlib, json, os, re, shutil, statistics, subprocess, sys, tempfile, time, urllib.error, urllib.request
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
DEFAULT_OUT = OUT   # what records_dir() chose; a test or a fallback that moves OUT elsewhere is no longer 'the default'
KEEP = False        # --keep / LATTICE_SCAN_KEEP=1: write records to the default folder even for a non-interactive run
FEED_URL = env("FEED", "https://namiq.io/lattice/recent.json")
KEY_API = env("KEY_URL", "https://namiq.io/api/v1/lattice/agent-keys")
TERMS_DOC = env("TERMS_URL", "https://namiq.io/lattice/openapi.json")


def saved_key() -> str:
    """The key `get-key` stored, if the file is still private to this user. A key file anyone else can read is ignored, not used."""
    f = OUT / "key"
    try:
        if f.is_file() and (f.stat().st_mode & 0o077) == 0:
            return f.read_text().strip()
    except OSError:
        pass
    return ""


if not KEY:
    KEY = saved_key()
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
PROGRESS = False


def progress(msg: str) -> None:
    """OCO-5837: what the scan is doing now, one line on stderr (never stdout, so csv, json and pipes are untouched). Nothing else is
    written, no key and no package list: only counts, file names under the folder given, and CVE ids."""
    if PROGRESS:
        print(msg, file=sys.stderr, flush=True)


def dbg(msg: str, file_only: bool = False) -> None:
    """Execution trace (--debug / LATTICE_SCAN_DEBUG=1): to stderr and to debug.log. Never writes the API key; request bodies hold only tool names and ids."""
    if not DEBUG:
        return
    line = f"{dt.datetime.now().isoformat(timespec='milliseconds')} {msg}"
    if not file_only:
        print(line, file=sys.stderr)
    private_dir()
    with open_private(OUT / "debug.log") as fh:
        fh.write(line + "\n")


class LatticeError(Exception):
    pass


RATE_RETRIES, MAX_RATE_WAIT = 2, 70.0   # a 429 that says 'retry after N seconds' is waited out (at most twice, and only if N is a minute or so)
PACE_CALLS, PACE_WINDOW = 5, 60.5         # keyless: 5 calls a minute, counted across runs; half a second of margin
RETRY_DELAYS = (2.0, 6.0)   # seconds before the 2nd and 3rd try of a request that failed on the network or with 502/503/504
MAX_REPLY = 8 * 1024 * 1024  # a reply bigger than this is not a Lattice answer


def clean(v):
    """Text that came from the network is data, never terminal commands: replace control characters (including ESC) before it is printed or logged."""
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "?", v) if isinstance(v, str) else v


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the key is in a header, and a redirect would carry it to wherever it points."""

    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def open_private(path: Path, mode: str = "a"):
    """Open a records file created 0600, whatever the umask: the records name this host's software, and the folder's own 0700 is not the only door."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if mode == "a" else os.O_TRUNC)
    return os.fdopen(os.open(path, flags, 0o600), mode)


def write_private(path: Path, text: str) -> None:
    with open_private(path, "w") as fh:
        fh.write(text)


def use_temp_records(note: str) -> None:
    """Send this run's records to a private temporary folder that is deleted when the run ends. WHY: an agent in its own sandbox has no home it may
    write to, or should not leave a list of installed packages in one. The findings of such a run are not remembered by the next one: LATTICE_SCAN_DIR or --keep opts in."""
    global OUT
    d = Path(tempfile.mkdtemp(prefix="lattice-scan-"))   # mkdtemp is 0700
    atexit.register(shutil.rmtree, d, True)
    OUT = d
    progress(f"[records] {note}: this run's records are kept in a temporary folder and deleted when it ends (LATTICE_SCAN_DIR or --keep keeps them)")


def private_dir(keep: bool = False) -> None:
    """The records directory exists and is 0700, and every file in it 0600, even if an earlier run or the user created it looser: it names this host's software.

    Three cases when it is the default folder (nothing set, no test override): it already exists (use it: the person chose records by having them);
    it does not exist and the run has no terminal on stdin or stderr, as with an agent or a cron job (use a temporary folder, unless --keep);
    it cannot be created (say so in one line if LATTICE_SCAN_DIR was named, else use a temporary folder). `keep` is for a key, which must outlive the run."""
    if not keep and not KEEP and OUT == DEFAULT_OUT and not env("DIR") and not OUT.exists() and not sys.stdin.isatty() and not sys.stderr.isatty():
        use_temp_records("no records folder yet and no terminal")
    try:
        OUT.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(OUT, 0o700)
        for f in OUT.iterdir():
            if f.is_file() and f.stat().st_mode & 0o077:
                os.chmod(f, 0o600)
    except OSError as err:
        if keep or env("DIR") or OUT != DEFAULT_OUT:
            sys.exit(f"lattice-scan: cannot use the records folder {OUT} ({err.strerror or err}). Set LATTICE_SCAN_DIR to a folder this user can write.")
        print(f"lattice-scan: cannot write {OUT} ({err.strerror or err}); using a temporary folder for this run.", file=sys.stderr)
        use_temp_records("the records folder is not writable")
        OUT.mkdir(parents=True, exist_ok=True, mode=0o700)


def check_url() -> None:
    """A key must not travel in clear text: refuse http:// unless it is this machine (the tests' stub server)."""
    from urllib.parse import urlparse
    u = urlparse(URL)
    if u.scheme == "https" or (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1")):
        return
    if u.scheme == "http" and not KEY:
        return  # no key to leak; the ids only
    raise LatticeError(f"refusing to use {URL}: a key is set and the address is not https")


def retry_after(header: str | None, body: str) -> float | None:
    """Seconds Lattice asked us to wait: the Retry-After header (seconds), else 'Retry after N seconds' in its message."""
    if header and re.fullmatch(r"\s*\d+(?:\.\d+)?\s*", header):
        return float(header)
    m = re.search(r"retry after\s+(\d+(?:\.\d+)?)\s*second", body, re.I)
    return float(m.group(1)) if m else None


PACE_FILE: Path | None = None   # tests point this at a temp file


def pace_path() -> Path:
    """Where call times are remembered: the user's cache folder, not the records (a project or enrich run writes no records)."""
    if PACE_FILE:
        return PACE_FILE
    if env("PACE_FILE"):
        return Path(env("PACE_FILE"))
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "lattice-scan" / "pace.json"


def pace_times() -> list[float]:
    try:
        return [t for t in json.loads(pace_path().read_text()) if isinstance(t, (int, float))]
    except (OSError, ValueError, TypeError):
        return []


def pace_wait(now: float | None = None) -> float:
    """Seconds to wait before the next keyless call so that no more than PACE_CALLS fall in a minute, counting calls made by other runs a moment ago."""
    now = time.time() if now is None else now
    recent = sorted(t for t in pace_times() if now - t < PACE_WINDOW)
    return recent[-PACE_CALLS] + PACE_WINDOW - now if len(recent) >= PACE_CALLS else 0.0


def pace_note() -> None:
    """Remember this call's time (a few numbers, no names), so the next run, even a separate one, can space itself. Best effort: a read-only home just means no memory."""
    now = time.time()
    keep = [t for t in pace_times() if now - t < PACE_WINDOW][-(PACE_CALLS - 1):] + [now]
    f = pace_path()
    try:
        f.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = f.with_name(f"{f.name}.{os.getpid()}")
        tmp.write_text(json.dumps(keep))
        os.replace(tmp, f)
    except OSError:
        pass


class Lattice:
    """Minimal MCP client over streamable HTTP. The server may answer plain JSON or an SSE stream; both are read."""

    def __init__(self) -> None:
        self.session = ""
        self.n = 0
        self.last_gap = 0.0

    @staticmethod
    def _wait_to_retry(attempt: int, why: str) -> None:
        """A lookup only reads, so asking again is safe. Say so on stderr, wait, and let the caller go round once more."""
        delay = RETRY_DELAYS[attempt]
        progress(f"Lattice did not answer ({why}); trying again in {delay:g}s ({attempt + 2} of {len(RETRY_DELAYS) + 1})")
        time.sleep(delay)

    def _post(self, body: dict) -> dict | None:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "User-Agent": f"lattice-scan/{__version__}"}
        if KEY:
            h["X-API-Key"] = KEY
        if self.session:
            h["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(URL, json.dumps(body).encode(), h)
        t0 = time.time()
        dbg(f"-> POST {URL} {body.get('method')} {json.dumps(body.get('params', {}).get('arguments', ''))} key={'set' if KEY else 'none'} session={self.session or '-'}")
        attempt = rate_tries = 0
        while True:
            try:
                with _OPENER.open(req, timeout=30) as r:
                    self.session = r.headers.get("Mcp-Session-Id", self.session)
                    raw = r.read(MAX_REPLY + 1).decode(errors="replace")
                    if len(raw) > MAX_REPLY:
                        raise LatticeError("reply from Lattice is larger than 8 MB: refusing it")
                    dbg(f"<- HTTP {r.status} {len(raw)} bytes in {time.time() - t0:.2f}s content-type={r.headers.get('Content-Type')}")
                break
            except urllib.error.HTTPError as e:
                detail = e.read().decode()[:300]
                dbg(f"<- HTTP {e.code} in {time.time() - t0:.2f}s body={detail}")
                if e.code == 429 and rate_tries < RATE_RETRIES:
                    wait = retry_after(e.headers.get("Retry-After"), detail)
                    if wait is not None and wait <= MAX_RATE_WAIT:
                        rate_tries += 1
                        progress(f"Lattice's keyless limit (5 calls a minute) was reached; waiting {wait:g}s as it asked, then trying again ({rate_tries} of {RATE_RETRIES})")
                        time.sleep(wait + 1)
                        continue
                if e.code in (502, 503, 504) and attempt < len(RETRY_DELAYS):
                    self._wait_to_retry(attempt, f"HTTP {e.code}")
                    attempt += 1
                    continue
                raise LatticeError(f"HTTP {e.code} from Lattice: {detail}")
            except (urllib.error.URLError, OSError) as e:   # includes a TLS handshake or read timeout
                dbg(f"<- failed in {time.time() - t0:.2f}s: {e!r}")
                if attempt < len(RETRY_DELAYS):
                    self._wait_to_retry(attempt, str(e))
                    attempt += 1
                    continue
                raise LatticeError(f"cannot reach Lattice after {attempt + 1} tries: {e}")
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
        # Keyless access allows 5 calls a minute, counted across every run on this machine: space them out instead of burning the day's units on 429s.
        if not KEY:
            wait = pace_wait()
            if wait > 1:   # a sub-second shortfall is not worth a message; the 429 handler covers the rare edge
                dbg(f"keyless pacing: sleeping {wait:.1f}s (5 calls/minute limit)")
                progress(f"keyless limit: 5 calls a minute, so waiting {wait:.0f}s before the next lookup")
                time.sleep(wait)
            pace_note()
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


from lattice_scan import report  # noqa: E402


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
        progress("[host] inventory read from a fixed file (LATTICE_SCAN_INVENTORY), nothing collected from this machine")
        return inv
    pk: dict[str, str] = {}
    manager = "dpkg"
    progress("[host] collecting installed packages ...")
    for line in run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"]).splitlines():
        n, _, v = line.partition("\t")
        if n:
            pk[n] = v
    if not pk:  # rpm and apk hosts
        manager = "rpm"
        for line in run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"]).splitlines():
            n, _, v = line.partition("\t")
            if n:
                pk[n] = v
    if not pk:
        manager = "apk"
        for line in run(["apk", "info", "-v"]).splitlines():
            m = re.match(r"(.+?)-(\d[^-]*-r\d+)$", line)
            if m:
                pk[m.group(1)] = m.group(2)
    progress(f"[host] packages: {len(pk)} installed ({manager if pk else 'no package manager found'})")
    snaps = {f[0]: f[1] for f in (l.split() for l in run(["snap", "list"]).splitlines()[1:]) if len(f) >= 2}
    progress(f"[host] snaps: {len(snaps)}")
    images = sorted({i for i in run(["docker", "ps", "--format", "{{.Image}}"]).splitlines() if i})
    progress(f"[host] container images running (names only): {len(images)}")
    osr = ""
    try:
        osr = next((l.split("=", 1)[1].strip('"') for l in Path("/etc/os-release").read_text().splitlines() if l.startswith("PRETTY_NAME=")), "")
    except OSError:
        pass
    kernel = run(["uname", "-r"]).strip()
    progress(f"[host] kernel: {kernel or 'unknown'}" + (f", os: {osr}" if osr else ""))
    inv = {"kernel": kernel, "os": osr, "packages": pk, "snaps": snaps, "images": images, "node": run(["node", "-v"]).strip(),
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
    lead          the declared package only shares a scope or name with the product, or is its client library (minio); no range is compared
    """
    # The ranges that belong to THIS entry's product: same vendor as CISA names it, and a shared product word. The host was already matched by name
    # (a kernel matches by uname, not by a package), so what is installed is not consulted here.
    kev_words = words(entry.get("product", ""))
    kev_words |= {w[:-2] for w in kev_words if w.endswith("js") and len(w) > 4}      # CISA says "Vitejs", NVD says vite
    vendor = re.sub(r"[^a-z0-9]", "", entry.get("vendor", "").lower())
    prod_forms = {_flat(entry.get("product", ""))}
    prod_forms |= {f[:-2] for f in prod_forms if f.endswith("js") and len(f) > 4}
    mine = []
    for r in entry.get("ranges", []):
        sv, _, sp = r.get("product", "").partition("/")
        # Another vendor's range is not ours, unless the product name is the same name: CISA's vendor is often the maintainer today ("Kludex Starlette")
        # while NVD files the product under the original one ("encode/starlette"), and "sudo_project/sudo" is CISA's "Sudo".
        vendor_ok = not vendor or re.sub(r"[^a-z0-9]", "", sv.lower()) in vendor or _flat(sp.replace("_", " ")) in prod_forms
        if words(sp.replace("_", " ")) & kev_words and vendor_ok:
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


def ransom(v: str) -> str:
    """CISA's known_ransomware_use as a table cell: 'known', or '-' when CISA has not recorded it (CISA's 'Unknown'), which is not the same as no ransomware use."""
    return "known" if (v or "").strip().lower() == "known" else "-"


def due_cell(due: str) -> str:
    """CISA's patch-due date, as the date only (days late or left are not shown: the date says it)."""
    try:
        return dt.date.fromisoformat(due).isoformat()
    except ValueError:
        return "-"


def cvss_cell(v) -> str:
    try:
        return f"{float(v):.1f}"
    except (TypeError, ValueError):
        return "-"


def cells(e: dict | None) -> list[str]:
    """EXPLOITED, CVSS, LISTED, PATCH DUE, RANSOMWARE, PRODUCT for one table row; '-' where Lattice gave nothing."""
    if e is None:
        return ["no", "-", "-", "-", "-", "-"]
    return ["yes", cvss_cell(e.get("cvss")), e.get("added") or "-", due_cell(e.get("due", "")), ransom(e.get("ransomware", "")),
            f"{e['vendor'] or '-'} {e['product'] or '-'}".strip()]


CONTEXT_DESC = 300


def fixed_in(entry: dict) -> dict[str, list[str]]:
    """The versions NVD says are the first unaffected, per product, from the ranges Lattice returned. Upstream numbers: a distro can fix under the same number."""
    out: dict[str, list[str]] = {}
    for r in entry.get("ranges", []):
        if r.get("end_excluding") and r.get("product"):
            out.setdefault(r["product"], [])
            if r["end_excluding"] not in out[r["product"]]:
                out[r["product"]].append(r["end_excluding"])
    return dict(list(out.items())[:3])


def context(lat: "Lattice", e: dict) -> dict:
    """What a person needs to judge how urgent a candidate is and what it is (Lattice serves graph_node and links without a key).

    One graph_node read of the NVD node (EPSS, CISA's SSVC, CWE, description, references) plus the links the lookup already carried (the ATT&CK
    techniques and weaknesses it connects to). All of it is text from a server: cleaned, and shown as data. If the server refuses the read or has no
    links the candidate is left as it was and the reason is one line on stderr. Returns {} when there is nothing.
    """
    props: dict = {}
    if e.get("nvdUid"):
        try:
            props = lat.call("graph_node", uid=e["nvdUid"]).get("properties") or {}
        except LatticeError as err:
            progress(f"{e['cve']}: no detail from Lattice ({clean(str(err))[:120]}); showing the candidate without it")
    md = props.get("metadata") or {}
    ctx: dict = {}
    epss = md.get("epss") or {}
    if epss.get("score") is not None:
        ctx["epss"] = {"score": epss.get("score"), "percentile": epss.get("percentile"), "date": clean(str(epss.get("date", "")))}
    ssvc = md.get("ssvc") or {}
    if ssvc:
        ctx["ssvc"] = {k: clean(str(ssvc[k])) for k in ("exploitation", "automatable", "technical_impact") if ssvc.get(k)}
    if props.get("cwe_refs"):
        ctx["cwe"] = [clean(str(c)) for c in props["cwe_refs"]][:5]
    if props.get("description"):
        ctx["description"] = clean(str(props["description"]))[:CONTEXT_DESC]
    refs = [clean(str(r)) for r in props.get("references") or [] if str(r).startswith(("http://", "https://"))][:3]
    if refs:
        ctx["references"] = refs
    tech = []
    for ln in e.get("links") or []:
        if not isinstance(ln, dict) or "ATTACK" not in (ln.get("labels") or []):
            continue
        tech.append({"id": clean(str(ln.get("id", ""))), "title": clean(str(ln.get("title", ""))), "likely": ln.get("evidence_class") == "inferred"})
    if tech:
        ctx["techniques"] = tech
    fx = fixed_in(e)
    if fx and ctx:
        ctx["fixedIn"] = fx
    return ctx


def priority(e: dict, imp: dict, ctx: dict) -> dict:
    """The tool's reading of CISA and FIRST fields, in three words and the reasons it rests on. Not a risk score and not a verdict."""
    fire, soon = [], []
    if (e.get("ransomware") or "").strip().lower() == "known":
        fire.append("CISA records ransomware use")
    ssvc = ctx.get("ssvc") or {}
    if ssvc.get("exploitation") == "active" and ssvc.get("automatable") == "yes":
        fire.append("CISA SSVC: exploitation active and automatable")
    if str(imp.get("dueStatus", "")).startswith("overdue"):
        fire.append(f"CISA patch-due date passed ({imp['dueStatus']})")
    score = (ctx.get("epss") or {}).get("score")
    try:
        if score is not None and float(score) >= 0.5:
            soon.append(f"EPSS {float(score):.2f}")
    except (TypeError, ValueError):
        pass
    if fire:
        return {"level": "fix first", "reasons": fire + soon}
    return {"level": "fix soon", "reasons": soon} if soon else {"level": "read", "reasons": []}


PRIORITY_RANK = {"fix first": 0, "fix soon": 1, "read": 2}


def add_context(lat: "Lattice", e: dict, imp: dict, reuse: dict | None = None) -> None:
    """Put the context and priority into an impact record. `reuse` is a record saved earlier: its context is kept so a repeat run makes no extra call."""
    ctx = (reuse or {}).get("context") if reuse else None
    if not ctx:
        ctx = context(lat, e)
    if ctx:
        imp["context"] = ctx
        imp["priority"] = priority(e, imp, ctx)


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
    primary = next((i for i in items if i.get("primary")), nvd)
    e = {"nvdUid": nvd.get("uid") or "", "links": primary.get("links") if isinstance(primary.get("links"), list) else [],
         "cve": cve, "title": clean(kev.get("title", "")), "added": clean(str(kev.get("date_added", ""))), "due": clean(str(kev.get("due_date", ""))),
         "vendor": clean(kev.get("vendor_project", "")), "product": clean(kev.get("product", "")), "ransomware": clean(str(kev.get("known_ransomware_use", ""))), "cvss": nvd.get("cvss_score"), "action": clean(kev.get("required_action", "")),
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
    with open_private(OUT / path) as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")


def append_found_once(rec: dict) -> bool:
    """Record a new finding unless one for the same id is already there, under a lock, so two runs at the same moment record it once. True when this call wrote it."""
    private_dir()
    with open_private(OUT / ".lock") as lock:
        try:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX)
        except ImportError:   # no fcntl (Windows): without a lock the worst case is a repeated line, which the status view already merges
            pass
        if any(e.get("event") == "found" and e.get("ref") == rec["ref"] for e in events()):
            return False
        append("findings.jsonl", rec)
        return True


def scanlog(line: str) -> None:
    """One human-readable line per run in scan.log, so 'what did the last scan see, and did it fail' is answerable without parsing the jsonl."""
    private_dir()
    with open_private(OUT / "scan.log") as fh:
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
    with open_private(OUT / "inventory.log") as fh:
        fh.write("\n".join(lines) + "\n")


def state() -> dict[str, dict]:
    s: dict[str, dict] = {}
    for e in events():
        f = s.setdefault(e["ref"], {"ref": e["ref"], "status": "open"})
        if e["event"] == "found":
            f.update(listed=e.get("listed", ""), found=e["on"], why=e.get("why", ""), title=e.get("title", ""), due=e.get("due", ""), kind=e.get("kind", "kev"), ransomware=e.get("ransomware", ""), cvss=e.get("cvss"), impact=e.get("impact"))
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


def detail_files(inv: dict) -> None:
    """Where the full detail of this run is kept, so nobody has to look for it (OCO-5837)."""
    here = [(n, what) for n, what in (("findings.jsonl", "one record per candidate, with its impact and every later status change"),
                                      ("scan.log", "one line per run: what was read, how many candidates"),
                                      ("inventory.json", f"this host's inventory as collected now (hash {inv['hash']}); names this host's software"),
                                      ("runs.jsonl", "one record per run"), ("debug.log", "the --debug trace, if it was on")) if (OUT / n).exists()]
    print(f"\nDETAILED RESULT FILES  ({OUT}, private to this user; they name this host's software, so do not share or commit them)")
    for n, what in here:
        print(f"  {n:<15} {what}")
    print("  lattice-scan list            every recorded finding and its status\n  lattice-scan impact CVE-...  the full impact detail of one finding\n"
          "  lattice-scan resolve CVE-... --status fixed --proof \"...\"   record the outcome")


def print_table(rows: list[list[str]]) -> None:
    """The RESULT BY CVE table of the host check, `recent` and `enrich` (nine columns, see cells())."""
    if not rows:
        return
    print("\nRESULT BY CVE")
    lines, hidden = report.table(["CVE", "Exploit", "CVSS", "Listed", "Patch due", "Ransom", "Product", "Result", "Matched / compared"], rows,
                                 report.width_for(None), fit=sys.stdout.isatty(), drop=("Listed", "Product", "CVSS"), min_last=45)
    print("\n".join(lines))
    if hidden:
        print(f"(narrow terminal: hidden {', '.join(h.upper() for h in hidden)}; pipe the output, for example `| cat`, to see every column)")
    print()


def cmd_run(a) -> int:
    private_dir()
    seen_f = OUT / "seen.json"
    seen = set(json.loads(seen_f.read_text())) if seen_f.exists() else set()
    ids = split_ids(a.cve)
    if a.cve_file:
        try:
            lines = Path(a.cve_file).read_text().splitlines()
        except OSError as err:
            print(f"cannot read --cve-file: {err}", file=sys.stderr)
            return 2
        ids += split_ids(l.split("#")[0] for l in lines)
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
        write_private(inv_f, json.dumps(inv, indent=1, sort_keys=True))
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
    inv = getattr(a, "inv", None) or inventory()
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
    write_private(inv_f, json.dumps(inv, indent=1, sort_keys=True))
    dbg(f"run: today={TODAY} window={WINDOW}d floor={floor} url={URL} key={'set' if KEY else 'none'} ids={len(set(ids))} discover={a.discover} again={a.again} records={OUT}")
    lat = Lattice()
    known = {e["ref"] for e in events()}
    hits, again_hits, read, not_listed = [], [], 0, []
    rows: list[list[str]] = []   # the result table, one row per CVE (columns in the report.table call below)
    try:
        lat.start()
        if a.discover:
            progress(f"[host] discovering exploited CVEs added since {floor} (needs a key) ...")
            ids += discover(lat, floor)
            progress(f"[host] discovery found {len(set(ids))} id(s) to read")
            dbg(f"discover: {len(set(ids))} exploited ids to read")
        order_ids = sorted(set(ids))
        for n_cve, cve in enumerate(order_ids, 1):
            tag = f"[{n_cve}/{len(order_ids)}] {cve}"
            if cve in seen and cve not in named and not (a.again or a.refresh):
                dbg(f"{cve}: skipped, already read (--again to re-read)")
                progress(f"{tag}  skipped, already read (--again to read it again)")
                rows.append([cve, *["-"] * 6, "skipped", "already read; use --again to read it again"])
                continue
            progress(f"{tag}  asking Lattice (only this id is sent) ...")
            e = kev_entry(lat, cve)
            dbg(f"{cve}: CHECK lattice says " + ("no CISA exploited entry in this snapshot (not the same as safe)" if e is None else
                f"CISA exploited: title={e['title']!r} vendor={e['vendor'] or '-'} product={e['product'] or '-'} added={e['added'] or '-'} due={e['due'] or '-'} nvd-affected={len(e['affected'])} ranges={len(e['ranges'])}"))
            if e is None:
                not_listed.append(cve)
                progress(f"{tag}  not in CISA's exploited list in this snapshot (that is not the same as safe)")
                rows.append([cve, *cells(None), "unlisted", "not in CISA's list in this snapshot (not the same as safe)"])
                continue
            if e["added"] and not (floor <= e["added"] <= TODAY) and not a.cve and not a.cve_file:
                dbg(f"{cve}: outside window {floor}..{TODAY} (added {e['added']}), skipped")
                progress(f"{tag}  outside the discovery window (added {e['added']}), skipped")
                rows.append([cve, *cells(e), "skipped", f"added {e['added']}, outside the discovery window"])
                continue  # discovery only reports the window; ids you named are always read
            read += 1
            progress(f"{tag}  CISA lists {e['vendor'] or '-'} {e['product'] or '-'}; comparing with {len(inv['packages'])} packages, {len(inv['snaps'])} snaps, "
                     f"{len(inv['images'])} container image names and the kernel ({inv['kernel'] or 'unknown'}) ...")
            m = candidate(e, inv)
            progress(f"{tag}  " + (f"CANDIDATE: {m[0]}" if m else "no installed package, snap, image or kernel matches the product"))
            rows.append([cve, *cells(e), ("RECORDED" if cve in known else "CANDIDATE") if m else "unmatch",
                         m[0] if m else "no package, snap, image or kernel matches"])
            if m and cve in known:
                imp = impact(e, inv, m[1], m[2])
                add_context(lat, e, imp, None if a.refresh else state()[cve].get("impact"))
                if a.refresh or not state()[cve].get("impact"):
                    append("findings.jsonl", {"event": "impact", "ref": cve, "on": TODAY, "impact": imp})
                again_hits.append((e, m[0], imp))
            if m and cve not in known:
                why, installed, vers = m
                imp = impact(e, inv, installed, vers)
                add_context(lat, e, imp)
                dbg(f"{cve}: IMPACT {json.dumps(imp)}")
                if append_found_once({"event": "found", "ref": cve, "on": TODAY, "listed": e["added"], "due": e["due"], "title": e["title"], "why": why, "kind": "kev", "ransomware": e["ransomware"], "cvss": e["cvss"], "impact": imp}):
                    hits.append((e, why, imp))
                else:   # another run recorded it a moment ago
                    again_hits.append((e, why, imp))
            seen.add(cve)
    except LatticeError as err:
        write_private(seen_f, json.dumps(sorted(seen)))
        scanlog(f"STOPPED after {read} read, {len(hits)} candidates: {err}")
        print(f"stopped: {err}", file=sys.stderr)
        return 1
    write_private(seen_f, json.dumps(sorted(seen)))
    append("runs.jsonl", {"on": TODAY, "read": read, "candidates": len(hits), "inventory": inv["hash"], "restartRequired": inv["restartRequired"]})
    scanlog(f"ok key={'yes' if KEY else 'no'} inventory={inv['hash']} read={read} candidates={len(hits)} already-recorded={len(again_hits)}"
            + "".join(f" [{e['cve']}: {why}]" for e, why, imp in hits) + (f" not-listed={','.join(not_listed)}" if not_listed else "")
            + (" restart-required" if inv["restartRequired"] else ""))
    print(f"host scan {TODAY}: {read} exploited entries read, {len(hits)} candidates (a person must read each against the installed version)")
    open_n = [f for f in state().values() if f["status"] in ("open", "verified")]
    listed_now = {r[0] for r in rows}
    for f in open_n:   # an open finding from an earlier run stays in the table, so it is listed once, in the table
        if f["ref"] not in listed_now:
            rows.append([f["ref"], "yes" if f.get("kind", "kev") == "kev" else "-", cvss_cell(f.get("cvss")), f.get("listed") or "-", due_cell(f.get("due", "")),
                         ransom(f.get("ransomware", "")), "-", f["status"].upper(),
                         f"{f.get('why', '')} (recorded {f.get('found', '?')}, not read in this run)"[:240]])
    rows += getattr(a, "extra_rows", [])   # `recent`: the feed's ids that were ruled out on this host and never sent to Lattice
    print_table(rows)
    hits.sort(key=lambda h: PRIORITY_RANK.get((h[2].get("priority") or {}).get("level", "read"), 2))   # fix first, then fix soon, then read; ties keep the id order
    for e, why, imp in hits:
        print(f"  {e['cve']}  {e['title'][:70]}\n      because: {why}")
        print_impact(imp)
    for e, why, imp in again_hits:
        print(f"  {e['cve']}  matches again ({why}); already recorded as {state()[e['cve']]['status']}, not counted as new")
        print_impact(imp)
    if not_listed:
        print(f"not in the graph's CISA list (not 'safe', only 'not listed in this snapshot'): {', '.join(not_listed)}")
    if inv["restartRequired"]:
        print("restart required: an installed update is waiting for a reboot")
    detail_files(inv)
    return 0


PROJECT_EPILOG = """\
who can do what:
  with a key (LATTICE_API_KEY) whose email is confirmed:   --kev-catalogue FILE, any number of ids
  without a key:                                          only the CVEs you name, comma separated:  --cve CVE-2026-46300,CVE-2021-44228

examples:
  lattice-scan project . --kev-catalogue known_exploited_vulnerabilities.json                  # needs a confirmed key
  lattice-scan project . --cve CVE-2026-46300,CVE-2021-44228                                    # works without a key
  lattice-scan project api/ web/ --name API --name WEB --cve CVE-2026-46300 --csv findings.csv
  lattice-scan project . --kev-catalogue kev.json --format csv > findings.csv
  lattice-scan project . --kev-catalogue kev.json --fail-on in-range        # exit 1 when a declared version is inside an affected range

csv columns (one row per finding and declared component; a header row always):
  project cve title verdict component ecosystem declared version file line listed due due_status action why
  verdict is one of in-range, undetermined, outside-range, lead, not-read. A cell that starts with = + - or @ has a leading ' so a spreadsheet does not run it.

exit status: 0 done; 1 --fail-on matched; 2 bad usage or an unreadable input; 3 stopped part-way (Lattice limit or unreachable): read the NOT READ list.
Only CVE ids leave the machine. Full manual: man lattice-scan.
"""


CONFIRMED_TIERS = ("trial_accepted", "commercial")
NEEDS_KEY = ("scanning against the exploited-vulnerability catalogue reads many ids, so it needs a Lattice key whose owner has confirmed their email. "
             "Without a key, name the CVEs instead: --cve CVE-2026-46300,CVE-2021-44228 (comma separated). A person requests a key at https://namiq.io/lattice/docs#agents.")


def split_ids(values) -> list[str]:
    """CVE ids from repeated --cve arguments or lines, each of which may hold several separated by commas or spaces: 'CVE-A,CVE-B' and 'CVE-A, CVE-B' both work."""
    out: list[str] = []
    for v in values or []:
        out += [t.strip().upper() for t in re.split(r"[,\s]+", str(v)) if t.strip()]
    return out


def project_inventory(comps) -> tuple[dict, dict[str, list]]:
    """An inventory in the shape the host matcher reads, built from declared components, and where each name was declared.

    A declared range, `latest` or no tag has no version, so its value is the declaration itself (`>=1.0`, `unpinned`): version_check cannot read it as a number and
    says `undetermined`, which is the truth. Where a lockfile pins a name, the unpinned declarations of that name are dropped: the lock is what is installed.
    A name with several different versions keeps each under `name#2`, `name#3`: they all matter.
    """
    pinned_names = {c.name for c in comps if c.version}
    packages: dict[str, str] = {}
    where: dict[str, list] = {}
    ecosystems: dict[str, str] = {}
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
        ecosystems[key] = c.ecosystem
        where.setdefault(key, []).append(c)
    inv = {"kernel": "", "os": "project manifests", "node": "", "restartRequired": False, "packages": packages, "snaps": {}, "images": [], "ecosystems": ecosystems}
    inv["hash"] = hashlib.sha256(json.dumps(packages, sort_keys=True).encode()).hexdigest()[:12]
    return inv, where


# Packages whose name IS a server product's name but which are only its client library (the PyPI "minio" is the Python SDK, not the MinIO server). A name match on one of
# these is a lead, never a version comparison. Kept short on purpose: add a name only when a real scan shows the mix-up.
CLIENT_LIBS = {"minio", "redis", "elasticsearch"}
CLIENT_ECOSYSTEMS = {"pypi", "npm"}
FAMILY_ECOSYSTEMS = {"maven", "cargo", "conan", "vcpkg", "cmake", "make", "c"}
GENERIC_PRODUCTS = {"core", "client", "server", "library", "tools", "runtime", "view", "framework", "platform", "engine", "common", "base", "utils", "api", "cli", "sdk", "web", "app"}


def _flat(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def project_candidate(entry: dict, inv: dict) -> tuple[str, list[str], list[str], bool, list[tuple[str, str, str, bool]]] | None:
    """A declared dependency that IS this entry's product, or None. Stricter than the host's word match, on purpose.

    A host's package list is flat and a product word may sit anywhere in a name; a project's names are single identifiers, and a loose match is noise
    ('WordPress Core' is not @babel/core, 'Chromium' is not electron-to-chromium, 'BIND' is not call-bind). So the flattened product must equal the flattened package
    name, the vendor+product, or one is a prefix of the other when the shorter has 6+ characters and covers 70% of the longer (postgres / PostgreSQL). A generic one-word
    product ('Core') also needs its vendor in the name. The title is the fallback when an answer has no product, as for the host.

    Beyond identity: for Maven, Cargo, Conan, vcpkg, CMake and Makefile names, which carry the product inside a longer coordinate (org.apache.logging.log4j:log4j-core is
    Log4j2; openssl-sys is OpenSSL), the product as one whole token of the name is a match of the same product family, whose versions are comparable. A match through an npm
    SCOPE only (@vitejs/plugin-react for Vite) is a lead and nothing more: its version is not the product's, so the fourth value is False and no range is compared.
    Returns (why, "name version" list, versions, whether every match is comparable, the matches as (key, name, version, comparable) so each can be judged on its own).
    """
    product = _flat(entry.get("product", ""))
    basis = "product"
    if not product:
        product, basis = _flat(re.sub(r"^\S+\s+", "", entry.get("title", ""))), "title"
    if len(product) < 4:
        return None
    forms_p = {product} | ({product[:-2]} if product.endswith("js") and len(product) > 4 else set())    # CISA "Vitejs" is the npm package "vite"
    vendor = _flat(entry.get("vendor", ""))
    generic = product in GENERIC_PRODUCTS
    eco = inv.get("ecosystems", {})
    hit: list[tuple[str, str, str, bool]] = []
    for key, val in inv["packages"].items():
        name = key.split("#")[0]
        base = _flat(name.rsplit("/", 1)[-1].rsplit(":", 1)[-1])
        scope = _flat(name.split("/")[0].lstrip("@")) if name.startswith("@") else ""
        vendor_in_name = bool(vendor) and (vendor in _flat(name) or (scope and scope in vendor))
        comparable, matched = True, False
        for pf in forms_p:
            forms = [f for f in ((base if (not scope or scope == pf or vendor_in_name) else ""), scope) if f]
            for f in forms:
                short, long_ = sorted((f, pf), key=len)
                same = f == pf or (vendor and f == vendor + pf) or (len(short) >= 6 and long_.startswith(short) and len(short) / len(long_) >= 0.7)
                if same and (not generic or vendor_in_name or f == scope or f == vendor + pf):
                    matched = True
                    comparable = not (scope and f == scope and base != f)     # matched only through the scope: not the same package
                    if eco.get(key) in CLIENT_ECOSYSTEMS and base in CLIENT_LIBS:
                        comparable = False                                      # a client SDK that shares the server's name
                    break
            if matched:
                break
        if not matched and eco.get(key) in FAMILY_ECOSYSTEMS and not generic:
            toks = {t.rstrip("0123456789") or t for t in re.findall(r"[a-z][a-z0-9]*", name.lower())}
            core = {pf.rstrip("0123456789") or pf for pf in forms_p}
            if any(len(c) >= 5 and c in toks for c in core):
                matched = True
        if matched:
            hit.append((key, name, val, comparable))
    if not hit:
        return None
    names = sorted({n for _, n, _, _ in hit})
    comparable = all(c for _, _, _, c in hit)
    vers = [v for _, _, v, _ in hit] if comparable else ["not the product's own package"]
    return (f"{basis} {product} is declared as " + ", ".join(names), [f"{n} {v}" for _, n, v, _ in hit], vers, comparable, hit)


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


def _file_progress(rel: str, kind: str, n: int) -> None:
    progress(f"[project] read {rel}  ({kind}, {n} component{'' if n == 1 else 's'})")


def cmd_project(a) -> int:
    """Declared dependencies of one or more project folders against CISA-exploited CVEs, through Lattice. Evidence for a person; it decides nothing, writes no host records."""
    from lattice_scan import manifests
    ids = split_ids(a.cve)
    if a.cve_file:
        try:
            ids += split_ids(l.split("#")[0] for l in Path(a.cve_file).read_text().splitlines())
        except OSError as err:
            print(f"cannot read --cve-file: {err}", file=sys.stderr)
            return 2
    bad = [i for i in ids if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", i)]
    if bad:
        print(f"not a CVE id: {', '.join(bad[:5])} (write them like CVE-2026-46300, separated by commas)", file=sys.stderr)
        return 2
    if not ids and not a.kev_catalogue:
        print("nothing to check: name CVEs with --cve CVE-A,CVE-B (or --cve-file), or give --kev-catalogue FILE (needs a key with a confirmed email)", file=sys.stderr)
        return 2
    if a.kev_catalogue and not KEY:
        print(f"no key: {NEEDS_KEY}", file=sys.stderr)
        return 2
    if a.max_read is None:
        a.max_read = 200 if KEY else 40
    results = []
    lat = Lattice()
    started = False
    stopped = ""
    catalogue = load_catalogue(a.kev_catalogue) if a.kev_catalogue else []
    if a.kev_catalogue:
        try:
            lat.start()
            started = True
            tier = ((lat.call("graph_meta").get("access") or {}).get("tier")) or "unknown"
        except LatticeError as err:
            print(f"stopped: {err}", file=sys.stderr)
            return 3
        if tier not in CONFIRMED_TIERS:
            print(f"this key's tier is '{tier}': the email behind it is not confirmed yet. Confirm it from the message Lattice sent to the key's owner, then run again. "
                  "Until then, name the CVEs with --cve CVE-A,CVE-B.", file=sys.stderr)
            return 2
    entries: dict[str, dict | None] = {}   # one read per id for the whole run, however many folders match it: the keyless day is 60 reads
    for root_s in a.paths:
        root = Path(root_s).resolve()
        if not root.is_dir():
            print(f"not a folder: {root_s}", file=sys.stderr)
            return 2
        progress(f"[project] {root.name or root}: looking for dependency files under {root}")
        comps, files, cut = manifests.read_project(root, on_file=_file_progress)
        progress(f"[project] {root.name or root}: {len(files)} file(s) read, {len(comps)} declared component(s)" + (" (file search was cut at the limit)" if cut else ""))
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
        checked: list[dict] = []   # one row per id for the result table: what was asked and what came of it
        for n_cve, cve in enumerate(todo, 1):
            tag = f"[{n_cve}/{len(todo)}] {cve}"
            if stopped:
                unread.append(cve)
                continue
            try:
                if cve not in entries:
                    if not started:
                        lat.start()
                        started = True
                    progress(f"{tag}  asking Lattice (only this id is sent) ...")
                    entries[cve] = kev_entry(lat, cve)
                e = entries[cve]
            except LatticeError as err:
                stopped = str(err)
                progress(f"{tag}  stopped: {err}")
                unread.append(cve)
                checked.append({"cve": cve, "listed": "not read", "product": "", "result": "not read (Lattice stopped)", "matched": ""})
                continue
            read += 1
            if e is None:
                not_listed.append(cve)
                checked.append({"cve": cve, "listed": "no", "product": "", "result": "not listed", "matched": ""})
                progress(f"{tag}  not in CISA's exploited list in this snapshot (that is not the same as safe)")
                continue
            progress(f"{tag}  CISA lists {e['vendor'] or '-'} {e['product'] or '-'}; comparing with {len(comps)} declared component(s) in {len(files)} file(s) ...")
            m = project_candidate(e, inv)
            prod = f"{e['vendor'] or '-'} {e['product'] or '-'}".strip()
            if not m:
                progress(f"{tag}  no declared component matches the product")
                checked.append({"cve": cve, "listed": "yes", "product": prod, "result": "no match", "matched": ""})
                continue
            progress(f"{tag}  CANDIDATE: {m[0]}")
            why, installed, vers, comparable, matches = m
            declared, verdicts = [], []
            for key, name, val, comp in matches:
                if comp:
                    vc_one = version_check(e, [val])
                else:
                    vc_one = {"verdict": "lead", "why": "the declared package shares a scope or name with the product, or is only its client library, but is not the product, so its version says nothing about the product's affected ranges"}
                verdicts.append(vc_one)
                for c in where.get(key, []):
                    declared.append({"name": c.name, "spec": c.spec, "version": c.version, "file": c.file, "line": c.line, "ecosystem": c.ecosystem,
                                     "verdict": vc_one["verdict"], "why": vc_one["why"]})
            # The finding's own verdict is the most pressing of its components': a lead (undetermined) must never hide a pinned version that is outside, or the other way round.
            order = {"in-range": 0, "undetermined": 1, "outside-range": 2, "lead": 3}     # a lead ranks below every real comparison
            vc = min(verdicts, key=lambda v: order[v["verdict"]])
            hits.append({"cve": cve, "title": e["title"], "why": why, "listed": e["added"], "due": e["due"], "action": e["action"][:400], "versionCheck": vc, "declared": declared})
            checked.append({"cve": cve, "listed": "yes", "product": prod, "result": vc["verdict"].upper().replace("-", " "),
                            "matched": "; ".join(dict.fromkeys(f"{d['name']} {d['version'] or d['spec'] or '(no version)'} ({d['file']})" for d in declared))})
        for cve in unread:
            if not any(c["cve"] == cve for c in checked):
                checked.append({"cve": cve, "listed": "not read", "product": "", "result": "not read", "matched": ""})
        results.append({"root": str(root), "files": files, "filesCut": cut, "components": len(comps), "pinned": pinned, "read": read, "candidates": hits, "checked": checked,
                        "notListed": not_listed, "unread": unread, "stopped": stopped})
    from lattice_scan import report
    names = a.name or []
    for i, r in enumerate(results):
        r["name"] = names[i] if i < len(names) else Path(r["root"]).name
    tool = f"lattice-scan {__version__}"
    if a.json:
        Path(a.json).write_text(json.dumps({"tool": tool, "on": TODAY, "projects": results}, indent=1))
    if a.csv:
        report.emit(report.to_csv(results, TODAY), a.csv)
    if a.format == "csv":
        report.emit(report.to_csv(results, TODAY), None)
    elif a.format == "json":
        report.emit(json.dumps({"tool": tool, "on": TODAY, "projects": results}, indent=1) + "\n", None)
    else:
        report.emit(report.console(results, TODAY, tool, report.width_for(a.width), report.use_color(a.color, sys.stdout), outputs={"csv": a.csv, "json": a.json}), None)
    if stopped:
        print(f"stopped: {stopped}", file=sys.stderr)
    bad = [h for r in results for h in r["candidates"] if (a.fail_on == "candidate") or (a.fail_on == "in-range" and h["versionCheck"]["verdict"] == "in-range")]
    return 1 if (bad and a.fail_on != "never") else (3 if stopped else 0)


CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def fetch_json(url: str, what: str, limit: int = 1024 * 1024) -> dict:
    """GET a small JSON document: https only (http only for this machine), no redirect, size-capped, the same three tries as a Lattice request."""
    from urllib.parse import urlparse
    u = urlparse(url)
    if not (u.scheme == "https" or (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1"))):
        raise LatticeError(f"refusing {what}: {url} is not https")
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": f"lattice-scan/{__version__}"})
    for attempt in range(len(RETRY_DELAYS) + 1):
        try:
            with _OPENER.open(req, timeout=30) as r:
                raw = r.read(limit + 1)
            if len(raw) > limit:
                raise LatticeError(f"{what} is larger than {limit // 1024} KB: refusing it")
            try:
                data = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                raise LatticeError(f"{what} at {url} is not JSON")
            if not isinstance(data, dict):
                raise LatticeError(f"{what} at {url} is not a JSON object")
            return data
        except urllib.error.HTTPError as e:
            if e.code in (502, 503, 504) and attempt < len(RETRY_DELAYS):
                Lattice._wait_to_retry(attempt, f"HTTP {e.code}")
                continue
            raise LatticeError(f"{what}: HTTP {e.code} from {url}")
        except (urllib.error.URLError, OSError) as e:
            if attempt < len(RETRY_DELAYS):
                Lattice._wait_to_retry(attempt, str(e))
                continue
            raise LatticeError(f"cannot read {what} at {url} after {attempt + 1} tries: {e}")
    raise LatticeError(f"cannot read {what}")


def read_feed(period: str = "weekly") -> dict:
    """namiq.io's list of recent exploited and critical CVE ids for one period (daily, weekly or open). Only well-formed rows are kept; every text is cleaned: it is data, never instructions.

    The list's schema is lattice-recent/N. Version 2 has daily and weekly; version 3 adds open. A later version that only adds fields still reads: what this needs is
    checked, not the number, so a feed that grows does not stop every installed tool. Version 1, or a list without the period asked for, is refused with a request to upgrade.
    """
    d = fetch_json(FEED_URL, "the recent-CVE list")
    m = re.fullmatch(r"lattice-recent/(\d+)", str(d.get("schema")))
    if not m or int(m.group(1)) < 2:
        raise LatticeError(f"the recent-CVE list has schema {clean(str(d.get('schema')))!r}; this lattice-scan reads lattice-recent/2 and later. Upgrade lattice-scan.")
    p = d.get(period)
    if not isinstance(p, dict):
        raise LatticeError(f"the recent-CVE list (schema {clean(str(d.get('schema')))}) has no {period} list: upgrade lattice-scan, or ask for daily or weekly")
    def rows(key: str) -> list[dict]:
        out = []
        for r in p.get(key) or []:
            if isinstance(r, dict) and isinstance(r.get("id"), str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", r["id"]):
                out.append({k: clean(str(v)) if isinstance(v, str) else v for k, v in r.items() if isinstance(v, (str, int, float, bool)) or v is None})
        return out
    return {"asOf": clean(str(d.get("exploitedAsOf", ""))), "builtAt": clean(str(d.get("builtAt", ""))), "period": period,
            "from": clean(str(p.get("from", ""))), "to": clean(str(p.get("to", ""))), "exploited": rows("exploited"), "critical": rows("critical")}


def feed_cells(r: dict) -> list[str]:
    """EXPLOIT .. PRODUCT cells from a feed row (what namiq.io says, not what Lattice says)."""
    return ["yes" if "added" in r else "no", cvss_cell(r.get("cvss")), r.get("added") or "-", due_cell(r.get("due", "")), ransom(r.get("ransomware", "")),
            f"{r.get('vendor', '')} {r.get('product', '')}".strip() or "-"]


def cmd_recent(a) -> int:
    """Start here when you have no CVE id: read namiq.io's recent exploited and critical ids, rule out locally what this host cannot have, and read only
    the rest from Lattice by exact id. The host's inventory never leaves the machine; the feed request carries no id and no host data."""
    private_dir()
    try:
        progress(f"[recent] reading the {a.period} list of recent exploited and critical CVEs from {FEED_URL} ...")
        feed = read_feed(a.period)
    except LatticeError as err:
        print(f"stopped: {err}", file=sys.stderr)
        return 1
    inv = inventory()
    rows: list[list[str]] = []
    look: list[str] = []
    for r in feed["exploited"][: a.max_read]:
        entry = {"cve": r["id"], "vendor": r.get("vendor", ""), "product": r.get("product", "")}
        m = candidate(entry, inv)
        progress(f"[recent] {r['id']}  {entry['vendor']} {entry['product']}: " + ("something installed may match, will read it from Lattice" if m else "nothing installed matches, not sent to Lattice"))
        if m:
            look.append(r["id"])
        else:
            rows.append([r["id"], *feed_cells(r), "unmatch", "no package, snap, image or kernel matches (not sent to Lattice)"])
    watch = 0
    if not a.no_critical:
        for r in feed["critical"]:
            m = candidate({"cve": r["id"], "vendor": r.get("vendor", ""), "product": r.get("product", "")}, inv)
            if m:
                watch += 1
                rows.append([r["id"], "no", cvss_cell(r.get("cvss")), "-", "-", "-", f"{r.get('vendor', '')} {r.get('product', '')}".strip() or "-", "WATCH",
                             f"critical, not known exploited: {m[0]}"])
    progress(f"[recent] {a.period} list {feed['from'] or '?'} to {feed['to'] or '?'}: {len(feed['exploited'])} exploited and {len(feed['critical'])} critical ids (CISA catalogue as of {feed['asOf'] or '?'}); "
             f"{len(look)} exploited may match this host, {watch} critical may match")
    a.inv, a.extra_rows = inv, rows
    if look:
        a.cve, a.cve_file, a.discover, a.refresh, a.again = look, None, False, False, False
        return cmd_run(a)
    print(f"recent {TODAY} ({a.period}, {feed['from'] or '?'} to {feed['to'] or '?'}): {len(feed['exploited'])} exploited and {len(feed['critical'])} critical CVEs read from namiq.io (as of {feed['asOf'] or '?'}); "
          f"none of the exploited ones match this host's installed software, so nothing was sent to Lattice")
    print_table(rows)
    print("That is not the same as safe: the list holds only what was recently added. To check a CVE you know of, run: lattice-scan --cve CVE-YYYY-NNNN")
    return 0


def cmd_enrich(a) -> int:
    """Look up CVE ids that already exist somewhere (an audit, an advisory, a ticket): is each one exploited, listed when, due when, ransomware. By exact id,
    no comparison with this host, nothing written to the records."""
    ids: list[str] = []
    for v in a.cve or []:
        ids += [x.upper() for x in CVE_ID.findall(v)]
    sources = list(a.file or [])
    if not sources and not a.cve and not sys.stdin.isatty():   # stdin only when nothing else was named: a bare `enrich` in a pipe
        sources = ["-"]
    for f in sources:
        try:
            text = sys.stdin.read() if f == "-" else Path(f).read_text(errors="replace")
        except OSError as err:
            print(f"cannot read {f}: {err}", file=sys.stderr)
            return 2
        ids += [x.upper() for x in CVE_ID.findall(text)]
    ids = list(dict.fromkeys(ids))
    if not ids:
        print("no CVE ids found: pipe text in (npm audit, pip-audit, an advisory), or pass --cve CVE-... / --file FILE", file=sys.stderr)
        return 2
    cap = a.max_read or (200 if KEY else 20)
    todo, rest = ids[:cap], ids[cap:]
    rows: list[list[str]] = []
    done: list[tuple[str, dict | None]] = []
    stopped = ""
    lat = Lattice()
    try:
        lat.start()
        for n, cve in enumerate(todo, 1):
            progress(f"[{n}/{len(todo)}] {cve}  asking Lattice (only this id is sent) ...")
            done.append((cve, kev_entry(lat, cve)))
    except LatticeError as err:
        stopped = str(err)
        print(f"stopped: {err}", file=sys.stderr)
    read_ids = {c for c, _ in done}
    for cve, e in done:
        rows.append([cve, *cells(e), "EXPLOITED" if e else "unlisted", clean((e or {}).get("title", "")) or "not in CISA's list in this snapshot (not the same as safe)"])
    unread = [c for c in todo if c not in read_ids] + rest
    rows.sort(key=lambda r: (r[7] != "EXPLOITED", r[4] if r[4] != "-" else "9999"))
    rows += [[c, "-", "-", "-", "-", "-", "-", "not read", "over the limit for one run" if c in rest else "stopped before this id"] for c in unread]
    n_exp = sum(1 for _, e in done if e)
    print(f"enrich {TODAY}: {len(ids)} CVE ids found, {len(done)} read, {n_exp} exploited (CISA), {sum(1 for _, e in done if e and ransom(e.get('ransomware', '')) == 'known')} with known ransomware use")
    print_table(rows)
    if unread:
        print(f"{len(unread)} id(s) not read: " + (f"keyless access allows about 20 reads an hour and 60 a day. For more, ask the person for a key: lattice-scan get-key --help" if not KEY else "run again later"))
    if a.fail_on == "exploited" and n_exp:
        return 1
    return 3 if unread else 0


def terms_version() -> str:
    """The terms version the key API wants, read from its own published OpenAPI document (it must be sent exactly as published)."""
    d = fetch_json(TERMS_DOC, "the key API description")
    try:
        v = d["components"]["schemas"]["AgentKeyRequest"]["properties"]["terms"]["properties"]["version"]["const"]
    except (KeyError, TypeError):
        raise LatticeError("the key API description has no terms version")
    return clean(str(v))


def cmd_get_key(a) -> int:
    """Ask for a Lattice key on behalf of a real person who gave these details and agreed to the terms. The key goes to a private file and is never printed."""
    terms_page = "https://namiq.io/lattice/docs"
    plan = f"for {a.name} ({a.position}, {a.company}), confirmation email to {a.email}"
    if not a.accept_terms:
        print(f"Not sent. A key would be requested {plan}.\n"
              f"Show the person the beta terms ({terms_page}) and the purpose below, and ask whether they agree and read that mailbox. Only then run the same command again with --accept-terms.\n"
              f"purpose: {a.purpose}", file=sys.stderr)
        return 2
    if (OUT / "key").exists() and not a.force:
        print(f"A key is already stored in {OUT / 'key'}: use it (it is read automatically). One key per person; asking again counts against the organisation. --force asks anyway.", file=sys.stderr)
        return 2
    try:
        version = terms_version()
        body = {"terms": {"version": version, "accepted": True}, "agent": {"name": "lattice-scan", "version": __version__},
                "principal": {"name": a.name, "position": a.position, "company": a.company, "email": a.email}, "purpose": a.purpose, "consent": True}
        req = urllib.request.Request(KEY_API, json.dumps(body).encode(), {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": f"lattice-scan/{__version__}"})
        try:
            with _OPENER.open(req, timeout=30) as r:
                status, raw = r.status, r.read(MAX_REPLY).decode(errors="replace")
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read(MAX_REPLY).decode(errors="replace")
        except (urllib.error.URLError, OSError) as e:
            raise LatticeError(f"cannot reach the key service: {e}")
    except LatticeError as err:
        print(f"stopped: {err}", file=sys.stderr)
        return 1
    try:
        d = json.loads(raw)
    except ValueError:
        d = {}
    if status == 202:
        print("The address has asked not to be contacted, so no key was issued. Stop here; do not try again.", file=sys.stderr)
        return 1
    if status != 201 or not isinstance(d, dict) or not d.get("key"):
        print(f"no key issued (HTTP {status}): {clean(str(d.get('error', 'unknown')))}: {clean(str(d.get('message', '')))[:300]}", file=sys.stderr)
        for i in d.get("issues", [])[:5] if isinstance(d.get("issues"), list) else []:
            print(f"  {clean(str(i.get('path', '')))}: {clean(str(i.get('message', '')))[:150]}", file=sys.stderr)
        return 1
    private_dir(keep=True)
    fd = os.open(OUT / "key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(str(d["key"]) + "\n")
    os.chmod(OUT / "key", 0o600)
    print(f"A key was issued and stored in {OUT / 'key'} (private to this user; it is not printed, and later runs read it by themselves).\n"
          f"key id {clean(str(d.get('key_id', '')))}, tier {clean(str(d.get('tier', '')))}, expires {clean(str(d.get('expires_at', '')))}\n"
          f"A confirmation email went to {a.email}. The person should open it: 'not me' withdraws the key, and the key is withdrawn if the mail cannot be delivered.")
    for line in (d.get("next") or [])[:4] if isinstance(d.get("next"), list) else []:
        print(f"  {clean(str(line))[:200]}")
    return 0


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
    print_context(imp)


def print_context(imp: dict) -> None:
    """The 'why it matters' lines. Server text, shown as data; priority is the tool's reading, not a verdict."""
    ctx, pr = imp.get("context"), imp.get("priority")
    if not ctx:
        return
    if pr:
        print(f"      priority: {pr['level']}" + (f" ({'; '.join(pr['reasons'])})" if pr["reasons"] else "") + " [the tool's reading of CISA and FIRST fields, not a verdict]")
    if ctx.get("epss"):
        e = ctx["epss"]
        pct = f", percentile {float(e['percentile']):.3f}" if e.get("percentile") is not None else ""
        print(f"      EPSS {float(e['score']):.3f}{pct} (FIRST, {e.get('date') or 'date not given'}): the estimated chance of exploitation in the next 30 days")
    if ctx.get("ssvc"):
        print("      CISA SSVC: " + ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in ctx["ssvc"].items()))
    if ctx.get("cwe"):
        print(f"      weakness: {', '.join(ctx['cwe'])}")
    if ctx.get("description"):
        print(f"      what it is (NVD): {ctx['description']}")
    for t in ctx.get("techniques", []):
        print(f"      ATT&CK: {t['id']} {t['title']}" + (" (likely: the graph inferred this link)" if t["likely"] else ""))
    for prod, vers in (ctx.get("fixedIn") or {}).items():
        print(f"      first unaffected upstream version (NVD): {prod} {', '.join(vers)} (a distro can fix under the same number)")
    for r in ctx.get("references", []):
        print(f"      reference: {r}")


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
    p.add_argument("--keep", action="store_true", help="keep this run's records in the default folder even with no terminal (also LATTICE_SCAN_KEEP=1); without it a terminal-less run with no folder yet uses a temporary one")
    p.add_argument("--refresh", action="store_true", help="collect the inventory again now and print all of it; with ids, also re-read them. Alone it makes no Lattice call")
    p.add_argument("--again", action="store_true", help="re-read ids already read before")
    p.add_argument("--progress", action="store_true", default=argparse.SUPPRESS, help="print what is being checked, step by step, on stderr (the default; see --quiet)")
    p.add_argument("--quiet", "-q", action="store_true", default=argparse.SUPPRESS, help="print no progress (also LATTICE_SCAN_PROGRESS=0)")
    sub = p.add_subparsers(dest="c")
    r = sub.add_parser("resolve"); r.add_argument("cve"); r.add_argument("--status", required=True, choices=["verified", "fixed", "not-applicable"]); r.add_argument("--proof", default=""); r.add_argument("--on")
    im = sub.add_parser("impact", help="the recorded impact detail of one finding"); im.add_argument("cve")
    d = sub.add_parser("add"); d.add_argument("--ref", required=True); d.add_argument("--note", required=True); d.add_argument("--on")
    pj = sub.add_parser("project", help="check the dependencies a project DECLARES (Python, JavaScript, Java, Rust, C/C++, Make, CMake, Docker); writes no host records",
                        formatter_class=argparse.RawDescriptionHelpFormatter,
                        epilog=PROJECT_EPILOG)
    pj.add_argument("paths", nargs="*", default=["."], help="project folders (default: the current folder)")
    pj.add_argument("--progress", action="store_true", default=argparse.SUPPRESS, help="print each file and CVE as it is checked, on stderr (the default; see --quiet)")
    pj.add_argument("--quiet", "-q", action="store_true", default=argparse.SUPPRESS, help="print no progress (also LATTICE_SCAN_PROGRESS=0)")
    pj.add_argument("--cve", action="append", help="CVE ids, comma separated (CVE-A,CVE-B); repeatable"); pj.add_argument("--cve-file", help="file of ids, one or several per line, # comments")
    pj.add_argument("--kev-catalogue", help="CISA's known_exploited_vulnerabilities.json; chooses which ids to read. Needs a key whose email is confirmed. Nothing from the file is sent")
    pj.add_argument("--max-read", type=int, default=None, help="most ids to read from Lattice per run (default 200 with a key, 40 without: the keyless day is 60)")
    pj.add_argument("--format", choices=["console", "csv", "json"], default="console", help="what to print (default console: a report for a person)")
    pj.add_argument("--csv", help="also write the findings as CSV to this file")
    pj.add_argument("--json", help="also write the full result as JSON to this file")
    pj.add_argument("--name", action="append", help="a label for each folder, in order (default: the folder name)")
    pj.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="colour the console report (auto: only on a terminal, never with NO_COLOR)")
    pj.add_argument("--width", type=int, help="console report width in columns (default: the terminal's, between 72 and 110)")
    pj.add_argument("--fail-on", choices=["never", "in-range", "candidate"], default="never", help="exit 1 when a candidate (or an in-range one) is found; default never: a person reads it")
    rc = sub.add_parser("recent", help="start here with no CVE id: read namiq.io's recent exploited and critical CVEs, check what this host could have, read only those from Lattice")
    rc.add_argument("--period", choices=["daily", "weekly", "open"], default="weekly", help="daily: added or published in the last day or two; weekly: the last seven days, which includes daily (default); open: exploited CVEs added before the weekly window but within 30 days, overdue first (overdue means CISA's due date has passed; it says nothing about any machine)")
    rc.add_argument("--open", dest="period", action="store_const", const="open", help="same as --period open")
    rc.add_argument("--daily", dest="period", action="store_const", const="daily", help="same as --period daily")
    rc.add_argument("--weekly", dest="period", action="store_const", const="weekly", help="same as --period weekly")
    rc.add_argument("--max-read", type=int, default=40, help="most exploited ids to consider from the list (default 40)")
    rc.add_argument("--no-critical", action="store_true", help="leave out the critical (not known exploited) ids")
    rc.add_argument("--progress", action="store_true", default=argparse.SUPPRESS, help="print each step on stderr (the default)")
    rc.add_argument("--quiet", "-q", action="store_true", default=argparse.SUPPRESS, help="print no progress (also LATTICE_SCAN_PROGRESS=0)")
    en = sub.add_parser("enrich", help="CVE ids you already have (audit, advisory, ticket): exploited? ransomware? patch due? No comparison with this host")
    en.add_argument("--cve", action="append", help="CVE ids or any text containing them (repeatable)")
    en.add_argument("--file", action="append", help="a file to find CVE ids in; - or a pipe on stdin works too")
    en.add_argument("--max-read", type=int, default=None, help="most ids to read from Lattice (default 200 with a key, 20 without)")
    en.add_argument("--fail-on", choices=["never", "exploited"], default="never", help="exit 1 when any id is exploited (default never)")
    en.add_argument("--progress", action="store_true", default=argparse.SUPPRESS, help="print each step on stderr (the default)")
    en.add_argument("--quiet", "-q", action="store_true", default=argparse.SUPPRESS, help="print no progress (also LATTICE_SCAN_PROGRESS=0)")
    gk = sub.add_parser("get-key", help="request a Lattice key for a real person who has read the terms and gave these details; the key is stored, never printed")
    for flag in ("name", "position", "company", "email", "purpose"):
        gk.add_argument(f"--{flag}", required=True, help=f"the person's {flag}" if flag != "purpose" else "what the key will be used for, one or two sentences (at least 20 characters)")
    gk.add_argument("--accept-terms", action="store_true", help="the person has read the beta terms and agreed, and reads that mailbox (without this nothing is sent)")
    gk.add_argument("--force", action="store_true", help="ask even though a key is already stored")
    sub.add_parser("list"); sub.add_parser("stats")
    il = sub.add_parser("inventory", help="show inventory.log: counts and changes per run"); il.add_argument("-n", type=int, default=20)
    lg = sub.add_parser("log"); lg.add_argument("-n", type=int, default=20, help="last N lines (default 20)")
    a = p.parse_args()
    global DEBUG, PROGRESS, KEEP
    DEBUG = a.debug or env("DEBUG") == "1"
    KEEP = a.keep or env("KEEP") == "1"
    # OCO-5837: progress goes to stderr and is on by default; --quiet or LATTICE_SCAN_PROGRESS=0 turns it off. stdout is never touched.
    PROGRESS = not getattr(a, "quiet", False) and (getattr(a, "progress", False) or env("PROGRESS") != "0")
    if a.c is None and not (a.cve or a.cve_file or a.discover or a.refresh):
        # Nothing asked for: do what a person or an agent with no CVE id wants, the daily list (lattice-scan recent --daily). Daily, not weekly: the weekly list is
        # long, and a keyless run that has to look many entries up reaches Lattice's limit (about 20 reads an hour).
        a.c, a.period, a.max_read, a.no_critical = "recent", "daily", 40, False
        progress("[recent] no command and no CVE id given: running the daily list (lattice-scan recent --daily)")
        return cmd_recent(a)
    if a.c == "project": return cmd_project(a)
    if a.c == "recent": return cmd_recent(a)
    if a.c == "enrich": return cmd_enrich(a)
    if a.c == "get-key": return cmd_get_key(a)
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
