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
  lattice-scan --discover --all                         the older software here: the items that matter, shown, confirmed, sent one at a time
  lattice-scan --discover [--daily|--weekly|--monthly|--open]   no key: exploited CVEs added in the window (default weekly), checked against this host; same as `recent`
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
package's own changelog names the CVE. --discover (listing what was added in the window) reads namiq.io's list, which is a plain request, so it needs no key;
without a key it reads at most 20 ids from Lattice per run (--max-read; 200 with a key). Get a key: https://namiq.io/lattice/docs#agents. If the server says quota_exceeded the run stops and
prints its message; a person decides about any link in it, the script never opens one.

Env: LATTICE_URL (default https://lattice.namiq.io/mcp), LATTICE_API_KEY, LATTICE_SCAN_DIR (a folder this user can write; set it for an agent in a sandbox), LATTICE_SCAN_KEEP=1, LATTICE_SCAN_INVENTORY (tests: fixed inventory JSON),
LATTICE_SCAN_TODAY (YYYY-MM-DD), LATTICE_SCAN_TEST=1 (our own test runs: the user agent reads `lattice-scan/<version> (test)` so the server's counts leave them out), LATTICE_SCAN_WINDOW (days back; default 6 = seven days counting today).
"""
from __future__ import annotations
import argparse, atexit, datetime as dt, hashlib, json, os, re, shutil, signal, statistics, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request
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


def user_agent() -> str:
    """`lattice-scan/<version>`, and ` (test)` after it when LATTICE_SCAN_TEST=1. The server's counts of who uses the tool cannot tell our own runs from a stranger's,
    and our test loops (hundreds of calls a day, often of a build not yet released) swamp the figures. The mark is the one thing added: no host, user or path."""
    return f"lattice-scan/{__version__}" + (" (test)" if os.environ.get("LATTICE_SCAN_TEST", "").strip().lower() in ("1", "true", "yes") else "")


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

# Ordinary words that are also product names ("Docs", "Support", "Media Server"). A product made only of these says nothing about the installed item that happens
# to contain the same word (gnome-user-docs, media-player-info), so it matches only when the vendor also appears among the installed names.
WEAK = set("""admin agent base center common content core desktop docs document documents driver editor engine extension files form forms framework gateway guide help host
image info install kit libre manager media member mobile module monitor multiple office panel player plugin portal print reader report search setup shell studio support suite
tool tools unknown update user viewer wiki window windows work""".split())


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


QUICK_ITEMS, KEY_ITEMS, RATE_WAIT_BUDGET = 25, 200, 5   # items per level; waits for the minute limit in one --discover --all run
RATE_RETRIES, MAX_RATE_WAIT = 2, 70.0   # a 429 that says 'retry after N seconds' is waited out (at most twice, and only if N is a minute or so)
PACE_CALLS, PACE_WINDOW = 5, 60.5         # keyless: calls a minute until the server says otherwise, counted across runs; half a second of margin
READ_CACHE_MAX = 400                      # entries kept in the read cache
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
CACHE_FILE: Path | None = None  # tests point this at a temp file


def pace_path() -> Path:
    """Where call times are remembered: the user's cache folder, not the records (a project or enrich run writes no records)."""
    if PACE_FILE:
        return PACE_FILE
    if env("PACE_FILE"):
        return Path(env("PACE_FILE"))
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "lattice-scan" / "pace.json"


def cache_dir() -> Path:
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "lattice-scan"


def limits_path() -> Path:
    if PACE_FILE or env("PACE_FILE"):   # a test or an operator that moved the pace file moves everything that belongs beside it
        p = pace_path()
        return p.with_name(p.name + ".limits.json")
    return cache_dir() / "server-limits.json"


def write_cache_file(f: Path, text: str) -> None:
    """Write a file in the user's cache folder, readable by the user only (the folder is already 0700). Atomic; raises OSError, which callers ignore:
    a cache that cannot be written (read-only home, a sandbox) just means nothing is remembered."""
    f.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = f.with_name(f"{f.name}.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.replace(tmp, f)


def pace_calls() -> int:
    """Calls a minute the server last said keyless access allows (its `access.limits.calls_per_minute`), else the built-in 5. Remembered across runs
    for a week, so a limit the operator raises is followed without a new release."""
    try:
        d = json.loads(limits_path().read_text())
        n = int(d["calls_per_minute"])
        if 1 <= n <= 600 and time.time() - float(d["seen"]) < 7 * 86400 and d.get("url") == URL:   # a limit seen on another server is not this server's
            return n
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return PACE_CALLS


def pace_learn(access: object) -> None:
    """Remember the per-minute limit a keyless answer reports. Best effort; nothing but one number and a time is stored."""
    try:
        n = int((access or {}).get("limits", {}).get("calls_per_minute"))   # type: ignore[union-attr]
    except (TypeError, ValueError, AttributeError):
        return
    if not 1 <= n <= 600 or n == pace_calls():
        return
    try:
        write_cache_file(limits_path(), json.dumps({"calls_per_minute": n, "seen": time.time(), "url": URL}))
    except OSError:
        pass


KEY_NOTICE_DAYS = 14


def key_days_notice(value: str | None, today: str | None = None) -> bool:
    """A keyed answer says how many days the key has left (`X-Lattice-Key-Days-Left`). When it is 14 or fewer, say so once a day on stderr (the progress line,
    so --quiet and the csv/json outputs are untouched). The renewal link is mailed to the address the key was issued for; the tool never opens or follows it.
    True when a line was printed."""
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return False
    if not 0 <= n <= KEY_NOTICE_DAYS:
        return False
    day = today or dt.date.today().isoformat()
    f = cache_dir() / "key-notice.json" if not (PACE_FILE or env("PACE_FILE")) else pace_path().with_name(pace_path().name + ".key-notice.json")
    try:
        if json.loads(f.read_text()).get("day") == day:
            return False
    except (OSError, ValueError, AttributeError):
        pass
    try:
        write_cache_file(f, json.dumps({"day": day}))
    except OSError:
        pass   # no folder to remember in: the line may repeat, which is harmless
    progress(f"Your Lattice key ends in {n} day{'s' if n != 1 else ''}. A renewal link was mailed to the address it was issued for; to get a new key: https://namiq.io/lattice")
    return True


def read_cache_path() -> Path:
    if CACHE_FILE:
        return CACHE_FILE
    if env("READ_CACHE_FILE"):
        return Path(env("READ_CACHE_FILE"))
    if PACE_FILE or env("PACE_FILE"):
        p = pace_path()
        return p.with_name(p.name + ".read-cache.json")
    return cache_dir() / "read-cache.json"


def read_cache_hours() -> float:
    """How long a lookup or node read is reused. LATTICE_SCAN_READ_CACHE=off (and --refresh) turns it off; LATTICE_SCAN_READ_CACHE_HOURS sets the age."""
    if env("READ_CACHE", "on").lower() == "off":
        return 0.0
    try:
        return max(0.0, float(env("READ_CACHE_HOURS", "6")))
    except ValueError:
        return 6.0


def _cache_key(tool: str, args: dict) -> str | None:
    if tool == "graph_lookup" and args.get("id"):
        return f"lookup:{str(args['id']).upper()}"
    if tool == "graph_node" and args.get("uid"):
        return f"node:{args['uid']}"
    return None


def read_cache_load() -> dict:
    try:
        d = json.loads(read_cache_path().read_text())
        return d if isinstance(d, dict) and isinstance(d.get("entries"), dict) else {"entries": {}}
    except (OSError, ValueError):
        return {"entries": {}}


def read_cache_get(tool: str, args: dict) -> dict | None:
    """A recent answer to the same lookup or node read, so a repeat run (or a second look at the same id) asks Lattice nothing. The cache holds graph
    data about public CVEs only, never anything about this host."""
    hours, key = read_cache_hours(), _cache_key(tool, args)
    if not hours or not key:
        return None
    e = read_cache_load()["entries"].get(key)
    try:
        if e and time.time() - float(e["at"]) < hours * 3600 and isinstance(e["data"], dict):
            return e["data"]
    except (KeyError, TypeError, ValueError):
        pass
    return None


def read_cache_put(tool: str, args: dict, data: dict) -> None:
    key = _cache_key(tool, args)
    if not read_cache_hours() or not key or data.get("error"):
        return
    d = read_cache_load()
    ents = d["entries"]
    ents[key] = {"at": time.time(), "data": data}
    if len(ents) > READ_CACHE_MAX:
        for k in sorted(ents, key=lambda x: float(ents[x].get("at", 0)))[: len(ents) - READ_CACHE_MAX]:
            del ents[k]
    try:
        write_cache_file(read_cache_path(), json.dumps({"v": 1, "entries": ents}))
    except OSError:
        pass


def pace_times() -> list[float]:
    try:
        return [t for t in json.loads(pace_path().read_text()) if isinstance(t, (int, float))]
    except (OSError, ValueError, TypeError):
        return []


def pace_wait(now: float | None = None) -> float:
    """Seconds to wait before the next keyless call so that no more than PACE_CALLS fall in a minute, counting calls made by other runs a moment ago."""
    now = time.time() if now is None else now
    n = pace_calls()
    recent = sorted(t for t in pace_times() if now - t < PACE_WINDOW)
    return recent[-n] + PACE_WINDOW - now if len(recent) >= n else 0.0


def pace_note() -> None:
    """Remember this call's time (a few numbers, no names), so the next run, even a separate one, can space itself. Best effort: a read-only home just means no memory."""
    now = time.time()
    keep = [t for t in pace_times() if now - t < PACE_WINDOW][-(pace_calls() - 1):] + [now]
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
        self.last_unlisted: dict | None = None   # the NVD node of the last lookup that had no CISA entry, for a named id
        self.cached = 0                          # answers served from the read cache in this run
        self.pending: list[str] = []             # ids the caller is about to ask for, in order (hint): the next lookup can fetch them together
        self.prefetched: dict[str, dict] = {}    # answers already fetched in a batch, as a single lookup would have answered
        self.batch_ok = True                     # turned off for the run when the server does not understand a batch lookup
        self.server_new = False                  # set once an answer carries the inline fields: only then is a batch tried (an older server is never asked)
        self.batches = 0
        self.rate_budget: int | None = None      # waits left for the minute limit in this run; None: only the per-request limit applies

    @staticmethod
    def _wait_to_retry(attempt: int, why: str) -> None:
        """A lookup only reads, so asking again is safe. Say so on stderr, wait, and let the caller go round once more."""
        delay = RETRY_DELAYS[attempt]
        progress(f"Lattice did not answer ({why}); trying again in {delay:g}s ({attempt + 2} of {len(RETRY_DELAYS) + 1})")
        time.sleep(delay)

    def _post(self, body: dict) -> dict | None:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "User-Agent": user_agent()}
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
                    if KEY:
                        key_days_notice(r.headers.get("X-Lattice-Key-Days-Left"))
                    raw = r.read(MAX_REPLY + 1).decode(errors="replace")
                    if len(raw) > MAX_REPLY:
                        raise LatticeError("reply from Lattice is larger than 8 MB: refusing it")
                    dbg(f"<- HTTP {r.status} {len(raw)} bytes in {time.time() - t0:.2f}s content-type={r.headers.get('Content-Type')}")
                break
            except urllib.error.HTTPError as e:
                detail = e.read().decode()[:300]
                dbg(f"<- HTTP {e.code} in {time.time() - t0:.2f}s body={detail}")
                if e.code == 429 and (rate_tries < RATE_RETRIES if self.rate_budget is None else self.rate_budget > 0):
                    wait = retry_after(e.headers.get("Retry-After"), detail)
                    if wait is not None and wait <= MAX_RATE_WAIT:
                        rate_tries += 1
                        if self.rate_budget is not None:
                            self.rate_budget -= 1
                        progress(f"Lattice's keyless limit ({pace_calls()} calls a minute) was reached; waiting {wait:g}s as it asked, then trying again (" + (f"{rate_tries} of {RATE_RETRIES}" if self.rate_budget is None else f"{self.rate_budget} wait(s) left in this run") + ")")
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

    def hint(self, ids: list[str]) -> None:
        """Tell the client which ids will be looked up, in order. Nothing is sent. The first lookup of one of them then fetches up to 10 together
        (ADR-LATTICE-API-001 C2), a call of one request instead of ten."""
        self.pending = list(dict.fromkeys(i.upper() for i in ids))

    def _prefetch(self, first: str) -> None:
        """Fetch `first` and the next hinted ids that are not already known, at most 10, in one batch lookup. A server that does not understand a batch, or
        any failure, turns batching off for the run and leaves the single lookups to do the work, so an older server behaves as before."""
        i = self.pending.index(first)
        batch = [first]
        for c in self.pending[i + 1:]:
            if len(batch) >= 10:
                break
            if c not in self.prefetched and read_cache_get("graph_lookup", {"id": c}) is None:
                batch.append(c)
        if len(batch) < 2:
            return
        try:
            data = self.call("graph_lookup", ids=batch)
        except LatticeError as err:
            dbg(f"batch lookup not used ({clean(str(err))[:120]}); looking ids up one at a time")
            self.batch_ok = False
            return
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            self.batch_ok = False   # an older server ignored ids and answered something else
            return
        self.batches += 1
        for r in results:
            if isinstance(r, dict) and r.get("id") and "error" not in r and isinstance(r.get("items"), list):
                ans = {"snapshot": data.get("snapshot"), "notices": data.get("notices", []), "items": r["items"], "access": data.get("access")}
                self.prefetched[str(r["id"]).upper()] = ans
                read_cache_put("graph_lookup", {"id": r["id"]}, ans)

    def call(self, tool: str, **args) -> dict:
        if tool == "graph_lookup" and args.get("id") and self.batch_ok and self.server_new and len(self.pending) > 1:
            cid = str(args["id"]).upper()
            if cid not in self.prefetched and cid in self.pending and read_cache_get(tool, args) is None:
                self._prefetch(cid)
            if cid in self.prefetched:
                self.cached += 1
                dbg(f"batch: {tool} {args} answered from the batch fetched earlier")
                return json.loads(json.dumps(self.prefetched[cid]))
        hit0 = read_cache_get(tool, args) if tool == "graph_lookup" else None
        if hit0 is not None:
            self._learn(hit0)
        hit = read_cache_get(tool, args)
        if hit is not None:   # asked before, recently: no call, no waiting, nothing used
            self.cached += 1
            dbg(f"cache: {tool} {args} answered from the read cache")
            return json.loads(json.dumps(hit))
        # Keyless access allows a few calls a minute (the server says how many), counted across every run on this machine: space them out instead of burning the day's units on 429s.
        if not KEY:
            wait = pace_wait()
            if wait > 1:   # a sub-second shortfall is not worth a message; the 429 handler covers the rare edge
                dbg(f"keyless pacing: sleeping {wait:.1f}s ({pace_calls()} calls/minute limit)")
                progress(f"keyless limit: {pace_calls()} calls a minute, so waiting {wait:.0f}s before the next lookup")
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
        if isinstance(data, dict):
            if not KEY:
                pace_learn(data.get("access"))
            read_cache_put(tool, args, data)
            if tool == "graph_lookup" and args.get("id"):
                self._learn(data)
        return data

    def _learn(self, answer: dict) -> None:
        """A lookup answer that carries the inline urgency fields (ADR-LATTICE-API-001 C1) comes from a server that also takes a batch (C2)."""
        if any(inline_context(i) for i in answer.get("items", []) if isinstance(i, dict) and i.get("source") == "nvd"):
            self.server_new = True


from lattice_scan import report  # noqa: E402
from lattice_scan import lattice_version as lv  # noqa: E402   # the one implementation of versions, ranges, product ids and the verdict ladder


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


PLACEHOLDER = {"", "none", "n/a", "not specified", "not applicable", "default string", "to be filled by o.e.m.", "system product name", "system version",
               "system manufacturer", "default", "unknown", "o.e.m.", "type1productconfigid"}
CHASSIS = {1: "other", 2: "unknown", 3: "desktop", 4: "low-profile desktop", 5: "pizza box", 6: "mini tower", 7: "tower", 8: "portable", 9: "laptop",
           10: "notebook", 11: "handheld", 12: "docking station", 13: "all-in-one", 14: "sub-notebook", 17: "server", 23: "rack-mount server",
           24: "blade", 28: "blade enclosure", 30: "tablet", 31: "convertible", 35: "mini PC", 36: "stick PC"}
IMAGE_FILES = (("os", "etc/os-release"), ("os2", "usr/lib/os-release"), ("apk", "lib/apk/db/installed"), ("dpkg", "var/lib/dpkg/status"),
               ("dpkgd", "var/lib/dpkg/status.d"), ("rpm", "usr/lib/sysimage/rpm/rpmdb.sqlite"), ("rpm2", "var/lib/rpm/rpmdb.sqlite"))
LANG_SECONDS = 180
CONTAINER_LABEL = "io.lattice-scan.run"
RUN_ID = f"{os.getpid()}-{int(time.time())}"
STALE_MINUTES = 15  # LATTICE_SCAN_STALE_MINUTES

IMAGE_FILE_LIMIT = 40 * 1024 * 1024
IMAGE_LIMIT = 60


def scrub(v):
    """clean() applied to every string inside v (dicts, lists, keys too): names, versions and labels read from an image or from firmware are data that someone else wrote,
    and must not carry terminal escape sequences to the screen."""
    if isinstance(v, str):
        return clean(v)
    if isinstance(v, dict):
        return {scrub(k): scrub(x) for k, x in v.items()}
    if isinstance(v, list):
        return [scrub(x) for x in v]
    return v


def hardware() -> dict:
    """What this machine is: manufacturer, model, version, board, firmware. Read from the kernel's own files; serial numbers and UUIDs are left out on purpose."""
    def rd(p: str) -> str:
        try:
            v = Path(p).read_text(errors="replace").replace("\0", "").strip()
        except OSError:
            return ""
        return "" if v.lower() in PLACEHOLDER else v
    d = "/sys/class/dmi/id/"
    h = {"manufacturer": rd(d + "sys_vendor"), "model": rd(d + "product_name"), "version": rd(d + "product_version"), "family": rd(d + "product_family"),
         "boardVendor": rd(d + "board_vendor"), "board": rd(d + "board_name"), "boardVersion": rd(d + "board_version"),
         "biosVendor": rd(d + "bios_vendor"), "biosVersion": rd(d + "bios_version"), "biosDate": rd(d + "bios_date")}
    ct = rd(d + "chassis_type")
    if ct.isdigit():
        h["chassis"] = CHASSIS.get(int(ct), f"type {ct}")
    if not h["model"]:  # ARM boards and many single-board computers carry no DMI table; the device tree names the board
        dtm = rd("/proc/device-tree/model") or rd("/sys/firmware/devicetree/base/model")
        if dtm:
            h["model"], h["source"] = dtm, "device-tree"
    h["arch"] = run(["uname", "-m"]).strip()
    cpu = ""
    try:
        for l in Path("/proc/cpuinfo").read_text(errors="replace").splitlines():
            if l.lower().startswith(("model name", "hardware", "cpu model")) and ":" in l:
                cpu = l.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    if not cpu:
        cpu = next((l.split(":", 1)[1].strip() for l in run(["lscpu"]).splitlines() if l.lower().startswith("model name") and ":" in l), "")
    h["cpu"] = cpu
    try:
        kb = next(int(l.split()[1]) for l in Path("/proc/meminfo").read_text().splitlines() if l.startswith("MemTotal:"))
        h["memoryGiB"] = round(kb / 1048576, 1)
    except (OSError, StopIteration, ValueError, IndexError):
        pass
    h["virtualisation"] = run(["systemd-detect-virt"]).strip() or ""
    return scrub({k: v for k, v in h.items() if v not in ("", None)})


def run_bytes(cmd: list[str]) -> bytes:
    """Like run(), for output that is not text (a tar stream). Reads at most IMAGE_FILE_LIMIT bytes into memory, then stops the command: a huge file is a failure,
    not an out-of-memory. Empty on any failure."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as e:
        dbg(f"collect: {' '.join(cmd[:3])}: failed {e!r}")
        return b""
    try:
        timer = threading.Timer(120, proc.kill)
        timer.start()
        try:
            data = proc.stdout.read(IMAGE_FILE_LIMIT + 1)
        finally:
            timer.cancel()
        if len(data) > IMAGE_FILE_LIMIT:
            proc.kill()
            dbg(f"collect: {' '.join(cmd[:3])}: more than {IMAGE_FILE_LIMIT} bytes, skipped")
            return b""
        proc.wait()
        if proc.returncode:
            dbg(f"collect: {' '.join(cmd[:3])}: rc={proc.returncode}, skipped")
            return b""
        return data
    except OSError as e:
        dbg(f"collect: {' '.join(cmd[:3])}: failed {e!r}")
        return b""
    finally:
        proc.kill()
        proc.wait()
        proc.stdout.close()


def tar_members(blob: bytes) -> dict[str, bytes]:
    """name -> content of every regular file in a tar stream (docker cp writes a file or a folder as a tar)."""
    import io, tarfile
    out: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(blob)) as t:
            for m in t:
                if m.isfile():
                    f = t.extractfile(m)
                    if f:
                        out[m.name] = f.read()
    except (tarfile.TarError, OSError, EOFError):
        pass
    return out


def parse_rpm_header(blob: bytes) -> dict[str, str]:
    """name, version, release, epoch from one RPM header blob (the value stored in rpmdb.sqlite): int32 index count, int32 data size, 16-byte index entries, data."""
    import struct
    if len(blob) < 8:
        return {}
    il, dl = struct.unpack(">II", blob[:8])
    if il > 100000 or 8 + il * 16 + dl > len(blob):
        return {}
    data = blob[8 + il * 16:8 + il * 16 + dl]
    out = {}
    for i in range(il):
        tag, typ, off, cnt = struct.unpack(">IIII", blob[8 + i * 16:24 + i * 16])
        if tag in (1000, 1001, 1002) and typ == 6 and off < len(data):
            end = data.find(b"\0", off)
            if end < 0:
                continue
            out[{1000: "name", 1001: "version", 1002: "release"}[tag]] = data[off:end].decode("utf-8", "replace")
        elif tag == 1003 and typ == 4 and off + 4 <= len(data):
            out["epoch"] = str(struct.unpack(">I", data[off:off + 4])[0])
    return out


def parse_rpm_sqlite(db: bytes) -> dict[str, str]:
    """name -> [epoch:]version-release from an rpmdb.sqlite (Fedora 33+, RHEL 9+, Amazon Linux 2023, SUSE Tumbleweed). Berkeley DB and ndb databases are not read."""
    import sqlite3
    out: dict[str, str] = {}
    if not db.startswith(b"SQLite format 3"):
        return out
    try:
        with tempfile.TemporaryDirectory() as d:  # removed on leaving, also on an error; a full disk makes the write fail and the image is read without packages
            f = Path(d) / "rpmdb.sqlite"
            f.write_bytes(db)
            con = sqlite3.connect(f"file:{f}?mode=ro", uri=True)
            try:
                con.execute("PRAGMA trusted_schema=OFF")   # the database comes from an image someone else built: no schema-defined functions or triggers
                con.execute("PRAGMA query_only=ON")
                for (blob,) in con.execute("SELECT blob FROM Packages LIMIT 50000"):
                    h = parse_rpm_header(bytes(blob))
                    if h.get("name") and h.get("name") != "gpg-pubkey":
                        out[h["name"]] = (f"{h['epoch']}:" if h.get("epoch") else "") + f"{h.get('version', '')}-{h.get('release', '')}"
            finally:
                con.close()
    except (OSError, sqlite3.Error, ValueError, TypeError) as e:
        dbg(f"collect: rpmdb unreadable {e!r}")
    return out


def image_languages(cid: str) -> tuple[dict[str, dict[str, str]], bool]:
    """Python, Node, Java and Ruby packages inside an image, from names and small manifests found while streaming `docker export` (nothing is extracted to disk).
    Returns ({ecosystem: {name: 'v1|v2'}}, complete). Stops at LANG_SECONDS and says so."""
    import tarfile
    found: dict[str, dict[str, set]] = {"pypi": {}, "npm": {}, "maven": {}, "gem": {}}

    def add(eco: str, name: str, ver: str) -> None:
        if name and ver and len(found[eco]) < 8000:
            found[eco].setdefault(name.lower() if eco != "maven" else name, set()).add(ver)
    t0 = time.time()
    proc = subprocess.Popen(["docker", "export", cid], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    complete = True
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|") as t:
            for m in t:
                if time.time() - t0 > LANG_SECONDS:
                    complete = False
                    break
                n = m.name
                parts = n.rstrip("/").split("/")
                last = parts[-1]
                if m.isdir() and last.endswith((".dist-info", ".egg-info")) and any(x in ("site-packages", "dist-packages") for x in parts[:-1]):
                    stem = re.sub(r"-py\d[\d.]*$", "", last.rsplit(".", 1)[0])
                    nm, _, ver = stem.rpartition("-")
                    if nm and ver[:1].isdigit():
                        add("pypi", nm.replace("_", "-"), ver)
                elif m.isfile() and last == "package.json" and len(parts) >= 3 and "node_modules" in parts[:-1] and (
                        parts[-3] == "node_modules" or (parts[-3].startswith("@") and parts[-4:-3] == ["node_modules"])) and m.size < 262144:
                    try:
                        j = json.loads(t.extractfile(m).read())
                        add("npm", str(j.get("name", "")), str(j.get("version", "")))
                    except (ValueError, AttributeError, OSError):
                        pass
                elif m.isfile() and last.endswith(".jar"):
                    jm = re.match(r"^(.+?)-(\d[\w.\-]*)\.jar$", last)
                    if jm:
                        add("maven", jm.group(1), jm.group(2))
                elif m.isdir() and len(parts) >= 2 and parts[-2] == "gems":
                    gm = re.match(r"^(.+)-(\d[\w.]*?)(?:-[a-z0-9_]+)?$", last)
                    if gm:
                        add("gem", gm.group(1), gm.group(2))
    except Exception as e:  # noqa: BLE001 - a damaged tar or an odd member must cost this image its language list, not the scan
        dbg(f"collect: export of {cid[:12]}: {e!r}")
        complete = False
    finally:
        proc.kill()
        proc.wait()
        proc.stdout.close()
    return {k: {n: "|".join(sorted(v)) for n, v in d.items()} for k, d in found.items() if d}, complete


def parse_os_release(text: str) -> dict:
    kv = {}
    for l in text.splitlines():
        k, eq, v = l.partition("=")
        if eq and k in ("ID", "ID_LIKE", "VERSION_ID", "VERSION_CODENAME", "PRETTY_NAME", "NAME"):
            kv[k] = v.strip().strip('"')
    return kv


def parse_apk_db(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for block in text.split("\n\n"):
        n = v = ""
        for l in block.splitlines():
            if l.startswith("P:"):
                n = l[2:].strip()
            elif l.startswith("V:"):
                v = l[2:].strip()
        if n:
            out[n] = v
    return out


def parse_dpkg_status(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for block in text.split("\n\n"):
        f = dict(l.split(": ", 1) for l in block.splitlines() if ": " in l and not l.startswith(" "))
        if f.get("Package") and "installed" in f.get("Status", "installed").split() and "not-installed" not in f.get("Status", ""):
            out[f["Package"]] = f.get("Version", "")
    return out


def image_ref_parts(ref: str) -> tuple[str, str]:
    """('postgres', '16-alpine') from 'docker.io/library/postgres:16-alpine'; the tag is '' for an id or a digest."""
    base = ref.split("@")[0]
    name, _, tag = base.rpartition(":") if ":" in base.rsplit("/", 1)[-1] else (base, "", "")
    return name.rsplit("/", 1)[-1], tag


def image_detail(ref: str, running: bool, lang: bool = False) -> dict | None:
    """What is inside one local image, without starting it: docker image inspect for its metadata, then docker create + docker cp for the OS release file
    and the package database (apk or dpkg), then docker rm. Environment values are never kept except keys ending _VERSION, because images carry secrets there."""
    raw = run(["docker", "image", "inspect", ref])
    try:
        meta = json.loads(raw)[0]
    except (ValueError, IndexError, TypeError):
        progress(f"[host] image {ref}: not readable, left as a name only")
        return None
    cfg = meta.get("Config") or {}
    labels = cfg.get("Labels") or {}
    name, tag = image_ref_parts(ref)
    d: dict = {"name": name, "tag": tag, "running": running, "arch": meta.get("Architecture", ""), "platform": meta.get("Os", ""),
               "id": (meta.get("Id") or "").replace("sha256:", "")[:12], "layers": (meta.get("RootFS") or {}).get("Layers") or []}
    for k, lk in (("title", "org.opencontainers.image.title"), ("version", "org.opencontainers.image.version"), ("vendor", "org.opencontainers.image.vendor"),
                  ("baseName", "org.opencontainers.image.base.name"), ("source", "org.opencontainers.image.source")):
        if labels.get(lk):
            d[k] = str(labels[lk])[:200]
    versions = {}
    for e in cfg.get("Env") or []:
        k, _, v = e.partition("=")
        if k.endswith("_VERSION") and v and len(v) < 40:
            versions[k] = v
    if versions:
        d["versions"] = versions
    cid = run(["docker", "create", "--pull", "never", "--network", "none", "--label", f"{CONTAINER_LABEL}={RUN_ID}", ref]).strip().splitlines()
    cid = cid[-1] if cid else ""
    if not cid:
        d["note"] = "metadata only: no container could be created to read files"
        return d
    langs: dict = {}
    try:
        got: dict = {}
        paths = dict(IMAGE_FILES)

        def fetch(key: str) -> bool:
            blob = run_bytes(["docker", "cp", f"{cid}:/{paths[key]}", "-"])
            if blob:
                got[key] = tar_members(blob)
            return bool(got.get(key))
        # one copy per file that can exist: the OS file first, then the package database that OS family uses, and the other databases only if that found nothing
        _ = fetch("os") or fetch("os2")
        fam = parse_os_release(next(iter((got.get("os") or got.get("os2") or {}).values()), b"").decode("utf-8", "replace"))
        ids = f"{fam.get('ID', '')} {fam.get('ID_LIKE', '')}".lower().split()
        order = [k for k in ("apk", "dpkg", "dpkgd", "rpm", "rpm2")]
        if "alpine" in ids:
            order = ["apk"] + [k for k in order if k != "apk"]
        elif {"debian", "ubuntu"} & set(ids):
            order = ["dpkg", "dpkgd"] + [k for k in order if k not in ("dpkg", "dpkgd")]
        elif {"fedora", "rhel", "centos", "amzn", "suse", "sles", "opensuse", "ol", "rocky", "almalinux"} & set(ids):
            order = ["rpm", "rpm2"] + [k for k in order if k not in ("rpm", "rpm2")]
        for k in order:
            if fetch(k):
                break
        if lang:
            langs, complete = image_languages(cid)
            if not complete:
                d["languagesPartial"] = True
    finally:
        run(["docker", "rm", "-f", cid])
    first = lambda k: next(iter((got.get(k) or {}).values()), b"").decode("utf-8", "replace")  # noqa: E731
    got_text = {k: first(k) for k in ("os", "os2", "apk", "dpkg")}
    osr = parse_os_release(got_text["os"] or got_text["os2"])
    if osr:
        d["os"] = osr.get("ID", "")
        d["osVersion"] = osr.get("VERSION_ID", "")
        d["osName"] = osr.get("PRETTY_NAME") or osr.get("NAME", "")
        if osr.get("ID_LIKE"):
            d["osLike"] = osr["ID_LIKE"]
    rpm = next((v for k in ("rpm", "rpm2") for v in (got.get(k) or {}).values()), b"")
    if got_text["apk"]:
        d["packages"], d["packageManager"] = parse_apk_db(got_text["apk"]), "apk"
    elif got_text["dpkg"]:
        d["packages"], d["packageManager"] = parse_dpkg_status(got_text["dpkg"]), "dpkg"
    elif got.get("dpkgd"):  # distroless: one control file per package
        pk: dict[str, str] = {}
        for name, raw in got["dpkgd"].items():
            if not name.endswith((".md5sums", ".list")):
                pk.update(parse_dpkg_status(raw.decode("utf-8", "replace")))
        if pk:
            d["packages"], d["packageManager"] = pk, "dpkg"
    elif rpm:
        pk = parse_rpm_sqlite(rpm)
        if pk:
            d["packages"], d["packageManager"] = pk, "rpm"
    if langs:
        d["languages"] = langs
    if not osr and "packages" not in d and not langs:
        d["note"] = "no OS release file or package database found (a minimal or distroless image)"
    return d


def sweep_containers(stale_only: bool) -> int:
    """Remove the never-started containers this tool made: every one of this run (at the end and on exit), or, at the start, those of an earlier run that
    was killed before it could clean up (older than STALE_MINUTES, so a scan running at the same time is not disturbed). Only containers carrying this
    tool's label are touched."""
    removed = 0
    for line in run(["docker", "container", "ls", "-a", "--no-trunc", "--filter", f"label={CONTAINER_LABEL}", "--filter", "status=created",
                     "--format", "{{.ID}}\t{{.Label \"" + CONTAINER_LABEL + "\"}}\t{{.CreatedAt}}"]).splitlines():
        cid, _, rest = line.partition("\t")
        run_id, _, created = rest.partition("\t")
        if not cid:
            continue
        if stale_only:
            if run_id == RUN_ID:
                continue
            try:
                age = time.time() - dt.datetime.strptime(created[:19], "%Y-%m-%d %H:%M:%S").timestamp()
            except ValueError:
                continue
            if age < int(env("STALE_MINUTES", str(STALE_MINUTES))) * 60:
                continue
        elif run_id != RUN_ID:
            continue
        run(["docker", "rm", "-f", cid])
        removed += 1
    if removed:
        progress(f"[host] removed {removed} leftover scan container{'s' if removed > 1 else ''}" + (" from an earlier run that was stopped" if stale_only else ""))
    return removed


def docker_free_mb() -> int | None:
    root = run(["docker", "info", "--format", "{{.DockerRootDir}}"]).strip()
    try:
        return shutil.disk_usage(root).free // 1048576 if root else None
    except OSError:
        return None


def parse_size_mb(text: str) -> float:
    """'1.2GB' / '455MB' / '12.3kB' (docker's own size text) as megabytes; 0 when it cannot be read."""
    m = re.match(r"^\s*([\d.]+)\s*([kKMGT]?)B\s*$", text)
    if not m:
        return 0.0
    return float(m.group(1)) * {"": 1 / 1048576, "k": 1 / 1024, "K": 1 / 1024, "M": 1, "G": 1024, "T": 1048576}[m.group(2)]


def deep_estimate(n_images: int, size_mb: float) -> int:
    """Rough seconds for a deep inventory: about 2 s of docker calls per image (two images at a time) plus the filesystem stream of each image. Calibrated
    on one 24-image, 31 GB host (about 6 minutes); other disks differ, so it is always shown as 'about'."""
    return int(n_images * 1.0 + size_mb / 1024 * 9)


def fmt_secs(sec: float) -> str:
    sec = int(sec)
    return f"{sec} s" if sec < 90 else f"{sec // 60} min" if sec < 3600 else f"{sec // 3600} h {sec % 3600 // 60} min"


DEEP_STAMP = "deep.json"
IMAGE_SCAN: dict = {}


def deep_hint(inv: dict) -> None:
    """After a quick inventory, one line on stderr (never stdout) saying what was not read, how long a deep one takes and when one was last done."""
    s = inv.get("imageScan") or {}
    if s.get("level") != "quick" or not s.get("local"):
        return
    r = s.get("reusedDeep")
    if r:
        progress(f"[host] Quick scan; {r['images']} image(s) come from the deep scan of {r['on']} (their id is unchanged). Run lattice-scan --deep to read them again.")
        return
    last = ""
    try:
        d = json.loads((OUT / DEEP_STAMP).read_text())
        age = (dt.date.fromisoformat(TODAY) - dt.date.fromisoformat(d["on"])).days
        last = f" Last deep scan: {d['on']} ({age} days ago" + ("; worth repeating)." if age >= 30 else ").")
    except (OSError, ValueError, KeyError):
        last = " A deep scan has not been done on this machine."
    progress(f"[host] Quick scan: opened {s['opened']} of {s['local']} local images (the ones containers run) and not the packages inside them (Python, Node, Java, Ruby). "
             f"A deep scan reads all of it in about {fmt_secs(s.get('deepSeconds', 0))}: lattice-scan --deep.{last}")


def scan_level() -> str:
    """quick (default) or deep. Deep opens every local image and the language packages inside; see --deep."""
    return "deep" if env("LEVEL", "quick").lower() == "deep" else "quick"


def lineage(details: dict[str, dict], others: dict[str, list] | None = None) -> None:
    """Which local image each image was built on: another local image whose layers are exactly the first layers of this one (the longest wins; an image
    with the same layers is a tag of the same image, not a base). Layer lists are dropped afterwards, keeping the count."""
    for ref, d in details.items():
        mine = d.get("layers") or []
        best = ""
        bestn = 0
        for other, ol in [(k, v.get("layers") or []) for k, v in details.items()] + list((others or {}).items()):
            if other != ref and 0 < len(ol) < len(mine) and mine[:len(ol)] == ol and len(ol) > bestn:
                best, bestn = other, len(ol)
        if best:
            d["builtOn"] = best
            d["sharedLayers"] = bestn
    for d in details.values():
        d["layerCount"] = len(d.pop("layers", []) or [])


DEEP_IMAGES = "deep-images.json"


def deep_cache_days() -> int:
    try:
        return int(env("DEEP_CACHE_DAYS", "30") or 30)
    except ValueError:
        return 30


def save_deep(out: dict[str, dict], ids_now: dict[str, str], seconds: int) -> None:
    """Keep what a complete deep scan read of each image (with the image id it read), so a later quick run does not lose it. Private to this user."""
    keep = {r: {"id": d.get("id") or ids_now.get(r, ""), "detail": d} for r, d in out.items() if d}
    try:
        write_private(OUT / DEEP_STAMP, json.dumps({"on": TODAY, "images": len(out), "seconds": seconds}))
        write_private(OUT / DEEP_IMAGES, json.dumps({"on": TODAY, "images": keep}))
    except OSError:
        pass


def reuse_deep(out: dict[str, dict], ids_now: dict[str, str], running: set[str]) -> None:
    """A quick run: for each local image whose id is unchanged since the last complete deep scan (at most LATTICE_SCAN_DEEP_CACHE_DAYS old), use that deep
    reading in place of the quick one, or add it when the quick run did not open the image. An image that changed, or is gone, is not reused.
    LATTICE_SCAN_DEEP_CACHE=off (and --refresh) turns this off."""
    if env("DEEP_CACHE", "on").lower() == "off":
        return
    try:
        saved = json.loads((OUT / DEEP_IMAGES).read_text())
        age = (dt.date.fromisoformat(TODAY) - dt.date.fromisoformat(saved["on"])).days
        images = saved["images"]
    except (OSError, ValueError, KeyError, TypeError):
        return
    if age > deep_cache_days() or not isinstance(images, dict):
        return
    reused = 0
    for ref, rec in images.items():
        now = ids_now.get(ref)
        if now and isinstance(rec, dict) and isinstance(rec.get("detail"), dict) and rec.get("id") == now:
            out[ref] = {**rec["detail"], "running": ref in running}   # what the image holds is from the deep scan; whether it runs is as of now
            reused += 1
    if reused:
        IMAGE_SCAN["reusedDeep"] = {"on": saved["on"], "images": reused}
        progress(f"[host] {reused} image(s) read from the deep scan of {saved['on']} ({age} days ago; their id is unchanged), not opened again. --refresh opens them again")


def image_details(running: list[str]) -> dict[str, dict]:
    """Detail for every image on this machine, keyed by its reference. LATTICE_SCAN_LEVEL / --deep sets the defaults (quick: running images, no language scan; deep: all images and the language scan);
    LATTICE_SCAN_IMAGES (all, running, off) and LATTICE_SCAN_IMAGES_LANG (all, running, off) override them."""
    deep = scan_level() == "deep"
    mode = env("IMAGES", "all" if deep else "running").lower()
    if mode == "off" or not shutil.which("docker"):
        return {}
    free, need = docker_free_mb(), int(env("MIN_FREE_MB", "1024") or 1024)
    if free is not None and free < need:
        progress(f"[host] images not opened: only {free} MB free where Docker keeps its data (needs {need}; LATTICE_SCAN_MIN_FREE_MB); the image names are still listed")
        return {}
    sweep_containers(stale_only=True)
    atexit.register(sweep_containers, False)
    refs = {r: True for r in running if not r.startswith("-")}
    ids_now: dict[str, str] = {}   # reference -> short image id now, to tell whether a saved deep reading still describes the image
    local, size_mb, sizes = set(running), 0.0, {}
    for l in run(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.ID}}"]).splitlines():
        ref, _, rest = l.partition("\t")
        size, _, short_id = rest.partition("\t")
        if ref and "<none>" not in ref and not ref.startswith("-"):   # a reference starting with a dash would reach docker as an option
            local.add(ref)
            ids_now[ref] = short_id.strip()
            sizes[ref] = parse_size_mb(size)
            size_mb += sizes[ref]
            if mode != "running":
                refs.setdefault(ref, False)
    IMAGE_SCAN.update({"level": "deep" if deep else "quick", "local": len(local), "opened": 0, "skipped": 0, "deepSeconds": deep_estimate(len(local), size_mb)})
    out = {}
    lang_mode = env("IMAGES_LANG", "all" if deep else "off").lower()
    todo = sorted(refs)[:IMAGE_LIMIT]

    deadline = time.time() + int(env("DEEP_SECONDS", "1800") or 1800)
    skipped: list[str] = []

    t_start, done, lock = time.time(), [0], threading.Lock()
    if lang_mode in ("all", "running") and deep:
        progress(f"[host] deep scan: {len(todo)} images, about {fmt_secs(IMAGE_SCAN['deepSeconds'])} (a rough estimate; Ctrl-C stops it and cleans up)")

    def tick(ref: str, what: str, t0: float) -> None:
        with lock:
            done[0] += 1
            progress(f"[host] [{done[0]}/{len(todo)} {done[0] * 100 // max(len(todo), 1)}%] {ref}: {what} ({time.time() - t0:.0f} s; {fmt_secs(time.time() - t_start)} elapsed)")

    def one(ref: str) -> dict | None:
        t0 = time.time()
        if time.time() > deadline:
            skipped.append(ref)
            tick(ref, "skipped, time limit", t0)
            return None
        with_lang = lang_mode == "all" or (lang_mode == "running" and refs[ref])
        if with_lang and sizes.get(ref, 0) >= 1000:  # only the ones that take a while, so the person knows what the quiet minutes are
            progress(f"[host] reading {ref} ({sizes[ref] / 1024:.1f} GB; the Python/Node/Java/Ruby scan of a large image takes minutes) ...")
        try:
            d = scrub(image_detail(ref, refs[ref], with_lang))
        except Exception as e:  # noqa: BLE001 - one unreadable image must not stop the scan
            tick(ref, f"skipped, {type(e).__name__}: {str(e)[:80]}", t0)
            return None
        tick(ref, ("not readable" if not d else (d.get("osName") or d.get("note") or "done")
                   + (f", {len(d['packages'])} packages" if d and d.get("packages") else "") + (", language scan stopped at its limit" if d and d.get("languagesPartial") else "")), t0)
        return d
    from concurrent.futures import ThreadPoolExecutor
    workers = 2 if lang_mode in ("all", "running") else 4  # the docker daemon does the work; the export stream is disk-heavy, so fewer at once
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for ref, d in zip(todo, ex.map(one, todo)):
            if d:
                out[ref] = d
    sweep_containers(stale_only=False)
    IMAGE_SCAN.update({"opened": len(out), "skipped": len(skipped), "seconds": int(time.time() - t_start)})
    progress(f"[host] images: {len(out)} opened, {len(todo) - len(out)} not opened, {fmt_secs(time.time() - t_start)} in all")
    if skipped:
        progress(f"[host] {len(skipped)} image(s) not opened, the time limit of {env('DEEP_SECONDS', '1800')} s (LATTICE_SCAN_DEEP_SECONDS) was reached: " + ", ".join(sorted(skipped)[:5]))
    others = {}  # images that were not opened still show their layers, which is all lineage needs and costs one inspect
    for l in run(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"]).splitlines() if mode == "running" else []:
        if l and "<none>" not in l and l not in out and l not in refs:
            try:
                others[l] = (json.loads(run(["docker", "image", "inspect", l]))[0].get("RootFS") or {}).get("Layers") or []
            except (ValueError, IndexError, TypeError):
                pass
    lineage(out, others)
    if deep and not skipped and out:
        save_deep(out, ids_now, int(IMAGE_SCAN.get("seconds", 0)))
    elif not deep:
        reuse_deep(out, ids_now, {r for r, on in refs.items() if on})
    if len(refs) > IMAGE_LIMIT:
        progress(f"[host] {len(refs) - IMAGE_LIMIT} more images not opened (limit {IMAGE_LIMIT}); set LATTICE_SCAN_IMAGES=running to open only running ones")
    return out


def inventory() -> dict:
    fixed = env("INVENTORY")
    if fixed:
        inv = json.loads(Path(fixed).read_text())
        inv.setdefault("hash", "fixed")
        inv.setdefault("host", {})
        inv.setdefault("imageDetails", {})
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
    host = hardware()
    progress("[host] hardware: " + (" ".join(x for x in (host.get("manufacturer"), host.get("model"), host.get("version")) if x) or "not reported by this machine"))
    IMAGE_SCAN.clear()
    details = image_details(images)
    inv = {"kernel": kernel, "os": osr, "manager": manager if pk else "", "host": host, "packages": pk, "snaps": snaps, "images": images, "imageDetails": details, "node": run(["node", "-v"]).strip(),
           "restartRequired": Path("/var/run/reboot-required").exists()}
    if IMAGE_SCAN:
        inv["imageScan"] = dict(IMAGE_SCAN)
        atexit.register(deep_hint, inv)  # printed last, after the scan's own output
    inv["hash"] = hashlib.sha256(json.dumps({k: inv[k] for k in ("kernel", "packages", "snaps", "images", "node")}
                                            | {"host": {k: host.get(k) for k in ("manufacturer", "model", "version", "biosVersion")},
                                               "imageDetails": {r: [d.get("id"), d.get("os"), d.get("osVersion"), len(d.get("packages") or {})] for r, d in details.items()}},
                                            sort_keys=True).encode()).hexdigest()[:12]
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
    items: list[tuple[str, set[str]]] = []   # each installed name with its words, to ask whether a product's words sit together in one of them
    for n in inv["packages"]:
        for w in stems(n):
            have.setdefault(w, n)
        items.append((n, stems(n)))
    for n in inv["snaps"]:
        have.setdefault(n.lower(), f"snap {n}")
        items.append((f"snap {n}", {n.lower()} | stems(n)))
    for im in inv["images"]:
        for w in stems(im):
            have.setdefault(w, f"container image {im.split('@')[0]}")
        items.append((f"container image {im.split('@')[0]}", stems(im)))
    # The vendor is evidence only when it is a distinctive word and something with that word is installed (a package, a snap, an image, or inside an image).
    vendor_words = {w for w in words(vendor) if w != "unknown"}
    seen_words = set(have)
    for ref, d in (inv.get("imageDetails") or {}).items():
        seen_words |= set(image_words(ref, d))
    vendor_ok = bool(vendor_words & seen_words)
    if want <= WEAK and not vendor_ok:
        dbg(f"   match {entry['cve']}: {sorted(want)} are ordinary words and vendor {vendor!r} is not installed, no match")
        return None
    whole = sorted(lab for lab, st in items if want <= st)   # installed names that hold every word of the product
    together = len(want) < 2 or bool(whole) or vendor_ok
    dbg(f"   match {entry['cve']} basis={basis} wanted={sorted(want)} found={sorted(w for w in want if w in have)} missing={sorted(w for w in want if w not in have)}")
    if all(w in have for w in want) and together:
        names = whole if len(want) > 1 and whole else sorted({have[w] for w in want})
        if all(n.startswith("container image ") for n in names):  # a bare image name says little; the opened image gives its versions
            opened = in_images(want, basis, inv)
            if opened:
                return opened
        installed = [f"{n} {inv['packages'][n]}" if n in inv["packages"] else n for n in names]
        vers = [inv["packages"][n] for n in names if n in inv["packages"]] + [inv["snaps"][n[5:]] for n in names if n.startswith("snap ") and n[5:] in inv["snaps"]]
        return f"{basis} " + " ".join(sorted(want)) + " matches " + ", ".join(names), installed, vers
    return in_images(want, basis, inv) or in_hardware(want, inv)


def product_version(d: dict) -> str:
    """The version of what the image is FOR: the *_VERSION variable named like the image (REDIS_VERSION in redis, PG_VERSION in postgres), else the version label,
    else a number leading the tag. Helper variables such as GOSU_VERSION are never taken for it."""
    ns = stems(d.get("name", ""))
    for k, v in (d.get("versions") or {}).items():
        base = k.removesuffix("_VERSION").lower()
        if stems(base) & ns or (base.startswith("pg") and "postgres" in ns) or (base.startswith("pg") and "pgvector" in ns):
            return v
    return d.get("version", "") or re.sub(r"[^0-9.].*$", "", d.get("tag", ""))


def image_words(ref: str, d: dict) -> dict[str, tuple[str, str]]:
    """word -> (what it names, its version) for one image: its package names, its product (name, labels, *_VERSION variables) and its base OS."""
    out: dict[str, tuple[str, str]] = {}
    prod_ver = product_version(d)
    for w in stems(d.get("name", "")) | stems(d.get("title", "")):
        out.setdefault(w, (f"{d.get('name') or w} {prod_ver}".strip(), prod_ver))
    for k, v in (d.get("versions") or {}).items():
        for w in stems(k.removesuffix("_VERSION")):
            out.setdefault(w, (f"{k.removesuffix('_VERSION').lower()} {v}", v))
    for n, v in (d.get("packages") or {}).items():
        if n.startswith("."):  # apk virtual packages (.redis-rundeps) are build bookkeeping, not software
            continue
        for w in stems(n):
            out.setdefault(w, (f"{n} {v}".strip(), v))
    for eco, pk in (d.get("languages") or {}).items():
        for n, v in pk.items():
            for w in stems(n.rsplit("/", 1)[-1].lstrip("@")):
                out.setdefault(w, (f"{eco} {n} {v.replace('|', ', ')}", v))
    if d.get("os"):
        out.setdefault(d["os"], (f"{d.get('osName') or d['os']}", d.get("osVersion", "")))
    return out


def in_images(want: set[str], basis: str, inv: dict) -> tuple[str, list[str], list[str]] | None:
    """A candidate from inside container images: every wanted word is found within ONE image, so an Alpine musl flaw names the Alpine images carrying musl."""
    installed, vers, refs = [], [], []
    for ref, d in sorted((inv.get("imageDetails") or {}).items()):
        have = image_words(ref, d)
        if want and all(w in have for w in want):
            refs.append(ref)
            for w in sorted(want):
                label, v = have[w]
                installed.append(f"{label} (image {ref})")
                vers += [x for x in v.split("|") if x]
    if not refs:
        return None
    return f"{basis} " + " ".join(sorted(want)) + " matches inside container image" + ("s " if len(refs) > 1 else " ") + ", ".join(refs), sorted(set(installed)), sorted(set(vers))


def in_hardware(want: set[str], inv: dict) -> tuple[str, list[str], list[str]] | None:
    """A candidate from the machine itself: firmware or board advisories name a maker and a model."""
    h = inv.get("host") or {}
    parts = {k: h[k] for k in ("manufacturer", "model", "board", "boardVendor", "biosVendor") if h.get(k)}
    have = {w for v in parts.values() for w in stems(v)}
    if want and all(w in have for w in want):
        return ("product " + " ".join(sorted(want)) + " matches this machine's hardware", [f"hardware {' '.join(parts.values())}"],
                [h["biosVersion"]] if h.get("biosVersion") else [])
    return None


def upstream(v: str) -> tuple[int, ...] | None:
    """The comparable upstream version of an installed version string, or None when it has no plain dotted number.

    '1:2.17.1-1' -> (2,17,1); '7.0.0-41-cix' -> (7,0,0); 'v22.22.1' -> (22,22,1). Distro revisions (-1ubuntu3), epochs and +suffixes are dropped, so a
    distro that backports a fix under the same upstream number looks unfixed here: the changelog check below exists for exactly that.
    """
    return lv.generic_key(v)


def cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    return lv._cmp_padded(a, b)


def in_range(ver: tuple[int, ...], r: dict) -> bool | None:
    """Is ver inside one NVD range? None when a bound is not a plain dotted number (a date, a build id): that range cannot be judged. See lattice_version."""
    return lv.in_range(".".join(map(str, ver)), "generic", r)


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
    names = [i.split(" ")[0] for i in installed if "(image " not in i and i.split(" ")[0] in inv["packages"]]
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


_POSTURE: list = []


def posture_data() -> dict | None:
    """The running layer (listeners, services), read once per run and only when a candidate needs it. LATTICE_SCAN_POSTURE names a fixed JSON file (tests, like
    LATTICE_SCAN_INVENTORY). None when it cannot be collected: the label then says so instead of guessing."""
    if _POSTURE:
        return _POSTURE[0]
    data = None
    try:
        fixed = env("POSTURE")
        if fixed:
            data = json.loads(Path(fixed).read_text())
        else:
            from . import posture
            progress("[posture] reading listeners and services for the exposure labels (read only, nothing is sent)")
            data = posture.collect()
    except Exception as err:  # noqa: BLE001 - a label must never stop a scan
        dbg(f"posture not read: {type(err).__name__}: {err}")
    _POSTURE.append(data)
    return data


def with_exposure(imp: dict, installed: list[str], inv: dict) -> dict:
    from . import exposure
    imp["exposure"] = exposure.label(installed, inv["packages"], posture_data() if any(not s.startswith("container image ") for s in installed) else None)
    return imp


def open_findings() -> dict[str, dict]:
    """The findings still open in the records, for a snapshot: id -> what is installed and the day it was first found."""
    return {c: {"installed": "; ".join(((f.get("impact") or {}).get("installed")) or []), "found": f.get("found", "")} for c, f in state().items() if f.get("status") == "open"}


def snapshot_report(post: dict | None, inv_hash: str, save_it: bool = True) -> None:
    """Print what is new, changed or gone since the last stored snapshot, then store this run's. Local only; a failure here never stops a scan."""
    from . import snapshot
    try:
        now = dt.datetime.now().isoformat(timespec="milliseconds")
        cur = snapshot.build(TODAY, now, inv_hash, post, open_findings())
        last = snapshot.latest(OUT)
        if last:
            d = snapshot.diff(last, cur)
            RESULT["change"] = d
            print(snapshot.render(d, cur))
        else:
            print("CHANGE SINCE THE LAST RUN: this is the first stored snapshot; the next run will say what is new, changed or gone.")
        if save_it:
            snapshot.save(OUT, cur)
    except Exception as err:  # noqa: BLE001
        dbg(f"snapshot not stored: {type(err).__name__}: {err}")


def impact(entry: dict, inv: dict, installed: list[str], vers: list[str]) -> dict:
    """What a person needs to judge this match, from what Lattice returned plus the inventory. It decides nothing.

    versionCheck compares upstream version numbers with NVD's ranges from Lattice (affected_ranges); it is evidence for a person, and 'outside-range'
    does not close a finding (only `resolve` does). The NVD product list is corroboration only (names that also appear here); it is never what makes an entry a candidate.
    """
    day = dt.date.fromisoformat(TODAY)
    have = set()
    for n in list(inv["packages"]) + list(inv["snaps"]) + list(inv["images"]):
        have |= stems(n)
    for ref, d in (inv.get("imageDetails") or {}).items():
        have |= set(image_words(ref, d))
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
    inline = e.get("inline") or {}
    if inline:   # the lookup already carried them (ADR-LATTICE-API-001 C1): no second call
        props = {"description": inline.get("description"), "cwe_refs": inline.get("cwe"), "references": inline.get("references"), "status": inline.get("status"),
                 "date_created": inline.get("date_created"), "date_modified": inline.get("date_modified"),
                 "metadata": {"epss": inline.get("epss"), "ssvc": inline.get("ssvc"), "affected_products": e.get("affected") or []}}
    elif e.get("nvdUid"):
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
    if props.get("status") or props.get("date_created"):
        ctx["record"] = {"status": clean(str(props.get("status", ""))), "created": clean(str(props.get("date_created", ""))), "modified": clean(str(props.get("date_modified", ""))),
                         "products": len(md.get("affected_products") or [])}
    if props.get("cwe_refs"):
        ctx["cwe"] = [clean(str(c)) for c in props["cwe_refs"]][:5]
    if props.get("description"):
        ctx["description"] = " ".join(clean(str(props["description"])).split())[:CONTEXT_DESC]   # NVD hard-wraps its text: one line
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


INLINE_KEYS = ("epss", "ssvc", "cwe", "description", "references", "status", "date_created", "date_modified")


def inline_context(nvd: dict) -> dict:
    """The urgency fields a server with ADR-LATTICE-API-001 C1 puts in the NVD item of a lookup. Empty from an older server, which is how the tool knows to
    ask graph_node instead."""
    return {k: nvd[k] for k in INLINE_KEYS if k in nvd}


def kev_entry(lat: Lattice, cve: str) -> dict | None:
    """The CISA exploited entry for one CVE, or None when the graph has no kev node (which is not 'safe', only 'not listed in this snapshot').

    The kev node of a graph_lookup carries vendor_project, product, date_added, due_date and required_action, and the nvd node carries
    affected_products as 'vendor/product; ...' (OCO-5819, option A): no key and no graph_node call needed. If an older server left them out and a key
    is set, graph_node fills them in.
    """
    items = lat.call("graph_lookup", id=cve).get("items", [])
    kev = next((i for i in items if i.get("source") == "kev"), None)
    lat.last_unlisted = None
    if not kev:
        nvd0 = next((i for i in items if i.get("source") == "nvd"), None)
        if nvd0 and nvd0.get("uid"):
            prim = next((i for i in items if i.get("primary")), nvd0)
            lat.last_unlisted = {"cve": cve, "nvdUid": nvd0["uid"], "ranges": [], "links": prim.get("links") if isinstance(prim.get("links"), list) else [], "inline": inline_context(nvd0),
                                 "affected": [clean(x.strip()) for x in str(nvd0.get("affected_products", "")).split(";") if x.strip()]}
        return None
    nvd = next((i for i in items if i.get("source") == "nvd"), {})
    primary = next((i for i in items if i.get("primary")), nvd)
    e = {"nvdUid": nvd.get("uid") or "", "links": primary.get("links") if isinstance(primary.get("links"), list) else [], "inline": inline_context(nvd),
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
             f"packages={len(inv['packages'])} snaps={len(inv['snaps'])} images={len(inv['images'])} restartRequired={inv['restartRequired']}",
             f"{now}   hardware {' '.join(x for x in ((inv.get('host') or {}).get(k) for k in ('manufacturer', 'model', 'version')) if x) or '-'}"
             f" firmware={(inv.get('host') or {}).get('biosVersion') or '-'}; images opened={len(inv.get('imageDetails') or {})}: "
             + ", ".join(f"{r}={d.get('os') or '?'}{d.get('osVersion') or ''}/{len(d.get('packages') or {})}pkg" for r, d in sorted((inv.get('imageDetails') or {}).items()))]
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
            f.update(listed=e.get("listed", ""), found=e["on"], why=e.get("why", ""), title=e.get("title", ""), due=e.get("due", ""), kind=e.get("kind", "kev"), vendor=e.get("vendor", ""), product=e.get("product", ""), ransomware=e.get("ransomware", ""), cvss=e.get("cvss"), impact=e.get("impact"))
        elif e["event"] == "impact":
            f["impact"] = e["impact"]
        elif e["event"] in ("verified", "fixed", "not-applicable", "withdrawn"):
            f["status"] = e["event"]
            f["proof"] = e.get("proof", "")
            if e["event"] in ("fixed", "not-applicable", "withdrawn"):
                f["closed"] = e["on"]
    return s


def show_inventory(inv: dict, full: bool = False) -> None:
    """The inventory for a person: totals and a short summary. The lists (every package, snap and image) are in inventory.json; full=True (--list) prints them."""
    print(f"inventory {inv['hash']}: {inv['os']}, kernel {inv['kernel']}, node {inv.get('node') or '-'}, restartRequired={inv['restartRequired']}")
    h = inv.get("host") or {}
    if h:
        print("\nhardware:")
        for k, label in (("manufacturer", "manufacturer"), ("model", "model"), ("version", "version"), ("family", "family"), ("chassis", "chassis"), ("boardVendor", "board maker"),
                         ("board", "board"), ("boardVersion", "board version"), ("biosVendor", "firmware maker"), ("biosVersion", "firmware version"), ("biosDate", "firmware date"),
                         ("arch", "architecture"), ("cpu", "cpu"), ("memoryGiB", "memory GiB"), ("virtualisation", "virtualisation")):
            if h.get(k):
                print(f"  {label:<17} {h[k]}")
    det = inv.get("imageDetails") or {}
    scan = inv.get("imageScan") or {}
    print(f"\nimages: {len(inv['images'])} running, {len(det)} opened" + (f" of {scan['local']} local ({scan.get('level')} scan)" if scan.get("local") else ""))
    if det and not full:
        by_os: dict[str, int] = {}
        for d in det.values():
            k = (d.get("osName") or d.get("os") or "OS unknown").split(" (")[0]
            by_os[k] = by_os.get(k, 0) + 1
        print("  by base OS: " + ", ".join(f"{k} {n}" for k, n in sorted(by_os.items(), key=lambda x: (-x[1], x[0]))))
        pk = sum(len(d.get("packages") or {}) for d in det.values())
        lang = {}
        for d in det.values():
            for e, v in (d.get("languages") or {}).items():
                lang[e] = lang.get(e, 0) + len(v)
        print(f"  packages inside images: {pk}" + "".join(f", {e} {n}" for e, n in sorted(lang.items())))
        built = sum(1 for d in det.values() if d.get("builtOn"))
        if built:
            print(f"  built on another local image: {built}")
        partial = [r for r, d in det.items() if d.get("languagesPartial")]
        if partial:
            print(f"  language scan stopped at its time limit for {len(partial)} image(s)")
    if full:
        print("".join(f"  {i}\n" for i in inv["images"]), end="")
        for ref, d in sorted(det.items()):
            print(f"  {ref}{'' if d.get('running') else ' (not running)'}: " + (d.get("osName") or d.get("note") or "OS unknown")
                  + (f", {len(d['packages'])} {d['packageManager']} packages" if d.get("packages") else "")
                  + (f", product version {product_version(d)}" if product_version(d) else "") + (f", {d['arch']}" if d.get("arch") else "")
                  + (f", built on {d['builtOn']} ({d['sharedLayers']} of {d['layerCount']} layers shared)" if d.get("builtOn") else "")
                  + "".join(f", {len(v)} {e}" for e, v in sorted((d.get("languages") or {}).items())) + (" (language scan stopped at its time limit)" if d.get("languagesPartial") else ""))
    if full:
        print(f"\nsnaps ({len(inv['snaps'])}):" + "".join(f"\n  {n:<32} {v}" for n, v in sorted(inv["snaps"].items())))
        print(f"\npackages ({len(inv['packages'])}):" + "".join(f"\n  {n:<44} {v}" for n, v in sorted(inv["packages"].items())))
    else:
        print(f"\nsnaps: {len(inv['snaps'])}\npackages: {len(inv['packages'])}")
        print(f"\nfull lists: {OUT / 'inventory.json'}  (or run again with --list)")


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


RESULT: dict[str, list[list[str]]] = {}
RESULT_KEYS = ["cve", "exploit", "cvss", "listed", "patchDue", "ransomware", "product", "result", "matched"]   # the nine columns of the console table


def print_table(rows: list[list[str]], title: str = "RESULT BY CVE") -> None:
    """The RESULT BY CVE table of the host check, `recent` and `enrich` (nine columns, see cells())."""
    if not rows:
        return
    RESULT.setdefault(title, []).extend(rows)   # --format json|csv|--json read the same rows the console table shows
    print("\n" + title)
    lines, hidden = report.table(["CVE", "Exploit", "CVSS", "Listed", "Patch due", "Ransom", "Product", "Result", "Matched / compared"], rows,
                                 report.width_for(None), fit=sys.stdout.isatty(), drop=("Listed", "Product", "CVSS"), min_last=45)
    print("\n".join(lines))
    if hidden:
        print(f"(narrow terminal: hidden {', '.join(h.upper() for h in hidden)}; pipe the output, for example `| cat`, to see every column)")
    print()


def structured(a, fn) -> int:
    """Run a command whose result is the RESULT BY CVE table (host check, `recent`, `enrich`) and give that table as `--format json` or `csv`, or write it to `--json FILE`.
    The human text of the run is not mixed in: progress and errors stay on stderr, and the exit code is in the document. Console output is unchanged."""
    import contextlib, csv, io
    fmt, jfile = getattr(a, "format", "console"), getattr(a, "json", None)
    if fmt == "console" and not jfile:
        return fn(a)
    RESULT.clear()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(a)
    stats = RESULT.get("statistics")
    rows = [dict(zip(RESULT_KEYS, r)) for r in RESULT.get("RESULT BY CVE", [])]
    earlier = [dict(zip(RESULT_KEYS, r)) for r in RESULT.get(EARLIER_TITLE, [])]
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    doc = {"schema": "lattice-scan-result/1", "tool": f"lattice-scan {__version__}", "command": a.c or "scan", "on": TODAY,
           "window": "all" if stats else getattr(a, "period", None), "exitCode": rc, "counts": counts, "rows": rows, "earlier": earlier}
    if stats:
        doc["statistics"] = stats
    if RESULT.get("change"):
        doc["change"] = RESULT["change"]
    if jfile:
        write_private(Path(jfile), json.dumps(doc, indent=1))   # names this host's software: mode 0600
    if fmt == "json":
        print(json.dumps(doc, indent=1))
    elif fmt == "csv":
        out = io.StringIO()
        w = csv.writer(out, lineterminator="\n")
        if stats:   # statistics only: verdict, year, count (a year of "-" is the total for the verdict)
            w.writerow(["verdict", "year", "count"])
            for k, v in stats["byVerdict"].items():
                w.writerow([k, "-", v])
            for y, d in stats["byYear"].items():
                for k, v in d.items():
                    w.writerow([k, y, v])
            sys.stdout.write(out.getvalue()); return rc
        w.writerow(RESULT_KEYS)
        for r in rows + earlier:
            w.writerow([report._cell(r[k]) for k in RESULT_KEYS])
        sys.stdout.write(out.getvalue())
    else:
        sys.stdout.write(buf.getvalue())
    return rc


def fail_on_exit(mode: str, imps: list[dict]) -> int:
    """Exit 1 when --fail-on asks for it: `candidate` for any candidate the run found (or still has open), `in-range` only when the version check puts the installed
    version inside an affected range. The default `never` keeps the old behaviour: a person reads the result."""
    if mode == "candidate" and imps:
        return 1
    if mode == "in-range" and any(((i.get("versionCheck") or {}).get("verdict") == "in-range") for i in imps):
        return 1
    if mode == "exposed" and any(((i.get("versionCheck") or {}).get("verdict") == "in-range") and (i.get("exposure") or {}).get("class") == "all" for i in imps):
        return 1
    return 0


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
    if a.refresh and a.inventory and not ids and not a.discover:
        # Inventory only (--refresh --inventory): collect again now, show it, log it. No Lattice call, nothing leaves the machine.
        inv = inventory()
        refresh_inventory(inv, full=a.list)
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
        show_inventory(inv, full=a.list)
    write_private(inv_f, json.dumps(inv, indent=1, sort_keys=True))
    dbg(f"run: today={TODAY} window={WINDOW}d floor={floor} url={URL} key={'set' if KEY else 'none'} ids={len(set(ids))} discover={a.discover} again={a.again} records={OUT}")
    lat = Lattice()
    known = {e["ref"] for e in events()}
    hits, again_hits, read, not_listed = [], [], 0, []
    bare: list[str] = []   # named ids for which the graph has only a stub node (no NVD record, no description, EPSS, SSVC, weakness or links)
    unlisted_ctx: list[tuple[str, dict]] = []   # named ids CISA does not list, with what Lattice holds on them
    rows: list[list[str]] = []   # the result table, one row per CVE (columns in the report.table call below)
    try:
        lat.start()
        if a.discover:
            progress(f"[host] discovering exploited CVEs added since {floor} (needs a key) ...")
            ids += discover(lat, floor)
            progress(f"[host] discovery found {len(set(ids))} id(s) to read")
            dbg(f"discover: {len(set(ids))} exploited ids to read")
        order_ids = list(dict.fromkeys(ids)) if getattr(a, "keep_order", False) else sorted(set(ids))   # recent passes its ids most urgent first
        lat.hint([c for c in order_ids if not (c in seen and c not in named and not (a.again or a.refresh))])   # the ids that will really be read
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
                if cve in named and lat.last_unlisted:
                    ctx = context(lat, lat.last_unlisted)
                    if ctx:
                        unlisted_ctx.append((cve, ctx))
                        rows[-1][-2:] = unlisted_summary(ctx, inv)   # the table row says what the detail below found, not only "unlisted"
                elif cve in named:
                    bare.append(cve)   # Lattice holds no NVD record for it: say that, and fall back on namiq.io's list
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
                imp = with_exposure(impact(e, inv, m[1], m[2]), m[1], inv)
                add_context(lat, e, imp, None if a.refresh else state()[cve].get("impact"))
                if a.refresh or not state()[cve].get("impact"):
                    append("findings.jsonl", {"event": "impact", "ref": cve, "on": TODAY, "impact": imp})
                again_hits.append((e, m[0], imp))
            if m and cve not in known:
                why, installed, vers = m
                imp = with_exposure(impact(e, inv, installed, vers), installed, inv)
                add_context(lat, e, imp)
                dbg(f"{cve}: IMPACT {json.dumps(imp)}")
                if append_found_once({"event": "found", "ref": cve, "on": TODAY, "listed": e["added"], "due": e["due"], "title": e["title"], "why": why, "kind": "kev", "vendor": e["vendor"], "product": e["product"], "ransomware": e["ransomware"], "cvss": e["cvss"], "impact": imp}):
                    hits.append((e, why, imp))
                else:   # another run recorded it a moment ago
                    again_hits.append((e, why, imp))
            seen.add(cve)
    except LatticeError as err:
        write_private(seen_f, json.dumps(sorted(seen)))
        scanlog(f"STOPPED after {read} read, {len(hits)} candidates: {err}")
        print(f"stopped: {err}", file=sys.stderr)
        return 3   # stopped part-way is 3 in every command; 1 is kept for a --fail-on match
    write_private(seen_f, json.dumps(sorted(seen)))
    append("runs.jsonl", {"on": TODAY, "read": read, "candidates": len(hits), "inventory": inv["hash"], "restartRequired": inv["restartRequired"]})
    scanlog(f"ok key={'yes' if KEY else 'no'} inventory={inv['hash']} read={read} candidates={len(hits)} already-recorded={len(again_hits)}"
            + "".join(f" [{e['cve']}: {why}]" for e, why, imp in hits) + (f" not-listed={','.join(not_listed)}" if not_listed else "")
            + (" restart-required" if inv["restartRequired"] else ""))
    print(f"host scan {TODAY}: {read} exploited entries read, {len(hits)} candidates (a person must read each against the installed version)")
    withdrawn = recheck_open(inv)   # an open finding from an older, looser matcher is withdrawn, not kept open for ever
    rows += getattr(a, "extra_rows", [])   # `recent`: the feed's ids that were ruled out on this host and never sent to Lattice
    earlier, earlier_rows = earlier_findings({r[0] for r in rows})   # open findings not read in this run: their saved detail is printed below, from the file, with no call
    print_table(rows)
    print_table(earlier_rows, EARLIER_TITLE)
    print_withdrawn(withdrawn)
    from . import exposure as _exp
    if getattr(a, "exposed", False):
        keep = [h for h in hits if (h[2].get("exposure") or {}).get("class") in _exp.EXPOSED]
        keep_again = [h for h in again_hits if (h[2].get("exposure") or {}).get("class") in _exp.EXPOSED]
        dropped = len(hits) - len(keep) + len(again_hits) - len(keep_again)
        hits, again_hits = keep, keep_again
        print(f"--exposed: {dropped} candidate(s) not listed because their package owns no listener and runs no service here (they are still recorded)")
    hits.sort(key=lambda h: (PRIORITY_RANK.get((h[2].get("priority") or {}).get("level", "read"), 2), _exp.sort_key(h[2].get("exposure"))))   # fix first, then fix soon, then read; then the more exposed; ties keep the id order
    for e, why, imp in hits:
        print(f"  {e['cve']}  {e['title'][:70]}\n      because: {why}")
        print_impact(imp)
    for e, why, imp in again_hits:
        print(f"  {e['cve']}  matches again ({why}); already recorded as {state()[e['cve']]['status']}, not counted as new")
        print_impact(imp)
    print_earlier(earlier)
    for block in getattr(a, "extra_detail", []):
        print(block)
    if not_listed:
        print(f"not in the graph's CISA list (not 'safe', only 'not listed in this snapshot'): {', '.join(not_listed)}")
    if bare:
        print_bare(bare, inv)
    for cve, ctx in unlisted_ctx:
        print(f"  {cve}  not CISA-listed (that is not the same as safe or unexploited); what Lattice holds on it:")
        print_context({"context": ctx})
        if ctx.get("description"):
            print_leads(ctx["description"], inv)
    if inv["restartRequired"]:
        print("restart required: an installed update is waiting for a reboot")
    detail_files(inv)
    from . import exposure as _e2
    cov = _e2.coverage(posture_data())
    if not cov["read"]:
        print("COVERAGE: the running layer (listeners, services) could not be read, so no exposure label was given.")
    elif cov["deep"]:
        print(f"COVERAGE: {cov['unownedProcesses']} running program(s) and {cov['unownedPersistence']} persistence entr(ies) belong to no package; they cannot be matched by name and are not checked here (see posture --deep).")
    else:
        print("COVERAGE: listeners and services were read; running programs and persistence entries that no package owns were not (they cannot be matched by name; posture --deep lists them)."
              + ("" if cov["firewallRead"] else " Firewall rules were not read: needs root."))
    snapshot_report(posture_data(), inv["hash"])
    return fail_on_exit(getattr(a, "fail_on", "never"), [imp for _, _, imp in hits + again_hits])


PROJECT_EPILOG = """\
who can do what:
  with a key (LATTICE_API_KEY) whose email is confirmed:   --kev-catalogue FILE, any number of ids
  without a key:                                          only the CVEs you name, comma separated:  --cve CVE-2026-46300,CVE-2021-44228

examples:
  lattice-scan project . --kev-catalogue known_exploited_vulnerabilities.json                  # needs a confirmed key
  lattice-scan project . --cve CVE-2026-46300,CVE-2021-44228                                    # works without a key
  lattice-scan project . --discover                                                             # no ids, no key: recent exploited CVEs (monthly); --weekly, --daily, --open narrow it
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


_PID_ECO = {"pypi": "pypi", "npm": "npm", "maven": "maven", "cargo": "cargo", "image": "docker", "apt": "deb"}   # manifests' names to lattice_version's


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
    discover = bool(a.discover or a.period)
    if not ids and not a.kev_catalogue and not discover:
        print("nothing to check: add --discover to check against the recent exploited list (no key needed), or name CVEs with --cve CVE-A,CVE-B (or --cve-file), "
              "or give --kev-catalogue FILE (needs a key with a confirmed email)", file=sys.stderr)
        return 2
    if a.kev_catalogue and not KEY:
        print(f"no key: {NEEDS_KEY}", file=sys.stderr)
        return 2
    if a.max_read is None:
        a.max_read = 200 if KEY else 20
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
    if discover:
        window = a.period or "monthly"
        progress(f"[project] --discover: reading the {window} list of recent exploited CVEs from {FEED_URL} (a plain request: nothing from your project is sent) ...")
        try:
            feed = read_feed("all" if window == "monthly" else window)   # the feed's whole list is the last thirty days, which is the monthly window
        except LatticeError as err:
            print(f"stopped: {err}", file=sys.stderr)
            return 3
        known = {e["cve"] for e in catalogue}
        catalogue += [{"cve": r["id"], "vendor": r.get("vendor", ""), "product": r.get("product", ""), "title": ""} for r in feed["exploited"] if r["id"] not in known]
        progress(f"[project] --discover: {len(feed['exploited'])} exploited CVE(s) in the {window} list; only those whose product a dependency here matches are read from Lattice")
    entries: dict[str, dict | None] = {}   # one read per id for the whole run, however many folders match it: the keyless day is 60 reads
    for root_s in a.paths:
        root = Path(root_s).resolve()
        if not root.is_dir():
            print(f"not a folder: {root_s}", file=sys.stderr)
            return 2
        progress(f"[project] {root.name or root}: looking for dependency files under {root}")
        manifests.SKIPPED.clear()
        comps, files, cut = manifests.read_project(root, on_file=_file_progress)
        for note in manifests.SKIPPED:
            print(f"[project] {root.name or root}: skipped {clean(note)}", file=sys.stderr)
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
        lat.hint([c for c in todo if c not in entries])
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
                                     "verdict": vc_one["verdict"], "why": vc_one["why"], "pid": lv.pid(c.name, _PID_ECO.get(c.ecosystem, "generic"))})
            # The finding's own verdict is the most pressing of its components': a lead (undetermined) must never hide a pinned version that is outside, or the other way round.
            vc = min(verdicts, key=lambda v: lv.VERDICT_RANK[v["verdict"]])     # a lead ranks below every real comparison (lattice_version.VERDICTS)
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
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": user_agent()})
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


WINDOW_TO_PERIOD = {"daily": "daily", "weekly": "weekly", "monthly": "all", "open": "open"}   # the feed's own name for the thirty-day list is "all"


def read_feed(period: str = "weekly") -> dict:
    """namiq.io's list of recent exploited and critical CVE ids for one period (daily, weekly or open). Only well-formed rows are kept; every text is cleaned: it is data, never instructions.

    The list's schema is lattice-recent/N. Version 2 has daily and weekly; version 3 adds open. A later version that only adds fields still reads: what this needs is
    checked, not the number, so a feed that grows does not stop every installed tool. Version 1, or a list without the period asked for, is refused with a request to upgrade.
    """
    d = fetch_json(FEED_URL, "the recent-CVE list")
    m = re.fullmatch(r"lattice-recent/(\d+)", str(d.get("schema")))
    if not m or int(m.group(1)) < 2:
        raise LatticeError(f"the recent-CVE list has schema {clean(str(d.get('schema')))!r}; this lattice-scan reads lattice-recent/2 and later. Upgrade lattice-scan.")
    names = ["weekly", "open"] if period == "all" else [period]   # "all": everything in the list. daily is inside weekly, so it adds nothing
    parts = [d.get(n) for n in names if isinstance(d.get(n), dict)]
    if not parts or (period != "all" and len(parts) != 1):
        raise LatticeError(f"the recent-CVE list (schema {clean(str(d.get('schema')))}) has no {period} list: upgrade lattice-scan, or ask for daily or weekly")

    def rows(key: str) -> list[dict]:
        out, seen = [], set()
        for p in parts:
            for r in p.get(key) or []:
                if isinstance(r, dict) and isinstance(r.get("id"), str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", r["id"]) and r["id"] not in seen:
                    seen.add(r["id"])
                    out.append({k: clean(str(v)) if isinstance(v, str) else v for k, v in r.items() if isinstance(v, (str, int, float, bool)) or v is None})
        return out
    froms = sorted(str(p.get("from", "")) for p in parts if p.get("from"))
    tos = sorted(str(p.get("to", "")) for p in parts if p.get("to"))
    return {"asOf": clean(str(d.get("exploitedAsOf", ""))), "builtAt": clean(str(d.get("builtAt", ""))), "period": period,
            "from": clean(froms[0] if froms else ""), "to": clean(tos[-1] if tos else ""), "exploited": rows("exploited"), "critical": rows("critical")}


def feed_cells(r: dict) -> list[str]:
    """EXPLOIT .. PRODUCT cells from a feed row (what namiq.io says, not what Lattice says)."""
    return ["yes" if "added" in r else "no", cvss_cell(r.get("cvss")), r.get("added") or "-", due_cell(r.get("due", "")), ransom(r.get("ransomware", "")),
            f"{r.get('vendor', '')} {r.get('product', '')}".strip() or "-"]


def refresh_inventory(inv: dict, full: bool = False) -> None:
    """Save the inventory (compared with the previous one in inventory.log) and show it."""
    inv_f = OUT / "inventory.json"
    try:
        prev = json.loads(inv_f.read_text()) if inv_f.exists() else None
    except ValueError:
        prev = None
    inventory_log(inv, prev, refresh=True)
    write_private(inv_f, json.dumps(inv, indent=1, sort_keys=True))
    show_inventory(inv, full=full)


DISTRO_REV = re.compile(r"(ubuntu|deb\d|build\d|\.el\d|\.fc\d|\+dfsg|~)")


def refine(imp: dict | None) -> tuple[str, str] | None:
    """A finer reading of a name match, from what the finding saved: (label, note), or None to keep the plain status. Never closes anything.

    OUTSIDE RANGE  every usable NVD range for the product excludes the installed version
    LIKELY FIXED   the version is inside the upstream range, but it carries a distro revision and its own changelog names the CVE
    VERIFY         the kernel's upstream number is inside the range, but it is a distro or vendor build that may carry the fix under the same number
    """
    if not imp:
        return None
    vc = imp.get("versionCheck") or {}
    inst = " ".join(imp.get("installed") or [])
    if vc.get("verdict") == "outside-range":
        return "OUTSIDE RANGE", "the installed version is outside every NVD range for this product"
    if vc.get("verdict") == "in-range":
        if inst.startswith("kernel "):
            return "VERIFY", "upstream number only: this kernel is a distro or vendor build, check its changelog or the vendor's advisory before treating it as exposed"
        if imp.get("changelogNamesCve") and DISTRO_REV.search(inst):
            return "LIKELY FIXED", "the version is inside the upstream range, but it has a distro revision and the package's own changelog names this CVE; read that line, then record it with: lattice-scan resolve CVE --status fixed --proof \"...\""
    return None


def recheck_open(inv: dict) -> list[dict]:
    """Open findings that the CURRENT matching no longer produces: withdrawn, with the reason recorded. A finding made by an older, looser matcher would otherwise stay open for ever.
    A finding that stored its vendor and product is matched again as it is. An older one stored only its title and reason, so only the one rule that changed is applied to it:
    a product of ordinary words (WEAK) needs its vendor installed, and the vendor is taken as the first word of the title."""
    out = []
    for f in list(state().values()):
        why = f.get("why", "")
        if f["status"] != "open" or f.get("kind", "kev") != "kev" or not why.startswith("product "):
            continue
        reason = ""
        if f.get("product"):
            if not candidate({"cve": f["ref"], "vendor": f.get("vendor", ""), "product": f["product"], "title": f.get("title", "")}, inv):
                reason = f"CISA's {f.get('vendor', '')} {f['product']}".strip() + " no longer matches anything installed under the current matching"
        else:
            m = re.match(r"product (.+?) matches ", why)
            want = set(m.group(1).split()) if m else set()
            first = (re.findall(r"[a-z][a-z0-9]+", f.get("title", "").lower()) or [""])[0]
            seen = set()
            for n in list(inv["packages"]) + list(inv["snaps"]) + list(inv["images"]):
                seen |= stems(n)
            for ref, d in (inv.get("imageDetails") or {}).items():
                seen |= set(image_words(ref, d))
            if want and want <= WEAK and first and first not in seen:
                reason = f"its product is only ordinary words ({' '.join(sorted(want))}) and the vendor ({first}) is not installed: that is no longer a match"
        if reason:
            append("findings.jsonl", {"event": "withdrawn", "ref": f["ref"], "on": TODAY, "proof": reason + " (recorded " + f.get("found", "?") + " as: " + why + ")"})
            out.append({"ref": f["ref"], "title": f.get("title", ""), "found": f.get("found", "?"), "why": why, "reason": reason})
    return out


def print_withdrawn(w: list[dict]) -> None:
    if not w:
        return
    print(f"\nWITHDRAWN: {len(w)} earlier finding(s) the current matching no longer produces (recorded by an older version; not counted as open, `lattice-scan list` still shows them)")
    for f in w:
        print(f"  {f['ref']}  {str(f['title'])[:70]}  [recorded {f['found']}: {f['why']}]\n      why withdrawn: {f['reason']}")


def earlier_findings(listed_now: set[str]) -> tuple[list[dict], list[list[str]]]:
    """Findings still open from earlier runs that this run did not read, and a table row for each (so each is listed once, in its own table)."""
    earlier: list[dict] = []
    rows: list[list[str]] = []
    for f in (f for f in state().values() if f["status"] in ("open", "verified")):
        if f["ref"] not in listed_now:
            earlier.append(f)
            r = refine(f.get("impact")) if f["status"] == "open" else None
            rows.append([f["ref"], "yes" if f.get("kind", "kev") == "kev" else "-", cvss_cell(f.get("cvss")), f.get("listed") or "-", due_cell(f.get("due", "")),
                         ransom(f.get("ransomware", "")), "-", r[0] if r else f["status"].upper(),
                         f"{f.get('why', '')} (recorded {f.get('found', '?')}, not read in this run)"[:240]])
    return earlier, rows


EARLIER_TITLE = "STILL OPEN FROM EARLIER RUNS (recorded before today; not part of today's list and not read in this run)"


def print_earlier(earlier: list[dict]) -> None:
    if earlier:
        print(f"\n{EARLIER_TITLE}\n  {len(earlier)} finding(s); the detail is what was saved when each was recorded, with its ages counted from today")
    for f in earlier:
        print(f"  {f['ref']}  {str(f.get('title', ''))[:70]}  [{f['status']}, recorded {f.get('found', '?')}; not read in this run, so this is the detail saved then]\n      because: {f.get('why', '')}")
        if f.get("impact"):
            print_impact(f["impact"])
        else:
            print("      no impact record (found before the impact check existed, or added by hand)")


def print_bare(ids: list[str], inv: dict) -> None:
    """For a named CVE that the graph holds only as a bare node: say so plainly, then use namiq.io's list of recent CVEs if it has the id (that request carries no id)."""
    rows: dict[str, tuple[str, dict]] = {}
    try:
        for period in ("weekly", "open"):
            f = read_feed(period)
            for kind in ("exploited", "critical"):
                for r in f.get(kind, []):
                    rows.setdefault(r["id"], (kind, r))
    except LatticeError as err:
        dbg(f"bare node: namiq.io list not read: {err}")
    for cve in ids:
        print(f"  {cve}  not CISA-listed (that is not the same as safe or unexploited); Lattice holds only a bare node for it:")
        print("      no NVD record, description, EPSS, CISA SSVC, weakness, ATT&CK link or reference is in the graph for this id yet. The graph snapshot is older than the CVE, or the CVE")
        print("      is not ingested. A bare node says nothing about risk. Ask again after the next graph update.")
        if cve in rows:
            kind, r = rows[cve]
            m = candidate({"cve": cve, "vendor": r.get("vendor", ""), "product": r.get("product", "")}, inv)
            what = f"{r.get('product') or '?'} (vendor {r.get('vendor') or '?'}), " + ("CISA-listed exploited" if kind == "exploited" else "critical, not known to be exploited")
            dates = "; ".join(x for x in (f"listed {r['added']}" if r.get("added") else "", f"published {r['published']}" if r.get("published") else "",
                                          f"CVSS {r['cvss']}" + (f" ({r['cvssSource']})" if r.get("cvssSource") else "") if r.get("cvss") is not None else "") if x)
            print(f"      namiq.io's list of recent CVEs has it: {what}; {dates}.")
            print("      " + (f"something installed may match this product ({m[0]}): read the vendor advisory against the installed version." if m
                              else "nothing installed matches this product by name; read the vendor advisory to be sure."))
        else:
            print("      namiq.io's list of recent CVEs does not have it either. Read the record at https://nvd.nist.gov/vuln/detail/" + cve + " and the vendor advisory.")


def why_not(entry: dict, inv: dict) -> str:
    """Why a CISA entry matched nothing here: the distinctive words of its product, and which of them this machine has."""
    want = words(entry.get("product", "").lower())
    if not want:
        return "its product name has no distinctive word to compare"
    have = set()
    for n in list(inv["packages"]) + list(inv["snaps"]) + list(inv["images"]):
        have |= stems(n)
    for ref, d in (inv.get("imageDetails") or {}).items():
        have |= set(image_words(ref, d))
    have |= {w for v in (inv.get("host") or {}).values() if isinstance(v, str) for w in stems(v)}
    found, missing = sorted(w for w in want if w in have), sorted(w for w in want if w not in have)
    return (f"needs all of: {', '.join(sorted(want))}; this machine has {', '.join(found) if found else 'none of them'}"
            + (f" (missing: {', '.join(missing)})" if found and missing else "") + f" among {len(inv['packages'])} packages, {len(inv['snaps'])} snaps, "
            f"{len(inv['images'])} running images and {len(inv.get('imageDetails') or {})} opened images")


def feed_detail(r: dict, kind: str, inv: dict, reason: str = "") -> str:
    """A detail block for a row that came from the feed only (nothing was sent to Lattice for it): what the feed says, and why it is or is not a match."""
    prod = f"{r.get('vendor', '')} {r.get('product', '')}".strip() or "-"
    out = [f"  {r['id']}  {prod}  [{'CISA-listed exploited, nothing here matches' if kind == 'exploited' else 'critical, not known exploited, may match: watch'}]"]
    bits = []
    if r.get("added"):
        bits.append(f"listed {r['added']}")
    if r.get("due"):
        try:
            left = (dt.date.fromisoformat(r["due"]) - dt.date.fromisoformat(TODAY)).days
            bits.append(f"due {r['due']} (" + (f"overdue by {-left} days" if left < 0 else f"in {left} days" if left else "today") + ")")
        except ValueError:
            bits.append(f"due {r['due']}")
    if r.get("published"):
        bits.append(f"published {r['published']}")
    if r.get("cvss") is not None:
        bits.append(f"CVSS {r['cvss']}" + (f" ({r['cvssSource']})" if r.get("cvssSource") else ""))
    if isinstance(r.get("epss"), (int, float)):
        bits.append(f"EPSS {r['epss']:.3f}")
    if kind == "exploited":
        bits.append("ransomware use: " + ("known" if ransom(r.get("ransomware", "")) == "known" else "not recorded by CISA"))
    if r.get("priority"):
        bits.append(f"namiq.io list priority: {r['priority']}")
    out.append("      " + "; ".join(bits))
    out.append("      " + (f"why it is a watch: {reason}" if kind != "exploited" else "why no match: " + why_not(r, inv)))
    out.append(f"      full detail from Lattice (one id is sent): lattice-scan --cve {r['id']}")
    return "\n".join(out)


def read_order(r: dict) -> tuple:
    """Most urgent first, so a run that is stopped (a limit, a closed laptop) has read the ids that matter most: ransomware use recorded by CISA,
    then a patch date already passed, then the feed's own priority, then the larger EPSS."""
    known = str(r.get("ransomware", "")).lower() == "known"
    prio = {"today": 0, "week": 1, "cycle": 2}.get(str(r.get("priority", "")), 3)
    try:
        epss = -float(r.get("epss") or 0)
    except (TypeError, ValueError):
        epss = 0.0
    return (not known, not r.get("overdue"), prio, epss)


def estimate_line(tag: str, ids: list[str]) -> str:
    """What reading these ids will take, said before the first call: how many calls (a lookup and one detail read each, at most), how many are already
    cached, and how long keyless pacing makes it. A person can stop before it starts."""
    cached = sum(1 for i in ids if read_cache_get("graph_lookup", {"id": i}) is not None)
    new = len(ids) - cached
    calls = new * 2
    when = ""
    if calls and not KEY:
        when = f"; at {pace_calls()} calls a minute that is about {max(1, round(calls / pace_calls()))} minute(s)"
    return (f"{tag} {len(ids)} id(s) to read from Lattice: {cached} already cached, so up to {calls} call(s) (a lookup, then one detail read for each match){when}. "
            f"The most urgent are read first; the server's own limit is reported in each answer.")


def cmd_share(a) -> int:
    """`inventory --share`: the host's important software as one copyable block (see share.py for the format and the rule). Nothing leaves the machine except, unless
    --no-feed, one request for namiq.io's public list, which carries no host data. The block goes to stdout alone; the guidance goes to stderr."""
    from . import posture, share
    private_dir()
    inv = inventory()
    ports: list[dict] = []
    post: dict | None = None
    try:
        post = posture.collect()
        ports = [p for p in (post.get("ports") or []) if isinstance(p, dict)]
    except Exception as err:  # noqa: BLE001 - a host that cannot be read for ports still has an inventory
        dbg(f"share: posture not read: {err}")
    matches, state = {}, "not read (--no-feed)"
    if not a.no_feed:
        try:
            feed = read_feed("all")
            entries = list(feed["exploited"]) + list(feed["critical"])
            matches = share.feed_matches(inv, entries, candidate)
            state = f"read {TODAY} ({len(entries)} entries)"
        except LatticeError as err:
            state = f"not read ({clean(str(err))[:60]}); matches with today's list may be missing"
    block = share.build(inv, ports, post, matches, state, TODAY, __version__, max(10, min(int(a.max_lines), share.MAX_LINES)))
    print(block, end="")
    if a.all:
        out = Path(a.all)
        lines = [f"pkg {n} {v}" for n, v in sorted(inv["packages"].items())] + [f"snap {n} {v}" for n, v in sorted(inv["snaps"].items())] + [f"image {i}" for i in sorted(inv["images"])]
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"[share] every package, snap and image written to {out} (mode 0600); it is not part of the block", file=sys.stderr)
    print("[share] copy everything above, from LATTICE INVENTORY v1 to end, and paste it into My products in the Lattice Analyst (https://lattice.namiq.io/chat). "
          "It names software and versions only: no host name, address, user name or path.", file=sys.stderr)
    if state.startswith("not read"):
        print(f"[share] the CISA list was {state}.", file=sys.stderr)
    return 0


def cmd_recent(a) -> int:
    """Start here when you have no CVE id: read namiq.io's recent exploited and critical ids, rule out locally what this host cannot have, and read only
    the rest from Lattice by exact id. The host's inventory never leaves the machine; the feed request carries no id and no host data."""
    private_dir()
    try:
        progress(f"[recent] reading the {'whole' if a.period == 'all' else a.period} list of recent exploited and critical CVEs from {FEED_URL} ...")
        feed = read_feed(a.period)
    except LatticeError as err:
        print(f"stopped: {err}", file=sys.stderr)
        return 3
    inv = inventory()
    if getattr(a, "refresh", False):   # --refresh: collect again, show it, log it, then run the scan on it
        refresh_inventory(inv, full=getattr(a, "list", False))
    rows: list[list[str]] = []
    look: list[str] = []
    by_id: dict[str, dict] = {}
    details: list[str] = []
    for r in feed["exploited"]:
        entry = {"cve": r["id"], "vendor": r.get("vendor", ""), "product": r.get("product", "")}
        m = candidate(entry, inv)
        progress(f"[recent] {r['id']}  {entry['vendor']} {entry['product']}: " + ("something installed may match, will read it from Lattice" if m else "nothing installed matches, not sent to Lattice"))
        if m:
            look.append(r["id"])
            by_id[r["id"]] = r
        else:
            rows.append([r["id"], *feed_cells(r), "unmatch", "no package, snap, image or kernel matches (not sent to Lattice)"])
            details.append(feed_detail(r, "exploited", inv))
    watch = 0
    if not a.no_critical:
        for r in feed["critical"]:
            m = candidate({"cve": r["id"], "vendor": r.get("vendor", ""), "product": r.get("product", "")}, inv)
            if m:
                watch += 1
                rows.append([r["id"], "no", cvss_cell(r.get("cvss")), "-", "-", "-", f"{r.get('vendor', '')} {r.get('product', '')}".strip() or "-", "WATCH",
                             f"critical, not known exploited: {m[0]}"])
                details.append(feed_detail(r, "critical", inv, m[0]))
    progress(f"[recent] {'whole' if a.period == 'all' else a.period} list {feed['from'] or '?'} to {feed['to'] or '?'}: {len(feed['exploited'])} exploited and {len(feed['critical'])} critical ids (CISA catalogue as of {feed['asOf'] or '?'}); "
             f"{len(look)} exploited may match this host, {watch} critical may match")
    a.inv, a.extra_rows, a.extra_detail = inv, rows, details
    look.sort(key=lambda i: read_order(by_id[i]))
    cap = a.max_read if a.max_read is not None else (200 if KEY else 20)   # the one read cap for every command (AD-3): reads from Lattice, not ids matched here
    unread = look[cap:]
    look = look[:cap]
    for cve in unread:
        rows.append([cve, *feed_cells(by_id[cve]), "skipped", f"may match; not read: over --max-read {cap} (run again with --max-read, or name it with --cve)"])
    if look:
        progress(estimate_line("[recent]", look))
    considered = len(feed["exploited"])
    crit = 0 if a.no_critical else len(feed["critical"])
    head = (f"recent {TODAY} ({getattr(a, 'window_name', None) or a.period}, {feed['from'] or '?'} to {feed['to'] or '?'}): {len(feed['exploited'])} exploited and {len(feed['critical'])} critical CVEs read from namiq.io "
            f"(as of {feed['asOf'] or '?'}). Checked against this host's software: exploited {considered - len(look) - len(unread)} ruled out, {len(look) + len(unread)} may match; "
            + (f"critical {crit - watch} ruled out, {watch} may match" if not a.no_critical else "critical not checked (--no-critical)") + ".")
    if unread:
        head += f" {len(unread)} may match but were not read (--max-read {cap}); they are listed as skipped."
    if look:
        print(head)
        a.cve, a.cve_file, a.discover, a.refresh, a.again = look, None, False, False, False
        a.keep_order = True
        return cmd_run(a)
    print(head + " None of the exploited ones match this host's installed software, so nothing was sent to Lattice.")
    withdrawn = recheck_open(inv)
    earlier, earlier_rows = earlier_findings({r[0] for r in rows})   # the findings still open from earlier runs belong in every scan, whether or not today's list matched anything
    print_table(rows)
    print_table(earlier_rows, EARLIER_TITLE)
    print_withdrawn(withdrawn)
    for block in details:
        print(block)
    print_earlier(earlier)
    print("That is not the same as safe: the list holds only what was recently added. To check a CVE you know of, run: lattice-scan --cve CVE-YYYY-NNNN")
    return 0


def confirm_send(a, heading: str, lines: list[str], note: str) -> bool:
    """Show exactly what will be sent and ask. On stderr, so it is seen even when the result goes to a file or `--format json`. `--yes` skips the question (scripts);
    with no terminal and no --yes nothing is sent."""
    print(heading, file=sys.stderr)
    for l in lines:
        print("  " + l, file=sys.stderr)
    print(note, file=sys.stderr)
    if getattr(a, "yes", False):
        return True
    if not sys.stdin.isatty():
        print("Nothing was sent: there is no terminal to ask on. Add --yes to send without asking.", file=sys.stderr)
        return False
    try:
        ans = input("Send these? [y/N] ")
    except EOFError:
        ans = ""
    if ans.strip().lower() not in ("y", "yes"):
        print("Nothing was sent.", file=sys.stderr)
        return False
    return True


VERDICT_ORDER = {"in-range": 0, "undetermined": 1, "outside-range": 2}


def cmd_all(a) -> int:
    """`--discover --all`: the old software the recent list cannot cover. The items that matter on this machine (what listens or runs, well-known server software, the
    kernel) are shown, confirmed, and sent one at a time to Lattice, which answers from its graph. The exposure label is joined here, from this machine's own listeners."""
    from . import exposure, items
    private_dir()
    inv = inventory()
    post = posture_data()
    level = "quick" if (not KEY or getattr(a, "quick", False)) else "key"
    limit = getattr(a, "max_items", None) or (QUICK_ITEMS if level == "quick" else KEY_ITEMS)
    sel = items.select(inv, post, level=level, also=tuple(getattr(a, "also", None) or ()), limit=limit)
    its = sel["items"]
    if not its:
        print("Nothing to check: no operating system, kernel or listening software was found.", file=sys.stderr)
        return 0
    lines = [f"{items.describe(it):<64} ({sel['why'].get(items.describe(it), '')})" for it in its]
    if sel["cut"]:
        lines.append(f"... {sel['cut']} more were left out by the limit of {limit} items")
    who = ("level 1, quick (no key): this machine, its images' operating systems and what listens or runs here" if level == "quick" else
           "level 2 (your key): the quick items, then foundational packages, well-known server software and the other packages, until your allowance ends")
    note = (f"{who}. {len(its)} item(s), one request each, {len(its)} unit(s) of your allowance. Sent: only the fields shown. Never sent: host name, addresses, ports, paths, user names, "
            "or the package list as a whole. The server keeps no record of who asked and counts each item anonymously for statistics.")
    if not confirm_send(a, "[all] these items will be sent to lattice.namiq.io, one at a time:", lines, note):
        return 2
    lat = Lattice()
    lat.rate_budget = RATE_WAIT_BUDGET          # a minute limit is waited out at most 5 times in a run: five times the limit in all
    rows: list[dict] = []
    nores = 0
    stopped = ""
    done = 0
    for n, it in enumerate(its, 1):
        progress(f"[item {n}/{len(its)}] {items.describe(it)}")
        try:
            ans = lat.call("graph_affects", **it)
        except LatticeError as err:
            stopped = clean(str(err))
            break
        done += 1
        res = [r for r in (ans.get("results") or []) if isinstance(r, dict)]
        if not res:
            nores += 1
        name = it["product"]
        label = exposure.label([f"{name} {it.get('version', '')}".strip()] if it.get("kind") != "kernel" else ["kernel " + it.get("version", "")], inv["packages"], post)
        for r in res:
            rows.append({"cve": str(r.get("cve")), "item": it, "verdict": str(r.get("verdict")), "why": str(r.get("why") or ""), "r": r, "exposure": label})
    if getattr(a, "exposed", False):
        kept = [x for x in rows if x["exposure"]["class"] in exposure.EXPOSED]
        hidden = len(rows) - len(kept)
        rows = kept
    else:
        hidden = 0
    rows.sort(key=lambda x: (VERDICT_ORDER.get(x["verdict"], 9), exposure.sort_key(x["exposure"]), str(x["r"].get("due") or "9999"), x["cve"]))
    table = [[x["cve"], "yes", "-", str(x["r"].get("added") or "-"), due_cell(str(x["r"].get("due") or "")), ransom(str(x["r"].get("ransomware") or "")),
              f"{x['r'].get('vendor') or '-'} {x['r'].get('product') or '-'}".strip(), x["verdict"],
              clean(f"{items.describe(x['item'])}: {x['why']}; {x['exposure']['text']}")] for x in rows]
    print(f"all {TODAY}: {done} of {len(its)} item(s) checked one at a time by Lattice; {len(rows)} lead(s), {nores} item(s) with no exploited CVE listed (that is not the same as safe).")
    print_table(table)
    if hidden:
        print(f"--exposed: {hidden} lead(s) for software with no listener or service were counted, not listed.")
    if sel["skipped"]:
        print(f"{sel['skipped']} name(s) did not fit the plain-name rule and were not sent.")
    left_host = sel["unscanned"]["host"] + sum(1 for it in its[done:] if "kind" not in it)
    print(f"Not scanned: {left_host} package(s) on this host and {sel['unscanned']['images']} package(s) inside images (an image's operating system is checked, its packages are not). "
          + ("With a key the scan goes further: `lattice-scan get-key`. " if level == "quick" else "")
          + "Checking every package in depth is the paid report, which is not on sale yet.")
    print("A lead is for a person to read: names are matched and versions compared as upstream numbers; a distribution can fix a CVE under an unchanged version number.")
    if stopped:
        left = len(its) - done
        print(f"stopped: {stopped}\n{left} item(s) were not sent. " + ("Without a key the allowance is small; `lattice-scan get-key` gives a larger one." if not KEY else "Your allowance for now is used up; the rest is not scanned."), file=sys.stderr)
        return 3
    imps = [{"versionCheck": {"verdict": x["verdict"]}, "exposure": x["exposure"]} for x in rows if x["verdict"] != "outside-range"]
    return fail_on_exit(getattr(a, "fail_on", "never"), imps)


def attack_techniques(a, d: dict) -> int:
    """`posture --attack`: each distinct signal code is shown, confirmed, and sent one at a time to Lattice, which names the ATT&CK techniques it may point to.
    A signal is a fixed code (for example ssh.password-auth), never the setting, port or path behind it."""
    from . import items
    codes = items.signals(d)
    if not codes:
        progress("[posture] no signals to explain")
        return 0
    if not confirm_send(a, "[posture] these signal codes will be sent to lattice.namiq.io, one at a time:", [f"signal={c}" for c in codes],
                        f"{len(codes)} request(s). A code is a fixed label, not your setting; no host name, address, port or path is sent. Each is counted anonymously."):
        return 2
    lat = Lattice()
    found: dict[str, list[str]] = {}
    for n, c in enumerate(codes, 1):
        progress(f"[signal {n}/{len(codes)}] {c}")
        try:
            ans = lat.call("graph_exposure", signal=c)
        except LatticeError as err:
            print(f"stopped: {clean(str(err))}\nThe techniques below are partial.", file=sys.stderr)
            for o in d["observations"]:
                o["techniques"] = found.get(o.get("code", ""), [])
            return 3
        found[c] = [str(r["technique"]) for r in (ans.get("results") or []) if isinstance(r, dict) and r.get("technique")]
    for o in d["observations"]:
        o["techniques"] = found.get(o.get("code", ""), [])
    return 0


WITHDRAWN_FEATURES = {
    "project-all": "`project --discover --all` is not available in this version. Dependency names of a project can be private, so they are not sent to be checked; "
                   "name the ids to look up with `project FOLDER --cve CVE-...`. Nothing was sent.",
}


def feature_withdrawn(which: str) -> int:
    print(WITHDRAWN_FEATURES[which], file=sys.stderr)
    return 2


def cmd_posture(a) -> int:
    """What this host exposes and runs: listening ports, firewall, SSH settings, services and (--deep) processes no package owns. Read only; nothing is sent anywhere."""
    from lattice_scan import posture
    deep = getattr(a, "posture_deep", False) or getattr(a, "deep", False)
    who = "root" if os.geteuid() == 0 else f"a normal user (uid {os.geteuid()})"
    progress(f"[posture] {'deep' if deep else 'quick'} scan as {who}: ports, firewall, ssh, services" + (", processes, persistence points" if deep else "")
             + ("" if os.geteuid() == 0 else "; what needs root will be listed, not guessed"))
    d = posture.collect(deep=deep)
    rc = 0
    if getattr(a, "attack", False):
        rc = attack_techniques(a, d)
    progress(f"[posture] done: {len(d['ports'])} listening ports, {len(d['observations'])} signals for a person to read")
    text = posture.dump(d)
    if a.json:
        try:
            write_private(Path(a.json), text)
        except OSError as err:
            print(f"cannot write {a.json}: {err}", file=sys.stderr)
            return 2
    print(text if a.format == "json" else posture.render(d))
    if getattr(a, "since", None) == "last" and a.format != "json":
        private_dir()
        snapshot_report(d, "posture")
    return rc


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
        lat.hint(todo)
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
        print(f"{len(unread)} id(s) not read: " + (f"keyless access has a small allowance (the server states it in each answer). Run it again later (answers already read are kept for a few hours and cost nothing), or ask the person for a key: lattice-scan get-key --help" if not KEY else "run again later"))
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
        req = urllib.request.Request(KEY_API, json.dumps(body).encode(), {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": user_agent()})
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


def age_text(listed: str, due: str) -> str:
    """' (N days ago), due DATE, overdue by N days', counted from today at the moment of printing: a saved finding must not show the ages of the day it was recorded."""
    day = dt.date.fromisoformat(TODAY)
    out = ""
    try:
        out += f" ({(day - dt.date.fromisoformat(listed)).days} days ago)"
    except ValueError:
        pass
    try:
        left = (dt.date.fromisoformat(due) - day).days
        out += f", due {due}, " + (f"overdue by {-left} days" if left < 0 else f"due in {left} days" if left else "due today")
    except ValueError:
        out += f", due {due or '-'}"
    return out


def print_impact(imp: dict) -> None:
    print(f"      installed: {'; '.join(imp['installed'])}")
    if imp.get("exposure"):
        print(f"      exposure: {imp['exposure']['text']}")
    print(f"      listed {imp.get('listed') or '-'}" + age_text(imp.get("listed") or "", imp.get("due") or ""))
    if imp.get("nvdAlsoNames"):
        print(f"      NVD also lists names found here: {', '.join(imp['nvdAlsoNames'])}")
    if imp.get("action"):
        print(f"      CISA required action: {imp['action'][:200]}")
    vc = imp.get("versionCheck")
    if vc:
        print(f"      version check: {vc['verdict']}: {vc['why']}")
    fine = refine(imp)
    if fine:
        print(f"      assessment: {fine[0].lower()}: {fine[1]}")
        if vc["verdict"] == "in-range":
            print("      (upstream numbers only: a distro can fix this under the same number, see the changelog line)")
    cl = imp.get("changelogNamesCve")
    print("      changelog names this CVE: " + (", ".join(cl) if cl else "no installed package's changelog does (or none is readable here)"))
    print_context(imp)


STOP_LEADS = set("""linux server client system windows version before after between affected allows allow when without which where there their other using used file files user
users string password passwords account accounts access attack attacker attackers remote local possible certain through under into this that with from have been does lack lacks
workaround misinterpretation related some configurations intended whether hash libc library package packages default configuration authentication function value values characters character bytes strings numbers length data name names""".split())


def installed_leads(text: str, inv: dict) -> dict:
    """Words of a CVE description that are also the name of something installed, on the host and in each opened image. A lead for a person, not a match:
    it uses the description only, which NVD may not have tied to products yet."""
    want = {w for w in words(text) if len(w) >= 4 and w not in STOP_LEADS}
    host: dict[str, list[str]] = {}
    for n, v in sorted(inv["packages"].items()):
        for w in stems(n) & want:
            host.setdefault(w, []).append(f"{n} {v}")
    for n, v in inv["snaps"].items():
        for w in stems(n) & want:
            host.setdefault(w, []).append(f"snap {n} {v}")
    images: dict[str, list[str]] = {}
    for ref, d in sorted((inv.get("imageDetails") or {}).items()):
        for w in set(image_words(ref, d)) & want:
            images.setdefault(w, []).append(ref)
    leads = sorted(set(host) | set(images))
    opened = sorted((inv.get("imageDetails") or {}))
    both = [r for r in opened if leads and all(r in images.get(w, []) for w in leads)]
    return {"words": leads, "host": host, "images": images, "allIn": both, "opened": len(opened)}


def unlisted_summary(ctx: dict, inv: dict) -> list[str]:
    """The Result and Matched / compared cells of a named CVE that CISA does not list. 'lead' when the description names something installed
    (a lead for a person, not a match); otherwise 'unlisted' with the usual sentence."""
    plain = ["unlisted", "not in CISA's list in this snapshot (not the same as safe)"]
    text = ctx.get("description") or ""
    lead = installed_leads(text, inv) if text else {"words": []}
    if not lead["words"]:
        return plain
    bits = []
    for w in lead["words"]:
        h, im = lead["host"].get(w, []), lead["images"].get(w, [])
        where = ([f"on the host ({h[0]})"] if h else []) + ([f"in {len(im)} opened image{'s' if len(im) > 1 else ''}"] if im else [])
        bits.append(f"{w} " + " and ".join(where))
    if len(lead["words"]) > 1:
        bits.append(f"{len(lead['allIn'])} opened image(s) have all of {', '.join(lead['words'])}" if lead["allIn"] else f"no opened image has all of {', '.join(lead['words'])}")
    m = re.search(r"\bbefore ([0-9][\w.]*)", text)
    if m:
        bits.append(f"description says before {m.group(1)}")
    return ["lead", "not CISA-listed (not the same as safe); description names: " + "; ".join(bits) + ". A lead, not a match: read the detail below"]


def print_leads(text: str, inv: dict) -> None:
    lead = installed_leads(text, inv)
    if not lead["words"]:
        print("      installed things the description names: none (no word of the description is the name of an installed package, snap or opened image)")
        return
    print("      installed things the description names (a lead for a person to read, not a match; NVD has not tied this CVE to products yet):")
    for w in lead["words"]:
        h, im = lead["host"].get(w, []), lead["images"].get(w, [])
        print(f"        {w}: " + (f"on the host {', '.join(h[:3])}{' ...' if len(h) > 3 else ''}" if h else "not on the host") + "; "
              + (f"in {len(im)} opened image{'s' if len(im) > 1 else ''}: {', '.join(im[:4])}{' ...' if len(im) > 4 else ''}" if im else "in no opened image"))
    if len(lead["words"]) > 1:
        print("      images that have all of " + ", ".join(lead["words"]) + ": " + (", ".join(lead["allIn"]) if lead["allIn"] else f"none of the {lead['opened']} opened") + ".")
    m = re.search(r"\bbefore ([0-9][\w.]*)", text)
    if m:
        print(f"      the description says: before {m.group(1)} (compare it with the installed version yourself)")


def print_context(imp: dict) -> None:
    """The 'why it matters' lines. Server text, shown as data; priority is the tool's reading, not a verdict."""
    ctx, pr = imp.get("context"), imp.get("priority")
    if not ctx:
        return
    if ctx.get("record"):
        r = ctx["record"]
        print(f"      NVD record: status {r['status'] or '-'}, created {r['created'] or '-'}, modified {r['modified'] or '-'}"
              + ("" if r["products"] else "; NVD lists no affected products yet, so no version check is possible"))
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
    real = [f for f in s if f["status"] not in ("not-applicable", "withdrawn")]
    fixed = [f for f in real if f["status"] == "fixed"]
    days = sorted({r["on"] for r in runs})
    gaps = [(dt.date.fromisoformat(f["closed"]) - dt.date.fromisoformat(f["listed"])).days for f in fixed if f.get("listed") and f.get("closed")]
    return {"runs": len(runs), "daysOfRecord": len(days), "firstRun": days[0] if days else None, "lastRun": days[-1] if days else None,
            "newExploitedRead": sum(r["read"] for r in runs), "candidates": len(kev),
            "touchedHost": len([f for f in kev if f["status"] not in ("not-applicable", "withdrawn")]),
            "wrongMatches": len([f for f in s if f["status"] == "not-applicable"]),
            "fixed": len(fixed), "open": len([f for f in real if f["status"] in ("open", "verified")]),
            "medianDaysListedToFixed": statistics.median(gaps) if gaps else None}


def main() -> int:
    p = argparse.ArgumentParser(prog="lattice-scan", description="Check a host against CISA-exploited CVEs through Lattice.")
    p.add_argument("--version", action="version", version=f"lattice-scan {__version__}")
    p.add_argument("--cve", action="append", help="a CVE id to check (repeatable)")
    p.add_argument("--cve-file", help="file of CVE ids, one per line, # comments allowed")
    p.add_argument("--discover", action="store_true", help="find exploited CVEs added in the window and check them against this host; no key needed (default window: weekly)")
    p.add_argument("--daily", dest="period", action="store_const", const="daily", help="with --discover: the last day or two")
    p.add_argument("--weekly", dest="period", action="store_const", const="weekly", help="with --discover: the last seven days (the default)")
    p.add_argument("--monthly", dest="period", action="store_const", const="monthly", help="with --discover: the last thirty days")
    p.add_argument("--open", dest="period", action="store_const", const="open", help="with --discover: exploited CVEs older than a week but within thirty days, overdue first")
    p.add_argument("--all", dest="all_index", action="store_true", help="with --discover: check the older software on this machine. The items that matter (what listens or runs, well-known server software, the kernel) are shown, confirmed, and sent one at a time to Lattice")
    p.add_argument("--yes", action="store_true", help="send what --all or posture --attack shows without asking first (for scripts)")
    p.add_argument("--quick", action="store_true", help="with --discover --all: level 1 only (this machine, image operating systems, what listens or runs), even with a key")
    p.add_argument("--also", action="append", metavar="PACKAGE", help="with --discover --all: also send this installed package (repeatable)")
    p.add_argument("--max-items", type=int, default=None, help="with --discover --all: most items to send (default 25 without a key, 200 with one)")
    p.add_argument("--max-read", type=int, default=None, help="with --discover: most ids to read from Lattice per run (default 20 without a key, 200 with one)")
    p.add_argument("--debug", action="store_true", help="detailed execution log to stderr and debug.log (also LATTICE_SCAN_DEBUG=1)")
    p.add_argument("--keep", action="store_true", help="keep this run's records in the default folder even with no terminal (also LATTICE_SCAN_KEEP=1); without it a terminal-less run with no folder yet uses a temporary one")
    p.add_argument("--inventory", action="store_true", help="with --refresh: only collect and show the inventory, no scan and no network call")
    p.add_argument("--list", action="store_true", help="with --refresh or when the inventory is shown: print every package, snap and image instead of totals")
    p.add_argument("--deep", action="store_true", help="deep inventory: open every local image, not only running ones, and list the Python/Node/Java/Ruby packages inside them (minutes). Default is quick")
    p.add_argument("--refresh", action="store_true", help="collect the inventory again now and print all of it; with ids, also re-read them. Alone it makes no Lattice call")
    p.add_argument("--format", choices=["console", "json", "csv"], default=argparse.SUPPRESS, help="what to print: console (default), json or csv. The result table only; progress stays on stderr")
    p.add_argument("--json", metavar="FILE", default=argparse.SUPPRESS, help="also write the result as JSON to FILE (mode 0600: it names this host's software)")
    p.add_argument("--fail-on", choices=["never", "in-range", "candidate", "exposed"], default="never", help="exit 1 when a candidate or an in-range one is found; exposed: in-range and listening on all interfaces; default never: a person reads it")
    p.add_argument("--exposed", action="store_true", default=argparse.SUPPRESS, help="list only candidates whose package owns a listener or runs as a service; the others are counted, not listed")
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
    pj.add_argument("--discover", action="store_true", help="no CVE ids needed, no key needed: read namiq.io's list of recent exploited CVEs, keep those whose product a dependency here matches, and read only those from Lattice (default window: monthly)")
    pj.add_argument("--daily", dest="period", action="store_const", const="daily", help="with --discover: CVEs added or published in the last day or two")
    pj.add_argument("--weekly", dest="period", action="store_const", const="weekly", help="with --discover: the last seven days")
    pj.add_argument("--monthly", dest="period", action="store_const", const="monthly", help="with --discover: the last thirty days (the default)")
    pj.add_argument("--open", dest="period", action="store_const", const="open", help="with --discover: exploited CVEs older than a week but within thirty days, overdue first")
    pj.add_argument("--all", dest="all_index", action="store_true", help="not available: dependency names can be private, so they are not sent to be checked (use --cve)")
    pj.add_argument("--max-read", type=int, default=None, help="most ids to read from Lattice per run (default 200 with a key, 20 without)")
    pj.add_argument("--format", choices=["console", "csv", "json"], default="console", help="what to print (default console: a report for a person)")
    pj.add_argument("--csv", help="also write the findings as CSV to this file")
    pj.add_argument("--json", help="also write the full result as JSON to this file")
    pj.add_argument("--name", action="append", help="a label for each folder, in order (default: the folder name)")
    pj.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="colour the console report (auto: only on a terminal, never with NO_COLOR)")
    pj.add_argument("--width", type=int, help="console report width in columns (default: the terminal's, between 72 and 160)")
    pj.add_argument("--fail-on", choices=["never", "in-range", "candidate"], default="never", help="exit 1 when a candidate (or an in-range one) is found; default never: a person reads it")
    po = sub.add_parser("posture", help="what this host exposes and runs: listening ports, firewall, SSH settings, services; --deep also processes that no package owns. Read only, nothing is sent")
    po.add_argument("--deep", dest="posture_deep", action="store_true", help="also check every readable process (where its executable is, whether a package owns it, outbound connections of those that none does) and persistence points; about a minute")
    po.add_argument("--attack", action="store_true", help="also name the ATT&CK techniques each signal may point to: the signal codes are shown, confirmed, and sent one at a time to Lattice (a fixed code, never the setting behind it)")
    po.add_argument("--yes", action="store_true", default=argparse.SUPPRESS, help="send the signal codes without asking first (for scripts)")
    po.add_argument("--since", choices=["last"], help="also print what is new, changed or gone since the last stored run (listeners, services, SSH settings, persistence entries, findings); this run is stored for the next comparison")
    po.add_argument("--format", choices=["console", "json"], default="console", help="what to print (default console)")
    po.add_argument("--json", metavar="FILE", help="also write the full result as JSON to FILE (mode 0600; it names this host's processes: do not share it)")
    po.add_argument("--progress", action="store_true", default=argparse.SUPPRESS, help="print each step on stderr (the default)")
    po.add_argument("--quiet", "-q", action="store_true", default=argparse.SUPPRESS, help="print no progress (also LATTICE_SCAN_PROGRESS=0)")
    rc = sub.add_parser("recent", help="start here with no CVE id: read namiq.io's recent exploited and critical CVEs, check what this host could have, read only those from Lattice")
    rc.add_argument("--period", choices=["all", "daily", "weekly", "open"], default="all", help="all: everything in the list, the weekly and the open parts (default); daily: added or published in the last day or two; weekly: the last seven days, which includes daily; open: exploited CVEs added before the weekly window but within 30 days, overdue first (overdue means CISA's due date has passed; it says nothing about any machine)")
    rc.add_argument("--open", dest="period", action="store_const", const="open", help="same as --period open")
    rc.add_argument("--daily", dest="period", action="store_const", const="daily", help="same as --period daily")
    rc.add_argument("--weekly", dest="period", action="store_const", const="weekly", help="same as --period weekly")
    rc.add_argument("--all", dest="period", action="store_const", const="all", help="same as --period all (the default)")
    rc.add_argument("--monthly", dest="period", action="store_const", const="all", help="same as --period all: the whole thirty-day list (what --all has always meant here)")
    rc.add_argument("--max-read", type=int, default=None, help="most ids to read from Lattice per run (default 20 without a key, 200 with one). Every id is still checked against this host locally")
    rc.add_argument("--format", choices=["console", "json", "csv"], default=argparse.SUPPRESS, help="what to print: console (default), json or csv")
    rc.add_argument("--json", metavar="FILE", default=argparse.SUPPRESS, help="also write the result as JSON to FILE (mode 0600)")
    rc.add_argument("--fail-on", choices=["never", "in-range", "candidate", "exposed"], default=argparse.SUPPRESS, help="exit 1 when a candidate (or an in-range one) is found; default never")
    rc.add_argument("--exposed", action="store_true", default=argparse.SUPPRESS, help="list only candidates whose package owns a listener or runs as a service")
    rc.add_argument("--no-critical", action="store_true", help="leave out the critical (not known exploited) ids")
    rc.add_argument("--progress", action="store_true", default=argparse.SUPPRESS, help="print each step on stderr (the default)")
    rc.add_argument("--quiet", "-q", action="store_true", default=argparse.SUPPRESS, help="print no progress (also LATTICE_SCAN_PROGRESS=0)")
    en = sub.add_parser("enrich", help="CVE ids you already have (audit, advisory, ticket): exploited? ransomware? patch due? No comparison with this host")
    en.add_argument("--cve", action="append", help="CVE ids or any text containing them (repeatable)")
    en.add_argument("--file", action="append", help="a file to find CVE ids in; - or a pipe on stdin works too")
    en.add_argument("--max-read", type=int, default=None, help="most ids to read from Lattice (default 200 with a key, 20 without)")
    en.add_argument("--format", choices=["console", "json", "csv"], default=argparse.SUPPRESS, help="what to print: console (default), json or csv")
    en.add_argument("--json", metavar="FILE", default=argparse.SUPPRESS, help="also write the result as JSON to FILE (mode 0600)")
    en.add_argument("--fail-on", choices=["never", "exploited"], default="never", help="exit 1 when any id is exploited (default never)")
    en.add_argument("--progress", action="store_true", default=argparse.SUPPRESS, help="print each step on stderr (the default)")
    en.add_argument("--quiet", "-q", action="store_true", default=argparse.SUPPRESS, help="print no progress (also LATTICE_SCAN_PROGRESS=0)")
    gk = sub.add_parser("get-key", help="request a Lattice key for a real person who has read the terms and gave these details; the key is stored, never printed")
    for flag in ("name", "position", "company", "email", "purpose"):
        gk.add_argument(f"--{flag}", required=True, help=f"the person's {flag}" if flag != "purpose" else "what the key will be used for, one or two sentences (at least 20 characters)")
    gk.add_argument("--accept-terms", action="store_true", help="the person has read the beta terms and agreed, and reads that mailbox (without this nothing is sent)")
    gk.add_argument("--force", action="store_true", help="ask even though a key is already stored")
    sub.add_parser("list"); sub.add_parser("stats")
    il = sub.add_parser("inventory", help="show inventory.log: counts and changes per run; --share prints the important software as one block to paste into the Lattice Analyst")
    il.add_argument("-n", type=int, default=20)
    il.add_argument("--share", action="store_true", help="print a LATTICE INVENTORY v1 block (at most 150 lines): the kernel, what listens, what today's CISA list may concern, images, snaps and server software")
    il.add_argument("--max-lines", type=int, default=150, help="with --share: at most this many lines (default 150, at most 150)")
    il.add_argument("--no-feed", action="store_true", help="with --share: do not read namiq.io's recent list (the block then may miss items the list would have kept)")
    il.add_argument("--all", metavar="FILE", help="with --share: also write every package, snap and image to FILE (private, 0600; never printed)")
    lg = sub.add_parser("log"); lg.add_argument("-n", type=int, default=20, help="last N lines (default 20)")
    a = p.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))  # a stopped run still cleans up (atexit); only SIGKILL cannot, and the next run sweeps what it left
    if getattr(a, "deep", False):
        os.environ["LATTICE_SCAN_LEVEL"] = "deep"
    if getattr(a, "refresh", False):
        os.environ["LATTICE_SCAN_DEEP_CACHE"] = "off"   # --refresh opens every image again, as it says
        os.environ["LATTICE_SCAN_READ_CACHE"] = "off"   # ... and asks Lattice again
    if getattr(a, "again", False):
        os.environ["LATTICE_SCAN_READ_CACHE"] = "off"   # --again reads the id again, from Lattice
    global DEBUG, PROGRESS, KEEP
    DEBUG = a.debug or env("DEBUG") == "1"
    KEEP = a.keep or env("KEEP") == "1"
    # OCO-5837: progress goes to stderr and is on by default; --quiet or LATTICE_SCAN_PROGRESS=0 turns it off. stdout is never touched.
    PROGRESS = not getattr(a, "quiet", False) and (getattr(a, "progress", False) or env("PROGRESS") != "0")
    if a.c is None and not (a.cve or a.cve_file or a.discover or (a.refresh and a.inventory)):
        # Nothing asked for: do what a person or an agent with no CVE id wants, the daily list (lattice-scan recent --daily). Daily, not weekly: the weekly list is
        # long, and a keyless run that has to look many entries up reaches Lattice's limit (about 20 reads an hour).
        a.c, a.period, a.no_critical = "recent", WINDOW_TO_PERIOD.get(a.period or "weekly", "weekly"), False
        progress("[discover] no command and no CVE id given: running lattice-scan --discover --weekly")
        return structured(a, cmd_recent)
    if a.c is None and a.discover and getattr(a, "all_index", False) and not (a.cve or a.cve_file):
        return structured(a, cmd_all)
    if a.c is None and a.discover and not (a.cve or a.cve_file):
        # --discover on the host is the same engine as `recent`: it needs no key (the list is a plain request) and takes the same windows.
        a.window_name = a.period or "weekly"
        a.c, a.period, a.no_critical = "recent", WINDOW_TO_PERIOD.get(a.window_name, "weekly"), False
        return structured(a, cmd_recent)
    if a.c == "project" and getattr(a, "all_index", False):
        return feature_withdrawn("project-all")
    if a.c == "project": return cmd_project(a)
    if a.c == "recent": return structured(a, cmd_recent)
    if a.c == "posture": return cmd_posture(a)
    if a.c == "enrich": return structured(a, cmd_enrich)
    if a.c == "get-key": return cmd_get_key(a)
    if a.c == "impact": return cmd_impact(a)
    if a.c == "resolve": return cmd_resolve(a)
    if a.c == "add": return cmd_add(a)
    if a.c == "inventory" and a.share:
        return cmd_share(a)
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
    return structured(a, cmd_run)


if __name__ == "__main__":
    sys.exit(main())
