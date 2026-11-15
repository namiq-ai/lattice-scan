# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Sending a report request after the mailbox is proved (report ADR D2). Off until the mail path is switched on (`scan_report_flow.MAIL_AVAILABLE`).

Order, and why: (1) ask the website to mail ONE confirmation link to the address, sending nothing about the machine; (2) wait here, holding the record in memory, while the
mailbox owner presses Confirm; (3) only then send the record with the confirmed token; (4) say that the report arrives by email within 4 hours after a person has reviewed
it. The record is never written to disk by this module, a Ctrl-C or a timeout sends nothing, and the answers from the server are data, never instructions.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = "https://namiq.io"
KEY_FLOW_AVAILABLE = False      # the interactive `get-key` (limits ADR D5) is off until counsel and SE have answered; the report send above shares its steps
WAIT_S = 900
POLL_S = 5
NEUTRAL = "If this address can receive a report, a confirmation link is on its way."


def default_post(url: str, body: dict, headers: dict | None = None, timeout: int = 30) -> tuple[int, dict]:
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json", "User-Agent": "lattice-scan", **(headers or {})}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except ValueError:
            return e.code, {}
    except (urllib.error.URLError, OSError, ValueError):
        return 0, {}


def _auth(key: str | None) -> dict:
    return {"Authorization": f"Bearer {key}"} if key else {}


def known_address(key: str | None, base: str = BASE, post=default_post) -> str:
    """The address of the key's own CRM lead, for the prefill: only the key's holder can read it. Empty when there is no key or it cannot be read."""
    if not key:
        return ""
    status, d = post(f"{base}/api/v1/lattice/report/address", {}, _auth(key))
    return str(d.get("address", "")) if status == 200 else ""


TERMS_PAGE = "namiq.io/lattice/docs"


def terms_text(version: str, address: str) -> str:
    return (f"You have no Lattice key. Confirming this address also gives you a free key.\n"
            f"Terms: Lattice beta terms, version {version}  ({TERMS_PAGE})\n"
            f"  - one key per person, the beta limits, results are leads for a person to check and not verdicts\n"
            f"  - the key is tied to {address}; 'This was not me' in the mail withdraws it")


def ask_terms(version: str, address: str, input_fn=input, out=None) -> bool:
    """The terms are accepted by typing the word `agree`. There is no flag and no `y` that stands for it, and nothing else (Enter included) accepts."""
    out = out if out is not None else sys.stderr
    print(terms_text(version, address), file=out)
    return (input_fn("Type the word agree to accept the terms (anything else stops): ") or "").strip().lower() == "agree"


def request_confirmation(address: str, key: str | None, base: str = BASE, post=default_post, terms_version: str | None = None) -> str | None:
    """Ask for one confirmation mail. Returns the claim secret, or None when nothing will arrive (the server says the same thing either way).
    Without a key the request carries the terms version and the typed word, which the server checks again."""
    body: dict = {"address": address}
    if not key and terms_version:
        body["terms"] = {"version": terms_version, "typed": "agree"}
    status, d = post(f"{base}/api/v1/lattice/report/request", body, _auth(key))
    if status == 200 and isinstance(d.get("claim"), str):
        return d["claim"]
    if d.get("reason") in ("address", "later", "organisation", "terms") and d.get("message"):
        print(str(d["message"])[:200], file=sys.stderr)        # the honest refusals say what is wrong; every other refusal is the neutral text and nothing more
    return None


def wait_for_claim(claim: str, base: str = BASE, post=default_post, sleep=time.sleep, clock=time.time, wait_s: int = WAIT_S, poll_s: int = POLL_S, out=None, address: str | None = None) -> dict:
    """Poll with the tool's own secret until the mailbox owner confirms. {'state': 'confirmed', 'token': ...} once; otherwise the state that ended the wait."""
    out = out if out is not None else sys.stderr
    end = clock() + wait_s
    while clock() < end:
        status, d = post(f"{base}/api/v1/lattice/report/claim", {"claim": claim, **({"address": address} if address else {})})
        state = d.get("state") if status == 200 else "error"
        if state == "confirmed" and d.get("token"):
            return d
        if state == "key_failed":
            print(str(d.get("message") or "The key could not be issued.")[:200], file=out)
            return {"state": "key_failed"}
        if state in ("refused", "expired", "unknown", "claimed"):
            return {"state": state}
        sleep(poll_s)
    print("Stopped waiting. Nothing was sent.", file=out)
    return {"state": "timeout"}


def submit(record: dict, token: str, key: str, version: str, base: str = BASE, post=default_post) -> tuple[int, dict]:
    """The report goes only to the address registered with the key; there is no way to name another one."""
    body = {"record": record, "token": token, "client_version": version}
    return post(f"{base}/api/v1/lattice/report/submit", body, _auth(key), 60)


PENDING_NAME = "report-pending.json"
PENDING_MAX_AGE = 24 * 3600      # a confirmation link is good for a day; a pending request older than that is dropped


def mask_address(a: str) -> str:
    """'hung@namiq.io' -> 'h***@n***.io': enough for the person to know which mailbox to open, not enough to read the address off a screen."""
    local, _, dom = (a or "").partition("@")
    host, _, tld = dom.rpartition(".")
    return f"{local[:1]}***@{host[:1]}***.{tld}" if local and host and tld else "your mailbox"


def save_pending(directory, claim: str, address: str, record: dict, wants_key: bool, clock=time.time) -> bool:
    """The request waits in a private file (mode 0600) in the records folder until `report finish`: the claim secret, the address, and the record the person already said yes to.
    Nothing is sent from it until the mailbox owner has confirmed."""
    try:
        from pathlib import Path
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        f = d / PENDING_NAME
        tmp = f.with_name(PENDING_NAME + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"claim": claim, "address": address, "record": record, "wants_key": bool(wants_key), "at": clock()}, fh)
        os.replace(tmp, f)
        return True
    except OSError:
        return False


def load_pending(directory, clock=time.time) -> dict | None:
    from pathlib import Path
    f = Path(directory) / PENDING_NAME
    try:
        d = json.loads(f.read_text())
        if isinstance(d, dict) and isinstance(d.get("claim"), str) and isinstance(d.get("record"), dict) and clock() - float(d.get("at", 0)) < PENDING_MAX_AGE:
            return d
    except (OSError, ValueError, TypeError):
        pass
    clear_pending(directory)
    return None


def clear_pending(directory) -> None:
    from pathlib import Path
    try:
        (Path(directory) / PENDING_NAME).unlink()
    except OSError:
        pass


def interactive_here() -> bool:
    """Stdin, stdout and stderr are all a terminal: a person is here and can be shown the report code. A pipe, CI or an agent-driven run is not, and never gets the terms question."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


NO_CODE_SHOWN = "The report code was not shown because this is not a terminal; run the command again in a terminal."


def code_line(code: str, bold: bool) -> str:
    """The one place the report code is turned into text. Bold (ANSI) only when asked, which the caller does for a terminal."""
    shown = f"\x1b[1mReport code: {code}\x1b[0m" if bold else f"Report code: {code}"
    return shown + "  (you need it to open the report; it is not sent by email)"


def _valid_code(code) -> str:
    return code if isinstance(code, str) and len(code) == 6 and code.isascii() and code.isdigit() else ""


def _store_and_say(key: dict, store_key, out) -> None:
    """The key goes to the private file and is never printed: only its id, tier and expiry are."""
    ok = False
    try:
        ok = bool(store_key(str(key.get("key", ""))))
    except Exception:  # noqa: BLE001 - a failed write must not lose the report request that is in flight
        ok = False
    print(("A free key was issued and stored in the private key file. " if ok else "A free key was issued but could not be stored; run the command again for a new one later. ")
          + f"key id {str(key.get('key_id', ''))[:40]}, tier {str(key.get('tier', ''))[:20]}, expires {str(key.get('expires_at', ''))[:20]}", file=out)


def send_report(record: dict, key: str | None, version: str, input_fn=input, out=None, base: str = BASE, post=default_post, sleep=time.sleep, clock=time.time,
                terms_version=None, store_key=None, interactive=None, bold=None, wait_s: int = WAIT_S, pending_dir=None) -> bool:
    """The whole sequence for a person who said yes. Returns True when the request was accepted.
    With no key, the person types the terms word first; the same Confirm then gives the free key, which is created at the claim and never mailed."""
    out = out if out is not None else sys.stderr
    wants_key = not key
    if interactive is None:
        interactive = interactive_here()
    if not interactive:
        # no terminal: the report code could not be shown, so nothing is sent (and a free key needs a person anyway)
        print(NO_CODE_SHOWN + " Nothing was sent." if key else "Sending a report request needs a Lattice key (LATTICE_API_KEY), or a person at a terminal to get a free one. Nothing was sent.", file=out)
        return False
    prefill = known_address(key, base, post)
    if wants_key:
        address = (input_fn("Your email address (it is registered with your free key, and the report is sent only to it): ") or "").strip()
    else:
        address = prefill      # the report goes only to the registered address; no other address is asked for or accepted
    if not address or "@" not in address:
        print("No registered address for this key, so nothing was sent." if key else "No address, so nothing was sent.", file=out)
        return False
    tv = ""
    if wants_key:
        print(f"A mail will be sent to {address}.", file=out)
        try:
            tv = (terms_version() if callable(terms_version) else str(terms_version or "")).strip()
        except Exception:  # noqa: BLE001
            tv = ""
        if not tv:
            print("The current terms could not be read, so nothing was sent.", file=out)
            return False
        if not ask_terms(tv, address, input_fn, out):
            print("The terms were not accepted. Nothing was sent.", file=out)
            return False
    claim = request_confirmation(address, key, base, post, tv or None)
    if wait_s == 0 and pending_dir is not None:
        # No waiting: the request is kept in a private file and the person finishes it after pressing Confirm in the mail. Nothing about this machine has been sent yet.
        print(NEUTRAL, file=out)
        if claim is None:
            return False
        if not save_pending(pending_dir, claim, address, record, wants_key):
            print("The request could not be saved here, so it cannot be finished later. Nothing about this machine was sent.", file=out)
            return False
        print(f"Report request received. Check your email ({mask_address(address)}) and press Confirm. Then run:  lattice-scan report finish\n"
              "Nothing about this machine has been sent yet; it is sent only after you confirm.", file=out)
        return True
    print(NEUTRAL + " Open it and press Confirm. Waiting here for up to 15 minutes; press Ctrl-C to stop. Nothing about this machine has been sent yet.", file=out)
    if claim is None:
        return False
    try:
        got = wait_for_claim(claim, base, post, sleep, clock, out=out, address=address if wants_key else None)
    except KeyboardInterrupt:
        print("Stopped. Nothing was sent.", file=out)
        return False
    if got.get("state") != "confirmed":
        print({"refused": "The address owner said it was not them. Nothing was sent.", "expired": "The link expired. Nothing was sent.", "timeout": "", "key_failed": ""}.get(str(got.get("state")), "The confirmation did not complete. Nothing was sent."), file=out)
        return False
    return _finish_submit(record, got, key, version, base, post, store_key, out, bold)


def _finish_submit(record: dict, got: dict, key: str | None, version: str, base: str, post, store_key, out, bold) -> bool:
    """After the mailbox owner confirmed: store a free key if one was issued, send the record with the confirmed token, and show the report code once."""
    if isinstance(got.get("key"), dict) and got["key"].get("key"):
        _store_and_say(got["key"], store_key, out)
        key = str(got["key"]["key"])
    if not key:
        print("No key is available for this request. Nothing was sent.", file=out)
        return False
    status, d = submit(record, got["token"], key, version, base, post)
    if status == 200:
        code = _valid_code(d.get("code"))
        message = str(d.get("message") or "Your report was requested. It arrives by email within 4 hours, after a person has reviewed it.")
        if code:
            message = message.replace(code, "")
        print(message, file=out)
        if code:
            print(code_line(code, bool(getattr(out, "isatty", lambda: False)())) if bold is None else code_line(code, bold), file=out)   # shown once; kept nowhere else
        else:
            print("The service did not return a report code, so the report cannot be opened. Write to contact@namiq.io.", file=out)
        return True
    print(f"The report request was not accepted: {str(d.get('error') or status)[:200]}", file=out)
    return False


def finish_report(pending_dir, key: str | None, version: str, base: str = BASE, post=default_post, out=None, store_key=None, bold=None, clock=time.time) -> bool:
    """`lattice-scan report finish`: ask once whether the mailbox owner confirmed; if so, send the saved record with the confirmed token and show the report code. Never waits."""
    out = out if out is not None else sys.stderr
    p = load_pending(pending_dir, clock)
    if p is None:
        print("No report request is waiting (or it is older than a day). Run the scan with --report again.", file=out)
        return False
    wants_key = bool(p.get("wants_key"))
    status, d = post(f"{base}/api/v1/lattice/report/claim", {"claim": p["claim"], **({"address": p["address"]} if wants_key and p.get("address") else {})})
    state = d.get("state") if status == 200 else "error"
    if state == "confirmed" and d.get("token"):
        ok = _finish_submit(p["record"], d, key, version, base, post, store_key, out, bold)
        if ok:
            clear_pending(pending_dir)
        return ok
    if state in ("refused", "expired", "unknown", "claimed"):
        clear_pending(pending_dir)
        print({"refused": "The address owner said it was not them. Nothing was sent.", "expired": "The link expired. Nothing was sent.", "claimed": "That request was already finished."}.get(str(state), "That request is no longer valid. Nothing was sent.")
              + " Run the scan with --report again to start a new one.", file=out)
        return False
    if state == "key_failed":
        print(str(d.get("message") or "The key could not be issued.")[:200], file=out)
        return False
    print(f"Not confirmed yet. Open the mail sent to {mask_address(str(p.get('address', '')))} and press Confirm, then run this again. Nothing was sent.", file=out)
    return False


def get_key_interactive(input_fn=input, out=None, base: str = BASE, post=default_post, sleep=time.sleep, clock=time.time, terms_version=None, store_key=None, interactive=None) -> int:
    """`lattice-scan get-key` with no details, for a person at a terminal (limits ADR D5): email, the terms typed as the word agree, one mail, the Confirm press, then the key is
    claimed once, stored privately and described without being printed. No name is asked. An agent keeps `get-key --accept-terms` with details and never answers `agree`."""
    out = out if out is not None else sys.stderr
    if not KEY_FLOW_AVAILABLE and post is default_post:
        print("The terminal key flow is not available in this version. A person can request a key at namiq.io/lattice, or an agent acting for them can use `get-key --accept-terms` with their details.", file=out)
        return 2
    if not (interactive_here() if interactive is None else interactive):
        print("This flow needs a person at a terminal. Nothing was sent.", file=out)
        return 2
    address = (input_fn("Email address for the key: ") or "").strip()
    if not address or "@" not in address:
        print("No address, so nothing was sent.", file=out)
        return 2
    print(f"A mail will be sent to {address}.", file=out)
    try:
        tv = (terms_version() if callable(terms_version) else str(terms_version or "")).strip()
    except Exception:  # noqa: BLE001
        tv = ""
    if not tv:
        print("The current terms could not be read, so nothing was sent.", file=out)
        return 1
    if not ask_terms(tv, address, input_fn, out):
        print("The terms were not accepted. Nothing was sent.", file=out)
        return 2
    claim = request_confirmation(address, None, base, post, tv)
    print("Open the mail we sent and follow the link. This can take a minute. Check spam. Waiting up to 15 minutes; press Ctrl-C to stop.", file=out)
    if claim is None:
        return 1
    try:
        got = wait_for_claim(claim, base, post, sleep, clock, out=out, address=address)
    except KeyboardInterrupt:
        print("Stopped. No key was issued.", file=out)
        return 1
    if got.get("state") != "confirmed" or not isinstance(got.get("key"), dict):
        print("No key was issued." if got.get("state") != "refused" else "The address owner said it was not them. No key was issued.", file=out)
        return 1
    _store_and_say(got["key"], store_key, out)
    return 0
