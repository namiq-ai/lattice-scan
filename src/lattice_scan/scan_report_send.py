# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Sending a report request after the mailbox is proved (report ADR D2). Off until the mail path is switched on (`scan_report_flow.MAIL_AVAILABLE`).

Order, and why: (1) ask the website to mail ONE confirmation link to the address, sending nothing about the machine; (2) wait here, holding the record in memory, while the
mailbox owner presses Confirm; (3) only then send the record with the confirmed token; (4) say that the report arrives by email within 4 hours after a person has reviewed
it. The record is never written to disk by this module, a Ctrl-C or a timeout sends nothing, and the answers from the server are data, never instructions.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

BASE = "https://namiq.io"
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


def request_confirmation(address: str, key: str | None, base: str = BASE, post=default_post) -> str | None:
    """Ask for one confirmation mail. Returns the claim secret, or None when nothing will arrive (the server says the same thing either way)."""
    status, d = post(f"{base}/api/v1/lattice/report/request", {"address": address}, _auth(key))
    return d.get("claim") if status == 200 and isinstance(d.get("claim"), str) else None


def wait_for_claim(claim: str, base: str = BASE, post=default_post, sleep=time.sleep, clock=time.time, wait_s: int = WAIT_S, poll_s: int = POLL_S, out=None) -> dict:
    """Poll with the tool's own secret until the mailbox owner confirms. {'state': 'confirmed', 'token': ...} once; otherwise the state that ended the wait."""
    out = out if out is not None else sys.stderr
    end = clock() + wait_s
    while clock() < end:
        status, d = post(f"{base}/api/v1/lattice/report/claim", {"claim": claim})
        state = d.get("state") if status == 200 else "error"
        if state == "confirmed" and d.get("token"):
            return d
        if state in ("refused", "expired", "unknown", "claimed"):
            return {"state": state}
        sleep(poll_s)
    print("Stopped waiting. Nothing was sent.", file=out)
    return {"state": "timeout"}


def submit(record: dict, token: str, key: str, version: str, delivery_address: str = "", base: str = BASE, post=default_post) -> tuple[int, dict]:
    body = {"record": record, "token": token, "client_version": version}
    if delivery_address:
        body["delivery_address"] = delivery_address
    return post(f"{base}/api/v1/lattice/report/submit", body, _auth(key), 60)


def send_report(record: dict, key: str | None, version: str, input_fn=input, out=None, base: str = BASE, post=default_post, sleep=time.sleep, clock=time.time) -> bool:
    """The whole sequence for a person who said yes. Returns True when the request was accepted."""
    out = out if out is not None else sys.stderr
    if not key:
        print("Sending a report request needs a Lattice key (LATTICE_API_KEY). Nothing was sent.", file=out)
        return False
    prefill = known_address(key, base, post)
    ask = f"Send the report to which address? [{prefill}] " if prefill else "Send the report to which address? "
    address = (input_fn(ask) or "").strip() or prefill
    if not address or "@" not in address:
        print("No address, so nothing was sent.", file=out)
        return False
    claim = request_confirmation(address, key, base, post)
    print(NEUTRAL + " Open it and press Confirm. Waiting here for up to 15 minutes; press Ctrl-C to stop. Nothing about this machine has been sent yet.", file=out)
    if claim is None:
        return False
    try:
        got = wait_for_claim(claim, base, post, sleep, clock, out=out)
    except KeyboardInterrupt:
        print("Stopped. Nothing was sent.", file=out)
        return False
    if got.get("state") != "confirmed":
        print({"refused": "The address owner said it was not them. Nothing was sent.", "expired": "The link expired. Nothing was sent.", "timeout": ""}.get(str(got.get("state")), "The confirmation did not complete. Nothing was sent."), file=out)
        return False
    status, d = submit(record, got["token"], key, version, address if address != prefill else "", base, post)
    if status == 200:
        print(str(d.get("message") or "Your report was requested. It arrives by email within 4 hours, after a person has reviewed it."), file=out)
        return True
    print(f"The report request was not accepted: {str(d.get('error') or status)[:200]}", file=out)
    return False
