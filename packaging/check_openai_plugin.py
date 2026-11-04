#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Check an OpenAI plugin ZIP against the rules OpenAI publishes, before anyone uploads it.

    python3 packaging/check_openai_plugin.py dist/lattice-scan-openai-plugin-X.Y.Z.zip

This is NOT OpenAI's validator (that one runs inside their portal, or in their Codex 'prepare-plugin-submission' skill, and is not public). It checks what is written down:
  * developers.openai.com/plugins/deploy/submission: the two manifest formats, the listing limits, what a skills-only plugin must not carry, image limits;
  * developers.openai.com/plugins/plugin-guidelines: naming, no credentials;
  * github.com/openai/skills (plugin-creator): the Codex manifest's fields, and that paths are relative and begin with ./ ;
  * agent-plugins.org plugin.schema.json: the portable manifest's allowed keys and name pattern.
It reports each finding as ERROR (the rule says it will be refused) or WARN (a rule is unclear or optional). Exit status 1 when there is an error.
"""
from __future__ import annotations
import json, re, struct, sys, zipfile

PORTABLE_KEYS = {"$schema", "name", "version", "description", "author", "homepage", "repository", "license", "keywords", "extensions"}
IMG = (".png", ".jpg", ".jpeg", ".webp", ".svg")
CODEX_REQUIRED = ("version", "description", "author", "interface")
IFACE_REQUIRED = ("displayName", "shortDescription", "longDescription", "developerName", "category", "websiteURL", "privacyPolicyURL", "termsOfServiceURL")


def png_size(b: bytes):
    return struct.unpack(">II", b[16:24]) if b[:8] == b"\x89PNG\r\n\x1a\n" else None


def check(path: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    err = lambda m: out.append(("ERROR", m))
    warn = lambda m: out.append(("WARN", m))
    z = zipfile.ZipFile(path)
    names = set(z.namelist())
    has_portable, has_codex = "plugin.json" in names, ".codex-plugin/plugin.json" in names
    if not (has_portable or has_codex):
        err("no manifest: need plugin.json (portable) or .codex-plugin/plugin.json (Codex)")
    if not has_codex:
        warn("no .codex-plugin/plugin.json: OpenAI says the portable format is accepted, but the Codex tooling treats the Codex manifest as the required structure")
    portable = json.loads(z.read("plugin.json")) if has_portable else None
    codex = json.loads(z.read(".codex-plugin/plugin.json")) if has_codex else None

    if portable is not None:
        if portable.get("$schema") != "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json":
            err("portable plugin.json: $schema must be https://agent-plugins.org/schemas/1.0.0/plugin.schema.json")
        extra = set(portable) - PORTABLE_KEYS
        if extra:
            err(f"portable plugin.json: keys the schema forbids: {sorted(extra)}")
        n = portable.get("name", "")
        if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", n) or "--" in n or ".." in n or len(n) > 64:
            err(f"name {n!r} does not match the schema pattern")
        if not isinstance(portable.get("version"), str):
            err("portable plugin.json: version must be a string")
        if "skills" in portable:
            err("portable plugin.json: the schema has no 'skills' key (skills/ is discovered)")
        if "interface" not in portable.get("extensions", {}).get("com.openai", {}):
            err("portable plugin.json: the listing belongs under extensions.com.openai.interface")
    if codex is not None:
        for k in CODEX_REQUIRED:
            if k not in codex:
                err(f".codex-plugin/plugin.json: missing {k}")
        if not isinstance(codex.get("author"), dict) or not codex["author"].get("name"):
            err(".codex-plugin/plugin.json: author.name is required")
        if codex.get("skills") != "./skills/":
            err(".codex-plugin/plugin.json: skills must be \"./skills/\"")
        if not isinstance(codex.get("interface", {}).get("capabilities", codex.get("capabilities")), list):
            err(".codex-plugin/plugin.json: capabilities (a list) is required")
        for k in ("composerIcon", "logo"):
            if k not in codex.get("interface", {}):
                err(f".codex-plugin/plugin.json: interface.{k} is required")
    if portable and codex and (portable.get("name"), portable.get("version")) != (codex.get("name"), codex.get("version")):
        err("the two manifests disagree on name or version")

    ifaces = []
    if portable is not None:
        ifaces.append(("portable extensions.com.openai.interface", portable.get("extensions", {}).get("com.openai", {}).get("interface", {})))
    if codex is not None:
        ifaces.append((".codex-plugin interface", codex.get("interface", {})))
    for label, i in ifaces:
        for k in IFACE_REQUIRED:
            if not i.get(k):
                err(f"{label}: missing {k}")
        for k, lim in (("displayName", 30), ("shortDescription", 30), ("longDescription", 4000)):
            if len(i.get(k, "")) > lim:
                err(f"{label}: {k} is {len(i[k])} characters, the limit is {lim}")
        for k in ("websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL"):
            if k in i and not str(i[k]).startswith("https://"):
                err(f"{label}: {k} must be https")
        if "supportURL" not in i:
            warn(f"{label}: no supportURL (the submission asks for customer support contact details)")
        for bad in ("MCP", "Plugin"):
            if bad.lower() in i.get("displayName", "").lower().split():
                err(f"{label}: do not append '{bad}' to the product name")
        dp = i.get("defaultPrompt", [])
        if len(dp) > 3:
            warn(f"{label}: defaultPrompt has {len(dp)} entries; only the first 3 are used")
        for p in dp:
            if len(p) > 128:
                warn(f"{label}: a defaultPrompt is over 128 characters and will be cut")
        for k in ("composerIcon", "logo"):
            if k in i:
                v = i[k]
                if not v.startswith("./"):
                    err(f"{label}: {k} {v!r} must be a relative path beginning with ./")
                if v.lstrip("./") not in names:
                    err(f"{label}: {k} {v!r} is not in the package")
        for s in i.get("screenshots", []):
            if not (s.startswith("./assets/") and s.lower().endswith(".png")):
                err(f"{label}: screenshots must be PNG files under ./assets/ ({s!r})")

    for label, i in ifaces:
        who = (portable or codex or {}).get("author", {}).get("name")
        if i.get("developerName") and who and i["developerName"] != who:
            err(f"{label}: developerName {i['developerName']!r} differs from the author {who!r}; the listing must name the verified publisher")
    skills = sorted({n.split("/")[1] for n in names if n.startswith("skills/") and n.count("/") >= 2})
    if not skills:
        err("no skills/<name>/ folder")
    for s in skills:
        f = f"skills/{s}/SKILL.md"
        if f not in names:
            err(f"{f} is missing"); continue
        head = z.read(f).decode().split("---")
        fm = head[1] if len(head) > 2 else ""
        nm = re.search(r"(?m)^name:\s*(\S+)", fm); ds = re.search(r"(?m)^description:\s*(.+)", fm)
        if not nm or not ds:
            err(f"{f}: front matter needs name and description")
        elif nm.group(1) != s:
            warn(f"{f}: name {nm.group(1)!r} differs from its folder {s!r}")

    for n in names:
        low = n.lower()
        if low.endswith((".app.json", "hooks.json")) or low.endswith(("mcp.json",)):
            err(f"{n}: a skills-only plugin must not carry apps, hooks or MCP entries")
        if low.endswith(IMG):
            b = z.read(n)
            if len(b) > 5 * 1024 * 1024:
                err(f"{n}: image over 5 MiB")
            sz = png_size(b)
            if sz and (sz[0] != sz[1] or min(sz) < 48):
                err(f"{n}: icons must be square and at least 48x48 (this is {sz[0]}x{sz[1]})")
    blob = b"".join(z.read(n) for n in names if not n.lower().endswith(IMG + (".pyz",)))
    for bad in (b"test_credentials", b"reviewer_instructions"):
        if bad in blob:
            err(f"the package contains {bad.decode()}, which is rejected")
    if re.search(rb"lat_[A-Za-z0-9]{20,}", blob):
        err("something that looks like a Lattice key is in the package")
    for n in names:
        if n.endswith(".pyz"):
            warn(f"{n}: a bundled executable; OpenAI says skills are scanned and does not say whether bundled scripts are allowed")
    return out


if __name__ == "__main__":
    res = check(sys.argv[1])
    for lvl, msg in res:
        print(f"{lvl:<5} {msg}")
    errs = sum(1 for l, _ in res if l == "ERROR")
    print(f"\n{errs} error(s), {sum(1 for l, _ in res if l == 'WARN')} warning(s)")
    sys.exit(1 if errs else 0)
