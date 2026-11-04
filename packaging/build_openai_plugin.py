#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Build the OpenAI plugin package: a skills-only plugin ZIP for platform.openai.com/plugins (shared by ChatGPT and Codex).

    python3 packaging/build_openai_plugin.py      -> dist/lattice-scan-openai-plugin-<version>.zip

The ZIP holds plugin.json (the portable Agent Plugins format, with the OpenAI listing under extensions.com.openai), .codex-plugin/plugin.json (the Codex format), skills/lattice-scan/ (SKILL.md, the
bundled script, agents/openai.yaml) and the icon. Two things differ from the Claude Code plugin, on purpose:
  * SKILL.md has no section on requesting a key. OpenAI's plugin guidelines do not allow collecting access credentials, and a skill that obtains and
    stores a key is too close to that line to leave to a reviewer's reading. The command line still has `get-key`; the directory skill just does not teach it.
  * Nothing here is uploaded. Upload needs a verified developer identity (organisation settings on platform.openai.com), so a person does it.
"""
from __future__ import annotations
import json, re, sys, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from lattice_scan import __version__  # noqa: E402

SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
# Who the listing says published it. It must be the identity verified on platform.openai.com, because OpenAI requires submissions to come from a verified
# individual or organisation: the owner verified as an individual, so this is a person, not the company. The links (namiq.io) are the project's own pages.
PUBLISHER = "Hung Le"
SKILL_DIR = ROOT / "skills" / "lattice-scan"
FIXED_TIME = (2026, 1, 1, 0, 0, 0)   # the same sources always give the same bytes


def plugin_skill_md() -> str:
    """SKILL.md for the directory: the Claude Code one without the key procedure (see the module docstring)."""
    t = (SKILL_DIR / "SKILL.md").read_text()
    a, b = t.index("## 5. A key, only for a person who asks for it"), t.index("## 6. If it fails")
    t = t[:a] + t[b:].replace("## 6. If it fails", "## 5. If it fails", 1)
    t = re.sub(r"[^\n]*get-key[^\n]*\n", "", t)
    return t


def manifest() -> dict:
    notes = (ROOT / "release-notes" / f"v{__version__}.md")
    first = notes.read_text().split("\n\n")[1].strip() if notes.exists() else f"lattice-scan {__version__}"
    return {
        "$schema": SCHEMA,
        "name": "lattice-scan",
        "version": __version__,
        "description": "Check the machine your agent runs on, or a project's dependencies, against CISA-known-exploited CVEs read through Lattice. Prints evidence for a person to read.",
        "author": {"name": PUBLISHER, "url": "https://namiq.io"},   # no email: this is public on every release; support is the contact page below
        "homepage": "https://github.com/namiq-ai/lattice-scan",
        "repository": "https://github.com/namiq-ai/lattice-scan",
        "license": "Apache-2.0",
        "keywords": ["security", "cve", "cisa", "kev", "vulnerability"],
        "extensions": {"com.openai": {
            "interface": {
                "displayName": "Lattice Scan",
                "shortDescription": "Check hosts for exploited CVEs",
                "longDescription": (
                    "Lattice Scan looks up CVE ids on the Lattice server and compares each with the software installed on the machine your agent runs on: packages, snaps, "
                    "running container image names and the kernel. It can also read the dependencies a project folder declares. With no CVE id to start from, it reads a daily "
                    "or weekly list of recently exploited and critical CVEs and checks only the ones that could apply. It prints evidence for a person to read: each match is a "
                    "candidate to check, not a finding that anything is vulnerable. Only CVE ids leave the machine. The inventory is never sent. It does not install, change or "
                    "remove anything. It needs Python 3.9 or newer and runs on your own computer, not in a hosted sandbox. The tool is open source under the Apache-2.0 licence; the Lattice "
                    "service it reads is the one at namiq.io."),
                "developerName": PUBLISHER,
                "category": "security",
                "websiteURL": "https://namiq.io/lattice",
                "supportURL": "https://namiq.io/contact",
                "privacyPolicyURL": "https://namiq.io/legal/privacy",
                "termsOfServiceURL": "https://namiq.io/legal/lattice-beta-terms",
                "composerIcon": "./assets/icon.png",
                "logo": "./assets/icon.png",
            },
            "publication": {"release_notes": first[:1000]},
        }},
    }


def codex_manifest() -> dict:
    """The Codex-format manifest, .codex-plugin/plugin.json: what OpenAI's own plugin tooling treats as the required structure. The listing sits in a root
    `interface` object here, and skills are named by path. The portable plugin.json keeps the OpenAI publication settings (OpenAI ignores a Codex file's
    when a portable one has them), so this file repeats only what Codex needs."""
    m = manifest()
    i = dict(m["extensions"]["com.openai"]["interface"])
    i["capabilities"] = ["Read"]   # the skill reads this machine's inventory and writes nothing outside its own records and cache
    i["defaultPrompt"] = ["Is this machine affected by recently exploited CVEs?", "Check this project's dependencies against exploited CVEs", "What is new and exploited this week?"]
    return {k: m[k] for k in ("name", "version", "description", "author", "homepage", "repository", "license", "keywords")} | {"skills": "./skills/", "interface": i}


def build(out_dir: Path | None = None) -> Path:
    out = (out_dir or ROOT / "dist")
    out.mkdir(parents=True, exist_ok=True)
    target = out / f"lattice-scan-openai-plugin-{__version__}.zip"
    files = {
        "plugin.json": (json.dumps(manifest(), indent=2) + "\n").encode(),
        ".codex-plugin/plugin.json": (json.dumps(codex_manifest(), indent=2) + "\n").encode(),
        "skills/lattice-scan/SKILL.md": plugin_skill_md().encode(),
        "skills/lattice-scan/agents/openai.yaml": (SKILL_DIR / "agents" / "openai.yaml").read_bytes(),
        "skills/lattice-scan/scripts/lattice-scan.pyz": (SKILL_DIR / "scripts" / "lattice-scan.pyz").read_bytes(),
        "assets/icon.png": (ROOT / ".claude-plugin" / "icon.png").read_bytes(),
    }
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.external_attr = (0o755 if name.endswith(".pyz") else 0o644) << 16
            z.writestr(info, data)
    return target


if __name__ == "__main__":
    t = build()
    print(f"{t.stat().st_size:>9}  {t.relative_to(ROOT)}")
