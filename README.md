# lattice-scan

Looks up CVEs that CISA lists as exploited, through the Lattice MCP server, and compares each with what is installed on **this** machine: packages,
snaps, running container images, the kernel. It prints the evidence, including installed version, CISA's dates and required action, and NVD's affected
version ranges. A person reads it and decides. It does not detect incidents or decide whether the host is affected, and it never closes a finding by itself.

Standard library only. Python 3.9 or newer.

## Install

```bash
pipx install lattice-scan                    # or: pip install lattice-scan
```

On Debian and Ubuntu, from the signed apt repository:

```bash
sudo curl -fsSL https://namiq.io/apt/lattice-scan.gpg -o /usr/share/keyrings/lattice-scan.gpg
echo "deb [signed-by=/usr/share/keyrings/lattice-scan.gpg] https://namiq.io/apt stable main" | sudo tee /etc/apt/sources.list.d/lattice-scan.list
sudo apt update && sudo apt install lattice-scan
```

The signing key's fingerprint is `C473 6154 4115 8A3E 775C 2EC2 7E61 15F4 0A41 061D`. Check it against the key you downloaded
(`gpg --show-keys /usr/share/keyrings/lattice-scan.gpg`). It is also published at https://namiq.io/lattice/docs, apart from the repository.

Or take the single-file `lattice-scan.pyz` or the `.deb` from the [releases page](https://github.com/namiq-ai/lattice-scan/releases) and check it with
`sha256sum -c SHA256SUMS`: `python3 lattice-scan.pyz --cve CVE-...`.

## Use

```bash
lattice-scan --cve CVE-2021-44228 --cve CVE-2026-46300     # works without a key
LATTICE_API_KEY=... lattice-scan --discover                # a key lists what was added in the last week
lattice-scan --refresh                                     # collect and print the inventory; no network call
lattice-scan list | impact CVE-... | resolve CVE-... --status fixed --proof "..."
lattice-scan --debug --cve CVE-...                         # every request, response and match decision
```

## Use it as a Claude Code skill

The same tool ships as a plugin whose skill runs it on the machine Claude is running on and reports each match as a candidate for a person to check.
```
/plugin install lattice-scan --marketplace namiq-ai/lattice-scan
```

The skill refuses to scan a hosted sandbox, because it would scan the sandbox and not the machine you mean.

## What leaves the machine

CVE ids, and the key if you set one. The inventory (package names and versions) is never sent; matching happens locally.

## What it writes

`~/.lattice-scan/` (or `LATTICE_SCAN_DIR`; records from the earlier internal name `~/.host-scan` are still found), mode 0700: findings, scan, inventory and debug logs. They name this host's installed software. Do not commit,
publish or share them.

## What it cannot tell you

- Version ranges are compared as upstream numbers. A distribution can fix a CVE under an unchanged version number, so `in-range` is a lead, not a finding;
  the report also shows whether an installed package's own changelog names the CVE (Debian-family hosts only).
- Without a key, only `graph_lookup` is available and the daily allowance is small. The script waits between calls to stay under it. Getting a key is
  described at https://namiq.io/lattice/docs#agents; a person does that, and the tool never requests one.
- Tested on Debian-family hosts. On rpm and apk hosts the inventory is collected (checked on Fedora and Alpine) but matching and the changelog check are not tested there; the changelog check is Debian-only.

## Reporting a problem

A wrong match, a crash, or anything that looks like a security problem: open an issue, or write to contact@namiq.io for anything you would rather not post
publicly. See `SECURITY.md`.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`. Copyright 2026 NamiQ LLC.

The licence does not grant the right to use the names "NamiQ" or "Lattice" or their logos. Releases up to v0.1.0 were published under MIT; see `NOTICE`.
