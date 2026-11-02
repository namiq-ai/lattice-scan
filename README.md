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

## Check a project's dependencies

```bash
lattice-scan project .  --kev-catalogue known_exploited_vulnerabilities.json     # CISA's file; used here only to choose which ids to read
lattice-scan project app/ api/ --cve CVE-2026-46300 --json result.json            # explicit ids; several folders at once
lattice-scan project . --kev-catalogue kev.json --fail-on in-range                # exit 1 when a declared version is inside an affected range
```

Reads what the project **declares**: `requirements*.txt` and `requirements*.lock` (with `-r` includes), `pyproject.toml` (PEP 621, optional groups, poetry), `package.json`
and `package-lock.json`, `Dockerfile*` (`FROM`, `pip install`, `apt-get install`) and `docker-compose` / `compose` files (`image:`). Nothing is executed and nothing is installed.

- A **pinned** version (`==2.14.0`, a lockfile entry, an image tag such as `16.2`) is compared with NVD's ranges. A range (`>=1.0`), `latest` or no tag has no version, and the
  answer for it is `undetermined`, never `outside-range`.
- Where a lockfile pins a name, the unpinned declarations of that name are left out: the lock says what is installed.
- Matching is by product name, like the host check. A match is a candidate for a person to read against what is really deployed (a distribution may backport a fix; a lockfile may not be what runs).
- Writes no host records (`~/.lattice-scan` is untouched). Skips `node_modules`, virtualenvs, build output and `.claude`. If its file search reaches its limit it says so.
- Without a key, Lattice allows 60 reads a day; `--max-read` (default 40) stops a project from using them all, and the ids not read are listed.

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
