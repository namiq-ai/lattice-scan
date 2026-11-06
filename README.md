# lattice-scan

Looks up CVEs that CISA lists as exploited, through the Lattice MCP server, and compares each with what is installed on **this** machine: packages,
snaps, the hardware, the running container images and what is inside them, the kernel. It prints the evidence, including installed version, CISA's dates and required action, and NVD's affected
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
lattice-scan                                               # no arguments: the same as `recent --daily`
lattice-scan recent                                        # no CVE id? read namiq.io's weekly list of recent exploited/critical CVEs; only likely matches go to Lattice (--daily: last day or two; --open: older ones, overdue first)
printf '...' | lattice-scan enrich                         # ids from an audit or advisory: exploited? since when? patch due? ransomware? (no key: 20 ids a run)
lattice-scan get-key --name ... --position ... --company ... --email ... --purpose "..."   # asks nothing until --accept-terms; for a real person who read the terms
lattice-scan --refresh                                     # collect the inventory and print its totals; no network call (--list prints every package)
lattice-scan list | impact CVE-... | resolve CVE-... --status fixed --proof "..."
lattice-scan --progress --cve CVE-...                      # which CVE, and which part of the host or project, as it runs (on by default; -q silences)
lattice-scan --debug --cve CVE-...                         # every request, response and match decision
```

## Check a project's dependencies

Not sure whether you want this command line, the Claude skill or the Lattice MCP server? The [channel guide](https://namiq.io/lattice/guides/choose-your-channel) compares them, lists what works without a key, and has a CI recipe.

**Who can scan what.** Reading many ids is for a key whose owner has confirmed their email. With a confirmed key, `--kev-catalogue` lets CISA's catalogue choose the ids. A key whose email is not
confirmed yet (tier `trial`) is refused with a message to confirm it; no id is read. **Without a key you name the CVEs yourself**, comma separated:
`lattice-scan project . --cve CVE-2026-46300,CVE-2021-44228` (at most 40 a run, inside the keyless daily allowance).

```bash
lattice-scan project . --cve CVE-2026-46300,CVE-2021-44228                       # no key needed: only the CVEs you name
LATTICE_API_KEY=... lattice-scan project .  --kev-catalogue known_exploited_vulnerabilities.json   # confirmed key: CISA's file chooses the ids
lattice-scan project app/ api/ --name APP --name API --cve CVE-2026-46300         # explicit ids; several folders at once, labelled
lattice-scan project . --cve CVE-2026-46300 --csv findings.csv                    # the report on screen, a CSV alongside
lattice-scan project . --cve CVE-2026-46300 --fail-on in-range                    # exit 1 when a declared version is inside an affected range
```

Reads what the project **declares**. Nothing is executed and nothing is installed.

| Ecosystem | Files |
|---|---|
| Python | `requirements*.txt` and `requirements*.lock` (with `-r` includes), `pyproject.toml` (PEP 621, optional groups, poetry) |
| JavaScript | `package.json`, `package-lock.json` |
| Java | `pom.xml` (properties resolved), `build.gradle`, `build.gradle.kts`, `gradle.lockfile`, `gradle/libs.versions.toml` |
| Rust | `Cargo.toml`, `Cargo.lock` |
| C and C++ | `CMakeLists.txt` and `*.cmake` (`find_package`, `FetchContent_Declare`, `ExternalProject_Add`, `CPMAddPackage`, `pkg_check_modules`), `conanfile.txt` / `conanfile.py`, `vcpkg.json` |
| Make | `Makefile`, `GNUmakefile`, `*.mk` (`NAME_VERSION = x.y.z`, `pkg-config` constraints, library names from `-l` flags, tarball names in download commands) |
| Containers | `Dockerfile*` (`FROM`, `pip install`, `apt-get install`, tarball names), `docker-compose` / `compose` files (`image:`) |

- A **pinned** version (`==2.14.0`, a lockfile entry, `=1.4.2` in Cargo, a Docker tag with two or more numbers such as `16.2` or `13.0.1-security-01`) is compared with NVD's ranges. A range
  (`>=1.0`), a caret requirement, `find_package(X 1.1)` (a minimum), a branch name, `latest` or a major-only tag (`16`) has no version, and the answer for it is `undetermined`, never `outside-range`.
- A `-lssl` link flag or an unversioned `find_package` names a library, not a version: it is listed so a person knows the library is used.
- Where a lockfile pins a name, the unpinned declarations of that name are left out: the lock says what is installed.
- Matching is by identity: the product must be the package (or its npm scope, or vendor+product). For Maven, Cargo, Conan, vcpkg, CMake and Make names the product as a whole token of a longer
  coordinate also matches (`org.apache.logging.log4j:log4j-core` is Log4j2), and its versions are compared. A match through an npm scope alone (`@vitejs/plugin-react` for Vite) is a lead only:
  that package's version is not the product's, so no range is compared. `minio` the Python client matches MinIO the server by name; reading the finding tells you which it is. A match is a candidate for a person to read against what is really deployed (a distribution may backport a fix; a lockfile may not be what runs).
- Writes no host records (`~/.lattice-scan` is untouched). Skips `node_modules`, virtualenvs, build output and `.claude`. If its file search reaches its limit it says so.
- Without a key, Lattice allows 60 reads a day; `--max-read` (default 40 without a key, 200 with one) stops a run from using them all, and the ids not read are listed.

### Reading the report

The default output is a report for a person: a summary table (one row per project, a total for several), then each project's findings with the declared component and its
file and line, CISA's dates ("listed 3 days ago, due in 18 days"), the version check and CISA's required action, then the ids that were not read, and a legend. Colour is used only on a
terminal (`--color auto`; never when `NO_COLOR` is set). `--width N` fixes the width.

| Verdict | Meaning |
|---|---|
| `in-range` | A declared, pinned version lies inside a range NVD lists as affected. Check what is really deployed. |
| `undetermined` | The declaration is a range, a minimum, a floating tag or has no version; NVD's bounds are dates or build ids. |
| `lead` | The declared package only shares a scope or name with the product, or is its client library (the PyPI `minio` is not the MinIO server). No range is compared. |
| `outside-range` | Every pinned version declared is outside every usable range. This does not close a finding. |
| `not-read` | An id that matches a dependency by name was not read from Lattice (a limit or a stop). Neither safe nor affected. |

### For scripts: CSV and JSON

`--format csv` prints (and `--csv FILE` writes) one row per finding and declared component, UTF-8, LF line ends, always with a header row, in this fixed column order:

```
project,cve,title,verdict,component,ecosystem,declared,version,file,line,listed,due,due_status,action,why
```

`version` is the pinned version alone (empty when there is none), `declared` is the text as written (`==2.14.0`). Text from outside (a CVE title, CISA's action, a file name) that starts with `=`, `+`, `-` or `@` is
written with one leading apostrophe so a spreadsheet does not run it as a formula; strip one leading `'` for the raw text. `--format json` (or `--json FILE`) is the same data with the files read and the ids not read.

```bash
lattice-scan project . --cve CVE-2026-46300,CVE-2021-44228 --format csv | \
  python3 -c 'import csv,sys; [print(r["cve"], r["component"]) for r in csv.DictReader(sys.stdin) if r["verdict"]=="in-range"]'
```

Exit status: `0` done, `1` `--fail-on` matched, `2` bad usage or an unreadable input, `3` stopped part-way (Lattice's allowance ran out or it could not be reached; the ids not read are listed).

The full manual is `man lattice-scan` (installed by the `.deb`; `man -l man/lattice-scan.1` from a checkout), and `lattice-scan project --help` has examples and the CSV columns.

## Use it as a Claude Code skill

The same tool ships as a plugin whose skill runs it on the machine Claude is running on and reports each match as a candidate for a person to check.
```
/plugin install lattice-scan --marketplace namiq-ai/lattice-scan
```

The skill refuses to scan a hosted sandbox, because it would scan the sandbox and not the machine you mean.

### In OpenAI Codex

Codex reads the same `SKILL.md` format. The repository carries it where Codex looks: clone it and `.agents/skills/lattice-scan` is found when you start Codex in the folder.
To use it everywhere, copy `skills/lattice-scan` to `~/.agents/skills/lattice-scan`, or ask Codex's skill installer for it from `namiq-ai/lattice-scan`, path `skills/lattice-scan`.
Each release also attaches `lattice-scan-openai-plugin-<version>.zip`, the package for OpenAI's plugin directory. In ChatGPT the skill stops at its first step, because
ChatGPT runs it in a hosted sandbox and it checks the machine it runs on; Codex on your own computer is where it does its work.

## What the host inventory collects: quick and deep

Every host scan starts by taking an inventory of the machine. It has two levels, because reading inside container images is slow.

| | **Quick** (default) | **Deep** (`--deep`, or `LATTICE_SCAN_LEVEL=deep`) |
|---|---|---|
| Hardware (maker, model, version, board, firmware version and date, architecture, CPU, memory, virtualisation) | yes | yes |
| Host packages (dpkg, rpm, apk), snaps, kernel, Node.js | yes | yes |
| Images that containers are running: base OS and release, package list, version label, `*_VERSION` variables | yes | yes |
| Every other local image (stopped, unused) | no | yes |
| Python, Node, Java and Ruby packages inside images | no | yes (every image) |
| Which local image each image was built on | yes | yes |
| Time (test host: 24 images, 31 GB, 7 running) | about 12 seconds | about 6 minutes |

After a quick scan the tool prints one line on stderr saying how many local images were opened, how long `--deep` would take and when a deep scan was last done (it suggests repeating one after 30 days). A deep scan prints a rough estimate first, then `[n/N %]` with elapsed time for each image and a summary. `-q` silences all of it. **A quick result is not "all clear":** stopped images and the packages inside images were not read.

`lattice-scan --refresh` prints the totals and a short summary of the images (by base OS, packages inside them); the full lists are in `inventory.json` in the records folder, and `--refresh --list` prints them.

**How images are read.** Nothing is started or pulled. For each image the tool runs `docker image inspect`, then `docker create` (with `--pull never`, `--network none` and the label `io.lattice-scan.run`), copies out only the OS release file and the package database with `docker cp`, and removes the container. The package database is chosen by the OS family: apk (Alpine), dpkg (Debian, Ubuntu, and distroless images through `status.d`) and rpm (sqlite databases: Fedora, RHEL 9 and later, Amazon Linux 2023; Berkeley DB and ndb databases are not read). In a deep scan it also streams `docker export` once per image and records the names and versions of Python (`dist-info`), Node (`package.json`), Java (jar file names) and Ruby (gems) packages, with a limit of 180 seconds per image after which that image is marked partial. Go and Rust binaries, Composer and NuGet are not read. The tool compares the image's own package versions, not the host's. A candidate found inside an image names the image (`musl 1.2.5-r8 (image redis:7-alpine)`). Environment variables of an image are never kept, except those ending in `_VERSION`. Serial numbers and UUIDs of the machine are never read. No registry is contacted.

**Safe to stop, safe to fail.** The container is removed after each image, also on an error. When the run ends or is stopped (Ctrl-C, SIGTERM) every container it made is removed. A run killed outright (SIGKILL) can leave a never-started container; the next run removes labelled containers older than 15 minutes. Only containers with that label are touched. `docker cp` and `docker export` write nothing to disk (at most 40 MB of one file is held in memory); an rpm database is written to a temporary folder that is removed at once. An image that fails is skipped and named, and the others are kept. Images are not opened when less than 1 GB is free where Docker keeps its data, and no new image is started after 30 minutes.

| Environment variable | Meaning |
|---|---|
| `LATTICE_SCAN_LEVEL` | `quick` (default) or `deep`, the same as `--deep` |
| `LATTICE_SCAN_IMAGES` | which images are opened, overriding the level: `all`, `running` or `off` |
| `LATTICE_SCAN_IMAGES_LANG` | which images get the Python/Node/Java/Ruby scan, overriding the level: `all`, `running` or `off` |
| `LATTICE_SCAN_MIN_FREE_MB` | free space needed where Docker keeps its data (default 1024) |
| `LATTICE_SCAN_DEEP_SECONDS` | no further image is started after this many seconds (default 1800) |
| `LATTICE_SCAN_STALE_MINUTES` | age after which a leftover container of a killed run is removed (default 15) |

**The inventory file.** `inventory.json` (and the file named by `LATTICE_SCAN_INVENTORY`, which replaces the collection for tests and other tools) is a JSON object with `kernel`, `os`, `node`, `restartRequired`, `packages` (name to version), `snaps` (name to version) and `images` (running image names). The new, optional keys are `host` (the hardware: `manufacturer`, `model`, `version`, `board`, `biosVersion`, ...), `imageDetails` (image reference to `{os, osVersion, osName, packageManager, packages, versions, languages, builtOn, running, ...}`) and `imageScan` (`level`, `local`, `opened`, `skipped`, `deepSeconds`). An inventory without them still works.

## What leaves the machine

CVE ids, and the key if you set one. The inventory (hardware, package names and versions, and what is inside images) is never sent; matching happens locally.
`recent` also downloads namiq.io's public list of recent CVE ids; that request carries no id and nothing about the host. `get-key` sends the name, position, company, email and purpose you give it, only after `--accept-terms`.

## What it writes

`~/.lattice-scan/` (or `LATTICE_SCAN_DIR`; records from the earlier internal name `~/.host-scan` are still found), mode 0700, every file 0600: findings, scan, inventory and debug logs. They name this host's installed software. Do not commit,
publish or share them. `lattice-scan get-key` also stores a key there as the file `key` (mode 0600, never printed). `enrich` and `project` write nothing.

**Running as an agent, in a sandbox.** With no terminal and no records folder yet, a host run writes to a temporary folder that is deleted when it ends, so nothing stays in the home folder; `--keep` (or `LATTICE_SCAN_KEEP=1`) keeps the records. If the home is read-only or missing the run says so in one line and does the same. Set `LATTICE_SCAN_DIR` to a folder the agent owns to choose where records go, and `LATTICE_API_KEY` for a key; if `LATTICE_SCAN_DIR` is set and cannot be written, the run stops with one line naming it.

## What it cannot tell you

- Version ranges are compared as upstream numbers. A distribution can fix a CVE under an unchanged version number, so `in-range` is a lead, not a finding;
  the report also shows whether an installed package's own changelog names the CVE (Debian-family hosts only).
- Without a key, only `graph_lookup` is available and the daily allowance is small. The script waits between calls to stay under it. Getting a key is
  described at https://namiq.io/lattice/docs#agents; a person does that, and the tool never requests one.
- Host inventory: see "What the host inventory collects" above for what quick and deep read and do not read inside container images.
- Tested on Debian-family hosts. On rpm and apk hosts the inventory is collected (checked on Fedora and Alpine) but matching and the changelog check are not tested there; the changelog check is Debian-only.

## Reporting a problem

A wrong match, a crash, or anything that looks like a security problem: open an issue, or write to contact@namiq.io for anything you would rather not post
publicly. See `SECURITY.md`.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`. Copyright 2026 NamiQ LLC.

The licence does not grant the right to use the names "NamiQ" or "Lattice" or their logos. Releases up to v0.1.0 were published under MIT; see `NOTICE`.
