# Changelog

## Unreleased

- The host inventory now knows the machine and what is inside each container image. Hardware: manufacturer, product model and version, board, firmware version and date, architecture, CPU, memory, virtualisation (from the kernel's DMI table, or the device tree on ARM boards; serial numbers and UUIDs are not read). Images: for every local image the tool reads its metadata and, without starting it (`docker create --network none`, then `docker cp` of the OS release file and the apk or dpkg package list, then `docker rm`), its base OS and release, its packages, its version label and its `*_VERSION` variables. Before, `postgres:16-alpine` was only a name, so a flaw in the musl or busybox inside it could never become a candidate. Now a CISA entry whose product words are all found in one image becomes a candidate that names that image and compares that image's package version. A CISA entry for firmware or a board matches the machine's maker and model. Other environment values of an image are never kept. `--refresh` prints the hardware and each image's OS and package count. `LATTICE_SCAN_IMAGES=running` opens only running images, `off` none. Distroless images and RPM databases give metadata only. Nothing leaves the machine.
- Images are read further. RPM images (sqlite rpm databases: Fedora, RHEL 9 and later, Amazon Linux 2023) and distroless images (`/var/lib/dpkg/status.d`) now give their package lists. With `--deep` the tool streams `docker export` once per image and records the Python, Node, Java and Ruby packages inside (names and versions from `dist-info`, `package.json`, jar file names and gem folders; 180 seconds per image, then marked partial; `LATTICE_SCAN_IMAGES_LANG=all` for every image, `off` for none). Each image shows the local image it was built on when that image's layers are its first layers. No registry is contacted. Berkeley DB and ndb rpm databases, Go and Rust binaries are not read.

- Two inventory levels. Quick (the default): hardware, host packages and snaps, and the images that containers are running (OS release and package list), with the package database chosen by the image's OS family and up to four images read at once. On the test host (7 running images) it takes about 12 seconds, where reading all 24 local images one by one took 87. Deep (`--deep` or `LATTICE_SCAN_LEVEL=deep`): also every other local image and the Python, Node, Java and Ruby packages inside every image; it took about 6 minutes for 24 images on the test host. `LATTICE_SCAN_IMAGES` and `LATTICE_SCAN_IMAGES_LANG` override the level. Which local image an image was built on is found in both levels.

## 0.4.1 — 2026-11-06

- A host scan now prints the saved detail (priority, EPSS, SSVC, weakness, description, techniques, references, version check) for every open finding recorded by an earlier run, not only for the CVEs read in this run. Before, such a CVE showed one table row (`OPEN ... not read in this run`) and nothing else. The detail comes from the records file: no extra call, nothing leaves the machine. Only CVEs that were read and matched nothing (`unmatch`) still have no detail block.
- A CVE you name that CISA does not list now shows what Lattice holds on it, instead of only `unlisted`: NVD's record status and dates, EPSS and SSVC when present, the weakness, the start of the description, the linked ATT&CK techniques ("likely" when inferred) and references, and a line saying so when NVD lists no affected products yet (no version check is possible). It costs one more call per such id and applies only to ids you typed, not to `recent`, `enrich` or discovery. There is no priority line and nothing is recorded as a finding. The skill explains how to read it and not to call a not-listed CVE safe.

## 0.4.0 — 2026-11-06

- A candidate now says how urgent it is and what it is. For each candidate the tool reads one more node from Lattice, which needs no key since Lattice began serving it keyless, and prints a priority (`fix first`, `fix soon` or `read`, with the reasons), the EPSS score and percentile, CISA's SSVC assessment, the weakness (CWE), the start of NVD's description, the linked ATT&CK techniques (marked "likely" when the graph inferred the link), the first unaffected upstream version NVD lists, and up to three references. Candidates are listed highest priority first, and `lattice-scan impact CVE-...` shows the saved context. The priority is the tool's reading of CISA and FIRST fields, not a risk score or a verdict. A server that refuses the read or sends no links leaves the candidate exactly as before, with one line on stderr. A candidate costs one more call, which counts against the keyless limit. Only CVE ids and node ids Lattice returned leave the machine.

## 0.3.6 — 2026-11-04

- An agent in its own sandbox can now run the host scan and `recent`. With a read-only or missing home folder the tool used to stop with a Python traceback (exit 1) when it first wrote its records; now it says on one line that the folder cannot be written and keeps that run's records in a temporary folder deleted when the run ends. If `LATTICE_SCAN_DIR` is set and cannot be used, it stops with exit 1 and one line naming it.
- A host run with no terminal (an agent, a cron job) and no records folder yet no longer leaves the list of installed packages in the home folder: its records go to a temporary folder. `--keep` (or `LATTICE_SCAN_KEEP=1`) keeps them in the default folder. A folder that already exists, and any folder named by `LATTICE_SCAN_DIR`, are used as before. `get-key` never uses a temporary folder, because the key must outlive the run.
- Every file in the records folder is now created mode 0600 (it was 0664), and existing ones are tightened on the next run.
- The skill's section 2 tells a sandboxed agent to set `LATTICE_SCAN_DIR` and `LATTICE_API_KEY`.

## 0.3.5 — 2026-11-04

- The OpenAI plugin package now names Hung Le as its publisher (`developerName` and author), the identity verified on platform.openai.com, instead of NamiQ LLC. Its manifests no longer carry an email address. `packaging/check_openai_plugin.py` rejects a package whose listing publisher differs from its author. Package only; the command-line tool and the skill are unchanged.
- Wording: the help for `recent --open`, the manual and the 0.3.1 release notes no longer say that "many machines are still unfixed". Nothing in the list supports that; it says only that CISA's due date has passed, and nothing about any machine.

## 0.3.4 — 2026-11-04

- The OpenAI plugin package now also carries the Codex-format manifest (`.codex-plugin/plugin.json`, with `skills`, `capabilities`, `defaultPrompt` and the listing under `interface`), and the icon paths in both manifests begin with `./`, as OpenAI's plugin-creator spec requires. `packaging/check_openai_plugin.py` checks a package against OpenAI's published rules, and the release workflow runs it. Package only; the command-line tool and the skill are unchanged.

## 0.3.3 — 2026-11-04

- `lattice-scan` with no arguments now runs `lattice-scan recent --daily` instead of printing "nothing to check". Daily, not weekly, because the weekly list is long and a keyless run that must look many entries up reaches Lattice's limit. Any argument or subcommand behaves as before, and `lattice-scan recent` is still weekly by default.
- Keyless limit (5 calls a minute): the tool now remembers when it last called Lattice (a small file in the user's cache folder, `LATTICE_SCAN_PACE_FILE`), so separate runs one after another space themselves out. Before, only calls inside one run were spaced, and the sixth call in a minute from an agent running the tool several times failed with HTTP 429.
- A 429 that says "Retry after N seconds" with N up to about a minute is waited out and retried, at most twice, with a line on stderr. A longer wait (the hourly or daily limit) still stops the run and lists what was not read.
- Two runs at the same moment record a new finding once, not twice (a lock on the records folder).

## 0.3.2 — 2026-11-04

- The Claude and Codex skill reads NamiQ's own published notes before any outside site when the user asks what a CVE means, what to do about it or whether a fix exists: the note for the CVE (found through the sitemap), today's watch, the weakness page and the report behind a note. The skill still quotes mitigations and never applies them. Only the skill's text changes; the command-line tool behaves as in 0.3.1.

## 0.3.1 — 2026-11-04

- Fix: `recent` stopped with "reads lattice-recent/2" when namiq.io's list moved to version 3. It now reads version 2 and every later version that only adds fields, and checks that the period it needs is there instead of matching one version number. Version 1 and a list that is not one are still refused with a request to upgrade.
- New: `recent --open` (or `--period open`) reads the list's open part, version 3's addition: exploited CVEs CISA added before the weekly window but within the last 30 days, overdue first. They are checked against the host in the same way as the daily and weekly lists. Without it nothing changes: weekly is still the default.

## 0.3.0 — 2026-11-04

- OpenAI: the skill folder carries `agents/openai.yaml` for Codex and the repository has `.agents/skills/lattice-scan`, so Codex finds the skill in a clone. `packaging/build_openai_plugin.py` builds `lattice-scan-openai-plugin-<version>.zip` (a skills-only plugin for platform.openai.com/plugins), and the release workflow attaches it. The directory copy of the skill omits the key procedure.

- `lattice-scan recent`: for an agent or person with no CVE id. It reads namiq.io's daily or weekly list of recent exploited (CISA) and critical (not known exploited) CVEs (`--daily`, `--weekly`, default weekly), compares each exploited entry with this host's inventory locally, and reads only the entries that may match from Lattice, by exact id. The others are `unmatch` and are never sent; a critical entry that may match is `WATCH`. The list request carries no id and nothing about the host.
- `lattice-scan enrich`: CVE ids from `--cve` text, `--file` or standard input (an `npm audit` or `pip-audit` report, an advisory, a ticket), each read once: exploited by CISA's list, since when, patch due, CVSS, ransomware. It does not look at the host and writes no records. Without a key it reads 20 ids a run; the rest are listed as `not read` and the exit status is 3.
- `lattice-scan get-key`: requests a Lattice key for a real person who gave their name, position, company and a mailbox they read, and agreed to the terms. Nothing is sent without `--accept-terms`. The key is stored as `~/.lattice-scan/key` (mode 0600), never printed, and used by later runs while the file stays private.
- A request to Lattice that times out or gets 502/503/504 is tried up to three times (2 s, then 6 s apart) instead of stopping the run.
- The Claude skill now opens with a "which command" table, so an agent with no CVE id starts with `recent`, an agent with audit output uses `enrich`, and it explains how to ask a person for a key (their details, their yes to the terms) and never to request one alone. See `man lattice-scan`.

## 0.2.3 — 2026-11-04

- The Claude skill (`SKILL.md`) now explains the result table, its columns (`EXPLOIT`, `CVSS`, `LISTED`, `PATCH DUE`, `RANSOM`, `RESULT`), the progress lines and `--quiet`, and how to word `RANSOM -` and `unlisted`.

- The host result table is narrower so the last column (what matched) keeps more room: header `EXPLOIT` and `RANSOM` (`known`, or `-` when CISA has not recorded it), results `unmatch`, `unlisted`, `RECORDED` and `OPEN` in place of the longer wordings, columns two spaces apart, and PATCH DUE shows the date only. On a terminal that is too narrow, LISTED, PRODUCT and CVSS are hidden in turn (with a note) so the last column keeps at least 45 characters; piped output always has every column. An open finding from an earlier run now leads with why it matched, then when it was recorded.

## 0.2.2 — 2026-11-04

- The host check prints one RESULT BY CVE table. An open finding recorded by an earlier run now appears in it (result `OPEN`, with the date and reason it was recorded), and the separate "N finding(s) not yet fixed" line is gone.
- New columns: EXPLOITED (CISA lists it as exploited), CVSS (NVD score), LISTED (date CISA added it), PATCH DUE (CISA's due date and days left or late), RANSOMWARE (`known`, `not recorded` or `-`; CISA's "Unknown" is never shown as "no").
- Table style follows `docker ps` and `kubectl get`: upper-case header, no rule line, one line per row, cells never wrap. Piped output keeps the whole cell; on a terminal the last column is cut with an ellipsis. A project report with `--width` still holds that width.
- A saved finding now also stores the ransomware flag and CVSS score; findings recorded by older versions show `-` for those until the CVE is read again.

## 0.2.1 — 2026-11-03

- Progress: `--progress` prints on stderr which part of the host (packages, snaps, container image names, kernel) or project (each dependency file, with its kind) is being read, and for each CVE which one it is (n of N), what CISA lists and whether anything matched. It is on by default; `--quiet` (`-q`) or `LATTICE_SCAN_PROGRESS=0` turns it off, for a script or CI log that must stay silent. Standard output, exit codes and records are unchanged (OCO-5837).
- Results: the host check and the console project report now print a RESULT BY CVE table (CVE, on CISA's list, product, result, what matched or was compared) and a DETAILED RESULT FILES section that names where the full detail is: the host's records folder and what each file holds, or the `--csv` and `--json` files you asked for (OCO-5837). The JSON result gains a `checked` list per project with the same rows.

- Every release now has notes: `release-notes/vX.Y.Z.md` is required by the release workflow and becomes the release body (see RELEASING.md).

- A package that only shares a scope or name with the product (`@vitejs/plugin-react` for Vite), or is its client library (the PyPI `minio`), is a new verdict, `lead`: it has its own summary column and ranks below every real comparison, so it no longer inflates `undetermined`.

## 0.2.0 — 2026-11-02

**New: `lattice-scan project` checks what a project declares it depends on.** Until now the tool only inspected an installed host. A project's own manifests say what it will install, and CI
or a developer machine has no inventory worth scanning.

- Reads Python (`requirements*.txt`/`.lock`, `pyproject.toml`), JavaScript (`package.json`, `package-lock.json`), Java (`pom.xml`, Gradle build, lockfile and version catalog), Rust (`Cargo.toml`,
  `Cargo.lock`), C and C++ (CMake, Conan, vcpkg), Make (`Makefile`, `*.mk`) and containers (`Dockerfile*`, compose files). Nothing is executed or installed.
- Only a version that is written down counts. A range, a minimum, a caret requirement, a floating tag or a branch is reported `undetermined`, never `outside-range`; lockfiles pin what manifests only range.
- **Who can scan what.** The catalogue scan (`--kev-catalogue`) needs a Lattice key whose owner has confirmed their email; an unconfirmed key is refused before any id is read. Without a key, name the CVEs:
  `--cve CVE-2026-46300,CVE-2021-44228` (comma separated).
- **A report for a person, and CSV and JSON for scripts.** The console report has a summary table, per-project findings with file and line, CISA's dates in plain words, the version check and the required
  action, the ids not read, and a legend. `--format csv` / `--csv FILE` write one row per finding in fixed columns (text from outside that starts with `=`, `+`, `-` or `@` gets a leading apostrophe);
  `--format json` / `--json FILE` carry everything. Exit status: 0 done, 1 `--fail-on` matched, 2 bad input or no confirmed key, 3 stopped part-way.
- Each declared component is judged on its own. A package that only shares an npm scope with the product (`@vitejs/plugin-react` for Vite) is a lead and never has its version compared with the product's ranges.
- Each exploited id is read once per run however many folders match it; a run that hits Lattice's allowance stops, lists what it did not read and says so once.
- A real manual page, `man lattice-scan`, installed by the `.deb`; `lattice-scan project --help` has examples and the CSV columns.

**Changed:** the range check no longer discards NVD ranges because CISA and NVD name the vendor differently (Kludex and encode for Starlette, Sudo and sudo_project), and treats CISA's `Vitejs` as the npm package `vite`.
`--cve` takes several ids separated by commas in host mode too.

**Found by running it on six real projects, fixed before release:** a loose word match gave 75 candidate ids for one project (3 after matching by identity), and the same Vite CVE got different verdicts in different
projects (fixed by judging each component on its own).

## 0.1.1 — 2026-11-02

Apache-2.0 licence, holder NamiQ LLC; the licence declared in the skill's frontmatter.

## 0.1.0

First release (MIT): match CISA-exploited CVEs, read through Lattice, against the packages, snaps, running container images and kernel of one host.
