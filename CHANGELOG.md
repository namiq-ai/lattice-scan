# Changelog

## Unreleased

- New: `lattice-scan --discover --all` matches every CISA-listed CVE in the signed exploited index against this host, locally. Nothing is read from Lattice and nothing is sent. The free output is statistics only, in the console, `--format json|csv` and `--json FILE`: counts by verdict (in-range, undetermined, outside-range) and by the year CISA added them, a count under 3 as `<3`, and no CVE id or product name. It needs a verified index no older than 14 days (exit 2 if refused or stale, 3 if unreachable). `recent --all` is unchanged (the thirty-day list).
- New: `lattice-scan --discover` on the host needs no key. It is the same engine as `recent`, with the windows `--daily`, `--weekly` (the default), `--monthly` and `--open`; `recent` accepts `--monthly` too (the whole thirty-day list, what `recent --all` has always read).
- Changed: running `lattice-scan` with no arguments is now `--discover --weekly` (it was `recent --daily`). The weekly window misses less; the read cap below keeps it inside the keyless allowance.
- Changed: one `--max-read` for every command: 20 reads from Lattice without a key, 200 with one (`project` was 40, `recent` and the bare run 200 and 40). Every id is still checked against the host locally; ids that match but are over the cap are listed as skipped (not read), not dropped.
- Fixed: `recent` counted ids as "ruled out" after the read cap was applied.
- New: `lattice-scan index` fetches, checks and caches the signed exploited index (every CISA-exploited CVE with NVD's version ranges) from namiq.io: sha256 against the manifest, then an Ed25519 signature against a pinned key, with generation, schema and as-of date taken from the signed file. It refuses a bad signature, an unknown key (upgrade), a lower generation and a damaged copy, keeps the previous copy, uses the cache for a day, and uses it offline while it is within 14 days of its as-of date. Nothing from the machine is sent. Nothing else uses it yet.
- New, internal: `ed25519`, a verify-only Ed25519 implementation in pure Python (RFC 8032 reference), so the tool can check a signed exploited index with only the standard library. Checked against the RFC test vector and OpenSSL signatures, and it refuses malformed or non-canonical input with False. Nothing uses it yet.

## 0.4.10 — 2026-11-08

- Fixed: the bundled script (`lattice-scan.pyz`, which the Claude skill and the plugin zip also carry) did not contain `share.py`, so `lattice-scan inventory --share` stopped with an ImportError there (it worked from a pip or apt install). The bundle now takes every module of the package, and a test runs the bundled script through `inventory --share`.
- New: `lattice_version`, one module for version comparison (semver, pep440, dpkg, apk, rpm, maven, generic), NVD range bounds, product ids and the verdict order, with golden tables of at least 200 cases per scheme and a stored corpus of expected matches. The scan's behaviour is unchanged; a finding in the project JSON now carries its `pid`. See docs/LATTICE-VERSION.md.
- Fixed: `project` no longer reads dependency files inside a `.build` folder (a build output folder; one project kept a third-party checkout there and its dependencies were counted as the project's own).

## 0.4.9 — 2026-11-08

- New: `--format json|csv` and `--json FILE` on the host check, `recent` and `enrich`: the RESULT BY CVE table as one JSON document (`lattice-scan-result/1`, with the exit code and counts) or CSV, nothing else on standard output. The file is written with mode 0600. The console output is unchanged.
- New: a test fails when the README or the skill text shows a `lattice-scan` command with an option the program does not define.
- Changed: a host check or `recent` that Lattice stops part-way (limit reached, unreachable, refused) now exits 3, as `project` and `enrich` already do. Exit 1 is kept for a `--fail-on` match. A script that tested for exit 1 after a stopped run must test for 3.
- New: `--fail-on never|in-range|candidate` on the host scan and on `recent`: exit 1 when a candidate (or one whose version check says in-range) is found. The default stays `never`.
- Fixed: the skill text said the host check takes `--format csv|json`; it does not (that is `project` and `posture`).
- New: `lattice-scan project . --discover` checks a project against namiq.io's list of recent exploited CVEs with no CVE ids and no key. The window is monthly by default; `--daily`, `--weekly`, `--monthly` and `--open` choose another. The list request carries nothing from the project, and only the ids whose product a declared dependency matches are read from Lattice. Without ids, the "nothing to check" message now names `--discover` first.

## 0.4.8 — 2026-11-08

- New: `lattice-scan inventory --share` prints the host's important software as one block to copy and paste into My products in the Lattice Analyst. The block (`LATTICE INVENTORY v1`, at most 150 lines and 12 KB, format in `docs/INVENTORY-BLOCK.md`) holds the kernel, what listens (with the package that owns it), any installed item the tool's own matcher links to an entry of today's CISA list, the running container images, snaps and a curated list of server, edge and admin software, each with the reason it is listed, and the firewall and SSH settings. It names software and versions only: no host name, address, user name, serial or path. It reads namiq.io's public recent list once so that nothing the list could concern is left out; `--no-feed` skips that and the block says so. `--max-lines N` lowers the cap; `--all FILE` writes every package, snap and image to a private file. Nothing else leaves the machine.

## 0.4.7 — 2026-11-07

- A key about to end says so. When the key you use has 14 days or fewer left, the tool prints one line a day on stderr (not with `--quiet`, and never in csv or json output): the days left, and that a renewal link was mailed to the address the key was issued for. The tool never opens or follows the link.
- A repeat run asks Lattice nothing it was just told. Answers to a lookup of one CVE id and to a detail read are kept in your cache folder for 6 hours (`LATTICE_SCAN_READ_CACHE`, `LATTICE_SCAN_READ_CACHE_HOURS`); `--again` and `--refresh` ask again. They hold public graph data only, nothing about this host.
- Keyless pacing follows the server. The per-minute limit Lattice reports in each answer (`access.limits.calls_per_minute`) is remembered for a week, so a limit the operator raises shortens your scans without a new release. Until told otherwise it stays 5 a minute.
- `recent` reads the most urgent ids first (ransomware use recorded, patch date passed, then CISA priority and EPSS), and says before the first call how many calls that will be, how many are already cached and how long pacing makes it. A run that is stopped has read what mattered most.
- The "20 reads an hour and 60 a day" wording is gone from the tool, the manual and the skill: the server states the allowance in every answer.
- One call per match, and ids looked up ten at a time. A Lattice server that carries the urgency fields in its lookup answer (EPSS, CISA's SSVC, weakness, description, references, record status) no longer needs a second `graph_node` read per match, and once it has shown that, the tool fetches up to 10 ids in one request. A 12-id scan on such a server is 3 lookups instead of 12 lookups plus 12 detail reads. Against an older server nothing changes: it is never sent a batch, and `graph_node` still supplies the detail. A batch that fails turns batching off for that run and the ids are looked up one by one.

## 0.4.6 — 2026-11-06

- `lattice-scan recent` now reads everything in namiq.io's recent list, as the name says. It read only the weekly part (7 days), so the 32 exploited CVEs CISA added earlier in the last 30 days (the `open` part) were left out unless you ran `recent --open`; on one day the list held 65 ids and the scan looked at 33. The default is now `--period all` (weekly and open together, each id once); `--daily`, `--weekly` and `--open` still narrow it, and `--all` names the default. `--max-read` defaults to 200, so the whole list is considered. Running `lattice-scan` with no argument still reads the daily list.
- The summary says what happened to every id: "exploited 32 ruled out, 3 may match; critical 30 ruled out, 0 may match". A critical id that matches nothing installed is not listed, which looked like 27 ids missing from "3 exploited and 30 critical read".

## 0.4.5 — 2026-11-06

- Open findings are re-checked on every run, and the report separates today from the past. After a matcher fix, findings made by the old matcher stayed `OPEN` for ever (seven false ones on one host: BeyondTrust, Siemens, ONLYOFFICE and four Plex CVEs, each matched on an ordinary word like `support` or `media`). Now a finding the current matching no longer produces is withdrawn with the reason recorded (`WITHDRAWN` block; `lattice-scan list` still shows it; it no longer counts as open or as touching the host). New findings store the vendor and product they matched on and are matched again as they are; older ones stored only a title and a reason, so only the one rule that changed (an ordinary-word product needs its vendor installed) is applied to them.
- A second table, `STILL OPEN FROM EARLIER RUNS`, lists the findings recorded before today, apart from the table of what this run read, so "0 may match" is no longer followed by eleven `OPEN` rows without a heading.
- Ages are counted from today when printed. A saved finding showed the "days ago" and "overdue by" of the day it was recorded (26 days for a CVE listed 29 days earlier).
- A finer reading of a name match, shown in the earlier-findings table and in the detail as `assessment:`: `OUTSIDE RANGE` (the installed version is outside every NVD range), `LIKELY FIXED` (inside the upstream range, but the version has a distro revision and the package's own changelog names the CVE; read that line and record it with `resolve --status fixed --proof`), `VERIFY` (a kernel whose upstream number is in range but is a distro or vendor build). Nothing is closed by it.
- A deep scan is no longer lost to the next quick run. Every run collected the inventory from scratch and overwrote `inventory.json`, so the image contents a deep scan read (all local images, and the Python, Node, Java and Ruby packages inside them) were gone after one plain run, and the CVE checks and "installed things the description names" leads fell back to the running images only. A complete deep scan is now kept in `deep-images.json` in the records folder, with each image's id. A later quick run reuses it for every local image whose id is unchanged (at most 30 days old, `LATTICE_SCAN_DEEP_CACHE_DAYS`), says so on stderr, and opens only what is new or changed. An image that changed or is gone is not reused. `--refresh` or `LATTICE_SCAN_DEEP_CACHE=off` opens every image again. Host packages, snaps, running images and the kernel are still collected on every run.
- The RESULT BY CVE row of a CVE you name that CISA does not list now says what the detail below it found. When the description names something installed, the row reads `lead` (not `unlisted`) and its last column names it: for example `openssh on the host (...)`, `musl in 9 opened images`, whether any opened image has all of them, and the "before X" version the description gives. It is a lead for a person to read, not a match. A CVE whose description names nothing installed keeps the plain `unlisted` row.

## 0.4.4 — 2026-11-06

- The package page on PyPI (the README) now has an overview table of what each command reads and what leaves the machine, and its Use section is grouped by purpose and lists `--deep`, `--refresh --inventory`, `--list` and `posture`. PyPI shows it from the next release.
- A CVE you name that the graph holds only as a bare node now says so. A new CVE can be in Lattice as a stub with no NVD record, so `lattice-scan --cve ID` printed only "not in the graph's CISA list" and nothing else, and it looked as if the scan had failed. It now explains that the graph has no NVD record, description, EPSS, SSVC, weakness, ATT&CK link or reference for the id yet, that a bare node says nothing about risk, and what to do. When namiq.io's list of recent CVEs has the id (that request carries no id), it adds the product, CVSS and publication date from that list and whether something installed may match the product.

## 0.4.3 — 2026-11-06

- Self-audit (docs/SELF-AUDIT.md): the tool has no runtime dependency, and the `.deb` has no maintainer scripts. The audit found and fixed: a `pom.xml` that declares entities or a DOCTYPE is skipped (it could exhaust memory); a manifest over 5 MB is skipped and named; text taken from an image or from firmware has control characters replaced before it is printed; an RPM database from an image is opened query-only with `trusted_schema` off and at most 50,000 rows; an image reference starting with a dash is not passed to docker; the build tools are required as setuptools 84.1.0 or later in CI and release (older versions have known advisories that affect building, not running).
- New command `lattice-scan posture`: what this host exposes and runs, beyond what is installed. Quick: the listening TCP and UDP sockets (all interfaces, loopback only or one address) with the owning process, package or container image; the host firewall (ufw, firewalld, nftables, iptables); the SSH server settings (first value wins, `Include` followed, OpenSSH defaults for unset keywords); the running services and whether a package owns each program. `--deep` also reads every process it may (program in a temporary folder, deleted while running, memory only, owned by no package, and outbound connections of those) and persistence points (`ld.so.preload`, extra uid 0 accounts, cron and setuid files no package owns). The scope follows the user: as root it reads firewall rules, `sshd -T` and every process; otherwise it lists what it could not read and never runs `sudo`. It reports signals for a person to read, each saying why it can be harmless; it is not an incident detector. Read only, nothing is sent, command line arguments are never recorded. Programs replaced by a package update after they started are one restart note, not a suspicion.

- `--refresh` now runs the scan. It collects the inventory again, shows its totals, then does what the same command would do without `--refresh` (the daily list when no id is given). Before, it stopped after the inventory. `--refresh --inventory` keeps the old behaviour: inventory only, no network call.
- The default scan no longer drops the findings still open from earlier runs. When nothing on the day's list matched, it printed only the list's rows; now it also lists every open finding with its saved detail, as a scan of named ids already did.
- Every row of the default scan's table now has a detail block: for a CISA-listed CVE that matched nothing, the dates, CVSS, EPSS and ransomware flag from namiq.io's list and why it did not match (the words it needs and which this machine has); for a watched critical CVE, why it is watched. Each says how to read the full detail from Lattice (`lattice-scan --cve ID`). No extra call is made.
- A CVE you name that CISA does not list is now related to what is installed. The words of its description that are also installed on the host or inside an opened image are listed (for the OpenSSH on musl libc flaw: openssh on the host, musl in the Alpine images), with whether any opened image has all of them and the version text of the description. It is a lead, not a match, and costs no call.
- A product named with ordinary words no longer matches an unrelated installed package. CISA's "Docs Server", "Remote Support", "Software Center" and "Media Server" matched `gnome-user-docs`, `armv8crc-support`, `gnome-control-center` and `media-player-info`, and "WP Libre Form" matched two different packages (`libhtml-form-perl` and `libre2-11`). Now a product made only of ordinary words (docs, support, media, center, form, libre and the like) matches only when the vendor is also installed, and a product of several words matches a host package only when all its words are in one installed name or the vendor is installed. `Google Brotli`, `ISC BIND` and the kernel still match. A finding already recorded by an earlier run stays until you close it with `resolve CVE-... --status not-applicable`.
- The CVE table and the project report use up to 160 columns on a wide terminal (they stopped at 110). `--width` is unchanged.

## 0.4.2 — 2026-11-06

- The host inventory now knows the machine and what is inside each container image. Hardware: manufacturer, product model and version, board, firmware version and date, architecture, CPU, memory, virtualisation (from the kernel's DMI table, or the device tree on ARM boards; serial numbers and UUIDs are not read). Images: for every local image the tool reads its metadata and, without starting it (`docker create --network none`, then `docker cp` of the OS release file and the apk or dpkg package list, then `docker rm`), its base OS and release, its packages, its version label and its `*_VERSION` variables. Before, `postgres:16-alpine` was only a name, so a flaw in the musl or busybox inside it could never become a candidate. Now a CISA entry whose product words are all found in one image becomes a candidate that names that image and compares that image's package version. A CISA entry for firmware or a board matches the machine's maker and model. Other environment values of an image are never kept. `--refresh` prints the hardware and each image's OS and package count. `LATTICE_SCAN_IMAGES=running` opens only running images, `off` none. Distroless images and RPM databases give metadata only. Nothing leaves the machine.
- Images are read further. RPM images (sqlite rpm databases: Fedora, RHEL 9 and later, Amazon Linux 2023) and distroless images (`/var/lib/dpkg/status.d`) now give their package lists. With `--deep` the tool streams `docker export` once per image and records the Python, Node, Java and Ruby packages inside (names and versions from `dist-info`, `package.json`, jar file names and gem folders; 180 seconds per image, then marked partial; `LATTICE_SCAN_IMAGES_LANG=all` for every image, `off` for none). Each image shows the local image it was built on when that image's layers are its first layers. No registry is contacted. Berkeley DB and ndb rpm databases, Go and Rust binaries are not read.
- Two inventory levels. Quick (the default): hardware, host packages and snaps, and the images that containers are running (OS release and package list), with the package database chosen by the image's OS family and up to four images read at once. On the test host (7 running images) it takes about 12 seconds, where reading all 24 local images one by one took 87. Deep (`--deep` or `LATTICE_SCAN_LEVEL=deep`): also every other local image and the Python, Node, Java and Ruby packages inside every image; it took about 6 minutes for 24 images on the test host. `LATTICE_SCAN_IMAGES` and `LATTICE_SCAN_IMAGES_LANG` override the level. Which local image an image was built on is found in both levels.
- Reading images is safe to interrupt and to fail. Each container is labelled and removed after its image, on an error too; when the run ends or is stopped (Ctrl-C, SIGTERM) all of its containers are removed; a run killed outright is cleaned up by the next one (containers with the label older than 15 minutes). A file larger than 40 MB is never read into memory. A damaged rpm database, a broken export stream or any error inside one image skips that image and names it. Images are not opened when less than 1 GB is free where Docker keeps its data, and no new image is started after 30 minutes. Checked on Python 3.9, 3.12 and 3.14.
- A person (or an agent) now learns that a deeper scan exists and how far a scan has got. After a quick inventory, one line on stderr says how many local images were opened, that the packages inside images were not, how long `--deep` takes (a rough estimate) and when a deep scan was last done (a repeat is suggested after 30 days). A deep scan prints the estimate first, then `[n/N %]` with elapsed time for each image, and a summary (opened, not opened, seconds); a completed one is recorded in `deep.json`. `--quiet` prints none of it. The skill runs quick first, says what quick did not cover, offers deep only after the hint or a thorough request, runs it in the background and reports one line per check-in.
- `--refresh` now prints totals instead of every package: the OS, kernel and hardware, the number of snaps and packages, a summary of the images (how many were opened, by base OS, packages inside them) and the path of `inventory.json`, which still holds the full lists. About 30 lines instead of 2,800 on the test host. `--list` prints everything as before.

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
