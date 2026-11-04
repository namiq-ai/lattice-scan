# Changelog

## Unreleased

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
