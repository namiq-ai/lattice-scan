# Changelog

## Unreleased

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
