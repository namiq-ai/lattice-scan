# Self-audit of lattice-scan

A scan tool must not bring trouble of its own. This is what the tool is made of, what was checked, what was found and what is not covered. First audit: 2026-11-06 (version 0.4.3). Repeat it before every release and when a file here changes; the commands are below.

## What a user installs

| Item | What it is | Third-party code |
|---|---|---|
| PyPI wheel / `.pyz` / Claude skill bundle | `cli.py`, `manifests.py`, `report.py`, the Python standard library | **none** (`dependencies = []`) |
| `.deb` | the same files and a `/usr/bin/lattice-scan` wrapper; `Depends: python3 (>= 3.9)` | none; **no maintainer scripts** (no `postinst`, `preinst` or `prerm`) |
| apt repository (namiq.io/apt) | signed `InRelease` (key fingerprint on namiq.io/lattice/docs) | none |

It runs as the user who starts it, installs nothing, changes nothing outside its own records folder (`~/.lattice-scan`, mode 0700, files 0600) and its cache, and sends only CVE ids and the optional key to the Lattice server.

## Checked

1. **Runtime dependencies:** `unzip -p dist/*.whl '*/METADATA' | grep Requires` shows only `Requires-Python: >=3.9`. Nothing to audit with `pip-audit`; there is no dependency tree.
2. **Static analysis:** `uvx bandit -r src`. Result: 0 high, 1 medium, 6 low. The six low ones are `subprocess` calls: every call passes a list, none uses `shell=True`, and the strings in them are fixed or come from `docker` itself. The medium one was the XML parser (below).
3. **Dangerous calls:** `grep -nE "shell=True|eval\(|exec\(|pickle|marshal|os.system|yaml.load|verify=False|_create_unverified" src/` finds nothing.
4. **Network:** HTTPS with certificate verification (no override); redirects are never followed because the key is in a header; a key is refused over plain `http` to anything but this machine; replies are size-limited and their text is passed through `clean()` before it is printed.
5. **Workflows:** every GitHub Action is pinned to a commit SHA; PyPI upload needs an approved `pypi` environment; the release is a draft until a person publishes it, with `SHA256SUMS`.
6. **Build tools:** `uvx pip-audit -r <resolved build requirements> --no-deps`. setuptools before 78.1.1 has a path traversal flaw (PYSEC-2025-49); before 83.0.0 a `MANIFEST.in` exclusion bypass when building an sdist (PYSEC-2026-3447); before 84.1.0 a Windows-only wheel install flaw (GHSA-xmj3-9gf7-h52w). They affect building, not running. The release and CI builds now require `setuptools>=84.1.0` (Python 3.12 in the workflow); `pyproject.toml` asks for `>=78.1.1`, because a user building from the sdist on Python 3.9 can get at most setuptools 82.

## Found and fixed in 0.4.3

| Finding | Fix |
|---|---|
| `pom.xml` parsed with `xml.etree`, which expands entities (memory exhaustion from a hostile project folder) | a file with a `DOCTYPE` or `ENTITY` is skipped and named |
| manifests read without a size limit | files over 5 MB are skipped and named |
| text taken from an image (package names, labels, OS name) or from firmware printed unchanged, so an image could send terminal escape sequences | every string from an image or from firmware goes through `clean()` |
| an RPM database from an image opened with default SQLite settings | `trusted_schema=OFF`, `query_only=ON`, at most 50,000 rows, read from a temporary copy that is removed |
| an image reference beginning with `-` would be read by docker as an option | such references are not passed to docker |
| build requirement `setuptools>=77` | raised (see 6) |

## Not covered, and standing risks

- **The `docker` command is trusted.** Reading images runs `docker` from `PATH`; a hostile `PATH` runs a hostile `docker`. Docker's own daemon is out of scope.
- **Python itself.** The tool runs on the Python of the host. Python 3.9 stopped receiving security fixes in October 2025; the tool still supports it because hosts that run it exist, and says so here. Use 3.10 or later where you can.
- **A hostile image can still make the scan slow** (a very large export): a time limit per image (180 s) and for the run (30 min) bound it, and the run never starts a container.
- **Data sources.** Lattice and namiq.io are trusted for CVE facts; their text is shown as data. A compromised server could send wrong facts, not commands.
- **No signing of the wheel on PyPI** beyond PyPI's own; the `.deb` repository is signed; GitHub releases carry `SHA256SUMS`.
- This is a self-audit by the maintainers' tooling, not an independent penetration test.

## Repeat it

```bash
unzip -p dist/*.whl '*/METADATA' | grep -E '^Requires'
uvx bandit -q -r src
grep -nE 'shell=True|eval\(|exec\(|pickle|marshal|os\.system|verify=False' src/lattice_scan/*.py
printf 'setuptools>=84.1.0\nwheel\n' > build.in && uv pip compile build.in -o build.txt && uvx --python 3.12 pip-audit -r build.txt --no-deps
python3 -m unittest tests.test_hardening
```
