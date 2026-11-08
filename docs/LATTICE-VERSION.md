# lattice_version: one implementation of versions, ranges and product ids

`src/lattice_scan/lattice_version.py` is the only place lattice-scan decides whether a version is inside an affected range, what a product's id is, and which
verdict is stronger. Any other program that must give the same answer (the exploited-index build, the MCP item tools, the report service) copies this file
unchanged and checks it against `VENDORED.sha256` in its own CI. After you change the module, run `python3 packaging/vendor_hash.py` and update every copy.

**Schemes.** semver, pep440, dpkg, apk, rpm, maven, generic. Each has a table of at least 200 cases in `tests/golden/version_<scheme>.json`. dpkg is checked
against `dpkg --compare-versions` and pep440 against the `packaging` library; the others follow their own specifications (semver 2.0.0 section 11, rpmvercmp,
apk-tools, Maven ComparableVersion) and have no external oracle. `python3 tests/golden/make_golden.py` regenerates the tables.

**Ranges** follow NVD: `start_including` and `end_including` are inclusive, `start_excluding` and `end_excluding` are exclusive. A version in a scheme different
from the range's, or one the scheme cannot parse, is undetermined, never outside-range. A range whose scheme is `generic` (NVD's bounds carry none) is compared
by dotted upstream numbers with a version of any scheme; a distribution can fix a CVE under an unchanged upstream number, so that result is a lead.

**Product ids.** `pid(name, ecosystem)` is `<ecosystem>:<normalised-name>`. `tests/corpus/` stores the (pid, CVE, verdict) triples the project matcher must give on
synthetic fixtures; a pair added or removed fails `tests/test_corpus.py`.

**Windows.** `window_days(anchor, name)` returns UTC calendar days anchored on the index's `exploitedAsOf`, never the local clock.
