"""The identity join (ADR-LATTICE-SCAN-004 AD-1, AD-6, AD-7): fixtures F1-F4 and F8 of the renovation brief, plus the rules each depends on.

Synthetic inventories only: invented versions, no host's real package list. The CVE ids are public CISA entries named in the brief's addendum.
"""
import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from lattice_scan import lattice_identity as li  # noqa: E402

OPENSSH = li.Row("CVE-2026-123158", ("deb:openssh",), li.Component("server", ("openssh-server",)), "osv-debian")
CHROMIUM = li.Row("CVE-2026-125350", ("deb:chromium", "generic:chromium"), None, "osv-debian")
SAP_DISPATCHER = li.Row("CVE-2026-89126", ("generic:sap-web-dispatcher",), None, "alias")
DEB_RANGE = [{"scheme": "dpkg", "end_excluding": "1:9.2p1-2+deb12u9"}]       # the distribution's own fixed version
UPSTREAM_RANGE = [{"start_including": "1.0", "end_excluding": "130.0.6723.91"}]  # an NVD bound: no scheme, so generic


def host(packages, sources=None, manager="dpkg", **extra):
    return {"manager": manager, "packages": packages, "sources": sources or {}, "snaps": {}, "kernel": "", **extra}


def outcomes(inv, rows, ranges, aliases=None, words=None):
    arts = li.host_artefacts(inv)
    bins = li.installed_binaries(arts)
    joins = li.join(arts, rows, aliases)
    out = [li.assess(next(r for r in rows if r.cve == j.cve), j, ranges, bins) for j in joins]
    for r in rows:
        out += [li.assess(r, j, ranges, bins) for j in li.word_leads(r.cve, (words or {}).get(r.cve, ()), arts, joins)]
    return out


class Fixtures(unittest.TestCase):
    def test_F1_ssh_client_only_is_component_absent_not_a_candidate(self):
        inv = host({"openssh-client": "1:9.2p1-2+deb12u3"}, {"openssh-client": "openssh"})
        [o] = outcomes(inv, [OPENSSH], DEB_RANGE)
        self.assertEqual(o.kind, "component-absent")
        self.assertIn("openssh-server", o.evidence)

    def test_F1_control_with_the_server_installed_it_is_a_candidate(self):
        inv = host({"openssh-client": "1:9.2p1-2+deb12u3", "openssh-server": "1:9.2p1-2+deb12u3"},
                   {"openssh-client": "openssh", "openssh-server": "openssh"})
        kinds = {o.join.artefact.name: o.kind for o in outcomes(inv, [OPENSSH], DEB_RANGE)}
        self.assertEqual(kinds, {"openssh-client": "candidate", "openssh-server": "candidate"})

    def test_F2_a_version_table_named_after_chromium_is_at_most_a_lead(self):
        inv = host({"node-electron-to-chromium": "1.4.700-1"})
        out = outcomes(inv, [CHROMIUM], UPSTREAM_RANGE, words={CHROMIUM.cve: ["chromium"]})
        self.assertEqual([o.kind for o in out], ["lead"])

    def test_F3_networkd_dispatcher_is_not_the_sap_web_dispatcher(self):
        inv = host({"networkd-dispatcher": "2.2.4-1"})
        out = outcomes(inv, [SAP_DISPATCHER], UPSTREAM_RANGE, words={SAP_DISPATCHER.cve: ["sap", "web", "dispatcher"]})
        self.assertEqual(out, [])

    def test_F4_google_chrome_stable_joins_through_a_reviewed_alias(self):
        inv = host({"google-chrome-stable": "130.0.6723.58-1"})
        rng = [{"scheme": "dpkg", "end_excluding": "130.0.6723.91-1"}]
        [o] = outcomes(inv, [CHROMIUM], rng, aliases={"deb:google-chrome-stable": "deb:chromium"})
        self.assertEqual((o.kind, o.join.confidence), ("candidate", "alias"))

    def test_F4_without_the_alias_it_is_only_a_lead(self):
        inv = host({"google-chrome-stable": "130.0.6723.58-1"})
        out = outcomes(inv, [CHROMIUM], UPSTREAM_RANGE, words={CHROMIUM.cve: ["chrome"]})
        self.assertEqual([o.kind for o in out], ["lead"])

    def test_F8_a_backported_fix_is_outside_the_distribution_range(self):
        inv = host({"openssh-server": "1:9.2p1-2+deb12u9"}, {"openssh-server": "openssh"})
        [o] = outcomes(inv, [OPENSSH], DEB_RANGE)
        self.assertEqual(o.kind, "outside-range")


class Rules(unittest.TestCase):
    def test_a_range_only_in_upstream_numbers_never_makes_a_candidate(self):
        inv = host({"openssh-server": "1:9.2p1-2+deb12u3"}, {"openssh-server": "openssh"})
        [o] = outcomes(inv, [OPENSSH], [{"end_excluding": "9.9"}])
        self.assertEqual(o.kind, "undetermined")

    def test_no_version_verdict_is_undetermined(self):
        inv = host({"openssh-server": "1:9.2p1-2+deb12u3"}, {"openssh-server": "openssh"})
        [o] = outcomes(inv, [OPENSSH], None)
        self.assertEqual(o.kind, "undetermined")

    def test_without_source_names_the_binary_is_the_identity(self):
        arts = li.host_artefacts(host({"openssh-client": "1:9.2p1-2"}))
        self.assertEqual(arts[0].pid, "deb:openssh-client")
        self.assertEqual(li.join(arts, [OPENSSH]), [])

    def test_owner_and_scheme_follow_the_package_manager(self):
        for manager, eco, scheme in (("dpkg", "deb", "dpkg"), ("rpm", "rpm", "rpm"), ("apk", "apk", "apk")):
            [a] = li.host_artefacts(host({"zlib": "1.3"}, manager=manager))
            self.assertEqual((a.pid, a.scheme, a.owner), (f"{eco}:zlib", scheme, manager))

    def test_kernel_and_node_are_artefacts_but_a_macos_kernel_is_not(self):
        arts = li.host_artefacts(host({}, kernel="6.1.0-25-amd64", node="v20.11.1"))
        self.assertEqual({a.owner for a in arts}, {"kernel", "runtime"})
        self.assertEqual([a.version for a in arts if a.owner == "runtime"], ["20.11.1"])
        self.assertEqual(li.host_artefacts(host({}, kernel="24.1.0", family="macos")), [])

    def test_a_word_lead_never_repeats_an_identity_join(self):
        inv = host({"openssh-server": "1:9.2p1-2+deb12u3"}, {"openssh-server": "openssh"})
        out = outcomes(inv, [OPENSSH], DEB_RANGE, words={OPENSSH.cve: ["openssh"]})
        self.assertEqual([o.kind for o in out], ["candidate"])

    def test_the_module_imports_only_the_standard_library_and_lattice_version(self):
        src = (ROOT / "src" / "lattice_scan" / "lattice_identity.py").read_text()
        mods = {l.split()[1].split(".")[0] for l in src.splitlines() if l.startswith(("import ", "from "))}
        self.assertLessEqual(mods, {"__future__", "re", "typing", "lattice_scan", "lattice_version"})

    def test_the_vendored_hash_names_this_module(self):
        import hashlib
        lines = dict(reversed(l.split()) for l in (ROOT / "src" / "lattice_scan" / "VENDORED.sha256").read_text().splitlines())
        src = (ROOT / "src" / "lattice_scan" / "lattice_identity.py").read_bytes()
        self.assertEqual(hashlib.sha256(src).hexdigest(), lines.get("lattice_identity.py"),
                         "lattice_identity.py changed: run python3 packaging/vendor_hash.py and update graph-mcp's copy")


if __name__ == "__main__":
    unittest.main()
