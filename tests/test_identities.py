"""The signed identity list on the client: every row of the failure table, signed by a throwaway test key. Reserved CVE ids, invented packages."""
import base64, datetime as dt, hashlib, json, sys, tempfile, unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import tmpfold  # noqa: E402  (one temp root per test run, removed at exit)
from lattice_scan import identities as ids, lattice_identity as li  # noqa: E402
import ed25519_signer as signer  # noqa: E402

SEED, OTHER = bytes(range(32)), bytes(range(1, 33))
KEY, OTHER_KEY = "test-key-0001", "test-key-0002"
T0 = dt.datetime(2099, 1, 3, 12, 0, tzinfo=dt.timezone.utc)
H = dt.timedelta(hours=1)
ROW = {"cve": "CVE-2099-0001", "pids": ["deb:examplessh"], "origin": ["osv-debian"], "component": {"role": "server", "binaries": ["examplessh-server"]},
       "kevAdded": "2099-01-02", "kevDue": "2099-01-23"}


def doc(generation=5, as_of="2099-01-02", rows=None, schema=ids.SCHEMA, aliases=None):
    return {"schema": schema, "generation": generation, "generatedAt": "2099-01-03T00:00:00.000Z", "exploitedAsOf": as_of, "kevRows": 3,
            "rows": rows if rows is not None else [ROW], "aliases": aliases or [], "sources": []}


def publish(d, seed=SEED, key=KEY, sign=True):
    raw = (json.dumps(d) + "\n").encode()
    sig = base64.b64encode(signer.sign(seed, raw)).decode() if sign else ""
    return raw, {"schema": "lattice-identities-manifest/1", "generation": d["generation"], "sha256": hashlib.sha256(raw).hexdigest(), "keyId": key, "signature": sig}


class Server:
    def __init__(self, raw, manifest):
        self.raw, self.manifest, self.calls, self.down = raw, manifest, [], False

    def __call__(self, url, limit):
        self.calls.append(url)
        if self.down:
            raise OSError("connection refused")
        return self.raw if url == ids.LIST_URL else json.dumps(self.manifest).encode()


class Base(unittest.TestCase):
    def setUp(self):
        self._keys = ids.PINNED_KEYS
        ids.PINNED_KEYS = {KEY: signer.public_key(SEED).hex()}
        self.dir = Path(tmpfold.mkdtemp())

    def tearDown(self):
        ids.PINNED_KEYS = self._keys


class FailClosed(Base):
    def test_a_signed_list_is_accepted_cached_and_turned_into_join_rows(self):
        r = ids.load(self.dir, Server(*publish(doc())), T0)
        self.assertEqual((r["source"], r["generation"], r["stale"]), ("network", 5, False))
        rows, aliases = ids.join_inputs(r["doc"])
        self.assertEqual(rows, [li.Row("CVE-2099-0001", ("deb:examplessh",), li.Component("server", ("examplessh-server",)), "osv-debian")])
        self.assertEqual(aliases, {})
        self.assertEqual(ids.load(self.dir, Server(b"", {}), T0 + H)["source"], "cache")

    def test_an_unsigned_list_is_refused_never_read_as_unsigned(self):
        with self.assertRaisesRegex(ids.IdentitiesRefused, "without a signature"):
            ids.load(self.dir, Server(*publish(doc(), sign=False)), T0)

    def test_a_bad_signature_or_an_unknown_key_is_refused(self):
        raw, m = publish(doc(), seed=OTHER)
        with self.assertRaisesRegex(ids.IdentitiesRefused, "does not verify"):
            ids.load(self.dir, Server(raw, m), T0)
        with self.assertRaisesRegex(ids.IdentitiesRefused, "does not know"):
            ids.load(self.dir, Server(*publish(doc(), key=OTHER_KEY)), T0)

    def test_an_older_generation_is_refused_and_the_cache_kept(self):
        ids.load(self.dir, Server(*publish(doc(generation=7))), T0)
        with self.assertRaisesRegex(ids.IdentitiesRefused, "rolled-back"):
            ids.load(self.dir, Server(*publish(doc(generation=6))), T0 + 13 * H)
        self.assertEqual(ids.load(self.dir, Server(b"", {}), T0 + H)["generation"], 7)   # within the refresh window: the kept cache answers

    def test_a_row_with_range_or_verdict_fields_refuses_the_whole_list(self):
        for field in ("ranges", "verdict", "fixed", "cvss"):
            with self.subTest(field=field), self.assertRaisesRegex(ids.IdentitiesRefused, field):
                ids.load(Path(tmpfold.mkdtemp()), Server(*publish(doc(rows=[{**ROW, field: []}]))), T0)

    def test_malformed_ids_schema_and_size_are_refused(self):
        bad = [doc(rows=[{**ROW, "pids": ["deb:Example SSH"]}]), doc(rows=[{**ROW, "cve": "CVE-99"}]), doc(schema="lattice-identities/2"),
               doc(aliases=[{"from": "x", "to": "deb:examplessh"}])]
        for d in bad:
            with self.subTest(d=d), self.assertRaises(ids.IdentitiesRefused):
                ids.load(Path(tmpfold.mkdtemp()), Server(*publish(d)), T0)
        raw, m = publish(doc())
        old = ids.MAX_BYTES
        ids.MAX_BYTES = len(raw) - 1
        try:
            with self.assertRaisesRegex(ids.IdentitiesRefused, "larger than the limit"):
                ids.load(self.dir, Server(raw, m), T0)
        finally:
            ids.MAX_BYTES = old

    def test_a_damaged_download_is_refused(self):
        raw, m = publish(doc())
        with self.assertRaisesRegex(ids.IdentitiesRefused, "does not match its manifest"):
            ids.load(self.dir, Server(raw.replace(b"examplessh", b"examplesst"), m), T0)

    def test_a_cache_file_edited_on_disk_is_not_used(self):
        ids.load(self.dir, Server(*publish(doc())), T0)
        (self.dir / ids.CACHE).write_bytes((self.dir / ids.CACHE).read_bytes().replace(b"examplessh", b"examplesst"))
        with self.assertRaises(ids.IdentitiesUnavailable):
            s = Server(b"", {})
            s.down = True
            ids.load(self.dir, s, T0 + H)


class Freshness(Base):
    def test_unreachable_uses_the_verified_cache_and_says_so(self):
        ids.load(self.dir, Server(*publish(doc())), T0)
        s = Server(b"", {})
        s.down = True
        r = ids.load(self.dir, s, T0 + 13 * H)
        self.assertEqual(r["source"], "cache")
        self.assertIn("could not reach", r["note"])

    def test_unreachable_with_nothing_cached_is_unavailable(self):
        s = Server(b"", {})
        s.down = True
        with self.assertRaises(ids.IdentitiesUnavailable):
            ids.load(self.dir, s, T0)

    def test_older_than_seven_days_is_stale_and_require_fresh_refuses(self):
        r = ids.load(self.dir, Server(*publish(doc(as_of="2098-12-20"))), T0)
        self.assertTrue(r["stale"])
        with self.assertRaisesRegex(ids.IdentitiesRefused, "days old"):
            ids.load(Path(tmpfold.mkdtemp()), Server(*publish(doc(as_of="2098-12-20"))), T0, require_fresh=True)

    def test_an_unchanged_list_is_not_downloaded_again(self):
        srv = Server(*publish(doc()))
        ids.load(self.dir, srv, T0)
        ids.load(self.dir, srv, T0 + 13 * H)
        self.assertEqual(srv.calls.count(ids.LIST_URL), 1)


class Bundled(Base):
    def bundle(self, d, seed=SEED):
        import types, zlib
        raw, m = publish(d, seed=seed)
        mod = types.SimpleNamespace(MANIFEST=json.dumps(m), LIST=(base64.b64encode(zlib.compress(raw)).decode(),))
        return mock.patch.dict(sys.modules, {"lattice_scan.identities_bundled": mod})

    def down(self):
        s = Server(b"", {})
        s.down = True
        return s

    def test_unreachable_with_nothing_cached_uses_the_release_copy_and_says_how_old(self):
        with self.bundle(doc(as_of="2099-01-01")):
            r = ids.load(self.dir, self.down(), T0)
        self.assertEqual((r["source"], r["generation"]), ("bundled", 5))
        self.assertIn("bundled in this release, 2 days old", r["note"])

    def test_a_release_copy_that_does_not_verify_is_not_used(self):
        with self.bundle(doc(), seed=OTHER), self.assertRaises(ids.IdentitiesUnavailable):
            ids.load(self.dir, self.down(), T0)

    def test_a_release_copy_older_than_one_already_accepted_is_not_used(self):
        ids.load(self.dir, Server(*publish(doc(generation=9))), T0)
        (self.dir / ids.CACHE).write_bytes(b"damaged")
        with self.bundle(doc(generation=5)), self.assertRaises(ids.IdentitiesUnavailable):
            ids.load(self.dir, self.down(), T0 + H)

    def test_the_shipped_copy_verifies_with_the_pinned_key(self):
        ids.PINNED_KEYS = self._keys
        d = ids._bundled()
        self.assertIsNotNone(d)
        self.assertGreater(len(d["rows"]), 100)


class EndToEnd(Base):
    def test_the_list_and_the_join_rule_out_a_client_only_host(self):
        r = ids.load(self.dir, Server(*publish(doc())), T0)
        rows, aliases = ids.join_inputs(r["doc"])
        arts = li.host_artefacts({"manager": "dpkg", "packages": {"examplessh-client": "1:9.2p1-2"}, "sources": {"examplessh-client": "examplessh"}})
        [j] = li.join(arts, rows, aliases)
        self.assertEqual(li.assess(rows[0], j, [{"scheme": "dpkg", "end_excluding": "1:9.2p1-9"}], li.installed_binaries(arts)).kind, "component-absent")


if __name__ == "__main__":
    unittest.main()
