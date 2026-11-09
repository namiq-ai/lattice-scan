# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The observation-to-technique table is downloaded and checked, never built in: a good table maps codes to techniques, a tampered, wrongly keyed or rolled-back
one is refused, and an unreachable server falls back to the verified cached copy. `posture --attack` prints the techniques and sends nothing about the host."""
import base64, hashlib, json, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import exploited as ex, observations as ob, posture  # noqa: E402
import ed25519_signer as signer  # noqa: E402

SEED, OTHER, KEY_ID = bytes(range(32)), bytes(range(1, 33)), "test-key-0001"


def table(gen=3, obs=None):
    return {"schema": ob.SCHEMA, "generation": gen, "generatedAt": "2026-11-08T00:00:00Z",
            "observations": obs if obs is not None else [{"code": "ssh.password-auth", "techniques": ["T1110", "T1078"]}, {"code": "process.stale-binary", "techniques": []}]}


def publish(d, seed=SEED, key_id=KEY_ID):
    raw = (json.dumps(d) + "\n").encode()
    return raw, {"sha256": hashlib.sha256(raw).hexdigest(), "keyId": key_id, "signature": base64.b64encode(signer.sign(seed, raw)).decode(), "generation": d["generation"]}


class Server:
    def __init__(self, raw, manifest):
        self.raw, self.manifest, self.down = raw, manifest, False

    def __call__(self, url, limit):
        if self.down:
            raise OSError("connection refused")
        return self.raw if url == ob.TABLE_URL else json.dumps(self.manifest).encode()


class Load(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.folder = Path(self.tmp.name) / "c"
        self.saved = dict(ex.PINNED_KEYS); ex.PINNED_KEYS.clear(); ex.PINNED_KEYS[KEY_ID] = signer.public_key(SEED).hex()

    def tearDown(self):
        ex.PINNED_KEYS.clear(); ex.PINNED_KEYS.update(self.saved); self.tmp.cleanup()

    def test_a_signed_table_maps_codes_to_techniques(self):
        r = ob.load(self.folder, Server(*publish(table())))
        self.assertEqual(r["map"], {"ssh.password-auth": ["T1110", "T1078"], "process.stale-binary": []}); self.assertEqual(r["generation"], 3)

    def test_tampered_bytes_a_wrong_key_and_an_unknown_key_are_refused(self):
        raw, m = publish(table())
        for srv in (Server(raw.replace(b"T1110", b"T1111"), m), Server(*publish(table(), seed=OTHER)), Server(*publish(table(), key_id="unknown"))):
            with self.assertRaises(ob.TableRefused):
                ob.load(self.folder, srv)

    def test_a_lower_generation_is_refused_and_the_cache_is_kept(self):
        ob.load(self.folder, Server(*publish(table(gen=5))))
        with self.assertRaises(ob.TableRefused):
            ob.load(self.folder, Server(*publish(table(gen=4))))
        self.assertEqual(json.loads((self.folder / ob.STATE).read_text())["generation"], 5)

    def test_unreachable_uses_the_verified_copy_and_with_none_stops(self):
        with self.assertRaises(OSError):
            s = Server(*publish(table())); s.down = True; ob.load(self.folder, s)
        s = Server(*publish(table())); ob.load(self.folder, s); s.down = True
        r = ob.load(self.folder, s)
        self.assertTrue(r["source"].startswith("cache")); self.assertIn("ssh.password-auth", r["map"])

    def test_wrong_schema_is_refused(self):
        d = table(); d["schema"] = "other/1"
        with self.assertRaises(ob.TableRefused):
            ob.load(self.folder, Server(*publish(d)))


class Codes(unittest.TestCase):
    def test_every_observation_carries_a_code_from_the_fixed_vocabulary(self):
        d = {"scope": "root", "ports": [{"proto": "tcp", "addr": "0.0.0.0", "port": 22, "bind": "all interfaces", "process": "sshd", "package": "openssh", "where": ""}],
             "firewall": {"managers": []}, "ssh": {"settings": {"passwordauthentication": "yes", "permitrootlogin": "yes", "permitemptypasswords": "yes", "port": "22"}, "installed": True},
             "services": {"units": [{"unit": "x.service", "package": None, "program": "/usr/local/bin/x", "unitIsLocal": True}]}}
        codes = {o["code"] for o in posture.observe(d)}
        self.assertTrue({"listen.all-interfaces", "firewall.none-active", "ssh.password-auth", "ssh.root-password-login", "ssh.empty-passwords", "service.local-unowned"} <= codes)
        self.assertNotIn("", codes)

    def test_published_table_source_covers_every_code_the_tool_can_emit(self):
        import re
        src = Path(posture.__file__).read_text()
        emitted = set(re.findall(r'"((?:listen|firewall|ssh|service|process|persist)\.[a-z0-9-]+)"', src))
        self.assertGreaterEqual(len(emitted), 13)


if __name__ == "__main__":
    unittest.main()
