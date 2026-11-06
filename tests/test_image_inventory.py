# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""the inventory knows the machine's hardware and what is inside each container image. Invented products, a fake docker, reserved ids only."""
import io, json, os, shutil, sys, tarfile, tempfile, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli  # noqa: E402

ALPINE_OS = 'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.21.3\nPRETTY_NAME="Alpine Linux v3.21"\n'
APK_DB = "P:musl\nV:1.2.5-r8\n\nP:busybox\nV:1.37.0-r12\n\nP:libexampleq\nV:2.0.1-r0\n"
DEBIAN_OS = 'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n'
DPKG = "Package: zlib1g\nStatus: install ok installed\nVersion: 1:1.3.dfsg-1\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 9\n"


def tar_of(text: str) -> bytes:
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as t:
        i = tarfile.TarInfo("f")
        i.size = len(text.encode())
        t.addfile(i, io.BytesIO(text.encode()))
    return b.getvalue()


IMAGES = {
    "redis:7-alpine": {"Id": "sha256:aaaaaaaaaaaaaaaa", "Os": "linux", "Architecture": "arm64",
                       "Config": {"Env": ["PATH=/x", "REDIS_VERSION=7.4.9", "GOSU_VERSION=1.19", "REDIS_PASSWORD=hunter2"], "Labels": {}},
                       "files": {"etc/os-release": ALPINE_OS, "lib/apk/db/installed": APK_DB}},
    "app:1": {"Id": "sha256:bbbbbbbbbbbbbbbb", "Os": "linux", "Architecture": "amd64", "Config": {"Env": [], "Labels": {"org.opencontainers.image.version": "4.5"}},
              "files": {"etc/os-release": DEBIAN_OS, "var/lib/dpkg/status": DPKG}},
    "tiny:1": {"Id": "sha256:cccccccccccccccc", "Os": "linux", "Architecture": "amd64", "Config": {}, "files": {}},
}


class FakeDocker:
    def __init__(self):
        self.calls = []

    def run(self, cmd):
        self.calls.append(cmd)
        if cmd[:3] == ["docker", "image", "inspect"]:
            m = IMAGES.get(cmd[3])
            return json.dumps([{k: v for k, v in m.items() if k != "files"}]) if m else ""
        if cmd[:2] == ["docker", "create"]:
            return "cid-" + cmd[-1] + "\n"
        if cmd[:3] == ["docker", "image", "ls"]:
            return "redis:7-alpine\napp:1\ntiny:1\n<none>:<none>\n"
        return ""

    def run_bytes(self, cmd):
        self.calls.append(cmd)
        ref, path = cmd[2][4:].split(":/", 1)
        txt = IMAGES[ref]["files"].get(path)
        return tar_of(txt) if txt else b""


def collect(running=("redis:7-alpine",), lang="off", level="deep", images=None):
    fd = FakeDocker()
    with mock.patch.object(cli, "run", fd.run), mock.patch.object(cli, "run_bytes", fd.run_bytes), mock.patch.object(cli.shutil, "which", lambda c: "/x/docker"):
        envs = {"LATTICE_SCAN_LEVEL": level}
        if lang:
            envs["LATTICE_SCAN_IMAGES_LANG"] = lang
        if images:
            envs["LATTICE_SCAN_IMAGES"] = images
        with mock.patch.dict("os.environ", envs):
            return cli.image_details(list(running)), fd


class Images(unittest.TestCase):
    def test_alpine_image_is_identified_with_its_packages(self):
        d, _ = collect()
        r = d["redis:7-alpine"]
        self.assertEqual((r["os"], r["osVersion"], r["packageManager"]), ("alpine", "3.21.3", "apk"))
        self.assertEqual(r["packages"]["musl"], "1.2.5-r8")
        self.assertTrue(r["running"])
        self.assertEqual(cli.product_version(r), "7.4.9")

    def test_debian_image_reads_only_installed_dpkg_packages(self):
        d, _ = collect()
        self.assertEqual(d["app:1"]["packages"], {"zlib1g": "1:1.3.dfsg-1"})
        self.assertEqual(d["app:1"]["os"], "debian")
        self.assertFalse(d["app:1"]["running"])
        self.assertEqual(cli.product_version(d["app:1"]), "4.5")

    def test_environment_secrets_are_never_kept(self):
        d, _ = collect()
        self.assertNotIn("hunter2", json.dumps(d))
        self.assertEqual(set(d["redis:7-alpine"]["versions"]), {"REDIS_VERSION", "GOSU_VERSION"})

    def test_minimal_image_is_noted_not_fatal(self):
        d, _ = collect()
        self.assertIn("minimal or distroless", d["tiny:1"]["note"])

    def test_no_container_is_ever_started(self):
        _, fd = collect()
        verbs = {tuple(c[:2]) for c in fd.calls}
        self.assertNotIn(("docker", "run"), verbs)
        self.assertNotIn(("docker", "start"), verbs)
        created = [c for c in fd.calls if c[:2] == ["docker", "create"]]
        self.assertTrue(created and all("--network" in c and "none" in c for c in created))
        self.assertEqual(len([c for c in fd.calls if c[:3] == ["docker", "rm", "-f"]]), len(created))

    def test_off_and_running_modes(self):
        with mock.patch.dict("os.environ", {"LATTICE_SCAN_IMAGES": "off"}):
            self.assertEqual(collect()[0], {})
        with mock.patch.dict("os.environ", {"LATTICE_SCAN_IMAGES": "running"}):
            self.assertEqual(set(collect()[0]), {"redis:7-alpine"})

    def test_unreadable_image_is_skipped(self):
        fd = FakeDocker()
        fd.run = lambda cmd: ""
        with mock.patch.object(cli, "run", fd.run), mock.patch.object(cli.shutil, "which", lambda c: "/x/docker"):
            self.assertEqual(cli.image_details(["ghost:1"]), {})


class Matching(unittest.TestCase):
    def inv(self):
        d, _ = collect()
        return {"kernel": "7.0.0", "os": "x", "packages": {}, "snaps": {}, "images": ["redis:7-alpine"], "node": "", "imageDetails": d, "host": {}}

    def test_cisa_entry_for_musl_names_the_alpine_image(self):
        hit = cli.candidate({"cve": "CVE-2099-0001", "vendor": "Musl", "product": "musl", "title": "t"}, self.inv())
        self.assertIsNotNone(hit)
        why, installed, vers = hit
        self.assertIn("inside container image redis:7-alpine", why)
        self.assertEqual(installed, ["musl 1.2.5-r8 (image redis:7-alpine)"])
        self.assertEqual(vers, ["1.2.5-r8"])

    def test_image_product_matches_with_its_version(self):
        hit = cli.candidate({"cve": "CVE-2099-0002", "vendor": "Redis", "product": "redis", "title": "t"}, self.inv())
        self.assertIn("7.4.9", hit[2])

    def test_a_package_in_another_image_does_not_match_a_word_in_this_one(self):
        self.assertIsNone(cli.candidate({"cve": "CVE-2099-0003", "vendor": "x", "product": "zlib1g redis", "title": "t"}, self.inv()))

    def test_image_packages_never_count_as_host_packages_for_changelog_check(self):
        inv = self.inv()
        inv["packages"] = {"musl": "9"}
        self.assertEqual(cli.changelog_mentions("CVE-2099-0001", ["musl 1.2.5-r8 (image redis:7-alpine)"], inv), [])

    def test_hardware_advisory_matches_the_machine(self):
        inv = self.inv()
        inv["host"] = {"manufacturer": "Examplecorp", "model": "Widgetbox9", "biosVersion": "2.1"}
        hit = cli.candidate({"cve": "CVE-2099-0004", "vendor": "Examplecorp", "product": "Widgetbox9", "title": "t"}, inv)
        self.assertEqual(hit[2], ["2.1"])

    def test_old_inventory_without_the_new_keys_still_matches(self):
        inv = {"kernel": "7.0.0", "os": "x", "packages": {"openssl": "3.0.1"}, "snaps": {}, "images": [], "node": ""}
        self.assertIsNotNone(cli.candidate({"cve": "CVE-2099-0005", "vendor": "OpenSSL", "product": "openssl", "title": "t"}, inv))


class Hardware(unittest.TestCase):
    def test_placeholders_and_serials_are_left_out(self):
        files = {"sys_vendor": "Examplecorp", "product_name": "To Be Filled By O.E.M.", "product_version": "1.0", "product_serial": "SN123", "chassis_type": "35"}
        real = Path.read_text

        def fake(self, *a, **k):
            if str(self).startswith("/sys/class/dmi/id/"):
                n = self.name
                if n in files:
                    return files[n] + "\n"
                raise OSError
            if str(self) == "/proc/device-tree/model":
                return "Example Board 2\0"
            return real(self, *a, **k)
        with mock.patch.object(Path, "read_text", fake), mock.patch.object(cli, "run", lambda c: ""):
            h = cli.hardware()
        self.assertEqual((h["manufacturer"], h["version"], h["chassis"]), ("Examplecorp", "1.0", "mini PC"))
        self.assertEqual(h["model"], "Example Board 2")
        self.assertNotIn("SN123", json.dumps(h))


def rpm_header(name, version, release, epoch=None):
    import struct
    data, idx = b"", []
    for tag, val in ((1000, name), (1001, version), (1002, release)):
        idx.append((tag, 6, len(data), 1))
        data += val.encode() + b"\0"
    if epoch is not None:
        data += b"\0" * (-len(data) % 4)
        idx.append((1003, 4, len(data), 1))
        data += struct.pack(">I", epoch)
    return struct.pack(">II", len(idx), len(data)) + b"".join(struct.pack(">IIII", *i) for i in idx) + data


def rpm_sqlite(rows):
    import sqlite3, os
    f = tempfile.mktemp(suffix=".sqlite")
    con = sqlite3.connect(f)
    con.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)")
    for r in rows:
        con.execute("INSERT INTO Packages (blob) VALUES (?)", (rpm_header(*r),))
    con.commit()
    con.close()
    data = Path(f).read_bytes()
    os.unlink(f)
    return data


def tree_tar(files, dirs=()):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as t:
        for d in dirs:
            i = tarfile.TarInfo(d)
            i.type = tarfile.DIRTYPE
            t.addfile(i)
        for n, txt in files.items():
            i = tarfile.TarInfo(n)
            i.size = len(txt.encode())
            t.addfile(i, io.BytesIO(txt.encode()))
    return b.getvalue()


class Formats(unittest.TestCase):
    def test_rpm_sqlite_gives_names_and_versions(self):
        pk = cli.parse_rpm_sqlite(rpm_sqlite([("bash", "5.2.1", "3.fc40"), ("openssl-libs", "3.2.1", "2.fc40", 1), ("gpg-pubkey", "1", "1")]))
        self.assertEqual(pk, {"bash": "5.2.1-3.fc40", "openssl-libs": "1:3.2.1-2.fc40"})

    def test_bdb_or_garbage_rpm_database_gives_nothing(self):
        self.assertEqual(cli.parse_rpm_sqlite(b"\x00\x06\x15\x61 not sqlite"), {})

    def test_rpm_image_end_to_end(self):
        db = rpm_sqlite([("bash", "5.2.1", "3.fc40")])
        fd = FakeDocker()
        fd.run = lambda c: json.dumps([{"Id": "sha256:dd", "Os": "linux", "Architecture": "arm64", "Config": {}}]) if c[:3] == ["docker", "image", "inspect"] else ("cid\n" if c[:2] == ["docker", "create"] else "")

        def rb(c):
            p = c[2].split(":/", 1)[1]
            if p == "etc/os-release":
                return tar_of('ID=fedora\nVERSION_ID=40\nPRETTY_NAME="Fedora Linux 40"\n')
            if p == "usr/lib/sysimage/rpm/rpmdb.sqlite":
                b = io.BytesIO()
                with tarfile.open(fileobj=b, mode="w") as t:
                    i = tarfile.TarInfo("rpmdb.sqlite")
                    i.size = len(db)
                    t.addfile(i, io.BytesIO(db))
                return b.getvalue()
            return b""
        with mock.patch.object(cli, "run", fd.run), mock.patch.object(cli, "run_bytes", rb):
            d = cli.image_detail("fedora:40", False)
        self.assertEqual((d["packageManager"], d["packages"]), ("rpm", {"bash": "5.2.1-3.fc40"}))

    def test_distroless_status_d(self):
        fd = FakeDocker()
        fd.run = lambda c: json.dumps([{"Id": "sha256:ee", "Config": {}}]) if c[:3] == ["docker", "image", "inspect"] else ("cid\n" if c[:2] == ["docker", "create"] else "")
        files = {"status.d/base-files": "Package: base-files\nStatus: install ok installed\nVersion: 13\n", "status.d/base-files.md5sums": "abc  x\n",
                 "status.d/libc6": "Package: libc6\nStatus: install ok installed\nVersion: 2.36-9\n"}
        rb = lambda c: tree_tar(files) if c[2].endswith("var/lib/dpkg/status.d") else b""  # noqa: E731
        with mock.patch.object(cli, "run", fd.run), mock.patch.object(cli, "run_bytes", rb):
            d = cli.image_detail("distroless:1", False)
        self.assertEqual(d["packages"], {"base-files": "13", "libc6": "2.36-9"})


class Languages(unittest.TestCase):
    def stream(self, tar_bytes):
        class P:
            stdout = io.BytesIO(tar_bytes)
            def kill(self): pass
            def wait(self): pass
        return mock.patch.object(cli.subprocess, "Popen", lambda *a, **k: P())

    def test_python_node_java_ruby_names_are_found_in_the_stream(self):
        t = tree_tar({"app/node_modules/leftpadq/package.json": json.dumps({"name": "leftpadq", "version": "1.2.3"}),
                      "app/node_modules/@sc/tool/package.json": json.dumps({"name": "@sc/tool", "version": "4.0.0"}),
                      "app/node_modules/leftpadq/node_modules/inner/package.json": json.dumps({"name": "inner", "version": "0.1.0"}),
                      "opt/lib/widgetq-2.0.1.jar": "x"},
                     dirs=("usr/lib/python3.12/site-packages/Examplepkg-9.9.dist-info", "usr/lib/python3.12/site-packages/my_pkg-1.0-py3.12.egg-info",
                           "var/lib/gems/3.2.0/gems/rackq-3.0.8"))
        with self.stream(t):
            langs, complete = cli.image_languages("cid")
        self.assertTrue(complete)
        self.assertEqual(langs["pypi"], {"examplepkg": "9.9", "my-pkg": "1.0"})
        self.assertEqual(langs["npm"], {"leftpadq": "1.2.3", "@sc/tool": "4.0.0", "inner": "0.1.0"})
        self.assertEqual(langs["maven"], {"widgetq": "2.0.1"})
        self.assertEqual(langs["gem"], {"rackq": "3.0.8"})

    def test_time_limit_marks_the_result_partial(self):
        with self.stream(tree_tar({"a": "b"})), mock.patch.object(cli, "LANG_SECONDS", -1):
            self.assertFalse(cli.image_languages("cid")[1])

    def test_language_package_inside_an_image_is_a_candidate_that_names_the_image(self):
        d, _ = collect()
        d["redis:7-alpine"]["languages"] = {"pypi": {"examplepkg": "9.9|9.8"}}
        inv = {"kernel": "7", "os": "x", "packages": {}, "snaps": {}, "images": [], "node": "", "imageDetails": d, "host": {}}
        why, installed, vers = cli.candidate({"cve": "CVE-2099-9", "vendor": "x", "product": "examplepkg", "title": "t"}, inv)
        self.assertIn("redis:7-alpine", why)
        self.assertEqual(vers, ["9.8", "9.9"])

    def test_language_scan_can_be_limited_to_running_images(self):
        seen = []
        with mock.patch.object(cli, "image_languages", lambda cid: (seen.append(cid) or ({"pypi": {"zz": "1"}}, True))):
            d, _ = collect(lang="running")
        self.assertEqual(seen, ["cid-redis:7-alpine"])
        self.assertEqual(d["redis:7-alpine"]["languages"], {"pypi": {"zz": "1"}})
        self.assertNotIn("languages", d["app:1"])


class Faults(unittest.TestCase):
    """A deep scan that meets an error loses that image, never the scan, and leaves nothing behind."""

    def test_run_bytes_stops_a_file_larger_than_the_limit(self):
        with mock.patch.object(cli, "IMAGE_FILE_LIMIT", 10):
            self.assertEqual(cli.run_bytes([sys.executable, "-c", "print('x' * 1000)"]), b"")
            self.assertEqual(cli.run_bytes([sys.executable, "-c", "print('ok')"]), b"ok\n")
        self.assertEqual(cli.run_bytes(["/nonexistent-command"]), b"")
        self.assertEqual(cli.run_bytes([sys.executable, "-c", "import sys; sys.exit(3)"]), b"")

    def test_damaged_rpm_data_costs_the_packages_only(self):
        self.assertEqual(cli.parse_rpm_header(b"\x00\x00"), {})
        self.assertEqual(cli.parse_rpm_header(b"\x00\x00\x00\x01\x00\x00\x00\x04" + b"\x00\x00\x03\xe8\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x01" + b"abcd"), {})
        db = rpm_sqlite([("bash", "5", "1")])
        with mock.patch.object(Path, "write_bytes", side_effect=OSError(28, "No space left on device")):
            self.assertEqual(cli.parse_rpm_sqlite(db), {})
        self.assertEqual(cli.parse_rpm_sqlite(db[:200]), {})

    def test_rpm_temp_folder_is_removed(self):
        seen = []
        real = tempfile.TemporaryDirectory

        class Spy(real):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                seen.append(self.name)
        with mock.patch.object(cli.tempfile, "TemporaryDirectory", Spy):
            cli.parse_rpm_sqlite(rpm_sqlite([("bash", "5", "1")]))
            cli.parse_rpm_sqlite(b"SQLite format 3\x00 broken")
        self.assertEqual(len(seen), 2)
        self.assertFalse(any(Path(x).exists() for x in seen))

    def test_damaged_export_stream_marks_partial_and_closes_the_pipe(self):
        closed = []

        class P:
            class stdout:
                @staticmethod
                def read(*a): return b"not a tar archive" * 100
                @staticmethod
                def readinto(*a): return 0
                @staticmethod
                def close(): closed.append(1)
            def kill(self): closed.append("kill")
            def wait(self): pass
        with mock.patch.object(cli.subprocess, "Popen", lambda *a, **k: P()):
            langs, complete = cli.image_languages("cid")
        self.assertEqual((langs, complete), ({}, False))
        self.assertIn("kill", closed)

    def test_one_image_that_raises_does_not_stop_the_others(self):
        real = cli.image_detail

        def flaky(ref, running, lang=False):
            if ref == "app:1":
                raise RuntimeError("boom")
            return real(ref, running, lang)
        fd = FakeDocker()
        with mock.patch.object(cli, "image_detail", flaky), mock.patch.object(cli, "run", fd.run), mock.patch.object(cli, "run_bytes", fd.run_bytes), \
                mock.patch.object(cli.shutil, "which", lambda c: "/x/docker"), mock.patch.dict("os.environ", {"LATTICE_SCAN_LEVEL": "deep", "LATTICE_SCAN_IMAGES_LANG": "off"}):
            d = cli.image_details(["redis:7-alpine"])
        self.assertEqual(set(d), {"redis:7-alpine", "tiny:1"})

    def test_low_storage_opens_no_image(self):
        fd = FakeDocker()
        with mock.patch.object(cli, "run", fd.run), mock.patch.object(cli, "docker_free_mb", lambda: 200), mock.patch.object(cli.shutil, "which", lambda c: "/x/docker"):
            self.assertEqual(cli.image_details(["redis:7-alpine"]), {})
        self.assertFalse([c for c in fd.calls if c[:2] == ["docker", "create"]])

    def test_time_limit_skips_the_remaining_images(self):
        fd = FakeDocker()
        with mock.patch.object(cli, "run", fd.run), mock.patch.object(cli, "run_bytes", fd.run_bytes), mock.patch.object(cli.shutil, "which", lambda c: "/x/docker"), \
                mock.patch.dict("os.environ", {"LATTICE_SCAN_LEVEL": "deep", "LATTICE_SCAN_DEEP_SECONDS": "-1", "LATTICE_SCAN_IMAGES_LANG": "off"}):
            self.assertEqual(cli.image_details(["redis:7-alpine"]), {})

    def test_every_created_container_is_removed_even_when_a_copy_fails(self):
        fd = FakeDocker()

        def boom(cmd):
            fd.calls.append(cmd)
            raise OSError("disk gone")
        with mock.patch.object(cli, "run", fd.run), mock.patch.object(cli, "run_bytes", boom):
            with self.assertRaises(OSError):
                cli.image_detail("redis:7-alpine", True)
        self.assertEqual(len([c for c in fd.calls if c[:2] == ["docker", "create"]]), len([c for c in fd.calls if c[:3] == ["docker", "rm", "-f"]]))

    def test_sweep_removes_this_runs_containers_and_only_old_ones_of_other_runs(self):
        old = "2020-01-01 00:00:00 +0000 UTC"
        new = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " +0000 UTC"
        rows = f"mine\t{cli.RUN_ID}\t{new}\nstale\t999-1\t{old}\nfresh\t999-2\t{new}\n"
        removed = []

        def run(cmd):
            if cmd[:3] == ["docker", "container", "ls"]:
                return rows
            if cmd[:3] == ["docker", "rm", "-f"]:
                removed.append(cmd[3])
            return ""
        with mock.patch.object(cli, "run", run):
            cli.sweep_containers(stale_only=True)
            self.assertEqual(removed, ["stale"])
            removed.clear()
            cli.sweep_containers(stale_only=False)
            self.assertEqual(removed, ["mine"])


class Levels(unittest.TestCase):
    def test_quick_is_the_default_and_opens_only_running_images_without_language_scan(self):
        with mock.patch.dict("os.environ", {}, clear=False):
            for k in ("LATTICE_SCAN_LEVEL", "LATTICE_SCAN_IMAGES", "LATTICE_SCAN_IMAGES_LANG", "HOST_SCAN_LEVEL"):
                os.environ.pop(k, None)
            seen = []
            with mock.patch.object(cli, "image_languages", lambda cid: seen.append(cid) or ({}, True)):
                fd = FakeDocker()
                with mock.patch.object(cli, "run", fd.run), mock.patch.object(cli, "run_bytes", fd.run_bytes), mock.patch.object(cli.shutil, "which", lambda c: "/x/docker"):
                    d = cli.image_details(["redis:7-alpine"])
        self.assertEqual(list(d), ["redis:7-alpine"])
        self.assertEqual(seen, [])

    def test_quick_still_finds_the_base_from_an_unopened_local_image(self):
        base = {"Id": "sha256:b", "RootFS": {"Layers": ["l1"]}, "Config": {}}
        app = {"Id": "sha256:a", "RootFS": {"Layers": ["l1", "l2"]}, "Config": {}}

        def run(cmd):
            if cmd[:3] == ["docker", "image", "inspect"]:
                return json.dumps([{"app:1": app, "base:1": base}[cmd[3]]])
            if cmd[:3] == ["docker", "image", "ls"]:
                return "app:1\nbase:1\n"
            return "cid\n" if cmd[:2] == ["docker", "create"] else ""
        with mock.patch.dict("os.environ", {"LATTICE_SCAN_LEVEL": "quick"}), mock.patch.object(cli, "run", run), mock.patch.object(cli, "run_bytes", lambda c: b""), \
                mock.patch.object(cli.shutil, "which", lambda c: "/x/docker"):
            d = cli.image_details(["app:1"])
        self.assertEqual(list(d), ["app:1"])
        self.assertEqual(d["app:1"]["builtOn"], "base:1")

    def test_deep_opens_every_image_and_scans_languages(self):
        seen = []
        with mock.patch.object(cli, "image_languages", lambda cid: (seen.append(cid) or ({}, True))):
            d, _ = collect(lang=None, level="deep")
        self.assertEqual(set(d), {"redis:7-alpine", "app:1", "tiny:1"})
        self.assertEqual(len(seen), 3)

    def test_deep_flag_sets_the_level(self):
        with mock.patch.dict("os.environ", {"LATTICE_SCAN_LEVEL": "deep"}):
            self.assertEqual(cli.scan_level(), "deep")
        with mock.patch.dict("os.environ", {"LATTICE_SCAN_LEVEL": ""}):
            self.assertEqual(cli.scan_level(), "quick")

    def test_package_database_is_chosen_by_os_family(self):
        _, fd = collect()
        cps = [c[2] for c in fd.calls if c[:2] == ["docker", "cp"]]
        mine = lambda ref: [p.split(":/", 1)[1] for p in cps if p.startswith("cid-" + ref + ":")]  # noqa: E731
        self.assertEqual(mine("redis:7-alpine"), ["etc/os-release", "lib/apk/db/installed"])
        self.assertEqual(mine("app:1"), ["etc/os-release", "var/lib/dpkg/status"])
        self.assertEqual(len(mine("tiny:1")), 7)  # an image with no OS file tries every database once


class Lineage(unittest.TestCase):
    def test_longest_layer_prefix_is_the_base_and_equal_layers_are_not(self):
        det = {"base:1": {"layers": ["a", "b"]}, "mid:1": {"layers": ["a", "b", "c"]}, "app:1": {"layers": ["a", "b", "c", "d"]},
               "app:copy": {"layers": ["a", "b", "c", "d"]}, "other:1": {"layers": ["z"]}}
        cli.lineage(det)
        self.assertEqual(det["app:1"]["builtOn"], "mid:1")
        self.assertEqual(det["mid:1"]["builtOn"], "base:1")
        self.assertNotIn("builtOn", det["other:1"])
        self.assertNotIn("builtOn", det["base:1"])
        self.assertEqual(det["app:1"]["layerCount"], 4)
        self.assertNotIn("layers", det["app:1"])


if __name__ == "__main__":
    unittest.main()
