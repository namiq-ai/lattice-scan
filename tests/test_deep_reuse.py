# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""a complete deep scan is kept, and a later quick run reuses what it read of every image whose id is unchanged. Invented images, a fake docker."""
import json, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli  # noqa: E402
import test_image_inventory as ti  # noqa: E402

IDS = {"redis:7-alpine": "aaaaaaaaaaaa", "app:1": "bbbbbbbbbbbb", "tiny:1": "cccccccccccc"}


class Docker(ti.FakeDocker):
    ids = IDS

    def run(self, cmd):
        if cmd[:3] == ["docker", "image", "ls"]:
            self.calls.append(cmd)
            return "".join(f"{r}\t10MB\t{i}\n" for r, i in self.ids.items()) + "<none>:<none>\t1MB\tdddddddddddd\n"
        return super().run(cmd)


class DeepReuse(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patches = [mock.patch.object(cli, "OUT", Path(self.tmp.name)), mock.patch.object(cli, "TODAY", "2026-11-06"),
                        mock.patch.object(cli.shutil, "which", lambda c: "/x/docker"), mock.patch.object(cli, "docker_free_mb", lambda: None)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def scan(self, level, docker=None, **env):
        d = docker or Docker()
        with mock.patch.object(cli, "run", d.run), mock.patch.object(cli, "run_bytes", d.run_bytes), \
             mock.patch.dict("os.environ", {"LATTICE_SCAN_LEVEL": level, "LATTICE_SCAN_IMAGES_LANG": "off", **env}):
            cli.IMAGE_SCAN.clear()
            return cli.image_details(["redis:7-alpine"]), d

    def test_a_quick_run_after_a_deep_one_has_every_image_the_deep_run_read_without_opening_them(self):
        deep, _ = self.scan("deep")
        self.assertEqual(set(deep), {"redis:7-alpine", "app:1", "tiny:1"})
        self.assertTrue((Path(self.tmp.name) / cli.DEEP_IMAGES).exists())
        quick, d = self.scan("quick")
        self.assertEqual(set(quick), set(deep))                                   # app:1 and tiny:1 are not running, quick alone would skip them
        self.assertEqual(quick["app:1"]["packages"], deep["app:1"]["packages"])
        self.assertEqual({r: d["running"] for r, d in quick.items()}, {"redis:7-alpine": True, "app:1": False, "tiny:1": False})   # as of this run
        self.assertEqual(cli.IMAGE_SCAN["reusedDeep"], {"on": "2026-11-06", "images": 3})
        self.assertEqual(len([c for c in d.calls if c[:2] == ["docker", "create"]]), 1)   # only the running image was opened (a container made to read files) this time

    def test_an_image_whose_id_changed_is_not_reused(self):
        self.scan("deep")
        class Changed(Docker):
            ids = {**IDS, "app:1": "eeeeeeeeeeee"}
        quick, _ = self.scan("quick", Changed())
        self.assertNotIn("app:1", quick)
        self.assertEqual(cli.IMAGE_SCAN["reusedDeep"]["images"], 2)

    def test_old_saved_data_and_the_off_switch_are_not_used(self):
        self.scan("deep")
        with mock.patch.object(cli, "TODAY", "2026-12-20"):                      # 44 days later, over the 30-day limit
            quick, _ = self.scan("quick")
        self.assertEqual(set(quick), {"redis:7-alpine"}); self.assertNotIn("reusedDeep", cli.IMAGE_SCAN)
        quick, _ = self.scan("quick", LATTICE_SCAN_DEEP_CACHE="off")
        self.assertEqual(set(quick), {"redis:7-alpine"})

    def test_an_incomplete_deep_scan_saves_nothing_and_a_damaged_file_is_ignored(self):
        self.scan("deep", LATTICE_SCAN_DEEP_SECONDS="-1")                        # every image skipped, time limit
        self.assertFalse((Path(self.tmp.name) / cli.DEEP_IMAGES).exists())
        (Path(self.tmp.name) / cli.DEEP_IMAGES).write_text("{not json")
        quick, _ = self.scan("quick")
        self.assertEqual(set(quick), {"redis:7-alpine"})


if __name__ == "__main__":
    unittest.main()
