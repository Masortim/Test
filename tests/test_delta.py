"""Регрессии paired CLI/GUI сборки Delta и её основного запуска."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from portablizer.core import launcher as launcher_mod
from portablizer.core import maintenance
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import Portablizer


class DeltaTargetSelectionTests(unittest.TestCase):
    def test_desktop_app_wins_over_cli_even_when_cli_is_larger(self):
        with tempfile.TemporaryDirectory() as temp:
            # Размер специально противоположен полезному признаку: scorer не
            # должен выбрать терминальный CLI только потому, что он больше.
            Path(temp, "Delta.exe").write_bytes(b"C" * (80 * 1024 * 1024))
            Path(temp, "delta-app.exe").write_bytes(b"A" * 1024)

            main, targets = Portablizer(Logger())._discover_app_executables(
                temp, "Delta")

            self.assertEqual(os.path.basename(main), "delta-app.exe")
            self.assertEqual(targets[0].rel_path, "App/delta-app.exe")

    def test_refresh_moves_existing_portable_to_desktop_app(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "App"
            app.mkdir()
            (app / "Delta.exe").write_bytes(b"cli")
            (app / "delta-app.exe").write_bytes(b"gui")
            cfg = launcher_mod.LauncherConfig(
                app_name="Delta",
                target_exe_rel="App/Delta.exe",
                targets=[
                    launcher_mod.TargetInfo(
                        name="Delta", rel_path="App/Delta.exe", role="main"),
                    launcher_mod.TargetInfo(
                        name="delta-app", rel_path="App/delta-app.exe",
                        role="main"),
                ],
            )
            (root / "launcher_config.json").write_text(
                launcher_mod.render_config_json(cfg), encoding="utf-8")

            report = maintenance.refresh(
                str(root), Logger(), shared_saves=False)

            self.assertTrue(report.success)
            updated = json.loads((root / "launcher_config.json").read_text(
                encoding="utf-8-sig"))
            self.assertEqual(updated["target_exe_rel"], "App/delta-app.exe")
            roles = {item["rel_path"]: item["role"]
                     for item in updated["targets"]}
            self.assertEqual(roles["App/delta-app.exe"], "main")
            self.assertEqual(roles["App/Delta.exe"], "auxiliary")
            bat = (root / "Launch.bat").read_text(encoding="ascii")
            self.assertIn("App\\delta-app.exe", bat)

    def test_refresh_leaves_other_targets_untouched(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "App").mkdir()
            (root / "App" / "Delta.exe").write_bytes(b"cli")
            cfg = launcher_mod.LauncherConfig(
                app_name="Delta", target_exe_rel="App/Delta.exe")
            (root / "launcher_config.json").write_text(
                launcher_mod.render_config_json(cfg), encoding="utf-8")

            maintenance.refresh(str(root), Logger(), shared_saves=False)

            updated = json.loads((root / "launcher_config.json").read_text(
                encoding="utf-8-sig"))
            # Без фактического GUI sibling ничего не переключаем.
            self.assertEqual(updated["target_exe_rel"], "App/Delta.exe")


if __name__ == "__main__":
    unittest.main()


class DeltaRuntimeTargetTests(unittest.TestCase):
    def test_launcher_migrates_old_default_cli_target(self):
        import portable_launcher_entry as entry

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "App"
            app.mkdir()
            (app / "Delta.exe").write_bytes(b"cli")
            (app / "delta-app.exe").write_bytes(b"gui")
            cfg = {"target_exe_rel": "App/Delta.exe"}
            (root / "launcher_config.json").write_text(
                json.dumps(cfg), encoding="utf-8")

            selected = entry._prefer_paired_gui_target(
                root, cfg, "App/Delta.exe")

            self.assertEqual(selected, "App/delta-app.exe")
            self.assertEqual(cfg["target_exe_rel"], "App/delta-app.exe")
            saved = json.loads((root / "launcher_config.json").read_text())
            self.assertEqual(saved["target_exe_rel"], "App/delta-app.exe")

    def test_launcher_does_not_invent_gui_target_when_it_is_absent(self):
        import portable_launcher_entry as entry

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "App").mkdir()
            (root / "App" / "Delta.exe").write_bytes(b"cli")
            cfg = {"target_exe_rel": "App/Delta.exe"}
            self.assertEqual(entry._prefer_paired_gui_target(
                root, cfg, "App/Delta.exe"), "App/Delta.exe")


class DeltaTermsBridgeTests(unittest.TestCase):
    def test_review_terms_url_is_forwarded_by_the_external_browser_bridge(self):
        import portable_launcher_entry as entry

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "App" / "delta-app.exe"
            target.parent.mkdir()
            target.write_bytes(b"MZ")
            bridge = entry.BrowserLoginBridge(
                root, {"browser_login": {}}, target, env={},
                log=lambda _message: None)
            url = "https://dashboard.zed.dev/delta-beta"
            table = [(10, 0, "delta-app.exe"), (20, 10, "browser.exe")]
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table", return_value=[]), \
                    mock.patch.object(entry, "_default_browser_images",
                                      return_value={"browser.exe"}), \
                    mock.patch.object(entry, "_default_browser_profile_pairs",
                                      return_value=set()):
                bridge.attach(10)
                plan = bridge.plan(
                    table,
                    command_line_of=lambda _pid:
                    '"browser.exe" "' + url + '"')

            self.assertEqual(plan, [(20, url, "browser.exe")])
