"""Cursor, VS Code и VSCodium: Electron без app.asar и перенос между дисками.

Жалоба, ради которой появился этот модуль:

    Портализировал ``CursorUserSetup-x64-3.27.14.exe``. После переноса папки
    на другой жёсткий диск с ``Launch.bat`` и ``App\\LaunchPortable.exe``
    программа не запускается, а с ``Cursor.exe`` — запускается.

Причин было две, и обе — в определении «это Electron или нет»:

* Cursor/VS Code держат приложение РАСПАКОВАННЫМ (``resources\\app``), а
  прежняя проверка требовала ``resources\\app.asar``. В результате Cursor не
  получал ``--no-sandbox``/``--disable-gpu-sandbox`` и переменные профиля, а
  его Chromium-песочница из папки портатива не запускается;
* у Cursor в ``product.json`` стоит ``"target": "user"`` — встроенный
  portable-режим VS Code (папка ``data`` рядом с exe) в такой сборке
  отключён, поэтому профиль задаётся только переменными
  ``VSCODE_APPDATA``/``VSCODE_EXTENSIONS``/``VSCODE_LOGS``/``VSCODE_CLI_DATA_DIR``
  и файлом ``argv.json``.

Здесь проверяется и сборка (``core/launcher.py``), и готовый лончер
(``portable_launcher_entry.py``): оба обязаны узнавать такую сборку и держать
пути внутри портатива.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import portable_launcher_entry as exe_launcher
from portablizer.core import launcher as launcher_mod
from portablizer.core import maintenance
from portablizer.core.logutil import Logger

CURSOR_PRODUCT = {
    "nameShort": "Cursor",
    "nameLong": "Cursor",
    "dataFolderName": ".cursor",
    "target": "user",
    "applicationName": "cursor",
}


def make_cursor_app(root: Path, product: "dict | None" = None) -> Path:
    """Раскладка ``%LOCALAPPDATA%\\Programs\\cursor`` после Inno-установки."""
    app = root / "App"
    app.mkdir(parents=True, exist_ok=True)
    target = app / "Cursor.exe"
    target.write_bytes(b"MZ" + b"\x00" * 4096)
    (app / "chrome_elf.dll").write_bytes(b"MZ")
    (app / "resources" / "app").mkdir(parents=True, exist_ok=True)
    (app / "resources" / "app" / "package.json").write_text(
        '{"name": "cursor", "main": "./out/main.js"}', encoding="utf-8")
    (app / "resources" / "app" / "product.json").write_text(
        json.dumps(CURSOR_PRODUCT if product is None else product),
        encoding="utf-8")
    return target


class CursorDetectionTests(unittest.TestCase):
    """Cursor — это Electron, хотя app.asar у него нет."""

    def test_unpacked_app_is_recognized_as_electron_and_vscode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_cursor_app(root)

            info = launcher_mod.vscode_product(str(target))
            self.assertIsNotNone(info)
            self.assertEqual(info["name"], "Cursor")
            self.assertEqual(info["data_folder"], ".cursor")
            # Именно это поле отключает встроенный portable-режим VS Code.
            self.assertEqual(info["target"], "user")

            self.assertTrue(launcher_mod.is_vscode_like_app(str(target)))
            self.assertTrue(launcher_mod.is_electron_app(str(target)))
            self.assertTrue(exe_launcher.is_electron_tree(target.parent))
            self.assertTrue(exe_launcher.needs_electron_sandbox_off(target))
            # Chromium создаёт собственные job-объекты: kill-on-close ломал бы
            # его GPU/renderer-процессы (как у Ollama).
            self.assertFalse(exe_launcher.should_use_job(target))

    def test_cef_program_with_chrome_elf_is_not_vscode(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp, "App")
            app.mkdir()
            (app / "libcef.dll").write_bytes(b"MZ")
            (app / "chrome_elf.dll").write_bytes(b"MZ")
            target = app / "SketchUp.exe"
            target.write_bytes(b"MZ" + b"\x00" * (9 * 1024 * 1024))

            self.assertIsNone(launcher_mod.vscode_product(str(target)))
            self.assertFalse(launcher_mod.is_electron_app(str(target)))
            self.assertFalse(exe_launcher.needs_electron_sandbox_off(target))

    def test_product_json_is_authoritative_over_the_exe_name(self):
        """Незнакомое имя exe с product.json — всё равно VS Code-семейство."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "App"
            app.mkdir()
            target = app / "MyEditor.exe"
            target.write_bytes(b"MZ")
            (app / "resources" / "app").mkdir(parents=True)
            (app / "resources" / "app" / "product.json").write_text(
                json.dumps({"nameShort": "MyEditor",
                            "dataFolderName": ".myeditor"}),
                encoding="utf-8")

            info = launcher_mod.vscode_product(str(target))
            self.assertEqual(info["name"], "MyEditor")
            self.assertEqual(info["data_folder"], ".myeditor")
            self.assertTrue(exe_launcher.needs_electron_sandbox_off(target))


class CursorProfileTests(unittest.TestCase):
    """Профиль Cursor лежит в PortableData и переживает перенос папки."""

    def test_portable_env_is_relative_to_the_root(self):
        env = launcher_mod.vscode_portable_env(
            {"name": "Cursor", "data_folder": ".cursor"}, "PortableData")

        self.assertEqual(env["VSCODE_APPDATA"],
                         "%PORTABLE_ROOT%\\PortableData\\AppData\\Roaming")
        self.assertEqual(env["VSCODE_EXTENSIONS"],
                         "%PORTABLE_ROOT%\\PortableData\\User\\.cursor\\extensions")
        self.assertEqual(env["VSCODE_LOGS"],
                         "%PORTABLE_ROOT%\\PortableData\\Logs")
        self.assertEqual(env["VSCODE_CLI_DATA_DIR"],
                         "%PORTABLE_ROOT%\\PortableData\\User\\.cursor\\cli")
        for value in env.values():
            self.assertNotIn(":", value.split("\\")[0][1:2])

    def test_build_writes_argv_and_settings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_cursor_app(root)

            notes = launcher_mod.prepare_vscode_profile(
                str(root), "App/Cursor.exe")

            self.assertTrue(any("disable-chromium-sandbox" in note
                                for note in notes))
            argv = root / "PortableData" / "User" / ".cursor" / "argv.json"
            settings = (root / "PortableData" / "AppData" / "Roaming"
                        / "Cursor" / "User" / "settings.json")
            self.assertTrue(argv.is_file())
            self.assertTrue(settings.is_file())
            self.assertTrue(json.loads(argv.read_text(encoding="utf-8"))[
                "disable-chromium-sandbox"])
            self.assertEqual(json.loads(settings.read_text(encoding="utf-8"))[
                "update.mode"], "none")
            # Второй проход ничего не переписывает.
            self.assertEqual(launcher_mod.prepare_vscode_profile(
                str(root), "App/Cursor.exe"), [])

    def test_existing_argv_json_is_merged_not_replaced(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_cursor_app(root)
            argv = root / "PortableData" / "User" / ".cursor" / "argv.json"
            argv.parent.mkdir(parents=True)
            argv.write_text(json.dumps({"locale": "ru",
                                        "enable-crash-reporter": False}),
                            encoding="utf-8")

            launcher_mod.prepare_vscode_profile(str(root), "App/Cursor.exe")

            data = json.loads(argv.read_text(encoding="utf-8"))
            self.assertEqual(data["locale"], "ru")
            self.assertFalse(data["enable-crash-reporter"])
            self.assertTrue(data["disable-chromium-sandbox"])

    def test_existing_settings_file_is_left_alone(self):
        """Пользователь мог сам выбрать режим обновлений — не перетираем."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_cursor_app(root)
            settings = (root / "PortableData" / "AppData" / "Roaming"
                        / "Cursor" / "User" / "settings.json")
            settings.parent.mkdir(parents=True)
            settings.write_text(json.dumps({"update.mode": "manual"}),
                                encoding="utf-8")

            launcher_mod.prepare_vscode_profile(str(root), "App/Cursor.exe")

            self.assertEqual(json.loads(settings.read_text(encoding="utf-8"))[
                "update.mode"], "manual")

    def test_non_vscode_app_gets_no_profile_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "App"
            app.mkdir()
            (app / "game.exe").write_bytes(b"MZ")

            self.assertEqual(launcher_mod.prepare_vscode_profile(
                str(root), "App/game.exe"), [])
            self.assertFalse((root / "PortableData").exists())


class CursorLaunchBatTests(unittest.TestCase):
    """Launch.bat: переменные профиля и видимая ошибка EXE-лончера."""

    def _render(self, extra_env=None):
        cfg = launcher_mod.LauncherConfig(
            app_name="Cursor",
            target_exe_rel="App/Cursor.exe",
            extra_env=extra_env or launcher_mod.vscode_portable_env(
                {"name": "Cursor", "data_folder": ".cursor"}),
            target_args=list(launcher_mod.ELECTRON_CHROMIUM_FLAGS),
        )
        return launcher_mod.render_bat(cfg)

    def test_profile_variables_are_expanded_by_cmd(self):
        bat = self._render()

        self.assertIn(
            'set "VSCODE_APPDATA=%PORTABLE_ROOT%\\PortableData\\AppData\\Roaming"',
            bat)
        self.assertIn(
            'set "VSCODE_EXTENSIONS=%PORTABLE_ROOT%\\PortableData\\User\\.cursor\\extensions"',
            bat)
        # Регрессия: _bat_set_value удваивал проценты, и программа получала
        # буквальный текст "%%PORTABLE_ROOT%%\\...".
        self.assertNotIn("%%PORTABLE_ROOT%%", bat)
        self.assertTrue(bat.isascii())

    def test_a_stray_percent_is_still_escaped(self):
        bat = self._render(extra_env={"TITLE": "100% ready"})
        self.assertIn('set "TITLE=100%% ready"', bat)

    def test_exe_launcher_is_watched_and_diagnose_is_offered(self):
        bat = self._render()

        # App\LaunchPortable.exe запускается и сразу проверяется: если он умер
        # (сломанный конфиг, пропавшая цель), BAT продолжает работу сам.
        self.assertIn("call :portable_exe_launcher_watch", bat)
        self.assertIn(":portable_exe_launcher_watch", bat)
        self.assertIn("tasklist.exe", bat)
        self.assertIn("launcher-exe-error.log", bat)
        self.assertIn("--diagnose", bat)


class CursorLauncherRuntimeTests(unittest.TestCase):
    """Готовый LaunchPortable.exe: окружение, профиль и починка цели."""

    def test_electron_flags_are_added_for_cursor(self):
        with tempfile.TemporaryDirectory() as temp:
            target = make_cursor_app(Path(temp))

            command = exe_launcher.with_electron_flags([str(target)], target)

            self.assertEqual(command[0], str(target))
            self.assertIn("--no-sandbox", command)

    def test_environment_pins_the_profile_inside_the_portable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_cursor_app(root)

            env = exe_launcher._vscode_environment(
                {}, root, {"data_dir_name": "PortableData"}, target)

            self.assertEqual(Path(env["VSCODE_APPDATA"]),
                             root / "PortableData" / "AppData" / "Roaming")
            self.assertEqual(Path(env["VSCODE_EXTENSIONS"]),
                             root / "PortableData" / "User" / ".cursor"
                             / "extensions")
            self.assertEqual(Path(env["VSCODE_CLI_DATA_DIR"]),
                             root / "PortableData" / "User" / ".cursor" / "cli")

    def test_a_configured_value_wins(self):
        """Значение из launcher_config.json не перетирается умолчанием.

        Сам ``extra_env`` подставляет ``_prepare_environment``; здесь важно,
        что второй проход (VS Code) не заменил его своей догадкой.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_cursor_app(root)
            cfg = {"data_dir_name": "PortableData",
                   "extra_env": {"VSCODE_LOGS": r"%PORTABLE_ROOT%\MyLogs"}}
            configured = {"VSCODE_LOGS": str(root / "MyLogs")}

            env = exe_launcher._vscode_environment(configured, root, cfg, target)

            self.assertEqual(env["VSCODE_LOGS"], str(root / "MyLogs"))
            self.assertIn("VSCODE_APPDATA", env)

    def test_profile_files_are_recreated_before_every_start(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_cursor_app(root)

            notes = exe_launcher._apply_vscode_profile(
                root, {"data_dir_name": "PortableData"}, target)

            self.assertTrue(any("argv.json" in note for note in notes))
            argv = root / "PortableData" / "User" / ".cursor" / "argv.json"
            self.assertTrue(json.loads(argv.read_text(encoding="utf-8"))[
                "disable-chromium-sandbox"])
            self.assertEqual(exe_launcher._apply_vscode_profile(
                root, {"data_dir_name": "PortableData"}, target), [])

    def test_missing_target_is_found_in_app_and_saved(self):
        """Конфиг указывает на пропавший файл — ищем программу в App."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_cursor_app(root)
            config = root / "launcher_config.json"
            config.write_text(json.dumps({
                "app_name": "Cursor",
                "target_exe_rel": "App/Program/Cursor.exe",
                "data_dir_name": "PortableData",
            }, indent=2), encoding="utf-8")
            cfg = exe_launcher.read_launcher_config(root)

            repaired = exe_launcher._repair_missing_target(
                root, cfg, cfg["target_exe_rel"])

            self.assertEqual(repaired, "App/Cursor.exe")
            self.assertEqual(cfg["target_exe_rel"], "App/Cursor.exe")
            saved = json.loads(config.read_text(encoding="utf-8"))
            self.assertEqual(saved["target_exe_rel"], "App/Cursor.exe")

    def test_absolute_legacy_target_is_not_prefixed_with_the_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            elsewhere = str(Path(temp, "OldDisk", "App", "Cursor.exe"))

            self.assertEqual(exe_launcher._as_relative_path(root, elsewhere),
                             Path(elsewhere))

    def test_diagnose_collects_the_launch_pipeline(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_cursor_app(root)
            (root / "launcher_config.json").write_text(json.dumps({
                "app_name": "Cursor",
                "target_exe_rel": "App/Cursor.exe",
                "data_dir_name": "PortableData",
                "generated_by": "Portablizer test",
            }, indent=2), encoding="utf-8")

            code = exe_launcher.diagnose(root)

            self.assertEqual(code, 0)
            report = root / "PortableData" / "diagnostics.txt"
            self.assertTrue(report.is_file())
            text = report.read_text(encoding="utf-8")
            self.assertIn("VS Code-семейство: Cursor", text)
            self.assertIn("песочница off:   да", text)
            self.assertIn("kill-on-close:   нет", text)
            self.assertIn("target_exe_rel:  App/Cursor.exe", text)


class CursorMaintenanceTests(unittest.TestCase):
    """«Обновить лончер» чинит уже собранный портатив Cursor."""

    def test_refresh_adds_profile_variables_and_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp, "Cursor_Portable")
            make_cursor_app(root)
            cfg = launcher_mod.LauncherConfig(
                app_name="Cursor",
                target_exe_rel="App/Cursor.exe",
                extra_env={"MY_FLAG": "1"},
            )
            (root / "launcher_config.json").write_text(
                launcher_mod.render_config_json(cfg), encoding="utf-8")

            report = maintenance.refresh(
                str(root), Logger(), shared_saves=False,
                copy_exe=lambda folder, rel: rel)

            self.assertTrue(report.success)
            config = json.loads((root / "launcher_config.json").read_text(
                encoding="utf-8-sig"))
            self.assertIn("VSCODE_APPDATA", config["extra_env"])
            self.assertEqual(config["extra_env"]["MY_FLAG"], "1")
            self.assertTrue((root / "PortableData" / "User" / ".cursor"
                             / "argv.json").is_file())
            bat = (root / "Launch.bat").read_text(encoding="ascii")
            self.assertIn(
                'set "VSCODE_APPDATA=%PORTABLE_ROOT%\\PortableData\\AppData\\Roaming"',
                bat)
            self.assertIn("call :portable_exe_launcher_watch", bat)


if __name__ == "__main__":
    unittest.main()
