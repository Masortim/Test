"""Относительные пути внутри портатива и перенос папки на другой диск.

Проверяется жалоба, ради которой писался ``core/relpaths.py``:

    собрал портатив на ``D:\\Apps\\XD_Portable``, скопировал на ``F:\\XD`` —
    программа ищет свои файлы по старому пути, падает или заводит второй
    профиль настроек.

Тесты идут от частного к общему: сначала замена конкретного пути (границы,
регистр, вид слэшей), затем штамп корня и починка чужих конфигов лончером,
затем проверка при сборке и отчёт, и в конце — собранный ``Launch.bat`` и
конфиг, в которых абсолютного пути быть не должно.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import portable_launcher_entry as exe_launcher
from portablizer.core import launcher as launcher_mod
from portablizer.core import portablizer as portablizer_mod
from portablizer.core import registry as registry_mod
from portablizer.core import relpaths
from portablizer.core.logutil import Logger

ROOT = r"D:\Apps\XD_Portable"


def _write(path: Path, text: str, encoding: str = "utf-8") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding=encoding)
    return path


class RootFormsTests(unittest.TestCase):
    """Все начертания корня: обратные, прямые и удвоенные слэши."""

    def test_backslash_doubled_and_forward_forms(self):
        forms = relpaths.root_forms(ROOT)
        self.assertIn(ROOT, forms)
        self.assertIn("D:/Apps/XD_Portable", forms)
        self.assertIn(r"D:\\Apps\\XD_Portable", forms)

    def test_longest_form_goes_first(self):
        forms = relpaths.root_forms(ROOT)
        self.assertEqual(forms, sorted(forms, key=len, reverse=True))

    def test_trailing_separator_is_dropped(self):
        self.assertEqual(relpaths.normalize_root(ROOT + "\\"), ROOT)
        self.assertEqual(relpaths.normalize_root(ROOT + "/"), ROOT)

    def test_empty_root_has_no_forms(self):
        self.assertEqual(relpaths.root_forms(""), [])


class TokenizeTests(unittest.TestCase):
    """Замена абсолютного корня маркером — с границами пути."""

    def test_path_inside_root_becomes_token(self):
        text = ROOT + r"\App\XD.exe"
        self.assertEqual(relpaths.tokenize_text(text, ROOT),
                         relpaths.ROOT_TOKEN + r"\App\XD.exe")

    def test_sibling_directory_with_common_prefix_is_untouched(self):
        # Именно эта ошибка портила настройки: путь находился внутри
        # «XData» и превращался в мусор.
        text = r"D:\Apps\XData\save.ini"
        self.assertEqual(relpaths.tokenize_text(text, ROOT), text)

    def test_partial_match_inside_a_word_is_untouched(self):
        text = r"C:\x\XD:\Apps\XD_Portable"
        self.assertEqual(relpaths.tokenize_text(text, ROOT), text)

    def test_forward_slashes_and_case(self):
        text = "d:/apps/xd_portable/App/XD.exe"
        self.assertEqual(relpaths.tokenize_text(text, ROOT),
                         relpaths.ROOT_TOKEN + "/App/XD.exe")

    def test_doubled_backslashes_inside_reg_value(self):
        text = r'"Install"="D:\\Apps\\XD_Portable\\App"'
        self.assertEqual(relpaths.tokenize_text(text, ROOT),
                         '"Install"="' + relpaths.ROOT_TOKEN + r'\\App"')

    def test_quoted_and_trailing_separator(self):
        text = f'"{ROOT}\\"'
        self.assertTrue(relpaths.tokenize_text(text, ROOT).startswith(
            '"' + relpaths.ROOT_TOKEN))

    def test_expand_restores_path(self):
        text = relpaths.tokenize_text(ROOT + r"\App", ROOT)
        self.assertEqual(relpaths.expand_text(text, r"F:\New"), r"F:\New\App")

    def test_expand_escaped_doubles_backslashes(self):
        text = '"' + relpaths.ROOT_TOKEN + r'\\App"'
        self.assertEqual(relpaths.expand_text(text, r"F:\New", escaped=True),
                         r'"F:\\New\\App"')

    def test_token_is_detected(self):
        self.assertTrue(relpaths.contains_token("x=" + relpaths.ROOT_TOKEN))
        self.assertFalse(relpaths.contains_token("x=y"))


class PathHelperTests(unittest.TestCase):
    """Пути: внутри корня, относительный вид, поиск абсолютных путей."""

    def test_is_within_ignores_case_and_separator_style(self):
        self.assertTrue(relpaths.is_within(r"d:/apps/xd_portable/App", ROOT))
        self.assertFalse(relpaths.is_within(r"D:\Apps\XData", ROOT))

    def test_relativize(self):
        self.assertEqual(relpaths.relativize(ROOT + r"\App\XD.exe", ROOT),
                         r"App\XD.exe")
        self.assertEqual(relpaths.relativize(ROOT, ROOT), ".")

    def test_absolute_paths_found_once(self):
        text = (r'path="C:\Program Files\Adobe\x.exe"; again="c:\program '
                r'files\adobe\x.exe"; unc="\\server\share\a.ini"')
        found = relpaths.absolute_paths(text)
        self.assertEqual(len(found), 2)
        self.assertTrue(found[0].lower().startswith("c:"))
        self.assertTrue(found[1].startswith("\\\\"))

    def test_join_rel_uses_forward_slashes(self):
        self.assertEqual(relpaths.join_rel("App", "XD", "XD.exe"),
                         "App/XD/XD.exe")


class RegistryTokenTests(unittest.TestCase):
    """Реестр: путь корня хранится маркером, соседние каталоги целы."""

    def test_reg_value_gets_marker(self):
        line = registry_mod.format_value(
            "Path", registry_mod.REG_SZ, ROOT + r"\App\XD.exe",
            [(ROOT, registry_mod.ROOT_TOKEN)])
        self.assertIn(registry_mod.ROOT_TOKEN, line)
        self.assertNotIn("Apps", line.replace(registry_mod.ROOT_TOKEN, ""))

    def test_sibling_path_is_not_tokenized(self):
        line = registry_mod.format_value(
            "Path", registry_mod.REG_SZ, r"D:\Apps\XData\save.ini",
            [(ROOT, registry_mod.ROOT_TOKEN)])
        self.assertNotIn(registry_mod.ROOT_TOKEN, line)

    def test_marker_matches_launcher_constant(self):
        self.assertEqual(registry_mod.ROOT_TOKEN, relpaths.ROOT_TOKEN)
        self.assertEqual(exe_launcher.ROOT_TOKEN, relpaths.ROOT_TOKEN)


class StampTests(unittest.TestCase):
    """Штамп корня: где лежит, что пишет, как читается."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "XD_Portable"
        self.root.mkdir()

    def test_stamp_is_written_inside_portable_data(self):
        path = relpaths.write_stamp(str(self.root), str(self.root), "1.15.0")
        self.assertTrue(path)
        self.assertTrue(str(path).endswith(
            os.path.join("PortableData", relpaths.STAMP_NAME)))
        self.assertEqual(relpaths.stored_root(str(self.root)), str(self.root))
        data = relpaths.read_stamp(str(self.root))
        self.assertEqual(data["version"], "1.15.0")
        # ASCII-копия для Launch.bat: cmd не разбирает JSON и не умеет
        # сравнивать не-ASCII пути побайтово.
        text_stamp = Path(relpaths.stamp_text_path(str(self.root)))
        self.assertTrue(text_stamp.is_file())
        self.assertEqual(text_stamp.read_text(encoding="ascii"),
                         str(self.root) + "\\" + "\n")

    def test_no_change_reported_for_same_root(self):
        relpaths.write_stamp(str(self.root))
        self.assertIsNone(relpaths.root_changed(str(self.root)))

    def test_move_is_detected(self):
        relpaths.write_stamp(str(self.root))
        other = Path(self.temp.name) / "Moved" / "XD_Portable"
        other.parent.mkdir(parents=True)
        # Перенос — это копия папки целиком, включая PortableData.
        shutil.move(str(self.root), str(other))
        changed = relpaths.root_changed(str(other))
        self.assertIsNotNone(changed)
        self.assertEqual(changed[0], str(self.root))
        self.assertEqual(changed[1], str(other))

    def test_broken_stamp_is_ignored(self):
        _write(Path(relpaths.stamp_path(str(self.root))), "{not json")
        self.assertIsNone(relpaths.read_stamp(str(self.root)))
        self.assertIsNone(relpaths.root_changed(str(self.root)))


class RepairTests(unittest.TestCase):
    """Починка после переноса: старый корень меняется новым."""

    def test_repair_text_all_forms(self):
        old, new = ROOT, r"F:\XD"
        text = (ROOT + r"\a.ini; D:/Apps/XD_Portable/b; "
                r"D:\\Apps\\XD_Portable\\c")
        fixed = relpaths.repair_text(text, old, new)
        self.assertNotIn("Apps", fixed)
        self.assertEqual(fixed, r"F:\XD\a.ini; F:\XD/b; F:\\XD\\c")

    def test_repair_text_keeps_siblings(self):
        self.assertEqual(relpaths.repair_text(r"D:\Apps\XData\x", ROOT, r"F:\XD"),
                         r"D:\Apps\XData\x")

    def test_repair_file_keeps_encoding_and_bom(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "settings.ini"
            path.write_bytes(b"\xff\xfe" + (
                "[Path]\r\nExe=" + ROOT + "\\App\\XD.exe\r\n").encode("utf-16-le"))
            hits = relpaths.repair_file(str(path), ROOT, r"F:\XD")
            self.assertEqual(hits, 1)
            raw = path.read_bytes()
            self.assertTrue(raw.startswith(b"\xff\xfe"))
            self.assertIn(r"F:\XD\App\XD.exe",
                          raw.decode("utf-16"))
            self.assertNotIn("Apps", raw.decode("utf-16"))

    def test_binary_file_is_not_touched(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "data.dat"
            payload = b"\x00\x01" + ROOT.encode("cp1251") + b"\xff\xfe"
            path.write_bytes(payload)
            self.assertEqual(relpaths.repair_file(str(path), ROOT, r"F:\XD"), 0)
            self.assertEqual(path.read_bytes(), payload)


class AuditTests(unittest.TestCase):
    """Проверка при сборке: что найдено, что записано в отчёт."""

    def _make_portable(self) -> Path:
        """Портатив во временной папке: абсолютные пути равны его же корню."""
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / "XD_Portable"
        _write(root / "launcher_config.json",
               json.dumps({"target_exe_rel": "App/XD.exe"}))
        _write(root / "PortableData" / "User" / "settings.ini",
               "[Path]\r\nExe=" + str(root) + os.sep + "App" + os.sep
               + "XD.exe\r\n")
        _write(root / "PortableData" / "Temp" / "ignored.ini",
               "[Path]\r\nExe=" + str(root) + os.sep + "App\r\n")
        _write(root / "App" / "readme.txt", "см. " + str(root) + os.sep + "App")
        (root / "App" / "XD.exe").write_bytes(b"MZ")
        return root

    def test_audit_separates_inside_and_outside(self):
        root = self._make_portable()
        _write(root / "PortableData" / "system.ini",
               "cache=C:\\Program Files\\Adobe\\cache\r\n"
               "self=" + str(root) + os.sep + "App\r\n")
        result = relpaths.audit(str(root))
        self.assertGreaterEqual(result.inside_count, 2)
        self.assertEqual(result.outside_count, 1)
        self.assertFalse(result.is_clean)

    def test_temp_is_skipped(self):
        root = self._make_portable()
        result = relpaths.audit(str(root))
        described = " ".join(hit.rel for hit in result.hits)
        self.assertNotIn("ignored.ini", described)

    def test_app_is_optional(self):
        root = self._make_portable()
        result = relpaths.audit(str(root), include_app=False)
        self.assertNotIn("readme.txt", " ".join(hit.rel for hit in result.hits))

    def test_clean_portable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "P"
            _write(root / "launcher_config.json", '{"target_exe_rel":"App/a.exe"}')
            result = relpaths.audit(str(root))
            self.assertTrue(result.is_clean)
            self.assertIn("переносить", result.summary())

    def test_report_and_stamp_written(self):
        root = self._make_portable()
        relpaths.write_stamp(str(root), str(root), "1.15.0")
        audit = relpaths.audit(str(root))
        path = relpaths.write_report(str(root), audit, version="1.15.0",
                                     stamp=relpaths.read_stamp(str(root)))
        self.assertIsNotNone(path)
        text = Path(path).read_text(encoding="utf-8")
        self.assertIn("portability-report", os.path.basename(path))
        self.assertIn("Portablizer: 1.15.0", text)
        self.assertIn("Проверка файлов", text)
        self.assertIn("Файлы с абсолютными путями", text)

    def test_report_mentions_launcher_for_repair(self):
        root = self._make_portable()
        audit = relpaths.audit(str(root))
        text = relpaths.render_report(audit, version="1.15.0")
        self.assertIn("LaunchPortable.exe", text)

    def test_launcher_section_has_no_absolute_path(self):
        section = relpaths.launcher_section("/tmp/x", enabled=True)
        self.assertTrue(section["enabled"])
        self.assertEqual(section["stamp"], relpaths.STAMP_REL)
        self.assertNotIn("/tmp/x", json.dumps(section))


class LauncherRepairTests(unittest.TestCase):
    """Тот же перенос, но глазами лончера ``App/LaunchPortable.exe``."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.old = self.base / "D" / "Apps" / "XD_Portable"
        self.old.mkdir(parents=True)
        _write(self.old / "launcher_config.json", "{}")
        (self.old / "App").mkdir()
        _write(self.old / "PortableData" / "User" / "prefs.ini",
               "[Path]\r\nExe=" + str(self.old) + "\\App\\XD.exe\r\n")
        exe_launcher.write_paths_stamp(self.old)

    def _move(self) -> Path:
        new = self.base / "F" / "XD_Portable"
        new.parent.mkdir(parents=True, exist_ok=True)
        # Перенос папки: на Windows os.replace каталога между разными
        # родительскими папками может вернуть «Access is denied».
        shutil.move(str(self.old), str(new))
        return new

    def test_same_root_does_nothing(self):
        self.assertEqual(exe_launcher.repair_paths(self.old), [])

    def test_moved_root_is_rewritten(self):
        new = self._move()
        lines = exe_launcher.repair_paths(new)
        self.assertTrue(lines)
        self.assertIn("moved", lines[0])
        text = (new / "PortableData" / "User" / "prefs.ini").read_text(
            encoding="utf-8")
        self.assertIn(str(new), text)
        self.assertNotIn(str(self.old), text)
        # Штамп обновлён: второй запуск уже ничего не правит.
        self.assertEqual(exe_launcher.repair_paths(new), [])

    def test_doubled_backslashes_in_json_are_rewritten(self):
        """В JSON и .reg обратные слэши удвоены — форма тоже должна ловиться."""
        new = self._move()
        old_win = "D:\\Apps\\XD_Portable"
        data = new / "PortableData" / "User" / "history.json"
        data.write_text(
            '{"dir": "' + old_win.replace("\\", "\\\\") + '\\\\App"}',
            encoding="utf-8")
        stamp_path = new / "PortableData" / "portable-root.json"
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
        stamp["previous"] = old_win
        stamp_path.write_text(json.dumps(stamp), encoding="utf-8")

        self.assertTrue(exe_launcher.repair_paths(new))
        text = data.read_text(encoding="utf-8")
        self.assertNotIn("D:", text)
        value = json.loads(text)["dir"]
        # Разделитель берётся из самого файла (в JSON он экранирован), важно,
        # что путь теперь указывает в новое место.
        self.assertTrue(value.startswith(str(new)), value)
        self.assertTrue(value.endswith("App"), value)

    def test_path_from_two_moves_ago_is_rewritten_too(self):
        """В настройках мог остаться путь не только прошлого места."""
        new = self._move()
        even_older = self.base / "C" / "Old" / "XD_Portable"
        (new / "PortableData" / "User" / "history.ini").write_text(
            "[Recent]\\r\\nDir=" + str(even_older) + "\\r\\n", encoding="utf-8")
        stamp = json.loads((new / "PortableData" / "portable-root.json")
                           .read_text(encoding="utf-8"))
        stamp["previous"] = str(even_older)
        (new / "PortableData" / "portable-root.json").write_text(
            json.dumps(stamp), encoding="utf-8")

        lines = exe_launcher.repair_paths(new)
        self.assertTrue(lines)
        text = (new / "PortableData" / "User" / "history.ini").read_text(
            encoding="utf-8")
        self.assertIn(str(new), text)
        self.assertNotIn(str(even_older), text)

    def test_stamp_text_file_is_ascii_copy(self):
        new = self._move()
        exe_launcher.repair_paths(new)
        stamp = new / "PortableData" / "portable-root.txt"
        self.assertTrue(stamp.is_file())
        self.assertEqual(stamp.read_text(encoding="ascii").strip(),
                         str(new) + "\\")

    def test_disabled_section_skips_repair(self):
        new = self._move()
        cfg = {"relative_paths": {"enabled": False}}
        self.assertEqual(exe_launcher.repair_paths(new, cfg), [])

    def test_force_ignores_disabled_section(self):
        new = self._move()
        cfg = {"relative_paths": {"enabled": False}}
        self.assertTrue(exe_launcher.repair_paths(new, cfg, force=True))

    def test_sibling_folder_is_not_harmed(self):
        sibling = self.base / "D" / "Apps" / "XD_Portable_Data" / "a.ini"
        _write(sibling, "self=" + str(self.old) + "_Data/x")
        new = self._move()
        exe_launcher.repair_paths(new)
        text = (self.base / "D" / "Apps" / "XD_Portable_Data" / "a.ini").read_text(
            encoding="utf-8")
        self.assertIn(str(self.old) + "_Data/x", text)

    def test_reg_packing_is_boundary_aware(self):
        text = r'"a"="D:\\Apps\\XD_Portable\\x"; "b"="D:\\Apps\\XData\\y"'
        fixed = exe_launcher._replace_root_text(
            text, r"D:\\Apps\\XD_Portable", exe_launcher.ROOT_TOKEN)
        self.assertIn(exe_launcher.ROOT_TOKEN, fixed)
        self.assertIn(r"D:\\Apps\\XData\\y", fixed)


class GeneratedLauncherTests(unittest.TestCase):
    """Собранный лончер: в BAT и конфиге нет абсолютных путей, есть починка."""

    def _cfg(self) -> "launcher_mod.LauncherConfig":
        return launcher_mod.LauncherConfig(
            app_name="Adobe XD", target_exe_rel="App/XD.exe",
            relative_paths=relpaths.launcher_section(enabled=True))

    def test_bat_delegates_repair_to_exe(self):
        bat = launcher_mod.render_bat(self._cfg())
        self.assertIn("call :portable_paths_check", bat)
        self.assertIn(":portable_paths_check", bat)
        self.assertIn("--repair-paths", bat)
        self.assertIn("portable-root.txt", bat)
        self.assertTrue(all(ord(ch) < 128 for ch in bat))

    def test_bat_has_no_drive_letter(self):
        bat = launcher_mod.render_bat(self._cfg())
        for line in bat.splitlines():
            stripped = line.strip()
            if stripped.startswith("rem"):
                continue
            self.assertNotRegex(stripped, r"[A-Za-z]:\\\\",
                                f"абсолютный путь в BAT: {line}")

    def test_config_carries_relative_section(self):
        data = json.loads(launcher_mod.render_config_json(self._cfg()))
        self.assertTrue(data["relative_paths"]["enabled"])
        self.assertEqual(data["relative_paths"]["stamp"],
                         relpaths.STAMP_REL)

    def test_config_round_trip_keeps_section(self):
        data = json.loads(launcher_mod.render_config_json(self._cfg()))
        restored = launcher_mod.config_from_dict(data)
        self.assertTrue(restored.relative_paths["enabled"])

    def test_missing_section_means_defaults(self):
        cfg = launcher_mod.config_from_dict({"app_name": "A",
                                             "target_exe_rel": "App/a.exe"})
        self.assertEqual(cfg.relative_paths, {})
        self.assertTrue(exe_launcher._paths_settings({})["enabled"])


class BuildStepTests(unittest.TestCase):
    """Шаг сборки: пишет штамп и отчёт, конфиг остаётся относительным."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "XD_Portable"
        (self.root / "App").mkdir(parents=True)
        (self.root / "App" / "XD.exe").write_bytes(b"MZ")
        _write(self.root / "PortableData" / "User" / "prefs.ini",
               "[Path]\r\nExe=" + str(self.root) + os.sep + "App" + os.sep
               + "XD.exe\r\n")

    def _options(self, relative: bool = True):
        return portablizer_mod.PortableOptions(
            installer_path="setup.exe", output_dir=self.temp.name,
            build_exe_launcher=False, relative_paths=relative)

    def test_report_and_stamp_are_written(self):
        engine = portablizer_mod.Portablizer(Logger())
        result = portablizer_mod.PortableResult(success=True)
        rel = engine._make_paths_relative(str(self.root), "XD",
                                          self._options(), result)
        self.assertEqual(rel, relpaths.REPORT_NAME)
        self.assertTrue((self.root / relpaths.REPORT_NAME).is_file())
        self.assertTrue(Path(relpaths.stamp_path(str(self.root))).is_file())
        self.assertEqual(relpaths.stored_root(str(self.root)), str(self.root))

    def test_disabled_flag_writes_nothing(self):
        engine = portablizer_mod.Portablizer(Logger())
        result = portablizer_mod.PortableResult(success=True)
        rel = engine._make_paths_relative(str(self.root), "XD",
                                          self._options(relative=False), result)
        self.assertEqual(rel, "")
        self.assertFalse((self.root / relpaths.REPORT_NAME).is_file())
        self.assertFalse(Path(relpaths.stamp_path(str(self.root))).is_file())

    def test_launcher_config_has_relative_section(self):
        engine = portablizer_mod.Portablizer(Logger())
        engine._write_launcher(str(self.root), "XD", "App\\XD.exe",
                               self._options(), [], None, [], None)
        data = json.loads((self.root / "launcher_config.json")
                          .read_text(encoding="utf-8"))
        self.assertTrue(data["relative_paths"]["enabled"])
        self.assertEqual(data["relative_paths"]["root_token"],
                         relpaths.ROOT_TOKEN)
        self.assertNotIn(str(self.root), json.dumps(data))

    def test_launcher_config_can_disable_relative_paths(self):
        engine = portablizer_mod.Portablizer(Logger())
        engine._write_launcher(str(self.root), "XD", "App\\XD.exe",
                               self._options(relative=False), [], None, [], None)
        data = json.loads((self.root / "launcher_config.json")
                          .read_text(encoding="utf-8"))
        self.assertFalse(data["relative_paths"]["enabled"])


class EndToEndMoveTests(unittest.TestCase):
    """Сборка → перенос → починка: настройки смотрят на новый корень."""

    def test_move_after_build_is_repaired_by_launcher(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "D" / "XD_Portable"
            (root / "App").mkdir(parents=True)
            (root / "App" / "XD.exe").write_bytes(b"MZ")
            prefs = _write(root / "PortableData" / "User" / "prefs.ini",
                           "[Path]\r\nExe=" + str(root) + os.sep + "App"
                           + os.sep + "XD.exe\r\n")
            engine = portablizer_mod.Portablizer(Logger())
            result = portablizer_mod.PortableResult(success=True)
            engine._make_paths_relative(
                str(root), "XD",
                portablizer_mod.PortableOptions(
                    installer_path="setup.exe", output_dir=temp,
                    build_exe_launcher=False),
                result)
            moved = base / "F" / "XD"
            moved.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(root), str(moved))

            lines = exe_launcher.repair_paths(moved)
            self.assertTrue(lines)
            text = (moved / "PortableData" / "User" / "prefs.ini").read_text(
                encoding="utf-8")
            self.assertIn(str(moved), text)
            self.assertNotIn(str(root), text)
            self.assertTrue(prefs.is_file() is False)  # старый путь исчез


if __name__ == "__main__":
    unittest.main()
