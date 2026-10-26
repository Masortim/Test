"""Ярлыки установщика: не оставлять свои и не трогать чужие.

Жалоба: после портирования на рабочем столе оставался ярлык программы, а
после переноса папки на другой диск он вёл по прежнему, статичному пути —
и обновление, запущенное оттуда, ставилось в старое место.

Проверяется главное свойство: удаляется только ярлык, которого не было до
установки И который указывает внутрь этой портативной папки (в том числе в
её прежнее место). Ярлык пользователя и ярлыки чужих программ остаются.
"""
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from portablizer.core import shortcuts  # noqa: E402


def _write(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")
    return path


def _lnk(path: Path, target: Path) -> Path:
    """«Сырой» ярлык: цель просто текстом (как ищет link_points_into)."""
    return _write(path, str(target).encode("utf-16-le"))


def make_lnk(path: Path, target: str, flags: int = 0x2) -> Path:
    """Настоящий файл ``.lnk`` с блоком LinkInfo (как его пишет установщик).

    Структура по MS-SHLLINK: заголовок 0x4C байт, сразу за ним LinkInfo,
    внутри — Ansi-строка с локальным путём.
    """
    raw = target.encode("latin-1", errors="replace") + b"\0"
    size = 0x1C + len(raw) + 1
    info = struct.pack("<IIIIIII", size, 0x1C, 1, 0, 0x1C, 0, 0x1C + len(raw))
    info += raw + b"\0"
    header = bytearray(0x4C)
    header[0:4] = b"L\x00\x00\x00"
    header[0x14:0x18] = struct.pack("<I", flags)
    path.parent.mkdir(parents=True, exist_ok=True)
    return _write(path, bytes(header) + info)


class ShortcutGuardTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = self.base / "Apps" / "Ollama_Portable"
        (self.root / "App").mkdir(parents=True)
        self.desktop = self.base / "Desktop"
        self.desktop.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _guard(self, extra_roots=(), desktop=None):
        return shortcuts.ShortcutGuard(
            self.root, extra_roots=extra_roots,
            folders=[desktop or self.desktop])

    def test_snapshot_counts_existing_links_recursively(self):
        _lnk(self.desktop / "Old.lnk", Path("C:/Other/Old.exe"))
        nested = self.desktop / "Folder"
        _write(nested / "Other.url", "[InternetShortcut]\nURL=https://x\n")
        _write(self.desktop / "notes.txt", "not a link")
        guard = self._guard()
        self.assertEqual(guard.snapshot(), 2)

    def test_created_link_into_the_portable_is_removed(self):
        guard = self._guard()
        guard.snapshot()
        link = _lnk(self.desktop / "Ollama.lnk",
                    self.root / "App" / "ollama app.exe")
        self.assertEqual(guard.cleanup(), [str(link)])
        self.assertFalse(link.exists())
        self.assertEqual(guard.cleanup(), [], "повторная уборка пуста")

    def test_link_that_existed_before_is_kept(self):
        link = _lnk(self.desktop / "Ollama.lnk",
                    self.root / "App" / "ollama app.exe")
        guard = self._guard()
        guard.snapshot()
        self.assertEqual(guard.cleanup(), [])
        self.assertTrue(link.exists(), "ярлык пользователя не удаляется")

    def test_created_link_to_another_program_is_kept(self):
        guard = self._guard()
        guard.snapshot()
        link = _lnk(self.desktop / "Other.lnk",
                    Path("C:/Program Files/Other/Other.exe"))
        self.assertEqual(guard.cleanup(), [])
        self.assertTrue(link.exists())

    def test_link_to_the_previous_location_is_removed(self):
        """Ярлык, созданный до переезда папки, содержит старый путь."""
        previous = self.base / "OldDrive" / "Ollama_Portable"
        (previous / "App").mkdir(parents=True)
        guard = self._guard(extra_roots=[str(previous)])
        guard.snapshot()
        link = _lnk(self.desktop / "Ollama.lnk",
                    previous / "App" / "ollama app.exe")
        self.assertEqual(guard.cleanup(), [str(link)])

    def test_url_file_pointing_into_the_portable_is_removed(self):
        guard = self._guard()
        guard.snapshot()
        link = _write(
            self.desktop / "Ollama.url",
            "[InternetShortcut]\nURL=file:///" +
            str(self.root / "App").replace("\\", "/") + "/ollama.exe\n")
        self.assertEqual(guard.cleanup(), [str(link)])

    def test_separate_folder_is_not_removed(self):
        guard = self._guard()
        guard.snapshot()
        other = _lnk(self.desktop / "Ollama2.lnk",
                     self.base / "Apps" / "Ollama_Portable2" / "App" / "x.exe")
        self.assertEqual(guard.cleanup(), [])
        self.assertTrue(other.exists(), "похожее имя — не наш ярлык")

    def test_resolver_is_the_fallback_for_unreadable_targets(self):
        guard = self._guard()
        guard.before = shortcuts.snapshot([self.desktop])
        link = _write(self.desktop / "Ollama.lnk", b"\x00binary\x00")
        guard.resolver = lambda path: (str(self.root / "App" / "x.exe")
                                       if str(path) == str(link) else "")
        self.assertEqual(guard.cleanup(), [str(link)])

    def test_without_a_snapshot_nothing_is_removed(self):
        link = _lnk(self.desktop / "Ollama.lnk",
                    self.root / "App" / "ollama app.exe")
        removed = shortcuts.remove_own_shortcuts(
            self.root, folders=[self.desktop], before=None)
        self.assertEqual(removed, [])
        self.assertTrue(link.exists())


class LinkTargetTests(unittest.TestCase):
    """Чтение цели ярлыка без COM и PowerShell."""

    def test_lnk_local_path_is_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = make_lnk(Path(tmp) / "App.lnk", "C:\\Apps\\App\\app.exe")
            self.assertEqual(shortcuts.lnk_target(str(link)),
                             "C:\\Apps\\App\\app.exe")

    def test_link_without_link_info_has_no_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = make_lnk(Path(tmp) / "App.lnk", "C:\\Apps\\app.exe", flags=0)
            self.assertEqual(shortcuts.lnk_target(str(link)), "")

    def test_url_file_target_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = _write(Path(tmp) / "App.url",
                          "[InternetShortcut]\nURL=file:///C:/Apps/app.exe\n")
            self.assertEqual(shortcuts.link_target(str(link)),
                             "C:" + chr(92) + "Apps" + chr(92) + "app.exe")

    def test_missing_target_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            gone = Path(tmp) / "temp-installer" / "app.exe"
            self.assertTrue(shortcuts.target_is_missing(str(gone)))
            existing = _write(Path(tmp) / "app.exe", "x")
            self.assertFalse(shortcuts.target_is_missing(str(existing)))
            # Ссылки в интернет и на недоступный сервер — не поломка.
            self.assertFalse(shortcuts.target_is_missing("https://example.com"))
            self.assertFalse(shortcuts.target_is_missing("\\\\server\\share\\a.exe"))


class StaleShortcutTests(unittest.TestCase):
    """«Пустой» ярлык после сборки: файл есть, цели нет."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = self.base / "Apps" / "Ollama_Portable"
        (self.root / "App").mkdir(parents=True)
        self.desktop = self.base / "Desktop"
        self.desktop.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _names(self):
        return shortcuts.app_name_candidates("Ollama", "OllamaSetup.exe")

    def test_empty_shortcut_of_the_program_is_removed(self):
        link = make_lnk(self.desktop / "Ollama.lnk",
                        str(self.base / "gone-temp" / "Ollama.exe"))
        removed = shortcuts.remove_stale_shortcuts(
            self._names(), roots=[str(self.root)], folders=[str(self.desktop)])
        self.assertEqual(removed, [str(link)])
        self.assertFalse(link.exists())

    def test_working_shortcut_of_the_program_is_kept(self):
        exe = _write(self.base / "Programs" / "Ollama" / "Ollama.exe", "x")
        link = make_lnk(self.desktop / "Ollama.lnk", str(exe))
        removed = shortcuts.remove_stale_shortcuts(
            self._names(), roots=[str(self.root)], folders=[str(self.desktop)])
        self.assertEqual(removed, [])
        self.assertTrue(link.exists())

    def test_empty_shortcut_of_another_program_is_kept(self):
        link = make_lnk(self.desktop / "Telegram.lnk",
                        str(self.base / "gone" / "Telegram.exe"))
        removed = shortcuts.remove_stale_shortcuts(
            self._names(), roots=[str(self.root)], folders=[str(self.desktop)])
        self.assertEqual(removed, [])
        self.assertTrue(link.exists())

    def test_shortcut_into_the_portable_is_removed_even_if_target_exists(self):
        """Ярлык на портатив бесполезен после переезда папки."""
        exe = _write(self.root / "App" / "Ollama.exe", "x")
        link = make_lnk(self.desktop / "Ollama Portable.lnk", str(exe))
        removed = shortcuts.remove_stale_shortcuts(
            self._names(), roots=[str(self.root)], folders=[str(self.desktop)])
        self.assertEqual(removed, [str(link)])

    def test_guard_sweep_works_without_a_snapshot(self):
        guard = shortcuts.ShortcutGuard(
            str(self.root), folders=[str(self.desktop)],
            app_names=self._names())
        link = make_lnk(self.desktop / "Ollama.lnk",
                        str(self.base / "gone" / "Ollama.exe"))
        self.assertEqual(guard.sweep(), [str(link)])
        self.assertEqual(guard.sweep(), [], "повторный обход ничего не находит")

    def test_names_cover_folder_and_installer_file(self):
        names = shortcuts.app_name_candidates(
            "Ollama_Portable", "OllamaSetup.exe", "ollama app.exe")
        self.assertIn("ollama", names)
        self.assertIn("ollamasetup", names)

    def test_names_extract_parent_folder_and_transliteration_for_generic_setup(self):
        names = shortcuts.app_name_candidates(
            "Multitran",
            r"E:\Backup\Apps\Portable\Multitran 03.11.2023\setup.exe",
        )
        self.assertIn("multitran", names)
        self.assertIn("мультитран", names)

    def test_guard_captures_target_and_removes_new_app_shortcut_outside_portable(self):
        names = shortcuts.app_name_candidates(
            "Multitran",
            r"E:\Backup\Apps\Portable\Multitran 03.11.2023\setup.exe",
        )
        guard = shortcuts.ShortcutGuard(
            str(self.root), folders=[str(self.desktop)], app_names=names)
        guard.snapshot()
        default_exe = self.base / "Multitran" / "network.exe"
        link = make_lnk(
            self.desktop / "Словарь Мультитран.lnk", str(default_exe))
        removed = guard.cleanup()
        self.assertEqual(removed, [str(link)])
        self.assertFalse(link.exists())
        self.assertEqual(guard.created_targets(), [str(default_exe)])


class LinkDetectionTests(unittest.TestCase):
    def test_slash_and_backslash_forms_both_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(Path(tmp) / "a.lnk",
                          "D:/Apps/Ollama_Portable/App/x.exe".encode("utf-16-le"))
            self.assertTrue(shortcuts.link_points_into(
                str(path), ["D:\\Apps\\Ollama_Portable"]))
            self.assertFalse(shortcuts.link_points_into(
                str(path), ["D:\\Apps\\Other"]))

    def test_path_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(Path(tmp) / "a.lnk",
                          str(Path("C:/Apps/FooBar/x.exe")).encode("utf-16-le"))
            self.assertFalse(shortcuts.link_points_into(
                str(path), ["C:\\Apps\\Foo"]))

    def test_lnk_target_parses_real_windows_lnk_with_idlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Multitran.lnk"
            header = bytearray(0x4C)
            header[0:4] = b"L\x00\x00\x00"
            import struct
            # HasLinkTargetIDList (0x01) | HasLinkInfo (0x02)
            struct.pack_into("<I", header, 0x14, 0x03)
            idlist_body = b"\x14\x00" + b"\x00" * 18 + b"\x00\x00"
            idlist = struct.pack("<H", len(idlist_body)) + idlist_body
            base_bytes = b"C:\\Multitran\\\x00"
            suffix_bytes = b"network.exe\x00"
            info_header_size = 0x1C
            base_offset = info_header_size
            suffix_offset = base_offset + len(base_bytes)
            info_size = suffix_offset + len(suffix_bytes)
            link_info = struct.pack(
                "<IIIIIII",
                info_size,
                info_header_size,
                0x01,
                info_header_size,
                base_offset,
                0,
                suffix_offset,
            ) + base_bytes + suffix_bytes
            path.write_bytes(bytes(header) + idlist + link_info)
            self.assertEqual(
                shortcuts.lnk_target(str(path)),
                r"C:\Multitran\network.exe",
            )


if __name__ == "__main__":
    unittest.main()
