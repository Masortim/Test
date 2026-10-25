"""Ярлыки установщика: не оставлять свои и не трогать чужие.

Жалоба: после портирования на рабочем столе оставался ярлык программы, а
после переноса папки на другой диск он вёл по прежнему, статичному пути —
и обновление, запущенное оттуда, ставилось в старое место.

Проверяется главное свойство: удаляется только ярлык, которого не было до
установки И который указывает внутрь этой портативной папки (в том числе в
её прежнее место). Ярлык пользователя и ярлыки чужих программ остаются.
"""
import os
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
    """Ярлык хранит цель в UTF-16LE — так же его и пишем."""
    return _write(path, str(target).encode("utf-16-le"))


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


if __name__ == "__main__":
    unittest.main()
