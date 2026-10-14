"""Свободное место: сколько нужно установщику и куда перенести его TEMP.

Регрессия, ради которой написан этот модуль:

    Офлайн-установщик GOG распаковывает данные СНАЧАЛА во временную папку и
    только потом переносит их в целевую. Portablizer перенаправляет TEMP
    внутрь портативной папки (правильно: после сборки на компьютере не
    остаётся следов), но у диска портатива появляется второй потребитель
    места. На флешке или небольшом разделе установщику не хватает места — и
    он не отказывается работать, а ПАДАЕТ (типичный код 0xC000041D:
    распаковка оборвалась, исключение прилетело в обработчик прогресса).

Проверяется, что:
  * вес дистрибутива считается вместе с его частями (``setup_hatred-1.bin``
    относится к ``setup_hatred_2.1.0.9_(…).exe``, а чужой установщик в той же
    папке — нет);
  * при нехватке места выбирается другой диск, и только если он реально
    свободнее;
  * без данных (размер неизвестен) никаких выводов не делается.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from portablizer.core import space as space_mod


def _file(path: Path, size: int) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(b"x" * size)
    return str(path)


class MediaBytesTests(unittest.TestCase):
    def test_installer_is_counted_together_with_its_parts(self):
        """Главный сценарий: GOG-установщик из двух частей."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            installer = _file(root / "setup_hatred_2.1.0.9_(2069488821).exe",
                              4 * 1024)
            _file(root / "setup_hatred-1.bin", 8 * 1024)
            _file(root / "setup_hatred-2.bin", 2 * 1024)
            self.assertEqual(space_mod.media_bytes(installer),
                             14 * 1024)

    def test_parts_of_another_installer_are_not_counted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            installer = _file(root / "setup_hatred_1.0_(1).exe", 1024)
            _file(root / "setup_hitman_1.0_(2).exe", 64 * 1024)
            _file(root / "setup_hitman-1.bin", 64 * 1024)
            self.assertEqual(space_mod.media_bytes(installer), 1024)

    def test_unrelated_files_are_not_counted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            installer = _file(root / "game_setup.exe", 1024)
            _file(root / "readme.txt", 4096)
            _file(root / "setup_hatred-1.bin", 4096)  # имя не совпадает
            self.assertEqual(space_mod.media_bytes(installer), 1024)

    def test_numbered_parts_and_cabs_are_recognised(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            installer = _file(root / "mygame_setup.exe", 512)
            _file(root / "mygame_setup.001", 256)
            _file(root / "mygame_setup.cab", 256)
            self.assertEqual(space_mod.media_bytes(installer), 1024)

    def test_unknown_size_means_no_estimate(self):
        with tempfile.TemporaryDirectory() as temp:
            missing = os.path.join(temp, "нет-такого-установщика.exe")
            self.assertEqual(space_mod.media_bytes(missing), 0)


class FreeSpaceTests(unittest.TestCase):
    def test_free_space_of_a_real_directory_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertGreater(space_mod.free_space(temp), 0)

    def test_missing_path_falls_back_to_the_existing_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            nested = os.path.join(temp, "нет", "ещё", "нет")
            self.assertEqual(space_mod.free_space(nested),
                             space_mod.free_space(temp))

    def test_unknown_path_reports_minus_one(self):
        self.assertEqual(space_mod.free_space(""), -1)


class VolumeTests(unittest.TestCase):
    def test_same_directory_is_the_same_volume(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertEqual(space_mod.volume_of(str(root)),
                             space_mod.volume_of(str(root / "PortableData")))


class PickTempRootTests(unittest.TestCase):
    """Выбор диска для переноса TEMP: делается по числам, а не наугад."""

    def test_enough_space_keeps_temp_inside_the_portable_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            chosen = space_mod.pick_temp_root(temp, 10,
                                              free=lambda p: 100, roots=[temp])
            self.assertIsNone(chosen)

    def test_short_on_the_portable_drive_moves_temp_to_a_bigger_one(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "portable")
            portable.mkdir()
            other = Path(temp, "other")
            other.mkdir()
            free = {str(portable): 10, str(other): 500}
            chosen = space_mod.pick_temp_root(
                str(portable), 100, free=lambda p: free.get(p, -1),
                roots=[str(other)], volume=lambda p: p)
            self.assertEqual(chosen, str(other))

    def test_candidate_on_the_same_volume_does_not_help(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            portable = root / "portable"
            portable.mkdir()
            same_volume = root / "temp"
            same_volume.mkdir()
            # free() отвечает одинаково: переносить некуда.
            self.assertIsNone(space_mod.pick_temp_root(
                str(portable), 100, free=lambda p: 10,
                roots=[str(same_volume)], volume=lambda p: "один-диск"))

    def test_smaller_candidate_is_never_chosen(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "portable")
            portable.mkdir()
            other = Path(temp, "other")
            other.mkdir()
            free = {str(portable): 100, str(other): 5}
            self.assertIsNone(space_mod.pick_temp_root(
                str(portable), 500, free=lambda p: free.get(p, -1),
                roots=[str(other)], volume=lambda p: p))

    def test_best_candidate_is_chosen_among_several(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "portable")
            portable.mkdir()
            small = Path(temp, "small")
            small.mkdir()
            big = Path(temp, "big")
            big.mkdir()
            free = {str(portable): 1, str(small): 300, str(big): 900}
            chosen = space_mod.pick_temp_root(
                str(portable), 100, free=lambda p: free.get(p, -1),
                roots=[str(small), str(big)], volume=lambda p: p)
            self.assertEqual(chosen, str(big))

    def test_unknown_need_changes_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertIsNone(space_mod.pick_temp_root(temp, 0,
                                                       free=lambda p: 0,
                                                       roots=[temp]))

    def test_missing_candidate_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp, "portable")
            portable.mkdir()
            ghost = str(Path(temp, "нет-такого-диска"))
            self.assertIsNone(space_mod.pick_temp_root(
                str(portable), 100, free=lambda p: 1000, roots=[ghost],
                volume=lambda p: p))


if __name__ == "__main__":
    unittest.main()
