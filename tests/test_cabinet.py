"""Тесты собственного распаковщика кабинетов.

Жалоба пользователя, из-за которой этот модуль появился: «Microsoft Visual
C++ 2008/2010/2012: пакет скачан, но распаковать его автоматически не
удалось». Распаковка чужими руками (запуск самого пакета с ключом ``/T:``,
``/x:``, ``/layout`` или ``expand``) зависит от того, как пакет разберёт
путь, от политик запуска exe и от наличия ``expand`` в PATH. Здесь кабинет
читается напрямую — и это должно работать всегда.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cabbuild import (make_burn_bundle, make_cabinet, make_lzx_cabinet,
                      make_self_extracting_exe)
from portablizer.core import cabinet


class CabinetReaderTests(unittest.TestCase):

    def test_plain_cabinet_round_trip(self):
        payload = {"msvcp110.dll": b"MZ" + os.urandom(70000),
                   "readme.txt": "привет".encode("utf-8")}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "vc_red.cab")
            path.write_bytes(make_cabinet(payload))
            out = Path(temp, "out")

            written = cabinet.extract_file(str(path), str(out))

            self.assertEqual({os.path.basename(p) for p in written},
                             set(payload))
            for name, data in payload.items():
                self.assertEqual((out / name).read_bytes(), data)
            self.assertTrue(cabinet.looks_like_cabinet(str(path)))

    def test_lzx_cabinet_round_trip(self):
        """Кабинет со сжатием LZX (используется во многих пакетах VC++ и DirectX)."""
        payload = {"msvcr90.dll": b"MZ" + os.urandom(80000),
                   "readme.txt": "test lzx content".encode("utf-8")}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "vc_red_lzx.cab")
            path.write_bytes(make_lzx_cabinet(payload))
            out = Path(temp, "out")

            written = cabinet.extract_file(str(path), str(out))

            self.assertEqual({os.path.basename(p) for p in written},
                             set(payload))
            for name, data in payload.items():
                self.assertEqual((out / name).read_bytes(), data)

    def test_uncompressed_cabinet_is_read_too(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "store.cab")
            path.write_bytes(make_cabinet({"a.dll": b"MZ" + b"a" * 5000},
                                          compress=False))
            out = Path(temp, "out")
            cabinet.extract_file(str(path), str(out))
            self.assertEqual((out / "a.dll").read_bytes(), b"MZ" + b"a" * 5000)

    def test_self_extracting_exe_is_opened_without_running_it(self):
        """VC++ 2005-2010: PE, к которому «довеском» приклеен кабинет."""
        dll = b"MZ" + os.urandom(120000)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "vcredist_x86.exe")
            path.write_bytes(make_self_extracting_exe(
                {"vc_red.msi": b"\xd0\xcf\x11\xe0" + os.urandom(2000),
                 "vc_red.cab": make_cabinet({"msvcr100.dll": dll})}))
            out = Path(temp, "out")

            cabinet.extract_file(str(path), str(out))

            # Вложенный кабинет раскрыт рекурсивно.
            self.assertEqual((out / "msvcr100.dll").read_bytes(), dll)
            self.assertTrue((out / "vc_red.msi").is_file())

    def test_burn_bundle_with_several_containers(self):
        """VC++ 2012-2022: WiX Burn, к PE приклеено несколько контейнеров."""
        dll = b"MZ" + os.urandom(40000)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "vc_redist.x64.exe")
            path.write_bytes(make_burn_bundle([
                {"manifest.xml": b"<BurnManifest/>"},
                {"cab1.cab": make_cabinet({"msvcp110.dll": dll})},
            ]))
            out = Path(temp, "out")

            cabinet.extract_file(str(path), str(out))

            self.assertTrue((out / "manifest.xml").is_file())
            self.assertEqual((out / "msvcp110.dll").read_bytes(), dll)

    def test_big_file_spanning_many_blocks(self):
        """Файл больше 32 КБ занимает несколько блоков CFDATA с общей историей."""
        dll = b"MZ" + os.urandom(300000)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "big.cab")
            path.write_bytes(make_cabinet({"d3dx9_43.dll": dll,
                                           "x3daudio1_7.dll": b"MZtail"}))
            out = Path(temp, "out")
            cabinet.extract_file(str(path), str(out))
            self.assertEqual((out / "d3dx9_43.dll").read_bytes(), dll)
            self.assertEqual((out / "x3daudio1_7.dll").read_bytes(), b"MZtail")

    def test_files_never_escape_the_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "evil.cab")
            path.write_bytes(make_cabinet(
                {r"..\..\windows\system32\evil.dll": b"MZ" + b"x" * 100}))
            out = Path(temp, "out")
            cabinet.extract_file(str(path), str(out))
            self.assertFalse(Path(temp, "windows").exists())
            self.assertTrue((out / "windows" / "system32" / "evil.dll").is_file())

    def test_garbage_is_not_mistaken_for_a_cabinet(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "notes.txt")
            path.write_bytes(b"MSCF is mentioned here but there is no cabinet "
                             + os.urandom(4096))
            out = Path(temp, "out")
            self.assertEqual(cabinet.extract_file(str(path), str(out)), [])
            self.assertFalse(cabinet.contains_cabinet(str(path)))

    def test_truncated_cabinet_does_not_raise(self):
        with tempfile.TemporaryDirectory() as temp:
            data = make_cabinet({"msvcp140.dll": b"MZ" + os.urandom(50000)})
            path = Path(temp, "broken.cab")
            path.write_bytes(data[:len(data) // 2])
            out = Path(temp, "out")
            self.assertEqual(cabinet.extract_file(str(path), str(out)), [])


if __name__ == "__main__":
    unittest.main()
