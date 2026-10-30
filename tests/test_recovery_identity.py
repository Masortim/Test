"""В App попадает только та программа, которую поставил выбранный установщик.

Жалоба
------
Пользователь собрал портатив из ``delta-windows-x86_64-setup.exe``. В ``App``
оказался ``mpc-hc64.exe`` (Media Player Classic) — чужая программа, которая
просто была открыта на этом ПК, — и ``Launch.bat`` запускал именно её.

Причина
-------
Восстановление результата установки считало доказательством «каталог появился
во время установки». Каталог, созданный любым другим процессом (обновлятор,
браузер, уже открытая программа), попадал в кандидаты и копировался в ``App``.

Договор, который проверяют эти тесты
------------------------------------
1. Источник копируется в ``App`` только при доказательстве принадлежности:
   exe запущен самим установщиком, имя exe (или каталога) совпадает с именем
   программы, либо на источник прямо указал созданный установщиком ярлык или
   новая запись ``InstallLocation``.
2. «Появился во время установки» само по себе доказательством не является.
3. Главным exe выбирается тот, который запускал установщик, даже если рядом
   лежит чужой бинарник большего размера.
4. Служебные папки сборки (``_bundle_layout`` и подобные) не остаются в
   готовом портативе.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from portablizer.core import portablizer as portablizer_mod
from portablizer.core.logutil import Logger
from portablizer.core.portablizer import Portablizer


def _write(path: Path, size: int = 64) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"MZ" + b"x" * max(0, size - 2))
    return path


class _Env:
    """Временные «места установки» Windows вместо настоящих."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.local = root / "LocalAppData"
        self.roaming = root / "Roaming"
        self.program_data = root / "ProgramData"
        self.program_files = root / "ProgramFiles"
        for path in (self.local, self.roaming, self.program_data,
                     self.program_files):
            path.mkdir(parents=True, exist_ok=True)
        self.env = {
            "LOCALAPPDATA": str(self.local),
            "APPDATA": str(self.roaming),
            "PROGRAMDATA": str(self.program_data),
            "PROGRAMFILES": str(self.program_files),
            "PROGRAMW6432": str(self.program_files),
            "PROGRAMFILES(X86)": str(self.program_files),
            "SystemDrive": str(root / "SysDrive"),
        }

    def __enter__(self, ) -> "_Env":
        self._patch = [
            mock.patch.dict(os.environ, self.env, clear=False),
            mock.patch.object(portablizer_mod, "IS_WINDOWS", True),
        ]
        for item in self._patch:
            item.start()
        return self

    def __exit__(self, *exc) -> None:
        for item in reversed(self._patch):
            item.stop()


class RecoveryIdentityTests(unittest.TestCase):
    def _engine(self) -> Portablizer:
        engine = Portablizer(Logger())
        engine._detection = None
        engine._install_images = set()
        return engine

    def _setup(self, root: Path):
        downloads = root / "Downloads"
        downloads.mkdir(parents=True, exist_ok=True)
        installer = _write(downloads / "delta-windows-x86_64-setup.exe")
        portable = root / "Portable"
        app_dir = portable / "App"
        app_dir.mkdir(parents=True, exist_ok=True)
        data_dir = portable / "PortableData"
        data_dir.mkdir(parents=True, exist_ok=True)
        return installer, portable, app_dir, data_dir

    def test_foreign_new_folder_is_not_copied(self):
        """Новый каталог с чужим exe не попадает в App (баг MPC-HC)."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with _Env(root) as env:
                installer, _portable, app_dir, data_dir = self._setup(root)
                engine = self._engine()
                # Снимок ДО установки: чужого плеера на диске ещё нет.
                before = engine._snapshot_install_locations(str(data_dir))
                _write(env.local / "Programs" / "MPC-HC" / "mpc-hc64.exe", 4096)
                recovered = engine._recover_installed_app(
                    app_dir=str(app_dir),
                    data_dir=str(data_dir),
                    app_name="delta",
                    installer_path=str(installer),
                    before=before,
                )
                self.assertFalse(
                    recovered,
                    "чужой каталог не должен считаться результатом установки")
                self.assertEqual(
                    [], sorted(p.name for p in app_dir.iterdir()),
                    "в App не должно быть ни одного чужого файла",
                )

    def test_only_the_installed_program_is_copied(self):
        """Из двух новых каталогов забирается только каталог программы."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with _Env(root) as env:
                installer, _portable, app_dir, data_dir = self._setup(root)
                engine = self._engine()
                before = engine._snapshot_install_locations(str(data_dir))
                _write(env.local / "Programs" / "MPC-HC" / "mpc-hc64.exe", 8192)
                _write(env.local / "Programs" / "delta" / "delta.exe", 1024)
                (env.local / "Programs" / "delta" / "themes").mkdir(
                    exist_ok=True)
                _write(env.local / "Programs" / "delta" / "themes"
                       / "default.toml", 32)
                recovered = engine._recover_installed_app(
                    app_dir=str(app_dir),
                    data_dir=str(data_dir),
                    app_name="delta",
                    installer_path=str(installer),
                    before=before,
                )
                self.assertTrue(recovered)
                names = sorted(
                    str(p.relative_to(app_dir)).replace(os.sep, "/")
                    for p in app_dir.rglob("*") if p.is_file())
                self.assertIn("delta.exe", names)
                self.assertIn("themes/default.toml", names)
                self.assertNotIn("mpc-hc64.exe", names,
                                 "чужой exe попал в App")

    def test_started_process_wins_over_a_bigger_foreign_exe(self):
        """Главный exe — тот, что запустил установщик, а не самый большой."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app_dir = root / "Portable" / "App"
            _write(app_dir / "zebra.exe", 8 * 1024 * 1024)
            started = _write(app_dir / "alpha.exe", 1024)
            engine = self._engine()
            engine._install_images = {
                os.path.normcase(os.path.abspath(str(started)))
            }
            main_exe, _targets = engine._discover_app_executables(
                str(app_dir), "Acme Suite")
            self.assertEqual(os.path.basename(main_exe), "alpha.exe")

    def test_service_folders_are_removed_from_the_portable(self):
        """``_bundle_layout`` и прочие служебные папки не остаются."""
        with tempfile.TemporaryDirectory() as temp:
            portable = Path(temp)
            (portable / "App").mkdir()
            (portable / "App" / "delta.exe").write_bytes(b"MZ")
            for name in ("_bundle_layout", "_sfx_content", "_adobe_payloads",
                         "_unpacked", "_redist_cache"):
                folder = portable / name
                folder.mkdir()
                (folder / "payload.bin").write_bytes(b"data")
            engine = self._engine()
            engine._cleanup_build_leftovers(str(portable))
            left = sorted(p.name for p in portable.iterdir())
            self.assertEqual(["App"], left)


class ProcessImageSnapshotTests(unittest.TestCase):
    def test_images_helper_returns_paths_only(self):
        """Помощник снимка процессов отдаёт список строк и не падает."""
        from portablizer.core import procutil

        images = procutil.all_process_images()
        self.assertIsInstance(images, list)
        self.assertTrue(all(isinstance(item, str) for item in images))

    def test_remember_install_images_collects_new_processes(self):
        engine = Portablizer(Logger())
        engine._install_images = set()
        engine._process_images = lambda: {
            os.path.normcase(os.path.abspath(r"C:\App\delta.exe")),
            os.path.normcase(os.path.abspath(r"C:\Tools\other.exe")),
        }
        engine._remember_install_images({
            os.path.normcase(os.path.abspath(r"C:\Tools\other.exe")),
        })
        self.assertEqual(
            {os.path.normcase(os.path.abspath(r"C:\App\delta.exe"))},
            engine._install_images,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
