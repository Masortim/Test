"""Ключ входа в аккаунт (Ollama и подобные): перенос, сверка и диагностика.

Жалоба, ради которой написан модуль: вход в Ollama через браузер проходит,
но после перезапуска портатива (и после переноса папки на флешку или другой
ПК) окно входа вечно крутится. Причина — программа берёт другой ключ
``~/.ollama/id_ed25519``, чем тот, что привязан к аккаунту на сайте.

Проверяется:

* ключ переносится из профиля Windows в портатив, если в портативе его нет;
* существующий ключ портатива никогда не перезаписывается;
* для программ без блока ``identity`` лончер ничего не трогает;
* блок ``identity`` появляется в конфиге только у Ollama;
* отпечатки публичной и закрытой частей совпадают (как у ``ssh-keygen``).

Ключи синтезируются по формату OpenSSH без настоящей криптографии: нужна
только структура файла, а не пригодность ключа для входа.
"""
import base64
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import portable_launcher_entry as exe_launcher
from portablizer.core import launcher as launcher_mod


def _ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _public_blob(seed: int = 0) -> bytes:
    """Публичный блок ed25519: строка типа и 32 байта ключа."""
    return _ssh_string(b"ssh-ed25519") + _ssh_string(bytes(range(seed, seed + 32)))


def _pub_file(blob: bytes, comment: str = "user@host") -> bytes:
    return (f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}\n"
            ).encode("ascii")


def _private_file(blob: bytes) -> bytes:
    """Закрытый ключ без пароля: структура openssh-key-v1, без шифрования."""
    body = (
        b"openssh-key-v1\x00"
        + _ssh_string(b"none") + _ssh_string(b"none") + _ssh_string(b"")
        + struct.pack(">I", 1)
        + _ssh_string(blob)
        + _ssh_string(b"private-section-is-opaque-to-the-parser")
    )
    encoded = base64.b64encode(body).decode()
    lines = [encoded[i:i + 70] for i in range(0, len(encoded), 70)]
    text = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + "\n".join(lines)
            + "\n-----END OPENSSH PRIVATE KEY-----\n")
    return text.encode("ascii")


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


class IdentityFixture:
    """Портатив с профилем и «профиль Windows» рядом, оба во временной папке."""

    def __init__(self, temp: str) -> None:
        self.temp = Path(temp)
        self.root = self.temp / "Ollama_Portable"
        (self.root / "App").mkdir(parents=True)
        self.host = self.temp / "Users" / "Tester"
        self.host.mkdir(parents=True)

    def config(self, with_identity: bool = True, **identity) -> dict:
        cfg = {
            "app_name": "Ollama",
            "target_exe_rel": "App/ollama app.exe",
            "data_dir_name": "PortableData",
        }
        if with_identity:
            cfg["identity"] = {"import_from_host": True,
                               "files": [".ollama/id_ed25519",
                                         ".ollama/id_ed25519.pub"],
                               **identity}
        return cfg

    def portable_key(self, rel: str = ".ollama/id_ed25519") -> Path:
        return self.root / "PortableData" / "User" / Path(rel)

    def host_key(self, rel: str = ".ollama/id_ed25519") -> Path:
        return self.host / Path(rel)

    def host_pair(self, blob: bytes) -> None:
        _write(self.host_key(), _private_file(blob))
        _write(self.host_key(".ollama/id_ed25519.pub"), _pub_file(blob))

    def portable_pair(self, blob: bytes) -> None:
        _write(self.portable_key(), _private_file(blob))
        _write(self.portable_key(".ollama/id_ed25519.pub"), _pub_file(blob))


class KeyParsingTests(unittest.TestCase):
    def test_public_blob_from_pub_file(self):
        blob = _public_blob(3)
        self.assertEqual(exe_launcher._public_blob_from_pub(_pub_file(blob)), blob)

    def test_public_blob_from_private_file_matches_pub(self):
        blob = _public_blob(7)
        self.assertEqual(
            exe_launcher._public_blob_from_private(_private_file(blob)), blob)

    def test_fingerprint_matches_between_private_and_public(self):
        blob = _public_blob(11)
        from_private = exe_launcher._fingerprint(
            exe_launcher._public_blob_from_private(_private_file(blob)))
        from_public = exe_launcher._fingerprint(
            exe_launcher._public_blob_from_pub(_pub_file(blob)))
        self.assertEqual(from_private, from_public)
        self.assertTrue(from_public.startswith("SHA256:"))
        self.assertNotIn("=", from_public)

    def test_garbage_is_not_a_key(self):
        self.assertIsNone(exe_launcher._public_blob_from_private(b"not a key"))
        self.assertIsNone(exe_launcher._public_blob_from_pub(b"just-one-word"))
        self.assertIsNone(exe_launcher._public_blob_from_private(
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n!!!\n"
            b"-----END OPENSSH PRIVATE KEY-----\n"))

    def test_truncated_private_key_is_rejected_without_crash(self):
        data = _private_file(_public_blob(1))
        self.assertIsNone(exe_launcher._public_blob_from_private(data[:60]))


    @unittest.skipUnless(shutil.which("ssh-keygen"),
                         "нужен ssh-keygen для настоящего ключа")
    def test_real_openssh_key_matches_ssh_keygen_fingerprint(self):
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp, "id_ed25519")
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q",
                            "-f", str(key), "-C", "test"], check=True)
            expected = subprocess.run(
                ["ssh-keygen", "-lf", str(key) + ".pub"],
                capture_output=True, text=True, check=True).stdout.split()[1]
            blob = exe_launcher._public_blob_from_private(key.read_bytes())
            self.assertIsNotNone(blob)
            self.assertEqual(blob, exe_launcher._public_blob_from_pub(
                Path(str(key) + ".pub").read_bytes()))
            self.assertEqual(exe_launcher._fingerprint(blob), expected)


class IdentityReportTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.fx = IdentityFixture(self._temp.name)

    def tearDown(self):
        self._temp.cleanup()

    def test_program_without_identity_block_is_left_alone(self):
        self.fx.host_pair(_public_blob(1))
        lines = exe_launcher.identity_report(
            self.fx.root, self.fx.config(with_identity=False), str(self.fx.host),
            import_from_host=True)
        self.assertEqual(lines, [])
        self.assertFalse(self.fx.portable_key().exists())

    def test_key_is_imported_when_portable_has_none(self):
        blob = _public_blob(2)
        self.fx.host_pair(blob)
        lines = exe_launcher.identity_report(
            self.fx.root, self.fx.config(), str(self.fx.host),
            import_from_host=True)
        self.assertTrue(self.fx.portable_key().is_file())
        self.assertTrue(self.fx.portable_key(".ollama/id_ed25519.pub").is_file())
        self.assertEqual(self.fx.portable_key().read_bytes(),
                         self.fx.host_key().read_bytes())
        self.assertTrue(any("перенесён" in line for line in lines), lines)

    def test_existing_portable_key_is_never_overwritten(self):
        self.fx.portable_pair(_public_blob(4))
        self.fx.host_pair(_public_blob(5))
        before = self.fx.portable_key().read_bytes()
        lines = exe_launcher.identity_report(
            self.fx.root, self.fx.config(), str(self.fx.host),
            import_from_host=True)
        self.assertEqual(self.fx.portable_key().read_bytes(), before)
        self.assertTrue(any("ВНИМАНИЕ" in line for line in lines), lines)

    def test_matching_keys_are_reported_as_the_same(self):
        blob = _public_blob(6)
        self.fx.portable_pair(blob)
        self.fx.host_pair(blob)
        lines = exe_launcher.identity_report(
            self.fx.root, self.fx.config(), str(self.fx.host),
            import_from_host=True)
        self.assertTrue(any("тот же ключ" in line for line in lines), lines)
        self.assertFalse(any("ВНИМАНИЕ" in line for line in lines))

    def test_check_mode_reads_but_never_copies(self):
        self.fx.host_pair(_public_blob(8))
        exe_launcher.identity_report(
            self.fx.root, self.fx.config(), str(self.fx.host),
            import_from_host=False)
        self.assertFalse(self.fx.portable_key().exists())

    def test_import_can_be_disabled_in_config(self):
        self.fx.host_pair(_public_blob(9))
        lines = exe_launcher.identity_report(
            self.fx.root, self.fx.config(import_from_host=False),
            str(self.fx.host), import_from_host=True)
        self.assertFalse(self.fx.portable_key().exists())
        self.assertTrue(any("перенос отключён" in line for line in lines), lines)

    def test_missing_key_everywhere_explains_the_consequence(self):
        lines = exe_launcher.identity_report(
            self.fx.root, self.fx.config(), str(self.fx.host),
            import_from_host=True)
        self.assertTrue(any("ключа входа в портативе нет" in line
                            for line in lines), lines)

    def test_portable_profile_as_host_is_not_copied_onto_itself(self):
        self.fx.portable_pair(_public_blob(10))
        portable_profile = self.fx.root / "PortableData" / "User"
        before = self.fx.portable_key().read_bytes()
        lines = exe_launcher.identity_report(
            self.fx.root, self.fx.config(), str(portable_profile),
            import_from_host=True)
        self.assertEqual(self.fx.portable_key().read_bytes(), before)
        self.assertTrue(any("ключ портатива" in line for line in lines), lines)

    def test_fingerprint_of_portable_key_is_reported(self):
        blob = _public_blob(12)
        self.fx.portable_pair(blob)
        lines = exe_launcher.identity_report(
            self.fx.root, self.fx.config(), "", import_from_host=False)
        expected = exe_launcher._fingerprint(blob)
        self.assertTrue(any(expected in line for line in lines), lines)

    def test_host_profile_is_optional(self):
        lines = exe_launcher.identity_report(
            self.fx.root, self.fx.config(), "", import_from_host=True)
        self.assertTrue(lines)
        self.assertFalse(self.fx.portable_key().exists())


class BuilderIdentityTests(unittest.TestCase):
    """Сборка пишет блок ``identity`` только для программ, которым он нужен."""

    def _config_for(self, app_name, exe_rel):
        cfg = launcher_mod.LauncherConfig(app_name=app_name,
                                          target_exe_rel=exe_rel)
        return launcher_mod.render_config_json(cfg)

    def test_ollama_gets_identity_block(self):
        import json

        data = json.loads(self._config_for("Ollama", "App/ollama app.exe"))
        self.assertEqual(data["identity"]["files"],
                         [".ollama/id_ed25519", ".ollama/id_ed25519.pub"])
        self.assertTrue(data["identity"]["import_from_host"])

    def test_identity_detected_from_executable_name(self):
        import json

        data = json.loads(self._config_for("Local AI", "App/Ollama.exe"))
        self.assertIn("identity", data)

    def test_other_programs_get_no_identity_block(self):
        import json

        data = json.loads(self._config_for("Fallout New Vegas",
                                           "App/FalloutNV.exe"))
        self.assertNotIn("identity", data)


if __name__ == "__main__":
    unittest.main()
