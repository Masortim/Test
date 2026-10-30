"""Вход в аккаунт — в браузере по умолчанию, без второй копии браузера.

Жалоба, ради которой появился этот модуль:

    Если портатив приложения требует логина в сети, то создаётся дубликат
    браузера по умолчанию. Лучше запускать процесс логина в существующем
    браузере по умолчанию, не устанавливая новый и не создавая его дубликаты
    нигде, в том числе и в реестре.

Механика жалобы: программа открывает страницу входа через оболочку Windows.
Оболочка запускает браузер по умолчанию с ТЕМ окружением, которое получил
вызывающий процесс, — а лончер перенаправил ``APPDATA``/``LOCALAPPDATA``/
``USERPROFILE`` внутрь ``PortableData``. Браузер видит пустой профиль и его
создаёт: второй браузер «по умолчанию» без закладок и сохранённых входов,
плюс новые ключи в реестре и мегабайты кэша на флешке.

Проверяется:

* адрес входа вытаскивается из командной строки браузера (Chrome, Edge,
  Firefox), а флаги без адреса — нет;
* мост реагирует только на НОВЫЙ процесс известного браузера, который
  стартовал из самой программы или уже создал профиль внутри портатива;
* уже открытые окна браузера (снимок до старта) не трогаются, повторный
  запуск того же адреса не повторяется;
* перехваченный профиль-дубликат удаляется из ``PortableData``, а профиль,
  который был там до сеанса, — нет;
* портатив самого браузера не перехватывается;
* сборщик не переносит в портатив регистрацию браузера по умолчанию
  (``http``/``https``, ``StartMenuInternet``, ``RegisteredApplications``,
  ``UrlAssociations``), а лончер вычищает такие секции из старого
  ``portable.reg`` перед импортом.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import portable_launcher_entry as entry
from portablizer.core import launcher as launcher_mod
from portablizer.core import registry as reg_mod

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
CHROME_LOGIN = (
    '"' + CHROME + '" --single-argument '
    "https://www.figma.com/login?redirect=%2Ffiles&state=abc")
EDGE_LOGIN = (r'"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" '
              "https://login.microsoftonline.com/common/oauth2/authorize?x=1")
FIREFOX_LOGIN = ('"C:\\Program Files\\Mozilla Firefox\\firefox.exe" '
                 '-osint -url "https://accounts.example.com/sign-in"')


def make_portable(root: Path, target_name: str = "Figma.exe") -> Path:
    app = root / "App"
    app.mkdir(parents=True, exist_ok=True)
    (app / target_name).write_bytes(b"MZ" + b"\x00" * 64)
    (root / "PortableData").mkdir(parents=True, exist_ok=True)
    return app / target_name


def make_bridge(root: Path, target: Path,
                settings=None) -> "entry.BrowserLoginBridge":
    cfg = {"browser_login": settings if settings is not None else {}}
    return entry.BrowserLoginBridge(root, cfg, target,
                                    log=lambda message: None)


class LoginUrlTests(unittest.TestCase):
    def test_chrome_single_argument_is_recognised(self):
        self.assertEqual(
            entry._browser_login_url(CHROME_LOGIN),
            "https://www.figma.com/login?redirect=%2Ffiles&state=abc")

    def test_edge_authorize_url_is_recognised(self):
        self.assertTrue(entry._browser_login_url(EDGE_LOGIN).startswith(
            "https://login.microsoftonline.com/common/oauth2/authorize"))

    def test_firefox_url_argument_quotes_are_not_kept(self):
        self.assertEqual(entry._browser_login_url(FIREFOX_LOGIN),
                         "https://accounts.example.com/sign-in")

    def test_command_line_without_url_gives_nothing(self):
        self.assertEqual(entry._browser_login_url(
            '"' + CHROME + '" --no-startup-window'), "")
        self.assertEqual(entry._browser_login_url(""), "")

    def test_trailing_sentence_punctuation_is_not_part_of_the_url(self):
        self.assertEqual(
            entry._browser_login_url('chrome.exe "https://example.com/x".'),
            "https://example.com/x")

    def test_browser_images_are_recognised_by_name(self):
        self.assertTrue(entry._is_known_browser(CHROME))
        self.assertTrue(entry._is_known_browser(r"D:\Edge\MSEDGE.EXE"))
        self.assertTrue(entry._is_known_browser("firefox.exe"))
        self.assertFalse(entry._is_known_browser(r"C:\App\Figma.exe"))
        self.assertFalse(entry._is_known_browser(""))


class BridgePlanTests(unittest.TestCase):
    """Решение «снять и открыть заново» без единого вызова WinAPI."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        self.target = make_portable(self.root)
        self.bridge = make_bridge(self.root, self.target)
        # Снимок «до старта»: оболочка и сама программа уже существуют.
        self.baseline = [(4, 0, "System"), (1, 0, "explorer.exe"),
                         (100, 1, "Figma.exe"), (50, 1, "chrome.exe")]
        windows = mock.patch.object(entry, "IS_WINDOWS", True)
        windows.start()
        self.addCleanup(windows.stop)
        with mock.patch.object(entry, "_process_table",
                               return_value=self.baseline):
            self.bridge.prepare()
        self.bridge.attach(100)

    def tearDown(self):
        self._temp.cleanup()

    def _plan(self, table, command_lines):
        def reader(pid):
            return command_lines.get(pid, "")
        return self.bridge.plan(table, command_line_of=reader)

    def test_browser_started_by_the_program_is_replaced(self):
        table = self.baseline + [(200, 100, "chrome.exe")]
        planned = self._plan(table, {200: CHROME_LOGIN})
        self.assertEqual(planned, [(200,
                                    "https://www.figma.com/login?redirect=%2F"
                                    "files&state=abc", "chrome.exe")])

    def test_browser_started_by_a_child_of_the_program_is_replaced(self):
        # Electron пускает вход через свой вспомогательный процесс, а тот —
        # через cmd/оболочку: цепочка родителей длиннее одного шага.
        table = self.baseline + [(150, 100, "FigmaHelper.exe"),
                                 (160, 150, "cmd.exe"),
                                 (210, 160, "msedge.exe")]
        planned = self._plan(table, {210: EDGE_LOGIN})
        self.assertEqual([pid for pid, _url, _image in planned], [210])

    def test_already_open_browser_window_is_not_touched(self):
        # pid 50 был в снимке до старта: это окно пользователя.
        table = self.baseline + [(51, 50, "chrome.exe")]
        self.assertEqual(self._plan(table, {51: CHROME_LOGIN}), [])

    def test_unrelated_browser_without_a_portable_profile_is_ignored(self):
        table = self.baseline + [(300, 1, "chrome.exe")]
        self.assertEqual(self._plan(table, {300: CHROME_LOGIN}), [])

    def test_browser_with_a_portable_profile_is_replaced_without_parents(self):
        # Оболочка могла стартовать браузер не от программы: признаком
        # служит профиль, появившийся внутри PortableData после старта.
        profile = self.root / "PortableData/AppData/Local/Google/Chrome"
        profile.mkdir(parents=True)
        table = self.baseline + [(310, 1, "chrome.exe")]
        planned = self._plan(table, {310: CHROME_LOGIN})
        self.assertEqual([pid for pid, _url, _image in planned], [310])

    def test_the_same_url_is_handled_once(self):
        table = self.baseline + [(200, 100, "chrome.exe")]
        self.assertEqual(len(self._plan(table, {200: CHROME_LOGIN})), 1)
        self.assertEqual(self._plan(table, {200: CHROME_LOGIN}), [])

    def test_browser_without_url_is_ignored(self):
        table = self.baseline + [(200, 100, "chrome.exe")]
        self.assertEqual(self._plan(table, {200: '"chrome.exe" --restore'}), [])

    def test_unknown_program_is_ignored_even_with_a_url(self):
        table = self.baseline + [(400, 100, "FigmaUpdater.exe")]
        self.assertEqual(self._plan(table, {400: CHROME_LOGIN}), [])


class BridgeSettingsTests(unittest.TestCase):
    def test_disabled_by_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root)
            bridge = make_bridge(root, target, {"enabled": False})
            with mock.patch.object(entry, "IS_WINDOWS", True):
                self.assertFalse(bridge.enabled)
                table = [(100, 0, "Figma.exe"), (200, 100, "chrome.exe")]
                self.assertEqual(bridge.plan(table), [])

    def test_portable_browser_itself_is_not_intercepted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root, "chrome.exe")
            bridge = make_bridge(root, target)
            with mock.patch.object(entry, "IS_WINDOWS", True):
                self.assertFalse(bridge.enabled)

    def test_enabled_by_default_on_windows(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root)
            bridge = make_bridge(root, target)
            with mock.patch.object(entry, "IS_WINDOWS", True):
                self.assertTrue(bridge.enabled)
            with mock.patch.object(entry, "IS_WINDOWS", False):
                self.assertFalse(bridge.enabled)

    def test_poll_interval_is_sane(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root)
            quick = make_bridge(root, target, {"poll_seconds": 0.01})
            slow = make_bridge(root, target, {"poll_seconds": 99})
            broken = make_bridge(root, target, {"poll_seconds": "x"})
            self.assertAlmostEqual(quick.poll_seconds, 0.1)
            self.assertAlmostEqual(slow.poll_seconds, 2.0)
            self.assertAlmostEqual(broken.poll_seconds, 0.3)


class DuplicateProfileTests(unittest.TestCase):
    def test_profile_created_by_the_intercepted_copy_is_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root)
            bridge = make_bridge(root, target)
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table", return_value=[]):
                bridge.prepare()
                profile = root / "PortableData/AppData/Local/Google/Chrome"
                (profile / "User Data/Default").mkdir(parents=True)
                (profile / "User Data/Default/Cookies").write_bytes(b"x")
                removed = bridge.cleanup_duplicate_profile(CHROME)
                self.assertEqual(len(removed), 1)
                self.assertFalse(profile.exists())

    def test_profile_that_existed_before_the_session_is_kept(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root)
            profile = root / "PortableData/AppData/Local/Google/Chrome"
            (profile / "User Data").mkdir(parents=True)
            bridge = make_bridge(root, target)
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table", return_value=[]):
                bridge.prepare()
                self.assertEqual(bridge.cleanup_duplicate_profile(CHROME), [])
                self.assertTrue(profile.exists())


class BridgePollTests(unittest.TestCase):
    def test_poll_stops_the_copy_and_opens_the_host_browser(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root)
            bridge = make_bridge(root, target)
            table = [(100, 0, "Figma.exe"), (200, 100, "chrome.exe")]
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table",
                                      return_value=[(100, 0, "Figma.exe")]), \
                    mock.patch.object(entry, "_process_command_line",
                                      return_value=CHROME_LOGIN), \
                    mock.patch.object(entry, "_terminate_pids") as terminated, \
                    mock.patch.object(entry, "open_in_host_browser",
                                      return_value=True) as opened:
                bridge.prepare()
                bridge.attach(100)
                bridge._last_poll = 0.0
                with mock.patch.object(entry, "_process_table",
                                       return_value=table):
                    bridge.poll()
            terminated.assert_called_once_with([200])
            opened.assert_called_once_with(
                "https://www.figma.com/login?redirect=%2Ffiles&state=abc")


class HostBrowserTests(unittest.TestCase):
    def test_nothing_is_opened_off_windows(self):
        with mock.patch.object(entry, "IS_WINDOWS", False):
            self.assertFalse(entry.open_in_host_browser("https://example.com"))

    def test_shell_execute_is_used_on_windows(self):
        with mock.patch.object(entry, "IS_WINDOWS", True), \
                mock.patch.object(entry.os, "startfile",
                                  create=True) as startfile:
            self.assertTrue(entry.open_in_host_browser("https://example.com"))
        startfile.assert_called_once_with("https://example.com")


class LauncherConfigTests(unittest.TestCase):
    def test_defaults_are_written_to_the_config(self):
        cfg = launcher_mod.LauncherConfig(app_name="Figma",
                                          target_exe_rel="App/Figma.exe")
        settings = launcher_mod.browser_login_settings(cfg)
        self.assertTrue(settings["enabled"])
        self.assertGreater(settings["poll_seconds"], 0)

    def test_explicit_settings_override_the_defaults(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="Figma", target_exe_rel="App/Figma.exe",
            browser_login={"enabled": False, "poll_seconds": 1.0})
        settings = launcher_mod.browser_login_settings(cfg)
        self.assertFalse(settings["enabled"])
        self.assertAlmostEqual(float(settings["poll_seconds"]), 1.0)

    def test_the_block_reaches_launcher_config_json(self):
        import json

        cfg = launcher_mod.LauncherConfig(app_name="Figma",
                                          target_exe_rel="App/Figma.exe")
        payload = json.loads(launcher_mod.render_config_json(cfg))
        self.assertTrue(payload["browser_login"]["enabled"])

    def test_the_block_survives_a_config_round_trip(self):
        cfg = launcher_mod.LauncherConfig(
            app_name="Figma", target_exe_rel="App/Figma.exe",
            browser_login={"enabled": False})
        payload = launcher_mod.render_config_json(cfg)
        import json

        restored = launcher_mod.config_from_dict(json.loads(payload))
        self.assertFalse(restored.browser_login["enabled"])


class BrowserRegistryTests(unittest.TestCase):
    """Регистрация браузера по умолчанию не переезжает в портатив."""

    def test_web_schemes_are_not_the_programs_protocols(self):
        for scheme in ("http", "https", "ftp", "mailto"):
            key = rf"HKCU\Software\Classes\{scheme}"
            values = {"URL Protocol": (reg_mod.REG_SZ, repr(""))}
            self.assertFalse(reg_mod.is_protocol_key(key, values), scheme)

    def test_application_protocols_are_still_recognised(self):
        key = r"HKCU\Software\Classes\figma"
        values = {"URL Protocol": (reg_mod.REG_SZ, repr(""))}
        self.assertTrue(reg_mod.is_protocol_key(key, values))

    def test_protocol_keys_of_skips_the_web(self):
        diff = mock.Mock()
        diff.touched_keys = [r"HKCU\Software\Classes\http",
                             r"HKCU\Software\Classes\https",
                             r"HKCU\Software\Classes\figma"]
        after = {
            r"HKCU\Software\Classes\http": {
                "URL Protocol": (reg_mod.REG_SZ, repr(""))},
            r"HKCU\Software\Classes\https": {
                "URL Protocol": (reg_mod.REG_SZ, repr(""))},
            r"HKCU\Software\Classes\figma": {
                "URL Protocol": (reg_mod.REG_SZ, repr(""))},
        }
        keys = reg_mod.protocol_keys_of(diff, after)
        self.assertIn(r"HKCU\Software\Classes\figma", keys)
        self.assertNotIn(r"HKCU\Software\Classes\http", keys)
        self.assertNotIn(r"HKCU\Software\Classes\https", keys)

    def test_browser_identity_keys_are_protected(self):
        for key in (r"HKCU\Software\Clients\StartMenuInternet\Chrome",
                    r"HKCU\Software\RegisteredApplications",
                    r"HKCU\Software\Microsoft\Windows\Shell\Associations"
                    r"\UrlAssociations\https\UserChoice"):
            self.assertTrue(reg_mod.is_protected(key), key)

    def test_application_keys_are_still_captured(self):
        self.assertFalse(reg_mod.is_protected(r"HKCU\Software\Vendor\App"))

    def test_old_registry_files_are_cleaned_before_import(self):
        text = "\n".join([
            "Windows Registry Editor Version 5.00",
            "",
            r"[HKCU\Software\Classes\http]",
            '@="URL:http"',
            "",
            r"[HKCU\Software\Classes\http\shell\open\command]",
            r'@="\"C:\\App\\chrome.exe\" \"%1\""',
            "",
            r"[HKCU\Software\Clients\StartMenuInternet\Portable]",
            '@="Portable"',
            "",
            r"[HKCU\Software\Vendor\App]",
            '"Setting"="1"',
            "",
            r"[HKCU\Software\Classes\figma\shell\open\command]",
            r'@="\"@@PORTABLE_ROOT@@\\App\\Figma.exe\" --open \"%1\""',
        ])
        cleaned, dropped = entry.sanitize_reg_text(text)
        joined = "\n".join(dropped)
        self.assertIn("Classes\\http", joined)
        self.assertIn("StartMenuInternet", joined)
        self.assertIn("Vendor\\App", cleaned)
        self.assertIn("Classes\\figma", cleaned)
        self.assertNotIn("chrome.exe", cleaned)


if __name__ == "__main__":
    unittest.main()
