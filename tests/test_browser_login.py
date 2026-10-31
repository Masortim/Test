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
YANDEX_CRASH_URL = "https://crash-reports.browser.yandex.net/submit"
DELTA_TERMS_URL = "https://dashboard.zed.dev/delta-beta"
YANDEX_CRASH = ('"C:\\Users\\user\\AppData\\Local\\Yandex\\YandexBrowser\\'
                'Application\\browser.exe" --crash-reporter-url="' +
                YANDEX_CRASH_URL + '"')


def isolated_host():
    """Не дать тесту соединить НАСТОЯЩИЕ каталоги профиля этого компьютера.

    На Windows такой вызов создал бы junction'ы к реальному профилю (тест
    работает с временным каталогом, но окружение-то настоящее).
    """
    return mock.patch.object(entry.BrowserLoginBridge, "connect_host_profiles",
                             return_value=[])


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

    def test_yandex_crash_report_is_not_a_login_url(self):
        self.assertEqual(entry._browser_login_url(YANDEX_CRASH), "")
        self.assertTrue(entry._has_only_browser_service_urls(YANDEX_CRASH))

    def test_real_terms_url_after_yandex_crash_report_is_selected(self):
        command_line = (YANDEX_CRASH + ' --single-argument "' +
                        DELTA_TERMS_URL + '"')
        self.assertEqual(entry._browser_login_url(command_line),
                         DELTA_TERMS_URL)
        self.assertFalse(entry._has_only_browser_service_urls(command_line))

    def test_similar_yandex_domain_is_not_overfiltered(self):
        url = "https://crash-reports.browser.yandex.net.example.com/login"
        self.assertEqual(entry._browser_login_url('browser.exe "' + url + '"'),
                         url)

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
        host = isolated_host()
        host.start()
        self.addCleanup(host.stop)
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

    def test_unrelated_browser_is_ignored_when_the_profile_is_linked(self):
        # Профиль соединён с настоящим: браузер, открытый вручную или по
        # ссылке из почты, трогать не нужно — он и так работает с профилем
        # пользователя.
        self.bridge._bridged.add(("LOCALAPPDATA", "Google/Chrome"))
        table = self.baseline + [(300, 1, "chrome.exe")]
        self.assertEqual(self._plan(table, {300: CHROME_LOGIN}), [])

    def test_brokered_launch_is_replaced_when_the_profile_is_not_linked(self):
        # Junction создать нельзя (exFAT, сетевая папка), а ShellExecute ушёл
        # в службу оболочки: родитель браузера — explorer/svchost, цепочки до
        # программы нет. Адрес всё равно открываем сами.
        table = self.baseline + [(320, 1, "chrome.exe")]
        planned = self._plan(table, {320: CHROME_LOGIN})
        self.assertEqual([pid for pid, _url, _image in planned], [320])

    def test_brokered_browser_without_url_is_ignored(self):
        table = self.baseline + [(321, 1, "chrome.exe")]
        self.assertEqual(self._plan(table, {321: '"chrome.exe" --restore'}), [])

    def test_browser_with_a_portable_profile_is_replaced_without_parents(self):
        # Оболочка могла стартовать браузер не от программы: признаком
        # служит профиль, появившийся внутри PortableData после старта.
        profile = self.root / "PortableData/AppData/Local/Google/Chrome"
        profile.mkdir(parents=True)
        table = self.baseline + [(310, 1, "chrome.exe")]
        planned = self._plan(table, {310: CHROME_LOGIN})
        self.assertEqual([pid for pid, _url, _image in planned], [310])

    def test_the_same_url_is_handled_once_per_live_process(self):
        table = self.baseline + [(200, 100, "chrome.exe")]
        self.assertEqual(len(self._plan(table, {200: CHROME_LOGIN})), 1)
        self.assertEqual(self._plan(table, {200: CHROME_LOGIN}), [])

    def test_repeated_clicks_with_the_same_url_are_not_suppressed(self):
        for pid in (200, 201, 202):
            table = self.baseline + [(pid, 100, "browser.exe")]
            command = 'browser.exe --single-argument "' + DELTA_TERMS_URL + '"'
            self.assertEqual(self._plan(table, {pid: command}),
                             [(pid, DELTA_TERMS_URL, "browser.exe")])

    def test_retired_pid_does_not_block_a_later_repeated_click(self):
        command = 'browser.exe --single-argument "' + DELTA_TERMS_URL + '"'
        table = self.baseline + [(200, 100, "browser.exe")]
        self.assertEqual(len(self._plan(table, {200: command})), 1)
        # Observe the process exit before Windows reuses its PID.
        self.assertEqual(self._plan(self.baseline, {}), [])
        self.assertEqual(self._plan(table, {200: command}),
                         [(200, DELTA_TERMS_URL, "browser.exe")])

    def test_service_only_process_is_cleaned_without_opening_its_url(self):
        table = self.baseline + [(200, 100, "browser.exe")]
        self.assertEqual(self._plan(table, {200: YANDEX_CRASH}),
                         [(200, "", "browser.exe")])
        self.assertEqual(self._plan(table, {200: YANDEX_CRASH}), [])

    def test_crash_report_does_not_consume_the_real_terms_handoff(self):
        table = self.baseline + [(200, 100, "browser.exe"),
                                 (201, 100, "browser.exe")]
        command = YANDEX_CRASH + ' --single-argument "' + DELTA_TERMS_URL + '"'
        planned = self._plan(table, {200: YANDEX_CRASH, 201: command})
        self.assertIn((200, "", "browser.exe"), planned)
        self.assertIn((201, DELTA_TERMS_URL, "browser.exe"), planned)
        self.assertNotIn(YANDEX_CRASH_URL, [url for _pid, url, _image in planned])

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
                    mock.patch.object(entry, "_process_table", return_value=[]), \
                    isolated_host():
                bridge.prepare()
                profile = root / "PortableData/AppData/Local/Google/Chrome"
                (profile / "User Data/Default").mkdir(parents=True)
                (profile / "User Data/Default/Cookies").write_bytes(b"x")
                removed = bridge.cleanup_duplicate_profile(CHROME)
                self.assertEqual(len(removed), 1)
                self.assertFalse(profile.exists())

    def test_leftover_duplicate_from_an_earlier_session_is_removed(self):
        # Именно это и видел пользователь: «второй браузер» остался в папке
        # портатива от прежнего запуска (или приехал из сборки).
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root)
            profile = root / "PortableData/AppData/Local/Google/Chrome"
            (profile / "User Data/Default").mkdir(parents=True)
            (profile / "User Data/Default/Cookies").write_bytes(b"x")
            bridge = make_bridge(root, target)
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table", return_value=[]), \
                    isolated_host():
                bridge.prepare()
                self.assertFalse(profile.exists())

    def test_a_browser_installation_is_not_deleted_as_a_duplicate(self):
        # Chrome, установленный «для одного пользователя», держит в этом
        # каталоге и профиль (User Data), и саму программу (Application).
        # Удалить её — значит заставить браузер при каждом старте решать,
        # что он не установлен, и запускать УСТАНОВЩИК вместо себя.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root)
            chrome = root / "PortableData/AppData/Local/Google/Chrome"
            (chrome / "Application").mkdir(parents=True)
            (chrome / "Application/chrome.exe").write_bytes(b"MZ")
            (chrome / "User Data/Default").mkdir(parents=True)
            bridge = make_bridge(root, target)
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table", return_value=[]), \
                    isolated_host():
                self.assertEqual(bridge.drop_duplicate_profiles(), [])
            self.assertTrue((chrome / "Application/chrome.exe").is_file())
            self.assertTrue((chrome / "User Data/Default").is_dir())

    def test_the_updater_next_to_the_program_is_kept(self):
        # Без своего обновлятора браузер запускает установку заново.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root)
            update = root / "PortableData/AppData/Local/Google/Update"
            update.mkdir(parents=True)
            (update / "GoogleUpdate.exe").write_bytes(b"MZ")
            bridge = make_bridge(root, target)
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table", return_value=[]), \
                    isolated_host():
                self.assertEqual(bridge.drop_duplicate_profiles(), [])
            self.assertTrue((update / "GoogleUpdate.exe").is_file())

    def test_cleanup_can_be_switched_off(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root)
            profile = root / "PortableData/AppData/Local/Google/Chrome"
            profile.mkdir(parents=True)
            bridge = make_bridge(root, target, {"clean_duplicates": False})
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table", return_value=[]), \
                    isolated_host():
                self.assertEqual(bridge.drop_duplicate_profiles(), [])
                self.assertTrue(profile.exists())


class HostProfileBridgeTests(unittest.TestCase):
    """Профиль не раздваивается: каталоги браузера ведут к настоящим."""

    def _bridge(self, root: Path, **kwargs):
        env = {
            "LOCALAPPDATA": str(root / "PortableData/AppData/Local"),
            "APPDATA": str(root / "PortableData/AppData/Roaming"),
        }
        for value in env.values():
            Path(value).mkdir(parents=True, exist_ok=True)
        target = make_portable(root)
        bridge = entry.BrowserLoginBridge(
            root, {"browser_login": kwargs}, target, env=env,
            log=lambda message: None)
        preferred = mock.patch.object(entry, "_default_browser_images",
                                      return_value={"chrome.exe"})
        preferred.start()
        self.addCleanup(preferred.stop)
        return bridge, target

    def test_host_profile_is_linked_and_survives_the_session(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            host = root / "host"
            host_profile = host / "Google/Chrome/User Data/Default"
            host_profile.mkdir(parents=True)
            (host_profile / "Bookmarks").write_bytes(b"bookmarks")
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table", return_value=[]), \
                    mock.patch.dict(os.environ, {"LOCALAPPDATA": str(host),
                                                 "APPDATA": str(host)}):
                bridge, _target = self._bridge(root)
                bridge.prepare()
                link = root / "PortableData/AppData/Local/Google/Chrome"
                self.assertTrue(entry._is_junction(link))
                self.assertTrue(bridge._bridged_image(CHROME))
                # Внутри ссылки — настоящий профиль, а не пустая копия.
                self.assertTrue((link / "User Data/Default/Bookmarks").is_file())
                bridge.teardown()
                self.assertFalse(entry._is_junction(link))
                self.assertFalse(link.exists())
                # Настоящий профиль не пострадал.
                self.assertTrue((host_profile / "Bookmarks").is_file())

    def test_partial_profile_bridge_keeps_fallback_monitoring(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bridge, _target = self._bridge(root)
            pairs = entry._BROWSER_PROFILE_DIRS["yandex.exe"]
            self.assertGreater(len(pairs), 1)
            for count in range(len(pairs)):
                bridge._bridged = set(pairs[:count])
                self.assertFalse(bridge._bridged_image("yandex.exe"),
                                 f"partial bridge must not disable fallback: {count}")
            bridge._bridged = set(pairs)
            self.assertTrue(bridge._bridged_image("yandex.exe"))

    def test_linked_browser_is_not_killed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            host = root / "host"
            (host / "Google/Chrome").mkdir(parents=True)
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table", return_value=[]), \
                    mock.patch.dict(os.environ, {"LOCALAPPDATA": str(host),
                                                 "APPDATA": str(host)}):
                bridge, _target = self._bridge(root)
                bridge.prepare()
                bridge.attach(100)
                table = [(100, 0, "Figma.exe"), (200, 100, "chrome.exe")]
                with mock.patch.object(entry, "_terminate_pids") as terminated, \
                        mock.patch.object(entry, "_process_command_line",
                                          return_value=CHROME_LOGIN), \
                        mock.patch.object(entry, "open_in_host_browser") as opened:
                    bridge._last_poll = 0.0
                    with mock.patch.object(entry, "_process_table",
                                           return_value=table):
                        bridge.poll()
                # Вход идёт в настоящем профиле: снимать и переоткрывать нечего.
                terminated.assert_not_called()
                opened.assert_not_called()

    def test_nothing_is_linked_when_the_host_has_no_browser(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            host = root / "host"
            host.mkdir()
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table", return_value=[]), \
                    mock.patch.dict(os.environ, {"LOCALAPPDATA": str(host),
                                                 "APPDATA": str(host)}):
                bridge, _target = self._bridge(root)
                bridge.prepare()
                self.assertFalse(bridge._bridged_image(CHROME))
                self.assertFalse(
                    (root / "PortableData/AppData/Local/Google/Chrome").exists())

    def test_duplicates_are_not_removed_through_a_link(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            host = root / "host"
            (host / "Google/Chrome/User Data").mkdir(parents=True)
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table", return_value=[]), \
                    mock.patch.dict(os.environ, {"LOCALAPPDATA": str(host),
                                                 "APPDATA": str(host)}):
                bridge, _target = self._bridge(root)
                bridge.prepare()
                # Повторная уборка (или сборка поверх) не должна утащить
                # настоящий профиль через ссылку.
                self.assertEqual(bridge.drop_duplicate_profiles(), [])
                self.assertTrue((host / "Google/Chrome/User Data").is_dir())
                self.assertTrue(entry._is_junction(
                    root / "PortableData/AppData/Local/Google/Chrome"))


class DefaultBrowserTests(unittest.TestCase):
    """Соединяется профиль браузера по умолчанию, а не всех подряд."""

    def test_known_progids_are_recognised(self):
        cases = {
            "ChromeHTML": "chrome.exe",
            "MSEdgeHTM": "msedge.exe",
            "FirefoxURL-308046B0AF4A39CB": "firefox.exe",
            "BraveHTML": "brave.exe",
            "VivaldiHTML": "vivaldi.exe",
            "YandexBrowserHTML": "yandex.exe",
        }
        for progid, image in cases.items():
            self.assertIn(image, entry._browser_images_for_progid(progid), progid)

    def test_unknown_progid_links_everything(self):
        # Пустой набор — «определить не удалось»: тогда соединяются все
        # найденные браузеры, лишь бы вход не создал дубликат.
        self.assertEqual(entry._browser_images_for_progid("SomeBrowserHTML"),
                         set())
        self.assertEqual(entry._browser_images_for_progid(""), set())

    def test_only_the_default_browser_is_linked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            host = root / "host"
            (host / "Google/Chrome").mkdir(parents=True)
            (host / "Mozilla").mkdir(parents=True)
            env = {
                "LOCALAPPDATA": str(root / "PortableData/AppData/Local"),
                "APPDATA": str(root / "PortableData/AppData/Roaming"),
            }
            for value in env.values():
                Path(value).mkdir(parents=True, exist_ok=True)
            target = make_portable(root)
            bridge = entry.BrowserLoginBridge(
                root, {"browser_login": {}}, target, env=env,
                log=lambda message: None)
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table", return_value=[]), \
                    mock.patch.object(entry, "_default_browser_images",
                                      return_value={"chrome.exe"}), \
                    mock.patch.dict(os.environ, {"LOCALAPPDATA": str(host),
                                                 "APPDATA": str(host)}):
                bridge.prepare()
            self.assertTrue(bridge._bridged_image("chrome.exe"))
            # Firefox на этом ПК установлен, но он не по умолчанию: его
            # каталог не трогаем.
            self.assertFalse(
                (root / "PortableData/AppData/Roaming/Mozilla").exists())


class SafeDeleteTests(unittest.TestCase):
    """Удаление копии профиля не должно утащить настоящий профиль."""

    def test_nested_link_is_not_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            host = Path(temp, "host/User Data")
            host.mkdir(parents=True)
            (host / "Login Data").write_bytes(b"passwords")
            duplicate = Path(temp, "PortableData/AppData/Local/Google/Chrome")
            duplicate.mkdir(parents=True)
            (duplicate / "Local State").write_bytes(b"x")
            if not entry._junction_directory(duplicate / "User Data", host):
                self.skipTest("эта файловая система не умеет ссылки на каталоги")

            self.assertTrue(entry._remove_tree(duplicate))

            self.assertFalse(duplicate.exists())
            self.assertTrue((host / "Login Data").is_file())


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
                    isolated_host(), \
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

    def test_poll_never_opens_yandex_crash_report_in_the_host_browser(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root)
            bridge = make_bridge(root, target)
            table = [(100, 0, "Figma.exe"), (200, 100, "browser.exe")]
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_process_table",
                                      return_value=[(100, 0, "Figma.exe")]), \
                    isolated_host(), \
                    mock.patch.object(entry, "_process_command_line",
                                      return_value=YANDEX_CRASH), \
                    mock.patch.object(entry, "_terminate_pids") as terminated, \
                    mock.patch.object(entry, "open_in_host_browser") as opened:
                bridge.prepare()
                bridge.attach(100)
                bridge._last_poll = 0.0
                with mock.patch.object(entry, "_process_table",
                                       return_value=table):
                    bridge.poll()
            terminated.assert_called_once_with([200])
            opened.assert_not_called()


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


class BuilderBrowserGuardTests(unittest.TestCase):
    """Сборка не приносит в портатив вторую копию браузера."""

    def _engine(self):
        from portablizer.core.logutil import Logger
        from portablizer.core.portablizer import Portablizer

        return Portablizer(Logger())

    def test_profiles_left_by_a_previous_build_are_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            data = Path(temp, "PortableData")
            chrome = data / "AppData/Local/Google/Chrome/User Data/Default"
            chrome.mkdir(parents=True)
            (chrome / "Cookies").write_bytes(b"x")
            app_data = data / "AppData/Local/Vendor/App"
            app_data.mkdir(parents=True)
            (app_data / "settings.ini").write_bytes(b"1")

            removed = self._engine()._drop_browser_duplicates(str(data))

            self.assertEqual(removed, [str(data / "AppData/Local/Google"
                                           / "Chrome")])
            self.assertFalse((data / "AppData/Local/Google/Chrome").exists())
            # Настройки самой программы остаются на месте.
            self.assertTrue((app_data / "settings.ini").is_file())

    def test_a_browser_build_keeps_its_own_folders(self):
        # Портатив самого браузера: эти каталоги — данные программы.
        with tempfile.TemporaryDirectory() as temp:
            data = Path(temp, "PortableData")
            chrome = data / "AppData/Local/Google/Chrome"
            (chrome / "User Data/Default").mkdir(parents=True)
            update = data / "AppData/Local/Google/Update"
            update.mkdir(parents=True)
            (update / "GoogleUpdate.exe").write_bytes(b"MZ")

            engine = self._engine()
            self.assertEqual(
                engine._drop_browser_duplicates(str(data), "ChromeSetup.exe"), [])
            self.assertTrue((chrome / "User Data/Default").is_dir())
            self.assertTrue((update / "GoogleUpdate.exe").is_file())

    def test_a_program_inside_the_portable_is_not_a_duplicate_profile(self):
        # Chromium-based программа держит свои файлы в таком каталоге.
        with tempfile.TemporaryDirectory() as temp:
            data = Path(temp, "PortableData")
            app = data / "AppData/Local/Chromium/App"
            app.mkdir(parents=True)
            (app / "App.exe").write_bytes(b"MZ")
            (app / "settings.ini").write_bytes(b"1")

            removed = self._engine()._drop_browser_duplicates(
                str(data), "AppSetup.exe")

            self.assertEqual(removed, [])
            self.assertTrue((app / "App.exe").is_file())

    def test_real_profile_behind_a_link_is_never_deleted(self):
        with tempfile.TemporaryDirectory() as temp:
            host = Path(temp, "host/Google/Chrome/User Data")
            host.mkdir(parents=True)
            (host / "Bookmarks").write_bytes(b"bookmarks")
            data = Path(temp, "PortableData")
            link = data / "AppData/Local/Google/Chrome"
            if not entry._junction_directory(link, host.parent):
                self.skipTest("эта файловая система не умеет ссылки на каталоги")

            engine = self._engine()
            engine._unlink_browser_profiles(str(data))
            self.assertEqual(engine._drop_browser_duplicates(str(data)), [])
            self.assertTrue((host / "Bookmarks").is_file())

    def test_updater_folders_are_covered_too(self):
        # Без своего обновлятора браузер в перенаправленном профиле решает,
        # что не установлен, и ставит себя заново — внутрь портатива.
        pairs = launcher_mod.browser_profile_pairs()
        self.assertIn(("LOCALAPPDATA", "Google/Update"), pairs)
        self.assertIn(("LOCALAPPDATA", "Microsoft/Edge"), pairs)

    def test_launcher_and_builder_agree_on_the_folders(self):
        pairs = set(launcher_mod.browser_profile_pairs())
        self.assertEqual(pairs, set(entry._browser_profile_pairs()))

    def test_launcher_config_carries_the_new_switches(self):
        cfg = launcher_mod.LauncherConfig(app_name="Figma",
                                          target_exe_rel="App/Figma.exe")
        settings = launcher_mod.browser_login_settings(cfg)
        self.assertTrue(settings["connect_host_profile"])
        self.assertTrue(settings["clean_duplicates"])

        off = launcher_mod.LauncherConfig(
            app_name="Figma", target_exe_rel="App/Figma.exe",
            browser_login={"connect_host_profile": False,
                           "clean_duplicates": False})
        settings = launcher_mod.browser_login_settings(off)
        self.assertFalse(settings["connect_host_profile"])
        self.assertFalse(settings["clean_duplicates"])


if __name__ == "__main__":
    unittest.main()


class DynamicDefaultBrowserTests(unittest.TestCase):
    """UserChoice/command, а не жёстко выбранный продукт."""

    def test_command_exe_wins_over_progid_alias(self):
        with mock.patch.object(entry, "IS_WINDOWS", True), \
                mock.patch.object(entry, "_default_browser_progid",
                                  return_value="YandexBrowser"), \
                mock.patch.object(entry, "_default_browser_command",
                                  return_value=(r'"C:\Users\me\AppData\Local\Yandex'
                                                r'\YandexBrowser\Application\browser.exe" '
                                                '"%1"')):
            self.assertEqual(entry._default_browser_images(), {"browser.exe"})

    def test_unknown_progid_is_resolved_from_its_command(self):
        with mock.patch.object(entry, "IS_WINDOWS", True), \
                mock.patch.object(entry, "_default_browser_progid",
                                  return_value="VendorCustomHTML"), \
                mock.patch.object(entry, "_default_browser_command",
                                  return_value=(r'C:\Program Files\Vendor\Custom Browser.exe '
                                                '--new-window "%1"')):
            self.assertEqual(entry._default_browser_images(),
                             {"custom browser.exe"})

    def test_command_parser_handles_quotes_and_environment(self):
        with mock.patch.dict(os.environ, {"CUSTOM_BROWSER_ROOT": r"C:\Browser"}):
            self.assertEqual(
                entry._browser_executable_from_command(
                    r'"%CUSTOM_BROWSER_ROOT%\Custom Browser.exe" -- "%1"'),
                r"C:\Browser\Custom Browser.exe")
        self.assertEqual(
            entry._browser_executable_from_command(
                r'C:\Program Files\Vendor\browser.exe --url "%1"'),
            r"C:\Program Files\Vendor\browser.exe")
        self.assertEqual(entry._browser_executable_from_command(
            'rundll32.exe url.dll,FileProtocolHandler "%1"'), "")

    def test_dynamic_default_process_is_used_by_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root)
            bridge = make_bridge(root, target)
            bridge.attach(10)
            with mock.patch.object(entry, "IS_WINDOWS", True), \
                    mock.patch.object(entry, "_default_browser_images",
                                      return_value={"custombrowser.exe"}), \
                    mock.patch.object(entry, "_default_browser_profile_pairs",
                                      return_value=set()):
                plan = bridge.plan(
                    [(20, 10, r"C:\Vendor\CustomBrowser.exe")],
                    command_line_of=lambda _pid:
                    '"CustomBrowser.exe" "https://login.example.test/oauth"')
            self.assertEqual(plan, [(20, "https://login.example.test/oauth",
                                     r"C:\Vendor\CustomBrowser.exe")])

    def test_yandex_browser_exe_has_profile_mapping_without_being_default_choice(self):
        self.assertIn(("APPDATA", "Yandex"),
                      entry._BROWSER_PROFILE_DIRS["browser.exe"])
        self.assertIn("browser.exe", entry._BROWSER_IMAGES)


class LegacySessionCleanupTests(unittest.TestCase):
    def test_old_session_reg_is_physically_cleaned(self):
        text = ("Windows Registry Editor Version 5.00\n\n"
                "[HKEY_CURRENT_USER\\Software\\Clients\\StartMenuInternet\\X]\n"
                '@="X"\n\n'
                "[HKEY_CURRENT_USER\\Software\\Vendor\\App]\n"
                '"Theme"="dark"\n')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            session = entry.RegistrySession(root, {
                "registry": {"enabled": True, "keys": []}})
            session.session.mkdir(parents=True)
            path = session.session / "session.reg"
            path.write_text(text, encoding="utf-16")
            session._sanitize_session_files()
            cleaned = path.read_text(encoding="utf-16")
            self.assertIn(r"Vendor\App", cleaned)
            self.assertNotIn("StartMenuInternet", cleaned)

    def test_browser_only_session_reg_is_removed(self):
        text = ("Windows Registry Editor Version 5.00\n\n"
                "[HKEY_CURRENT_USER\\Software\\Classes\\https]\n"
                '@="URL:HTTPS"\n')
        with tempfile.TemporaryDirectory() as temp:
            session = entry.RegistrySession(Path(temp), {
                "registry": {"enabled": True, "keys": []}})
            session.session.mkdir(parents=True)
            path = session.session / "session.reg"
            path.write_text(text, encoding="utf-16")
            session._sanitize_session_files()
            self.assertFalse(path.exists())


class BrowserAssociationSnapshotTests(unittest.TestCase):
    def test_default_browser_is_not_portable_but_is_restorable_on_host(self):
        key = (r"HKCU\Software\Microsoft\Windows\Shell\Associations"
               r"\UrlAssociations\https\UserChoice")
        values = {"ProgId": (reg_mod.REG_SZ, repr("VendorHTML"))}
        self.assertTrue(reg_mod.is_protected(key))
        self.assertTrue(reg_mod.is_association_key(key))
        self.assertEqual(reg_mod.compute_diff({}, {key: values}).touched_keys, [])
        self.assertIn(key, reg_mod.association_snapshot({key: values}))


@unittest.skipUnless(sys.platform.startswith("win"),
                     "настоящий UserChoice доступен только на Windows")
class RealDefaultBrowserTests(unittest.TestCase):
    def test_real_userchoice_progid_and_open_command(self):
        progid = entry._default_browser_progid()
        if not progid:
            self.skipTest("на runner не назначен HTTPS UserChoice")
        command = entry._default_browser_command(progid)
        if not command:
            self.skipTest("этот AppX/browser ProgID не имеет open command")
        executable = entry._browser_executable_from_command(command)
        self.assertTrue(executable, (progid, command))
        self.assertIn(executable.replace("/", "\\").rsplit("\\", 1)[-1].casefold(),
                      entry._default_browser_images())


class BuilderNestedLinkSafetyTests(unittest.TestCase):
    def test_duplicate_cleanup_does_not_follow_nested_link(self):
        from portablizer.core.logutil import Logger
        from portablizer.core.portablizer import Portablizer

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            host = root / "host-profile"
            host.mkdir()
            sentinel = host / "Bookmarks"
            sentinel.write_bytes(b"keep")
            duplicate = root / "PortableData/AppData/Local/Google/Chrome"
            duplicate.mkdir(parents=True)
            (duplicate / "User Data").mkdir()
            link = duplicate / "User Data/LinkedHost"
            if not entry._junction_directory(link, host):
                self.skipTest("эта файловая система не умеет ссылки на каталоги")
            Portablizer(Logger())._drop_browser_duplicates(
                str(root / "PortableData"))
            self.assertTrue(sentinel.is_file())
            self.assertFalse(duplicate.exists())


class LauncherHookIntegrationTests(unittest.TestCase):
    def test_wait_target_runs_browser_hook_without_update_watch(self):
        class FakeProcess:
            def __init__(self):
                self.calls = 0

            def wait(self, timeout=None):
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired("target", timeout)
                return 0

        import subprocess
        process = FakeProcess()
        hooks = []
        self.assertEqual(entry._wait_target(process, None,
                                            hooks=(lambda: hooks.append(1),)), 0)
        self.assertEqual(hooks, [1])

    def test_bat_host_appdata_is_preferred_for_profile_link(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = make_portable(root)
            bridge = make_bridge(root, target)
            host = root / "host-roaming"
            portable = root / "portable-roaming"
            host.mkdir()
            portable.mkdir()
            with mock.patch.dict(os.environ, {
                    "PORTABLE_HOST_APPDATA": str(host),
                    "APPDATA": str(portable)}):
                self.assertEqual(bridge._host_root("APPDATA"), host)


class SafeRegistryImportTests(unittest.TestCase):
    def test_reg_exe_fallback_never_receives_original_browser_file(self):
        text = ("Windows Registry Editor Version 5.00\n\n"
                "[HKEY_CURRENT_USER\\Software\\Classes\\YandexBrowser]\n"
                '@="Yandex"\n\n'
                "[HKEY_CURRENT_USER\\Software\\Vendor\\App]\n"
                '"Theme"="dark"\n')
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.reg"
            path.write_text(text, encoding="utf-16")
            seen = []

            def fake_reg(args):
                seen.append(Path(args[1]).read_text(encoding="utf-16"))
                return 0

            with mock.patch.object(entry, "import_registry_text", return_value=False), \
                    mock.patch.object(entry, "_reg", side_effect=fake_reg):
                self.assertTrue(entry.import_registry_file(path))
            self.assertEqual(len(seen), 1)
            self.assertIn("Vendor\\App", seen[0])
            self.assertNotIn("YandexBrowser", seen[0])
