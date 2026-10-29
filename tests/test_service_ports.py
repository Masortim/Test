"""Сторож служебных портов: «Managed service port ... already in use».

Жалоба: портированный OpenCode Desktop при запуске Launch.bat падал с
«Desktop IPC handler failed», а причиной было вот это сообщение самого
OpenCode: «Managed service port 28894 on 127.0.0.1 is already in use by
another process. Configure another port with `opencode service set port
<port>`». Программа поднимает фоновый сервис на ЗАФИКСИРОВАННОМ порту,
и занятый порт (остаток прошлого запуска, установленная на ПК копия той же
программы, зарезервированный Windows диапазон портов под WSL/Hyper-V) убивает
её ещё до первого окна.

Проверяется лечение в лончере:

* до старта программы объявленные порты (блок ``service_ports``) проверяются
  на занятость;
* владелец из папки портатива (в том числе с прежнего места папки) — это
  остаток прошлого запуска, он закрывается;
* чужой процесс не трогается, а программа переносится на свободный порт через
  её же конфиг — для OpenCode это
  ``PortableData\\User\\.config\\opencode\\service.json`` (``{"port": N}``),
  ровно то, что советует сам OpenCode;
* уже работающая программа (второй запуск) не трогается вовсе.

Файловая логика проверяется по-настоящему; таблица TCP-соединений и снятие
процессов подменяются двойниками (эти вызовы существуют только на Windows).
"""
import inspect
import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import portable_launcher_entry as exe_launcher
from portablizer.core import launcher as launcher_mod

OPENCODE_CFG = {
    "app_name": "OpenCode",
    "target_exe_rel": "App/OpenCode.exe",
    "data_dir_name": "PortableData",
}

SERVICE_JSON = "PortableData/User/.config/opencode/service.json"


def make_opencode_portable(tmp: str, cfg=None) -> Path:
    root = Path(tmp) / "OpenCode_Portable"
    (root / "App").mkdir(parents=True)
    (root / "App" / "OpenCode.exe").write_text("app", encoding="utf-8")
    (root / "launcher_config.json").write_text(
        json.dumps(cfg or OPENCODE_CFG), encoding="utf-8")
    return root


def winpath(path: Path) -> str:
    """Путь в записи Windows (в тестах на Linux разделитель другой)."""
    return str(path).replace("/", "\\")


def free_tcp_port() -> int:
    """Свободный прямо сейчас порт: взяли и тут же отдали."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class SettingsTests(unittest.TestCase):
    """Блок service_ports: профиль программы + явные настройки."""

    def test_opencode_profile_detected_by_name(self):
        settings = exe_launcher.service_port_settings(OPENCODE_CFG)
        self.assertEqual(settings["defaults"], [28894])
        (entry,) = settings["config_files"]
        self.assertEqual(entry["path"], "User/.config/opencode/service.json")
        self.assertEqual(entry["key"], "port")
        self.assertEqual(entry["base"], "data")

    def test_profile_detected_by_target_path(self):
        settings = exe_launcher.service_port_settings({
            "app_name": "Мой агент",
            "target_exe_rel": "App/opencode-cli.exe",
        })
        self.assertEqual(settings["defaults"], [28894])

    def test_unknown_program_gets_no_block(self):
        self.assertEqual(exe_launcher.service_port_settings({
            "app_name": "SketchUp",
            "target_exe_rel": "App/SketchUp.exe",
        }), {})

    def test_explicit_block_overrides_profile_keys(self):
        cfg = dict(OPENCODE_CFG, service_ports={"defaults": [7777]})
        settings = exe_launcher.service_port_settings(cfg)
        self.assertEqual(settings["defaults"], [7777])
        # Записи конфига пришли из профиля: переопределение по ключам.
        self.assertEqual(settings["config_files"],
                         [{"base": "data",
                           "path": "User/.config/opencode/service.json",
                           "key": "port"}])

    def test_enabled_false_disables_the_check(self):
        cfg = dict(OPENCODE_CFG, service_ports={"enabled": False})
        self.assertEqual(exe_launcher.service_port_settings(cfg), {})

    def test_builder_and_launcher_profiles_do_not_drift(self):
        self.assertEqual(dict(launcher_mod.SERVICE_PORT_PROFILES),
                         dict(exe_launcher.SERVICE_PORT_PROFILES))


class BindableTests(unittest.TestCase):
    """Проверка занятости порта на настоящих сокетах."""

    def test_free_port_is_bindable_and_busy_port_is_not(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        busy = int(listener.getsockname()[1])
        try:
            self.assertFalse(exe_launcher._tcp_bindable(busy))
        finally:
            listener.close()
        self.assertTrue(exe_launcher._tcp_bindable(free_tcp_port()))

    def test_out_of_range_port_is_not_bindable(self):
        self.assertFalse(exe_launcher._tcp_bindable(0))
        self.assertFalse(exe_launcher._tcp_bindable(70000))


class GuardTests(unittest.TestCase):
    """Сценарии guard_service_ports: остаток, чужой процесс, второй запуск."""

    def setUp(self):
        # В тестах паузы не нужны: всё решают двойники вокруг сокетов.
        patches = [
            mock.patch.object(exe_launcher, "SERVICE_PORT_WAIT_SECONDS", 0.0),
            mock.patch.object(exe_launcher, "SERVICE_PORT_RECHECK_SECONDS", 0.0),
            mock.patch.object(exe_launcher, "_portable_process_list",
                              return_value=[]),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def test_free_port_changes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_opencode_portable(tmp)
            with mock.patch.object(exe_launcher, "_tcp_bindable",
                                   return_value=True):
                self.assertEqual(
                    exe_launcher.guard_service_ports(root, OPENCODE_CFG), [])

    def test_real_busy_port_frees_itself_within_grace(self):
        port = free_tcp_port()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        self.addCleanup(listener.close)
        with tempfile.TemporaryDirectory() as tmp:
            root = make_opencode_portable(tmp)
            # Настоящий слушатель на 0.3 с: лончер должен дождаться его сам,
            # не трогая процессы и не переписывая конфиг.
            with mock.patch.object(exe_launcher, "SERVICE_PORT_WAIT_SECONDS",
                                   1.0), \
                 mock.patch.object(exe_launcher, "_tcp_listener_owner") as owner, \
                 mock.patch.object(exe_launcher, "_stop_port_owner") as stop:
                lines = exe_launcher.guard_service_ports(root, OPENCODE_CFG)
            self.assertEqual(lines, [])
            owner.assert_not_called()
            stop.assert_not_called()
            self.assertFalse((root / SERVICE_JSON).exists())

    def test_leftover_from_portable_folder_is_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_opencode_portable(tmp)
            image = winpath(root / "App" / "opencode-cli.exe")
            # Порт занят, а после закрытия остатка - свободен.
            binds = [False, True]
            with mock.patch.object(exe_launcher, "_tcp_bindable",
                                   side_effect=lambda p: binds.pop(0)), \
                 mock.patch.object(exe_launcher, "_tcp_listener_owner",
                                   return_value=(4711, image)), \
                 mock.patch.object(exe_launcher, "_stop_port_owner",
                                   return_value=True) as stop:
                lines = exe_launcher.guard_service_ports(root, OPENCODE_CFG)
            stop.assert_called_once_with(4711)
            self.assertEqual(len(lines), 1)
            self.assertIn("остаток прошлого запуска", lines[0])
            self.assertIn("opencode-cli.exe", lines[0])
            # Конфиг программы при своём остатке не переписывается.
            self.assertFalse((root / SERVICE_JSON).exists())

    def test_leftover_at_previous_location_is_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_opencode_portable(tmp)
            old = Path(tmp) / "OpenCode_Portable_old"
            (old / "App").mkdir(parents=True)
            image = winpath(old / "App" / "opencode-cli.exe")
            binds = [False, True]
            with mock.patch.object(exe_launcher, "remembered_roots",
                                   return_value=[str(old)]), \
                 mock.patch.object(exe_launcher, "_tcp_bindable",
                                   side_effect=lambda p: binds.pop(0)), \
                 mock.patch.object(exe_launcher, "_tcp_listener_owner",
                                   return_value=(15, image)), \
                 mock.patch.object(exe_launcher, "_stop_port_owner",
                                   return_value=True) as stop:
                lines = exe_launcher.guard_service_ports(root, OPENCODE_CFG)
            stop.assert_called_once_with(15)
            self.assertTrue(lines and "остаток прошлого запуска" in lines[0])

    def test_leftover_that_survives_kill_still_gets_a_redirect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_opencode_portable(tmp)
            image = winpath(root / "App" / "opencode-cli.exe")
            # Занят -> (после завершения остатка) всё ещё занят -> свободен.
            busy = {28894}
            def bindable(port):
                return int(port) not in busy
            with mock.patch.object(exe_launcher, "_tcp_bindable",
                                   side_effect=bindable), \
                 mock.patch.object(exe_launcher, "_tcp_listener_owner",
                                   return_value=(4711, image)), \
                 mock.patch.object(exe_launcher, "_stop_port_owner",
                                   return_value=True) as stop:
                lines = exe_launcher.guard_service_ports(root, OPENCODE_CFG)
            stop.assert_called_once_with(4711)
            # Остаток закрыт, но порт так и не освободился: чтобы программа
            # всё-таки запустилась, она переносится на свободный порт.
            self.assertTrue(any("не освободился" in line for line in lines))
            data = json.loads((root / SERVICE_JSON).read_text(encoding="utf-8"))
            self.assertNotEqual(data["port"], 28894)

    def test_foreign_process_is_not_killed_and_port_is_redirected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_opencode_portable(tmp)
            foreign = "C:\\Program Files\\OpenCode\\opencode-cli.exe"
            def bindable(port):
                return int(port) != 28894
            with mock.patch.object(exe_launcher, "_tcp_bindable",
                                   side_effect=bindable), \
                 mock.patch.object(exe_launcher, "_tcp_listener_owner",
                                   return_value=(4242, foreign)), \
                 mock.patch.object(exe_launcher, "_stop_port_owner") as stop:
                lines = exe_launcher.guard_service_ports(root, OPENCODE_CFG)
            # Чужой процесс (установленная на ПК копия) не завершается.
            stop.assert_not_called()
            self.assertTrue(any("перенаправлен" in line for line in lines))
            self.assertTrue(any("28894" in line for line in lines))
            data = json.loads((root / SERVICE_JSON).read_text(encoding="utf-8"))
            self.assertNotEqual(data["port"], 28894)

    def test_unknown_owner_is_redirected_not_killed(self):
        """Зарезервированный Windows диапазон: владельца в таблице нет."""
        with tempfile.TemporaryDirectory() as tmp:
            root = make_opencode_portable(tmp)
            def bindable(port):
                return int(port) != 28894
            with mock.patch.object(exe_launcher, "_tcp_bindable",
                                   side_effect=bindable), \
                 mock.patch.object(exe_launcher, "_tcp_listener_owner",
                                   return_value=(0, "")), \
                 mock.patch.object(exe_launcher, "_stop_port_owner") as stop:
                lines = exe_launcher.guard_service_ports(root, OPENCODE_CFG)
            stop.assert_not_called()
            self.assertTrue(any("перенаправлен" in line for line in lines))
            data = json.loads((root / SERVICE_JSON).read_text(encoding="utf-8"))
            self.assertTrue(data["port"])

    def test_redirect_picks_port_next_to_the_busy_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_opencode_portable(tmp)
            # 28895 занят чужим сервисом: подбор обязан его пропустить.
            def bindable(port):
                return int(port) not in (28894, 28895)
            with mock.patch.object(exe_launcher, "_tcp_bindable",
                                   side_effect=bindable), \
                 mock.patch.object(exe_launcher, "_tcp_listener_owner",
                                   return_value=(0, "")):
                exe_launcher.guard_service_ports(root, OPENCODE_CFG)
            data = json.loads((root / SERVICE_JSON).read_text(encoding="utf-8"))
            self.assertEqual(data["port"], 28896)

    def test_port_written_by_the_program_is_guarded_too(self):
        """Порт, уже записанный программой в service.json, тоже проверяется."""
        with tempfile.TemporaryDirectory() as tmp:
            root = make_opencode_portable(tmp)
            config = root / SERVICE_JSON
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(
                {"port": 30100, "note": "пользовательская настройка"}),
                encoding="utf-8")
            cfg = dict(OPENCODE_CFG, service_ports={"defaults": []})
            def bindable(port):
                return int(port) != 30100
            with mock.patch.object(exe_launcher, "_tcp_bindable",
                                   side_effect=bindable), \
                 mock.patch.object(exe_launcher, "_tcp_listener_owner",
                                   return_value=(0, "")):
                lines = exe_launcher.guard_service_ports(root, cfg)
            self.assertTrue(any("перенаправлен" in line for line in lines))
            data = json.loads(config.read_text(encoding="utf-8"))
            self.assertNotEqual(data["port"], 30100)
            # Остальные ключи файла программы сохраняются.
            self.assertEqual(data["note"], "пользовательская настройка")

    def test_broken_service_json_is_replaced_with_valid_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_opencode_portable(tmp)
            config = root / SERVICE_JSON
            config.parent.mkdir(parents=True)
            config.write_text("{not json at all", encoding="utf-8")
            def bindable(port):
                return int(port) != 28894
            with mock.patch.object(exe_launcher, "_tcp_bindable",
                                   side_effect=bindable), \
                 mock.patch.object(exe_launcher, "_tcp_listener_owner",
                                   return_value=(0, "")):
                lines = exe_launcher.guard_service_ports(root, OPENCODE_CFG)
            self.assertTrue(lines)
            data = json.loads(config.read_text(encoding="utf-8"))
            self.assertTrue(data["port"])

    def test_second_instance_is_left_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_opencode_portable(tmp)
            with mock.patch.object(exe_launcher, "_portable_process_list",
                                   return_value=[(123, "whatever")]), \
                 mock.patch.object(exe_launcher, "_tcp_bindable") as bindable, \
                 mock.patch.object(exe_launcher, "_stop_port_owner") as stop:
                lines = exe_launcher.guard_service_ports(root, OPENCODE_CFG)
            self.assertEqual(len(lines), 1)
            self.assertIn("already running", lines[0])
            bindable.assert_not_called()
            stop.assert_not_called()

    def test_failure_of_one_port_does_not_stop_the_others(self):
        cfg = dict(OPENCODE_CFG, service_ports={"defaults": [28894, 30100]})
        calls = []

        def bindable(port):
            calls.append(int(port))
            if int(port) == 28894:
                raise RuntimeError("boom")
            return True

        with tempfile.TemporaryDirectory() as tmp:
            root = make_opencode_portable(tmp)
            with mock.patch.object(exe_launcher, "_tcp_bindable",
                                   side_effect=bindable):
                lines = exe_launcher.guard_service_ports(root, cfg)
            self.assertEqual(calls, [28894, 30100])
            self.assertTrue(any("28894" in line for line in lines))


class HelperTests(unittest.TestCase):
    """Узкие места: определение «своего» процесса и закрытие владельца."""

    def test_process_from_portable_matches_current_and_previous_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_opencode_portable(tmp)
            old = Path(tmp) / "elsewhere"
            with mock.patch.object(exe_launcher, "remembered_roots",
                                   return_value=[str(old)]):
                self.assertTrue(exe_launcher._process_from_portable(
                    root, OPENCODE_CFG, winpath(root / "App" / "x.exe")))
                self.assertTrue(exe_launcher._process_from_portable(
                    root, OPENCODE_CFG, winpath(old / "App" / "x.exe")))
            self.assertFalse(exe_launcher._process_from_portable(
                root, OPENCODE_CFG,
                "C:\\Program Files\\OpenCode\\opencode-cli.exe"))
            self.assertFalse(exe_launcher._process_from_portable(
                root, OPENCODE_CFG, ""))
            # Сама папка-корень «порождением» не считается.
            self.assertFalse(exe_launcher._process_from_portable(
                root, OPENCODE_CFG, winpath(root)))

    def test_stop_port_owner_returns_true_when_process_goes_away(self):
        # Процесс ушёл сам во время вежливой паузы: до TerminateProcess
        # дело не доходит.
        with mock.patch.object(exe_launcher, "SERVICE_PORT_CLOSE_GRACE", 0.5), \
             mock.patch.object(exe_launcher, "_post_close_to_windows") as close, \
             mock.patch.object(exe_launcher, "_query_image_path",
                               side_effect=["C:\\a\\x.exe", ""]), \
             mock.patch.object(exe_launcher, "_terminate_pids") as kill:
            self.assertTrue(exe_launcher._stop_port_owner(4321))
            close.assert_called_once_with([4321])
            kill.assert_not_called()

    def test_stop_port_owner_terminates_stubborn_process(self):
        with mock.patch.object(exe_launcher, "SERVICE_PORT_CLOSE_GRACE", 0.0), \
             mock.patch.object(exe_launcher, "_post_close_to_windows"), \
             mock.patch.object(exe_launcher, "_query_image_path",
                               return_value="C:\\a\\x.exe"), \
             mock.patch.object(exe_launcher, "_terminate_pids",
                               return_value=[4321]) as kill:
            self.assertTrue(exe_launcher._stop_port_owner(4321))
            kill.assert_called_once_with([4321])

    def test_stop_port_owner_reports_failure(self):
        with mock.patch.object(exe_launcher, "SERVICE_PORT_CLOSE_GRACE", 0.0), \
             mock.patch.object(exe_launcher, "_post_close_to_windows"), \
             mock.patch.object(exe_launcher, "_query_image_path",
                               return_value="C:\\a\\x.exe"), \
             mock.patch.object(exe_launcher, "_terminate_pids",
                               return_value=[]):
            self.assertFalse(exe_launcher._stop_port_owner(4321))

    def test_windows_only_helpers_are_safe_off_windows(self):
        if exe_launcher.IS_WINDOWS:
            self.skipTest("проверяется только вне Windows")
        self.assertEqual(exe_launcher._tcp_listener_owner(28894), (0, ""))
        self.assertEqual(exe_launcher._query_image_path(4321), "")


class BuilderTests(unittest.TestCase):
    """Сборщик: блок service_ports попадает в launcher_config.json."""

    def test_builder_writes_service_ports_for_opencode(self):
        cfg = launcher_mod.config_from_dict(dict(OPENCODE_CFG))
        payload = json.loads(launcher_mod.render_config_json(cfg))
        block = payload["service_ports"]
        self.assertEqual(block["defaults"], [28894])
        (entry,) = block["config_files"]
        self.assertEqual(entry["path"], "User/.config/opencode/service.json")

    def test_builder_omits_block_for_unknown_program(self):
        cfg = launcher_mod.config_from_dict(
            {"app_name": "SketchUp", "target_exe_rel": "App/SketchUp.exe"})
        payload = json.loads(launcher_mod.render_config_json(cfg))
        self.assertNotIn("service_ports", payload)

    def test_builder_round_trip_keeps_the_block(self):
        raw = dict(OPENCODE_CFG, service_ports={"defaults": [5555]})
        cfg = launcher_mod.config_from_dict(raw)
        payload = json.loads(launcher_mod.render_config_json(cfg))
        self.assertEqual(payload["service_ports"]["defaults"], [5555])
        again = launcher_mod.config_from_dict(payload)
        self.assertEqual(again.service_ports["defaults"], [5555])

    def test_builder_disabled_block_is_not_written(self):
        cfg = launcher_mod.config_from_dict(
            dict(OPENCODE_CFG, service_ports={"enabled": False}))
        payload = json.loads(launcher_mod.render_config_json(cfg))
        self.assertNotIn("service_ports", payload)


class WiringTests(unittest.TestCase):
    """Проверка запускается до старта программы, а не в фоне."""

    def test_run_session_calls_the_guard_before_start(self):
        source = inspect.getsource(exe_launcher._run_session)
        self.assertIn("guard_service_ports", source)
        # Шаг обязателен: перенос в фон означал бы проверку ПОСЛЕ старта
        # программы, когда её сервис уже упал на занятом порту.
        self.assertNotIn("_run_step(\"service ports\"", source)


if __name__ == "__main__":
    unittest.main()
