"""No invented elevation advice and no closing external processes' handles."""
import os
import ctypes
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from portablizer.core import filelocks, maintenance, procutil, restart_manager
from portablizer.core.logutil import Logger
import portable_launcher_entry as launcher


class ReleaseDiagnosticsTests(unittest.TestCase):
    def test_admin_is_not_told_to_restart_as_admin(self):
        with tempfile.TemporaryDirectory() as temp:
            locked = str(Path(temp, 'lockfile'))
            with mock.patch.object(procutil, 'release_folder', return_value=[]), \
                 mock.patch.object(procutil, 'folder_is_free', return_value=False), \
                 mock.patch.object(procutil, 'busy_files', return_value=[locked]), \
                 mock.patch.object(procutil, 'holders', return_value=[]), \
                 mock.patch.object(maintenance.elevate_mod, 'is_elevated', return_value=True):
                report = maintenance.release(temp, Logger())
            text = ' '.join(report.messages)
            self.assertFalse(report.success)
            self.assertIn('уже запущен с повышенными правами', text)
            self.assertNotIn('запустите Portablizer от имени администратора', text)
            self.assertIn('не был принудительно закрыт', text)

    def test_incomplete_scan_cannot_claim_folder_free(self):
        with tempfile.TemporaryDirectory() as temp:
            def incomplete(_root, **kwargs):
                kwargs['scan_status'].append('проверка не завершена')
                return []
            with mock.patch.object(procutil, 'busy_files', side_effect=incomplete):
                errors = []
                self.assertFalse(procutil.folder_is_free(temp, errors))
                self.assertIn('проверка не завершена', errors)

    def test_scan_errors_and_limits_are_never_success(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, 'one').write_text('1')
            Path(temp, 'two').write_text('2')
            kernel = mock.Mock()
            kernel.CreateFileW.return_value = ctypes.c_void_p(-1).value
            kernel.GetLastError.return_value = 32
            dll = mock.Mock(kernel32=kernel)
            for module, root in ((procutil, temp), (launcher, Path(temp))):
                with self.subTest(module=module.__name__), \
                     mock.patch.object(module, 'IS_WINDOWS', True), \
                     mock.patch.object(ctypes, 'windll', dll, create=True):
                    status = []
                    self.assertTrue(module.busy_files(root, limit=1, scan_status=status))
                    self.assertTrue(status, 'limit must mark the walk incomplete')
                    def inaccessible(_root, onerror):
                        onerror(PermissionError('denied'))
                        return iter(())
                    with mock.patch.object(module.os, 'walk', side_effect=inaccessible):
                        status = []
                        self.assertEqual(module.busy_files(root, scan_status=status), [])
                        self.assertTrue(status, 'walk error must not look like success')

    def test_launcher_incomplete_scan_not_cached_as_clean(self):
        with mock.patch.object(launcher, 'IS_WINDOWS', True), \
             mock.patch.object(launcher, '_LAST_CLEAN_SWEEP', 0), \
             mock.patch.object(launcher, 'busy_files', side_effect=lambda *a, **kw:
                               kw['scan_status'].append('incomplete') or []):
            launcher.release_leftover_handles(Path('portable'))
            self.assertEqual(launcher._LAST_CLEAN_SWEEP, 0)

    def test_extended_paths_for_drive_unc_and_already_extended(self):
        for source, expected in ((r'C:\Portable\App\file', r'\\?\C:\Portable\App\file'),
                                 (r'\\server\share\file', r'\\?\UNC\server\share\file'),
                                 (r'\\?\C:\deep\file', r'\\?\C:\deep\file')):
            self.assertEqual(filelocks.extended_path(source), expected)
            self.assertEqual(filelocks.display_path(expected),
                             source if not source.startswith('\\\\?\\') else source[4:])

    def test_access_denied_reports_exact_path_and_readonly_without_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, 'readonly.bin')
            path.write_text('unchanged')
            kernel = mock.Mock()
            kernel.CreateFileW.return_value = ctypes.c_void_p(-1).value
            kernel.GetLastError.return_value = 5
            kernel.GetFileAttributesW.return_value = 1
            for module, root in ((procutil, temp), (launcher, Path(temp))):
                with self.subTest(module=module.__name__), \
                     mock.patch.object(module, 'IS_WINDOWS', True), \
                     mock.patch.object(ctypes, 'windll', mock.Mock(kernel32=kernel), create=True):
                    status = []
                    self.assertEqual(module.busy_files(root, scan_status=status), [])
                    self.assertIn(str(path), ' '.join(status))
                    self.assertIn('WinError 5', ' '.join(status))
                    self.assertIn('только чтение', ' '.join(status))
                    self.assertEqual(path.read_text(), 'unchanged')

    def test_timed_out_probe_reports_path_and_later_closes_handle(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, 'slow.bin')
            path.write_text('unchanged')
            release, closed = threading.Event(), threading.Event()
            kernel = mock.Mock()
            def delayed(*_args):
                release.wait(5)
                return 42
            kernel.CreateFileW.side_effect = delayed
            kernel.CloseHandle.side_effect = lambda *_args: closed.set()
            with mock.patch.object(ctypes, 'windll', mock.Mock(kernel32=kernel), create=True):
                try:
                    start = time.monotonic()
                    locked, status = filelocks.scan([temp], budget=0.1)
                    self.assertLess(time.monotonic() - start, 2)
                    self.assertEqual(locked, [])
                    self.assertIn(str(path), ' '.join(status))
                    self.assertIn('не завершилась', ' '.join(status))
                finally:
                    release.set()
                    self.assertTrue(closed.wait(2), 'eventual successful handle must be closed')

    def test_many_files_use_a_single_worker_thread(self):
        with tempfile.TemporaryDirectory() as temp:
            for i in range(200):
                Path(temp, str(i)).touch()
            kernel = mock.Mock()
            kernel.CreateFileW.return_value = 42
            real_thread = threading.Thread
            with mock.patch.object(ctypes, 'windll', mock.Mock(kernel32=kernel), create=True), \
                 mock.patch.object(filelocks.threading, 'Thread', wraps=real_thread) as thread:
                locked, status = filelocks.scan([temp], budget=5)
            self.assertEqual((locked, status), ([], []))
            self.assertEqual(thread.call_count, 1)
            self.assertEqual(kernel.CreateFileW.call_count, 200)
            self.assertEqual(kernel.CloseHandle.call_count, 200)

    def test_incomplete_details_are_not_hidden_by_holder(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(procutil, 'release_folder', return_value=[]), \
                 mock.patch.object(procutil, 'folder_is_free', side_effect=lambda root, errors:
                                   errors.append('file.dat: WinError 5') or False), \
                 mock.patch.object(procutil, 'busy_files', return_value=['locked']), \
                 mock.patch.object(procutil, 'holders', return_value=[]):
                report = maintenance.release(temp, Logger())
            self.assertFalse(report.success)
            self.assertIn('file.dat: WinError 5', ' '.join(report.messages))

    def test_restart_manager_results_are_reported_without_termination(self):
        root = r'D:\\P'
        path = root + r'\\PortableData\\lockfile'
        owner = restart_manager.FileOwner(1234, 'Browser', '', path)
        with mock.patch.object(procutil, '_snapshot', return_value=[]), \
             mock.patch.object(restart_manager, 'file_owners', return_value=[owner]), \
             mock.patch.object(procutil, 'open_files_in', side_effect=AssertionError('unneeded scan')):
            result = procutil.holders(root, locked_files=[path])
        self.assertEqual(result, [procutil.Holder(1234, 'Browser', 'file', path)])
        self.assertIn('pid 1234', procutil.describe_holders(result)[0])

    def test_launcher_never_kills_external_owner_or_closes_its_handles(self):
        with mock.patch.object(launcher, 'IS_WINDOWS', True), \
             mock.patch.object(launcher, 'open_files_in', return_value=[(10, 7, r'D:\\P\\lockfile', r'D:\\Other\\Browser.exe')]), \
             mock.patch.object(launcher, '_portable_process_list', return_value=[]), \
             mock.patch.object(launcher, '_close_remote_handle') as close, \
             mock.patch.object(launcher, '_terminate_pids') as kill:
            self.assertEqual(launcher.release_open_files(Path(r'D:\\P')), [])
        close.assert_not_called()
        kill.assert_not_called()


class ScanPrivilegeTests(unittest.TestCase):
    """Best-effort backup/restore privileges for ACL-hidden cache folders."""

    def test_privileges_are_noop_off_windows(self):
        if os.name == 'nt':
            self.skipTest('POSIX no-op path')
        self.assertEqual(filelocks.acquire_scan_privileges(), [])
        # Release is a symmetric no-op; it must not raise either.
        filelocks.release_scan_privileges([filelocks.SE_BACKUP_NAME,
                                           filelocks.SE_RESTORE_NAME])

    def test_privilege_acquisition_failure_never_breaks_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, 'file.bin').write_text('x')
            kernel = mock.Mock()
            kernel.CreateFileW.return_value = 42
            with mock.patch.object(filelocks, 'acquire_scan_privileges',
                                   side_effect=RuntimeError('no token')), \
                 mock.patch.object(ctypes, 'windll', mock.Mock(kernel32=kernel), create=True):
                locked, issues = filelocks.scan([temp], budget=5)
            self.assertEqual((locked, issues), ([], []))

    def test_privilege_release_failure_never_breaks_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, 'file.bin').write_text('x')
            kernel = mock.Mock()
            kernel.CreateFileW.return_value = 42
            with mock.patch.object(filelocks, 'release_scan_privileges',
                                   side_effect=RuntimeError('gone')), \
                 mock.patch.object(ctypes, 'windll', mock.Mock(kernel32=kernel), create=True):
                locked, issues = filelocks.scan([temp], budget=5)
            self.assertEqual((locked, issues), ([], []))

    def test_privileges_are_released_after_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, 'file.bin').write_text('x')
            released = []
            kernel = mock.Mock()
            kernel.CreateFileW.return_value = 42
            with mock.patch.object(filelocks, 'acquire_scan_privileges',
                                   return_value=['SeBackupPrivilege']), \
                 mock.patch.object(filelocks, 'release_scan_privileges',
                                   side_effect=lambda names: released.extend(names)), \
                 mock.patch.object(ctypes, 'windll', mock.Mock(kernel32=kernel), create=True):
                locked, issues = filelocks.scan([temp], budget=5)
            self.assertEqual((locked, issues), ([], []))
            self.assertEqual(released, ['SeBackupPrivilege'])

    @staticmethod
    def _win_error_5_walk(_root, onerror):
        exc = PermissionError(13, 'denied')
        exc.winerror = 5
        onerror(exc)
        return iter(())

    def test_walk_error_without_privileges_suggests_elevated_run(self):
        with tempfile.TemporaryDirectory() as temp:
            kernel = mock.Mock()
            kernel.CreateFileW.return_value = 42
            with mock.patch.object(filelocks, 'acquire_scan_privileges', return_value=[]), \
                 mock.patch.object(filelocks.os, 'walk', side_effect=self._win_error_5_walk), \
                 mock.patch.object(ctypes, 'windll', mock.Mock(kernel32=kernel), create=True):
                locked, issues = filelocks.scan([temp], budget=5)
        text = ' '.join(issues)
        self.assertEqual(locked, [])
        self.assertIn('WinError 5', text)
        self.assertIn('администратора', text)
        self.assertEqual(text.count('администратора'), 1)

    def test_walk_error_with_privileges_reports_no_elevation_hint(self):
        with tempfile.TemporaryDirectory() as temp:
            kernel = mock.Mock()
            kernel.CreateFileW.return_value = 42
            with mock.patch.object(filelocks, 'acquire_scan_privileges',
                                   return_value=['SeBackupPrivilege']), \
                 mock.patch.object(filelocks.os, 'walk', side_effect=self._win_error_5_walk), \
                 mock.patch.object(ctypes, 'windll', mock.Mock(kernel32=kernel), create=True):
                locked, issues = filelocks.scan([temp], budget=5)
        text = ' '.join(issues)
        self.assertEqual(locked, [])
        self.assertIn('WinError 5', text)
        self.assertNotIn('администратора', text)


@unittest.skipUnless(sys.platform == 'win32', 'Windows actual handle test')
class WindowsFileOwnerTests(unittest.TestCase):
    CHILD = r'''
import ctypes, sys, time
k = ctypes.WinDLL('kernel32', use_last_error=True)
k.CreateFileW.restype = ctypes.c_void_p
h = k.CreateFileW(sys.argv[1], 0x80000000, int(sys.argv[2]), None, 3, 0x80, None)
if h in (0, None, ctypes.c_void_p(-1).value):
    print('ERROR', ctypes.get_last_error(), flush=True); sys.exit(2)
print('READY', flush=True)
time.sleep(90)
k.CloseHandle(ctypes.c_void_p(h))
'''

    def _holder(self, path, share):
        proc = subprocess.Popen([sys.executable, '-c', self.CHILD, str(path), str(share)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ready = proc.stdout.readline().strip()
        self.assertEqual(ready, 'READY', ready)
        def cleanup():
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=10)
        self.addCleanup(cleanup)
        return proc

    def test_exact_file_owner_found_and_foreign_holder_not_killed(self):
        with tempfile.TemporaryDirectory(prefix='portable locks ', ignore_cleanup_errors=True) as temp:
            file = Path(temp, 'lockfile')
            file.write_text('keep')
            proc = self._holder(file, 0)
            table, kind = procutil._table_with_file_type()
            self.assertTrue(table)
            self.assertGreaterEqual(kind, 0, 'file handle must be open before snapshot')
            table2, kind2 = launcher._table_with_file_type()
            self.assertTrue(table2)
            self.assertEqual(kind, kind2)
            self.assertIn(str(file), procutil.busy_files(temp, recheck=0))
            owners = restart_manager.file_owners([str(file)])
            self.assertTrue(any(owner.pid == proc.pid for owner in owners), owners)
            report = maintenance.release(temp, Logger())
            self.assertFalse(report.success)
            self.assertIsNone(proc.poll(), 'external process must not be terminated')
            self.assertTrue(file.exists())
            self.assertTrue(any(str(proc.pid) in item for item in report.holders), report.holders)
            proc.terminate()
            proc.wait(timeout=10)

    def test_deep_windows_path_is_scanned_and_locked_owner_survives(self):
        with tempfile.TemporaryDirectory(prefix='portable deep ') as temp:
            directory = temp
            while len(directory) < 290:
                directory = os.path.join(directory, 'long_' + 'a' * 32)
            native_dir = filelocks.extended_path(directory)
            os.makedirs(native_dir)
            path = os.path.join(directory, 'locked.db')
            native_path = filelocks.extended_path(path)
            with open(native_path, 'w') as stream:
                stream.write('keep')
            status = []
            self.assertEqual(procutil.busy_files(temp, recheck=0, scan_status=status), [])
            self.assertEqual(status, [])
            proc = self._holder(native_path, 0)
            status = []
            self.assertIn(path, procutil.busy_files(temp, recheck=0, scan_status=status))
            self.assertEqual(status, [])
            self.assertIsNone(proc.poll())
            proc.terminate()
            proc.wait(timeout=10)
            self.assertEqual(procutil.busy_files(temp, recheck=0), [])
            # Python's default temporary-directory cleanup uses non-prefixed
            # paths on some Windows configurations.
            os.remove(native_path)
            while directory != temp:
                os.rmdir(filelocks.extended_path(directory))
                directory = os.path.dirname(directory)

    def test_open_file_allowing_delete_is_not_a_sharing_conflict(self):
        with tempfile.TemporaryDirectory(prefix='portable share ', ignore_cleanup_errors=True) as temp:
            file = Path(temp, 'file.db')
            file.write_text('keep')
            proc = self._holder(file, 7)
            self.assertEqual(procutil.busy_files(temp, recheck=0), [])
            proc.terminate()
            proc.wait(timeout=10)


if __name__ == '__main__':
    unittest.main()
