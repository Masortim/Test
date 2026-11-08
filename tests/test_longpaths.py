"""Path shortening never reuses or deletes a stranger's directory."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from portablizer.core import longpaths


class ShortPathsTests(unittest.TestCase):
    def test_long_name_is_shortened_but_a_short_name_is_not(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertTrue(longpaths.should_use_short_root(temp, 'PyCharm_2025.2.3_x64-(IDEa)'))
            self.assertFalse(longpaths.should_use_short_root(temp, 'P'))
            self.assertFalse(longpaths.should_use_short_root(temp, 'PyCharm'))

    def test_fresh_directories_are_inside_selected_root_and_preserve_existing(self):
        with tempfile.TemporaryDirectory() as temp:
            existing = Path(temp, 'PyCharm_2025.2.3_x64-(IDEa)_Portable', 'App')
            existing.mkdir(parents=True)
            (existing / 'keep.txt').write_text('untouched')
            first = longpaths.reserve_short_root(temp)
            Path(first, 'App').mkdir()
            Path(first, 'App', 'keep.txt').write_text('untouched too')
            second = longpaths.reserve_short_root(temp)
            self.assertNotEqual(first, second)
            self.assertEqual(Path(first).parent, Path(temp))
            self.assertEqual(Path(second).parent, Path(temp))
            self.assertLess(len(Path(first).name), 20)
            self.assertEqual((existing / 'keep.txt').read_text(), 'untouched')
            self.assertEqual(Path(first, 'App', 'keep.txt').read_text(), 'untouched too')

    def test_mkdtemp_retries_collision_without_opening_existing_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            foreign = Path(temp, 'P-existing')
            foreign.mkdir()
            (foreign / 'keep.txt').write_text('valuable')
            with mock.patch('tempfile._get_candidate_names', return_value=iter(['existing', 'newname1'])):
                reserved = longpaths.reserve_short_root(temp)
            self.assertEqual(Path(reserved).name, 'P-newname1')
            self.assertEqual((foreign / 'keep.txt').read_text(), 'valuable')

    def test_utf16_units_count_non_bmp_characters(self):
        self.assertEqual(longpaths.path_units('A😀'), 3)
