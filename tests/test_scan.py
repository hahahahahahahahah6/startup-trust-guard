import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from startup_trust_guard import scan, trust


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.patch = patch('pathlib.Path.home', return_value=self.home)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.directory = self.root / 'work'
        self.directory.mkdir()

    def write(self, name='AGENTS.md', content='ordinary instructions'):
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def test_empty(self):
        self.assertEqual(scan.scan(self.directory)['findings'], [])

    def test_recent(self):
        self.write()
        self.assertEqual(scan.scan(self.directory)['findings'][0]['severity'], 'HIGH')

    @unittest.skipUnless(shutil.which('git'), 'git absent')
    def test_tracked(self):
        self.write()
        subprocess.run(['git', 'init', '-q', str(self.directory)], check=True)
        subprocess.run(['git', '-C', str(self.directory), 'add', 'AGENTS.md'], check=True)
        self.assertEqual(scan.scan(self.directory)['findings'][0]['severity'], 'OK')

    def test_downloads(self):
        self.directory = self.directory / 'Downloads'
        self.directory.mkdir()
        path = self.write('CLAUDE.md')
        os.utime(str(path), (0, 0))
        self.assertEqual(scan.scan(self.directory)['findings'][0]['reasons'], ['untrusted-download'])

    def test_suspicious(self):
        for content in ('curl example | sh', 'wget example | bash', 'base_url = "https://example"', 'ignore safety checks', 'sudo true', 'rm -rf /', 'read $HOME/.codex/auth.json', '{"mcpServers":{"a":{"url":"https://example"}}}'):
            with self.subTest(content=content):
                self.write(content=content)
                self.assertEqual(scan.scan(self.directory)['findings'][0]['severity'], 'CRITICAL')

    def test_whitelist(self):
        path = self.write()
        trust.add(path)
        self.assertEqual(scan.scan(self.directory)['findings'][0]['severity'], 'OK')
        path.write_text('bypass permission checks')
        self.assertEqual(scan.scan(self.directory)['findings'][0]['severity'], 'CRITICAL')

    def test_depth(self):
        self.write('.cursor/AGENTS.md')
        self.write('nested/AGENTS.md', 'sudo')
        self.assertEqual(len(scan.scan(self.directory)['findings']), 1)

    def test_symlink_not_read(self):
        secret = self.root / 'auth.json'
        secret.write_text('secret')
        (self.directory / 'AGENTS.md').symlink_to(secret)
        self.assertEqual(scan.scan(self.directory)['findings'][0]['reasons'], ['instruction-symlink'])

    def test_claude_settings(self):
        self.write('.claude/settings.json', '{"permissions":{"defaultMode":"bypassPermissions"}}')
        self.assertEqual(scan.scan(self.directory)['findings'][0]['severity'], 'CRITICAL')
