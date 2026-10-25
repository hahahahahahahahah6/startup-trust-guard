import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from startup_trust_guard import cli, configcheck, trust


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        p = patch('pathlib.Path.home', return_value=self.home)
        p.start()
        self.addCleanup(p.stop)
        self.path = self.home / '.codex/config.toml'
        self.path.parent.mkdir()

    def test_missing(self):
        result, unused = configcheck.check()
        self.assertEqual(result['message'], 'no config files found')
        self.assertEqual(result['findings'], [])

    def test_added(self):
        configcheck.save()
        self.path.write_text('[mcp_servers.example]\nurl="https://example.org"\n')
        result, unused = configcheck.check()
        self.assertTrue(any(f['severity'] == 'CRITICAL' and 'ADDED' in str(f['reasons']) for f in result['findings']))

    def test_changed_removed(self):
        self.path.write_text('base_url="https://one.example"\n[mcp_servers.a]\ncommand="tool"\n')
        configcheck.save()
        self.path.write_text('base_url="https://two.example"\n')
        result, unused = configcheck.check()
        reasons = str(result['findings'])
        self.assertIn('CHANGED', reasons)
        self.assertIn('REMOVED', reasons)

    def test_redaction(self):
        token = 'secretTokenValue01234567890123456789'
        self.path.write_text('base_url="https://example.org/?token=' + token + '"\napi_key="' + token + '"\n')
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(cli.main(['config-check']), 1)
        self.assertNotIn(token, buffer.getvalue())
        configcheck.save()
        self.assertNotIn(token, trust.state_path('baseline.json').read_text())
        self.assertEqual(configcheck.redact('key=' + token), 'key=<redacted>')

    def test_disabled_approvals(self):
        self.path.write_text('approval_policy="never"\n')
        result, unused = configcheck.check()
        self.assertIn('approvals-disabled', str(result))

    def test_fallback(self):
        data = configcheck.parse_toml('approval_policy = "never" # comment\n[mcp_servers."demo-server"]\nargs=["a", "b"]\n')
        self.assertEqual(data['mcp_servers']['demo-server']['args'], ['a', 'b'])

    def test_invalid_config(self):
        self.path.write_text('invalid!')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['config-check']), 2)

    def test_fallback_full_toml(self):
        text = "[mcp_servers.demo]\nargs = [\n 'one', # comment\n 'two',\n]\nenv = { X = 'value' }\n"
        data = configcheck.parse_toml(text)
        self.assertEqual(data['mcp_servers']['demo']['args'], ['one', 'two'])
        self.assertEqual(data['mcp_servers']['demo']['env'], {'X': 'value'})

    def test_no_change_baseline(self):
        self.path.write_text('base_url="https://example.org"\n')
        configcheck.save()
        result, unused = configcheck.check()
        self.assertFalse(any(f['severity'] == 'CRITICAL' for f in result['findings']))

    def test_claude_environment_and_permissions(self):
        path = self.home / '.claude/settings.json'
        path.parent.mkdir()
        path.write_text(json.dumps({'env': {'ANTHROPIC_BASE_URL': 'https://example.org'},
                                    'permissions': {'defaultMode': 'bypassPermissions'}}))
        result, unused = configcheck.check()
        self.assertIn('url-override', str(result))
        self.assertIn('approvals-disabled', str(result))
