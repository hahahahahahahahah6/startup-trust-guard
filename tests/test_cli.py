import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from startup_trust_guard.cli import main


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        p = patch('pathlib.Path.home', return_value=self.root)
        p.start()
        self.addCleanup(p.stop)

    def run_cli(self, args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(args)
        return code, output.getvalue()

    def test_codes_json(self):
        code, output = self.run_cli(['check', str(self.root), '--json'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['findings'], [])
        (self.root / 'AGENTS.md').write_text('ordinary')
        code, output = self.run_cli(['check', str(self.root), '--json'])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output)['findings'][0]['severity'], 'HIGH')
        self.assertEqual(self.run_cli(['check', str(self.root / 'missing')])[0], 2)

    def test_missing_config(self):
        code, output = self.run_cli(['config-check'])
        self.assertEqual(code, 0)
        self.assertIn('no config files found', output)

    def test_trust_commands(self):
        path = self.root / 'AGENTS.md'
        path.write_text('ordinary')
        self.assertEqual(self.run_cli(['trust', 'add', str(path)])[0], 0)
        self.assertIn(str(path), self.run_cli(['trust', 'list'])[1])
        self.assertEqual(self.run_cli(['check', str(self.root)])[0], 0)

    def test_baseline(self):
        self.assertEqual(self.run_cli(['baseline', 'save'])[0], 0)
        self.assertEqual(json.loads(self.run_cli(['baseline', 'show'])[1]), {})
        custom = self.root / 'custom.json'
        self.assertEqual(self.run_cli(['baseline', 'save', '--out', str(custom)])[0], 0)
        self.assertTrue(custom.is_file())

    def test_invalid_trust(self):
        path = self.root / '.config/startup-trust-guard/trusted.json'
        path.parent.mkdir(parents=True)
        path.write_text('{}')
        self.assertEqual(self.run_cli(['check', str(self.root)])[0], 2)

    def test_usage(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main(['unknown'])
        self.assertEqual(caught.exception.code, 2)
