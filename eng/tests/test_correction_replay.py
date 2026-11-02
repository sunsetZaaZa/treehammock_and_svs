"""Local tooling evidence is separate from real server/native qualification."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReplayToolingTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('texlua'), 'Optional local Lua interpreter absent')
    def test_shipped_replay_scripts_boundary_logic_with_explicit_nonserver_shim(self):
        result = subprocess.run(['texlua', str(ROOT / 'eng/tests/replay-script-boundaries.lua'), str(ROOT)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count('Passed:'), 4)
