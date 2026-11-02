"""Tooling checks; Lua shim results never qualify a real cache server or C# adapter."""
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('counter_contracts', ROOT / 'eng/validate-counter-contracts.py')
contracts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contracts)


class CounterToolingTests(unittest.TestCase):
    def test_resp_decoder_preserves_array_integers_and_null(self):
        client = contracts.Client.__new__(contracts.Client)
        client.stream = io.BytesIO(b'*3\r\n:1\r\n:900000\r\n$-1\r\n')
        self.assertEqual(client.read(), [1, 900000, None])

    def test_resp_decoder_rejects_truncation_and_unbounded_array(self):
        for wire in (b'$6\r\nhello', b'*101\r\n', b'garbage'):
            client = contracts.Client.__new__(contracts.Client)
            client.stream = io.BytesIO(wire)
            with self.assertRaises((ValueError, ConnectionError)):
                client.read()

    def test_resp_errors_do_not_become_success(self):
        client = contracts.Client.__new__(contracts.Client)
        client.stream = io.BytesIO(b'-WRONGTYPE incompatible legacy key\r\n')
        with self.assertRaises(contracts.RedisError):
            client.read()

    @unittest.skipUnless(shutil.which('texlua'), 'Optional local Lua syntax/boundary interpreter absent')
    def test_shipped_lua_boundary_contracts_with_explicit_nonserver_shim(self):
        result = subprocess.run(['texlua', str(ROOT / 'eng/tests/counter-script-boundaries.lua'), str(ROOT)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count('Passed:'), 4)
