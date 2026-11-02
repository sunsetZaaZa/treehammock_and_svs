#!/usr/bin/env python3
"""Run shipped COR14 nonce consumption Lua on the pinned, owned real cache matrix."""
import concurrent.futures
import importlib.util
import json
from pathlib import Path
import time
import uuid
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cor05', ROOT / 'eng/validate-counter-contracts.py')
cor05 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cor05)
SCRIPT = (ROOT / 'Rigging/Abuse/Scripts/captcha-consume-v1.lua').read_text()

def main():
    key = 'reset-captcha:qualification-' + uuid.uuid4().hex
    def consume():
        with cor05.Client() as c:
            return c.call('EVAL', SCRIPT, 1, key)
    with cor05.Client() as c:
        try:
            assert c.call('SET', key, 'issued', 'PX', 1000, 'NX') == 'OK'
            assert c.call('SET', key, 'issued', 'PX', 1000, 'NX') is None
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                outcomes = list(pool.map(lambda _: consume(), range(32)))
            assert outcomes.count(1) == 1 and outcomes.count(0) == 31
            assert c.call('GET', key) == 'consumed' and 0 < c.call('PTTL', key) <= 1000
            assert consume() == 0
            c.call('DEL', key)
            assert consume() == 0  # Eviction/missing cannot resurrect authority.
            c.call('SET', key, 'issued', 'PX', 30)
            deadline = time.monotonic() + 2
            while c.call('EXISTS', key):
                assert time.monotonic() < deadline
                time.sleep(.01)
            assert consume() == 0
            c.call('SET', key, 'issued')
            assert consume() == 0 and c.call('EXISTS', key) == 0
            print(json.dumps({'status': 'Passed', 'cases': ['single-winner', 'no-overwrite', 'ttl-preserved', 'replay', 'eviction', 'expiry', 'immortal-denial']}))
        finally:
            c.call('DEL', key)
if __name__ == '__main__': main()
