#!/usr/bin/env python3
"""Execute shipped COR06 scripts on an owned REAL Redis/Dragonfly listener."""
import concurrent.futures
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('counter_contracts', ROOT / 'eng/validate-counter-contracts.py')
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)
Client, RedisError = cache.Client, cache.RedisError
SCRIPTS = {name: (ROOT / f'Rigging/Replay/Scripts/{name}-v2.lua').read_text() for name in ('reserve', 'complete', 'renew')}


def run(client, action, key, owner='a', generation='a', request='request', operation='operation', ttl=3000, result=None):
    arguments = [owner, generation, request, operation, ttl]
    if result is not None:
        arguments.append(result)
    return client.call('EVAL', SCRIPTS[action], 1, key, *arguments)


def run_contracts():
    cases = []
    key = 'cor06:owned:{' + uuid.uuid4().hex + '}'
    sentinel = 'cor06:unrelated:' + uuid.uuid4().hex
    with Client() as client:
        try:
            client.call('SET', sentinel, 'keep', 'PX', 60000)
            assert run(client, 'reserve', key, ttl=40) == 1
            cache.eventually(lambda: client.call('EXISTS', key) == 0)
            assert run(client, 'reserve', key, owner='b', generation='b') == 1
            assert run(client, 'complete', key, result='late-a') == 0
            assert run(client, 'renew', key) == 0
            assert client.call('HGET', key, 'owner') == 'b'
            assert run(client, 'renew', key, owner='b', generation='b') == 1
            assert run(client, 'complete', key, owner='b', generation='b', result='original-b') == 1
            assert run(client, 'complete', key, owner='b', generation='b', result='overwrite') == 0
            assert client.call('HGET', key, 'result') == 'original-b'
            assert run(client, 'reserve', key) == 2
            cases.append('expired_owner_late_completion_and_renewal_are_fenced')

            client.call('DEL', key)
            def reserve_one(index):
                with Client() as contender:
                    return run(contender, 'reserve', key, owner=str(index), generation=str(index))
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                results = list(pool.map(reserve_one, range(32)))
            assert results.count(1) == 1 and results.count(0) == 31
            assert 0 <= client.call('PTTL', key) <= 3000
            assert run(client, 'reserve', key, request='changed') == -1
            assert run(client, 'reserve', key, operation='changed') == -1
            assert run(client, 'renew', key, owner=client.call('HGET', key, 'owner'), generation='wrong') == 0
            cases.append('concurrent_reservation_and_content_operation_generation_conflicts')

            client.call('DEL', key)
            for ttl in (0, 900001, 1.5):
                try:
                    run(client, 'reserve', key, ttl=ttl)
                    raise AssertionError('Invalid lease was accepted')
                except RedisError:
                    assert client.call('EXISTS', key) == 0
            client.call('SET', key, 'wrong-type', 'PX', 3000)
            try:
                run(client, 'reserve', key)
                raise AssertionError('Wrong type was accepted')
            except RedisError:
                assert client.call('GET', key) == 'wrong-type'
            cases.append('invalid_duration_and_wrong_type_fail_before_mutation')

            client.call('DEL', key)
            child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--lose-reply', key],
                                     stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                # Independently observe the write before killing a client which has not read
                # the reply. This is a cache client process fault, not an ASP.NET host crash.
                cache.eventually(lambda: client.call('HGET', key, 'owner') == 'lost-client')
                child.terminate(); child.communicate(timeout=3)
                assert run(client, 'reserve', key, owner='replacement', generation='replacement') == 0
                assert 0 <= client.call('PTTL', key) <= 3000
                assert client.call('GET', sentinel) == 'keep'
                cases.append('client_loss_after_observed_write_retains_finite_lease_and_unrelated_key')
            finally:
                if child.poll() is None:
                    child.kill(); child.communicate(timeout=3)
        finally:
            client.call('DEL', key, sentinel)
    return cases


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--lose-reply':
        with Client() as client:
            client.socket.sendall(cache.encode(['EVAL', SCRIPTS['reserve'], 1, sys.argv[2], 'lost-client', 'lost-generation', 'request', 'operation', 3000]))
            sys.stdin.readline()  # Intentionally never read the Redis acknowledgment.
    else:
        print(json.dumps(dict(status='Passed', cases=run_contracts()), indent=2))
