#!/usr/bin/env python3
"""Execute the shipped Lua against a REAL owned Redis/Dragonfly listener. No cache emulator."""
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import select
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
INCREMENT = (ROOT / 'Rigging/Abuse/Scripts/increment-v1.lua').read_text()
COOLDOWN = (ROOT / 'Rigging/Abuse/Scripts/cooldown-v1.lua').read_text()


def encode(arguments):
    values = [str(value).encode() for value in arguments]
    return b'*%d\r\n' % len(values) + b''.join(b'$%d\r\n' % len(value) + value + b'\r\n' for value in values)


class RedisError(Exception):
    pass


class Client:
    def __init__(self):
        host, port = os.environ['TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT'].rsplit(':', 1)
        if host != '127.0.0.1':
            raise ValueError('Counter qualification requires the owned loopback fixture')
        self.socket = socket.create_connection((host, int(port)), timeout=2)
        self.stream = self.socket.makefile('rb')
        try:
            self.call('AUTH', os.environ['TREEHAMMOCK_CORRECTION_CACHE_PASSWORD'])
        except Exception:
            self.stream.close()
            self.socket.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()
        self.socket.close()

    def read(self):
        line = self.stream.readline(1_000_001)
        if not line.endswith(b'\r\n'):
            raise ConnectionError('Incomplete RESP reply')
        prefix, value = line[:1], line[1:-2]
        if prefix == b'-':
            raise RedisError(value.decode())
        if prefix == b'+':
            return value.decode()
        if prefix == b':':
            return int(value)
        if prefix == b'$':
            length = int(value)
            if length == -1:
                return None
            if not 0 <= length <= 1_000_000:
                raise ValueError('Unbounded RESP bulk value')
            data = self.stream.read(length + 2)
            if len(data) != length + 2 or not data.endswith(b'\r\n'):
                raise ConnectionError('Incomplete RESP bulk value')
            return data[:-2].decode()
        if prefix == b'*':
            length = int(value)
            if not 0 <= length <= 100:
                raise ValueError('Unbounded RESP array')
            return [self.read() for _ in range(length)]
        raise ValueError('Unexpected RESP type')

    def call(self, *arguments):
        self.socket.sendall(encode(arguments))
        return self.read()


def eventually(predicate, seconds=3):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('Real server state did not converge before deadline')


def increment(client, keys, maximum=5, window=1000, cooldown=0):
    return client.call('EVAL', INCREMENT, 2, *keys, maximum, window, cooldown, 'failure_cooldown_active')


def key_pair():
    identifier = uuid.uuid4().hex
    return ['abuse:twofactorchallenge:challenge:' + identifier,
            'abuse:cooldown:twofactorchallenge:challenge:' + identifier]


def run_contracts():
    cases = []
    with Client() as client:
        keys = key_pair()
        sentinel = 'cor05:unrelated:' + uuid.uuid4().hex
        try:
            client.call('SET', sentinel, 'keep', 'PX', 60000)
            client.call('SET', keys[0], 9)  # Legacy immortal count ABOVE one/threshold.
            assert increment(client, keys, window=300) == [0, 10, 300, 2, 0]
            assert 0 <= client.call('PTTL', keys[0]) <= 300
            first_ttl = client.call('PTTL', keys[0])
            time.sleep(.03)
            assert increment(client, keys, window=300)[0] == 0
            assert 0 <= client.call('PTTL', keys[0]) < first_ttl
            eventually(lambda: client.call('EXISTS', keys[0]) == 0)
            assert increment(client, keys, window=300)[0:2] == [1, 1]
            cases.append('legacy_immortal_repair_fixed_window_and_eventual_admission')

            client.call('DEL', *keys)
            for count in range(1, 6):
                assert increment(client, keys, cooldown=300)[0:2] == [1, count]
            assert increment(client, keys, cooldown=300) == [0, 6, 300, 2, 1]
            before = client.call('PTTL', keys[1])
            time.sleep(.03)
            active = increment(client, keys, cooldown=300)
            assert active[0:2] == [0, 6] and active[3:] == [1, 0]
            assert 0 < active[2] < before
            assert client.call('GET', keys[0]) == '6'
            cases.append('exact_limit_and_cooldown_not_extended_or_incremented')

            client.call('DEL', *keys)
            client.call('SET', keys[0], 8)
            client.call('SET', keys[1], 'legacy')
            assert increment(client, keys, window=300, cooldown=0)[3] == 1
            assert 0 <= client.call('PTTL', keys[0]) <= 300
            assert 0 <= client.call('PTTL', keys[1]) <= 300
            eventually(lambda: client.call('EXISTS', keys[1]) == 0)
            assert increment(client, keys, window=300)[0] == 1
            client.call('SET', keys[1], 'legacy')
            assert client.call('EVAL', COOLDOWN, 1, keys[1], 200) == 200
            eventually(lambda: client.call('EXISTS', keys[1]) == 0)
            assert client.call('EVAL', COOLDOWN, 1, keys[1], 200) == 0
            cases.append('immortal_cooldown_repaired_in_admission_and_lookup_zero_new_cooldown')

            client.call('DEL', *keys)
            def attempt(_):
                with Client() as concurrent:
                    return increment(concurrent, keys, maximum=16, window=10000)
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                results = list(pool.map(attempt, range(32)))
            assert sum(result[0] for result in results) == 16
            assert sorted(result[1] for result in results) == list(range(1, 33))
            assert client.call('GET', keys[0]) == '32'
            assert 0 < client.call('PTTL', keys[0]) <= 10000
            assert client.call('EXISTS', keys[1]) == 0
            cases.append('concurrent_first_increments_one_counter_window_zero_cooldown')

            client.call('DEL', *keys)
            client.call('SET', keys[0], '9223372036854775807')
            assert increment(client, keys, window=300)[1] == 2147483647
            assert client.call('PTTL', keys[0]) >= 0
            client.call('DEL', *keys)
            client.call('SET', keys[0], 7)
            client.call('LPUSH', keys[1], 'wrong-type')
            try:
                increment(client, keys)
                raise AssertionError('Wrong-type key was admitted')
            except RedisError:
                pass
            assert client.call('GET', keys[0]) == '7'
            assert client.call('PTTL', keys[0]) == -1  # Error happened before ANY write.
            client.call('DEL', *keys)
            client.call('SET', keys[0], 'not-numeric')
            try:
                increment(client, keys)
                raise AssertionError('Malformed numeric counter was admitted')
            except RedisError:
                pass
            assert client.call('GET', keys[0]) == 'not-numeric'
            assert client.call('PTTL', keys[0]) == -1
            assert client.call('EXISTS', keys[1]) == 0
            client.call('DEL', *keys)
            cases.append('saturation_and_wrong_type_preflight_no_partial_write')

            # Kill a real client PROCESS before send, then after actual server mutation,
            # while it has not read the EVAL acknowledgment. Observe server state independently.
            for phase in ('before', 'after'):
                client.call('SET', keys[0], 5)
                child = subprocess.Popen([sys.executable, __file__, '--interrupted-client', phase, json.dumps(keys)],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                try:
                    assert select.select([child.stdout], [], [], 5)[0], 'Interrupted client did not become ready'
                    assert child.stdout.readline().strip() == 'READY'
                    if phase == 'after':
                        eventually(lambda: client.call('GET', keys[0]) == '6')
                        assert 0 <= client.call('PTTL', keys[0]) <= 1000
                    child.kill()
                    child.wait(timeout=2)
                    decision = increment(client, keys, window=1000)
                    assert decision[0] == 0 and client.call('PTTL', keys[0]) >= 0
                    eventually(lambda: client.call('EXISTS', keys[0]) == 0)
                    assert increment(client, keys)[0:2] == [1, 1]
                    client.call('DEL', *keys)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=2)
                    child.stdin.close()
                    child.stdout.close()
            cases.append('client_process_loss_before_send_and_after_server_write_without_ack')
            client.call('DEL', *keys)
            assert client.call('GET', sentinel) == 'keep'
            cases.append('reset_and_cleanup_leave_unrelated_keys_intact')
        finally:
            client.call('DEL', *keys, sentinel)
    return cases


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--interrupted-client':
        with Client() as client:
            if sys.argv[2] == 'after':
                client.socket.sendall(encode(['EVAL', INCREMENT, 2, *json.loads(sys.argv[3]), 5, 1000, 0, 'failure_cooldown_active']))
            print('READY', flush=True)
            sys.stdin.readline()  # Parent kills us; never read EVAL acknowledgment.
        sys.exit(0)
    print(json.dumps({'status': 'Passed', 'cases': run_contracts()}))
