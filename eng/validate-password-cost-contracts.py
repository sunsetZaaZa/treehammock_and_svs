#!/usr/bin/env python3
"""Supplementary real libsodium ABI cost evidence; NOT Geralt/.NET qualification."""
import ctypes
import ctypes.util
import json
import platform
import resource
import time


def main():
    library = ctypes.util.find_library('sodium')
    if not library:
        print(json.dumps({'status': 'Blocked', 'reason': 'Installed libsodium unavailable', 'native_dotnet_qualification': 'Not run'}))
        return 2
    sodium = ctypes.CDLL(library)
    sodium.sodium_init.restype = ctypes.c_int
    if sodium.sodium_init() < 0:
        raise RuntimeError('libsodium startup failed')
    sodium.sodium_version_string.restype = ctypes.c_char_p
    sodium.crypto_pwhash_str_alg.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_ulonglong, ctypes.c_size_t, ctypes.c_int]
    sodium.crypto_pwhash_str_verify.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulonglong]
    cases = []
    for memory, expected_kib in [(67108864, 65536), (65536, 64)]:
        password = 'synthetic pa\u0308ssword'.encode('utf-8')
        output = ctypes.create_string_buffer(128)
        start = time.monotonic()
        assert sodium.crypto_pwhash_str_alg(output, password, len(password), 3, memory, 2) == 0
        elapsed = (time.monotonic() - start) * 1000
        phc = output.value.decode('ascii')
        assert phc.startswith(f'$argon2id$v=19$m={expected_kib},t=3,p=1$')
        assert sodium.crypto_pwhash_str_verify(output.value, password, len(password)) == 0
        wrong = 'synthetic pässword'.encode('utf-8')
        assert sodium.crypto_pwhash_str_verify(output.value, wrong, len(wrong)) == -1
        cases.append({'input_memory_bytes': memory, 'encoded_memory_KiB': expected_kib, 'iterations': 3, 'parallelism': 1,
                      'storage_buffer_bytes': len(output.raw), 'hash_ms_observed': elapsed, 'exact_utf8_verified': True,
                      'different_normalization_rejected': True})
    print(json.dumps({'status': 'Passed', 'evidence_kind': 'supplementary-installed-libsodium-ABI',
                      'library_version': sodium.sodium_version_string().decode(), 'platform': platform.platform(),
                      'cases': cases, 'max_rss_platform_units': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                      'native_dotnet_qualification': 'Not run; pinned Geralt 4.1.0/C# tests remain required',
                      'capacity_claim': 'None; two sequential synthetic hashes, not the application limiter/workload'}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
