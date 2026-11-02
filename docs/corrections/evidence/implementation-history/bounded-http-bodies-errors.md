# COR23F — Bound encoded bodies and normalize HTTP errors

Owns R07-03 only; builds on completed COR23E. Implementation is FixedPendingQualification; native qualification is NotRun. No database/setup, SDK/package, data migration, backfill or compatibility layer changes.

## Current request contract

All application request bodies, including unmatched routes, pass through a bounded, eager validation boundary before security-operation canonicalization, authentication and MVC. Controllers carry immutable RequestBodyPolicyMetadata describing the same global limits; endpoint metadata cannot opt out. The previous lazy framework decompression middleware is removed. Empty unencoded requests avoid a body buffer/capacity reservation.

RequestBodySettings defaults are explicit in all eight shipped profiles. An omitted section uses these validated defaults, including existing isolated test hosts. Unknown settings and out-of-range values fail startup. RequestBodyPolicy snapshots validated IOptions once and shares a semaphore across requests; configuration reload cannot resize active reservations. Allowed configuration ranges never permit unlimited bytes, concurrency or time.

| Setting | Default | Allowed range | Boundary |
| --- | ---: | ---: | --- |
| EncodedBytes | 262144 (256 KiB) | 1–1048576 | Complete wire body, independent of Content-Length |
| DecodedBytes | 1048576 (1 MiB) | 1–4194304 | Expanded bytes supplied to canonicalization/MVC |
| ConcurrentRequests | 16 | 1–64 | Buffered bodies, held through downstream completion |
| ReadMilliseconds | 5000 | 100–30000 | Linked deadline for reading and decoding, distinct from caller cancellation |

At-limit bodies are accepted; a single probe byte determines over-limit bodies. Kestrel's transport limit is EncodedBytes + 1 even when explicit listeners are disabled, and a writable per-request transport feature is capped likewise. Known oversized lengths are rejected before a read. Lengthless/chunked bodies follow the same counting rule. An independently stricter, read-only transport/proxy limit remains authoritative; pre-pipeline HTTP framing errors are server errors outside this application's envelope/privacy boundary.

No Content-Encoding means identity bytes. A single case-insensitive gzip, deflate or br value is supported. Deflate is RFC 1950 zlib-wrapped DEFLATE, including Adler checksum. Gzip accepts a single complete member (including optional header fields/FHCRC), checks CRC32 and ISIZE, and rejects concatenated members/trailing bytes. Brotli requires terminal Done and consumption of the full frame. Explicit identity, an empty value and other encodings are unsupported; repeated headers or a comma-separated encoding stack are rejected. Clients must select one supported encoding and satisfy both byte budgets.

Raw DEFLATE/zlib input is fully buffered before decoding. A stream that throws InvalidDataException on exhausted codec input prevents truncated input from becoming a normal EOF on .NET 8. Bulk reads retain a 256-byte tail; terminal tail reads are one byte each, so a codec cannot consume trailing data merely through read-ahead. Exact consumed length and wrapper checks are required. Brotli uses the public incremental decoder with bounded output windows. Native .NET 8 verification of every proper prefix and complete frame is authored, not executed here.

## Error and operation contract

| Condition | HTTP | ApiResponse code |
| --- | ---: | --- |
| Encoded bytes exceed limit | 413 | REQUEST_ENCODED_BODY_TOO_LARGE |
| Decoded bytes exceed limit | 413 | REQUEST_DECODED_BODY_TOO_LARGE |
| Unsupported/empty encoding | 415 | REQUEST_CONTENT_ENCODING_UNSUPPORTED |
| Multiple encodings | 415 | REQUEST_CONTENT_ENCODING_MULTIPLE |
| Invalid, truncated, trailing or checksum-invalid supported frame | 400 | REQUEST_COMPRESSED_BODY_INVALID |
| Body read/decode deadline expires | 408 | REQUEST_BODY_TIMEOUT |
| Buffered-body capacity unavailable | 503 | REQUEST_BODY_CAPACITY_EXCEEDED (Retry-After: 2) |

These failures return the existing ApiResponse envelope: success=false, matching statusCode, declared code, null data/errors. They clear unsent response state and apply COR23E no-store/Pragma/Expires. Compression classification catches only InvalidDataException around the codec over our owned memory; network/disk I/O and unrelated downstream exceptions keep the sanitized fallback (unexpected 500 / INTERNAL_SERVER_ERROR, known HTTP request status / HTTP_REQUEST_FAILED). No body, credential, proof, path/query or raw exception message/object is logged by the boundary. Invalid JSON in a valid frame remains MVC's VALIDATION_FAILED contract. When multiple faults coexist, encoding-header policy precedes declared-length rejection, wire limits precede decoding, and a decoded over-limit probe takes precedence over subsequent trailer validation.

RequestAborted cancellation propagates without a fabricated success/envelope. It is checked before reading, before and after downstream work; the operation exception handler now propagates cancellation and started-response errors rather than silently returning. The independent body deadline never cancels the caller token. Permits, streams, request headers/length and body features are restored in finally, including failed reads, decoder errors and downstream failures. Started responses are never rewritten.

Only fully validated, rewindable decoded input reaches SecurityOperationMiddleware. Its canonical reader uses the validated decoded limit (the previous defensive 1 MiB default for direct callers), preserves stable JSON normalization and rewinds for MVC. The blanket IOException-to-size-error catch is removed. No operation admission or account write can run after a body rejection. Actual PostgreSQL refresh regressions snapshot both sessions and security_operations and require unchanged snapshots/generation after malformed, truncated and oversized requests; accepted compressed refresh rotates once through the existing real operation service/repositories.

## Resource policy and qualification

There is no body admission queue: a full semaphore immediately returns the declared 503. Each admitted nonempty body allocates at most EncodedBytes + 1 and DecodedBytes + 1 owned byte arrays; identity uses only the encoded array. At defaults, these two buffers have a host-wide upper bound of 20971552 bytes for 16 concurrent bodies. The read-only MemoryStream introduces no body buffering disk spill. This is an owned-buffer bound, not a total process/MVC/JSON/canonicalization/response memory claim. Empty requests and downstream resources retain their own COR22 budgets. Do not interpret source math as measured CPU, heap, disk or tail latency.

The owned Kestrel resource regression demonstrates capacity saturation, bounded immediate overload, permit recovery, then records 12 maximum-expanded, chunked Brotli requests at concurrency 2: CPU/wall time, allocations, working-set delta/peak and p95/p99. It reports the configured memory-only disk-spill policy separately. It is a local sample harness, not production capacity qualification. Native resource results and actual spill/resource profiling are NotRun; COR22 and COR24 qualification must supply CPU/memory/disk/p95/p99 results and enforce release budgets. Read deadlines cannot preempt a codec's synchronous native call, but input/output work and concurrency remain bounded; deployment latency must be measured.

## Validation and preserved administration

Authored native coverage runs the same body boundary and real MVC/canonicalization over TestServer and owned loopback Kestrel, plus actual Program routes. It includes all proper compressed prefixes, malformed data, complete frames, checksum/trailing/concatenated gzip rejection, exact wire/expanded thresholds with and without Content-Length, header policy, plain and compressed malformed JSON, unrelated I/O 500, configured controller metadata, read deadline, caller cancellation, original request restoration and permit cleanup. Owned TCP tests send a slow partial request and disconnect without executing the endpoint. Native SQL methods live in the already mandatory Cor09RefreshHttpTests harness selector; existing refresh hosts now use this body boundary.

Run the available checks and native harness after restoring prerequisites:

```bash
python3 -m unittest discover -s eng/tests -v
python3 eng/check-request-body-boundary.py
python3 eng/check-security-response-cache.py
python3 eng/check-correction-evidence.py
python3 eng/generate-database-baseline.py --check
python3 eng/cor23-reconciliation.py --check
python3 eng/correction-baseline.py --lane all --output .correction-results/cor23f-final
python3 eng/correction-sql-fixture.py
```

Supplemental Python mutation checks protect the source contract; they are not native protocol evidence. .NET SDK, PostgreSQL, Docker/cache and PowerShell are unavailable here. Native tests/performance remain Blocked/NotRun. R07-03 is FixedPendingQualification with appended history. Other 83 findings, the original 451-file inventory, frozen reviews and all 186 Open release gates are preserved; no finding or gate is Closed. Current totals: 58 FixedPendingQualification, 26 Open. Next ordered correction: COR23G.

Client limits and supported frame policy are the direct pre-1.0 contract. Rollback must retain bounded request handling and the shared no-store/error boundary; do not disable all body limits. There is no stored-data transition. Existing COR23E implementation evidence remains historical; coordinated runtime qualification of both boundaries is still required.
