# matoclserv: Pre-auth heap OOB read in matoclserv_syslog() via length check

**Reporter**: Olivier Laflamme
**Pwno ID**: `PWNO-0052-M`
**Pwno index date**: 2026-05-15
**Pwno status**: Indexed at [bugs.pwno.io/diff](https://bugs.pwno.io/diff); public entry currently redacted

**Component**: mfsmaster (matoclserv.c, matomlserv.c, matocsserv.c)
**Severity**: Medium (pre-auth, heap OOB read on all three master ports)
**Tested against**: MooseFS commit `83142d5` (2026-04-08)
**Fixed in**: [`1274d1f`](https://github.com/moosefs/moosefs/commit/1274d1f) ("fixed some security issues")

---

The syslog message handlers in MooseFS master validate minimum packet length as 3 bytes but then proceed to read 7 bytes (1 + 4 + 2) from the packet data. A packet with `length=3` passes the check but causes `get32bit` and `get16bit` to read 4 bytes beyond the allocated heap buffer. The handler is reachable without authentication on all three master ports:

- Port 9419 — `matomlserv_syslog` (line 415)
- Port 9420 — `matocsserv_syslog` (line 2526)
- Port 9421 — `matoclserv_syslog` (line 1112)

## Vulnerable code

The pattern is identical across all three. From `matoclserv.c:1112`:

```c
// matoclserv.c:1116-1124
if (length<3) {                      // BUG: header is actually 7 bytes
    // ... kill ...
}
priority = get8bit(&data);           // 1 byte  — OK (byte 0)
timestamp = get32bit(&data);         // 4 bytes — OOB read at bytes 3-4
msgsize = get16bit(&data);           // 2 bytes — OOB read at bytes 5-6
if (length!=3U+msgsize) {            // BUG: should be 7U+msgsize
```

The packet header is `priority` (1B) + `timestamp` (4B) + `msgsize` (2B) = 7 bytes. The check requires only 3. A 3-byte packet passes validation; the `get32bit` and `get16bit` calls then read up to 4 bytes past the end of the 19-byte heap allocation (16 bytes of internal packet framing + 3 bytes of payload).

## ASan output

```
=================================================================
READ of size 2 at 0xffff7ba026c5 thread T0
    #0 0xaaaadcbb9ea8 in matoclserv_syslog /build/moosefs/mfsmaster/matoclserv.c:1118
    #1 0xaaaadcbe8d7c in matoclserv_gotpacket /build/moosefs/mfsmaster/matoclserv.c:6467
    #2 0xaaaadcbea19c in matoclserv_parse /build/moosefs/mfsmaster/matoclserv.c:6985
    #3 0xaaaadcbeb1a8 in matoclserv_serve /build/moosefs/mfsmaster/matoclserv.c:7229
    #4 0xaaaadcbfb7e0 in mainloop ../mfscommon/main.c:682
    #5 0xaaaadcbffdc0 in main ../mfscommon/main.c:1806
    #6 0xffff7ec773fc in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #7 0xffff7ec774d4 in __libc_start_main_impl ../csu/libc-start.c:392
    #8 0xaaaadca9c76c in _start (/usr/sbin/mfsmaster+0x4c76c)

0xffff7ba026c5 is located 2 bytes to the right of 19-byte region [0xffff7ba026b0,0xffff7ba026c3)
allocated by thread T0 here:
    #0 0xffff7eeaf418 in __interceptor_malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:145
    #1 0xaaaadcbe9a48 in matoclserv_read /build/moosefs/mfsmaster/matoclserv.c:6941
    #2 0xaaaadcbeb188 in matoclserv_serve /build/moosefs/mfsmaster/matoclserv.c:7223
    #3 0xaaaadcbfb7e0 in mainloop ../mfscommon/main.c:682
    #4 0xaaaadcbffdc0 in main ../mfscommon/main.c:1806
    #5 0xffff7ec773fc in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #6 0xffff7ec774d4 in __libc_start_main_impl ../csu/libc-start.c:392
    #7 0xaaaadca9c76c in _start (/usr/sbin/mfsmaster+0x4c76c)

SUMMARY: AddressSanitizer: heap-buffer-overflow /build/moosefs/mfsmaster/matoclserv.c:1118 in matoclserv_syslog
Shadow bytes around the buggy address:
  0x200fef740480: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x200fef740490: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x200fef7404a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x200fef7404b0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x200fef7404c0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x200fef7404d0: fa fa fa fa fa fa 00 00[03]fa fa fa fd fd fd fd
  0x200fef7404e0: fa fa fd fd fd fa fa fa fd fd fd fa fa fa fd fd
  0x200fef7404f0: fd fa fa fa fd fd fd fa fa fa 00 00 02 fa fa fa
  0x200fef740500: 00 00 00 05 fa fa 00 00 06 fa fa fa 00 00 00 fa
  0x200fef740510: fa fa 00 00 01 fa fa fa 00 00 00 fa fa fa 00 00
  0x200fef740520: 02 fa fa fa 00 00 00 fa fa fa 00 00 00 07 fa fa
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
```

The `[03]` shadow byte at the crash address marks the end of the 19-byte allocation (19 = 2×8 + 3). The `get16bit` reads 2 bytes starting at offset 5 in a 3-byte payload — landing squarely in the heap redzone.

## Patch

Two changes applied to all three instances:

```diff
-if (length<3) {
+if (length<7) {
     mfs_log(MFSLOG_SYSLOG,MFSLOG_WARNING,"ANTOMA_SYSLOG - wrong size");
     eptr->mode = KILL;
     return;
 }
 priority = get8bit(&data);
 timestamp = get32bit(&data);
 msgsize = get16bit(&data);
-if (length!=3U+msgsize) {
+if (length!=7U+msgsize) {
```

Additionally, `ANTOMA_SYSLOG` is removed from the `NOTREGISTERED` dispatch block on port 9421.

## Disclosure timeline

- **2026-04-08** Reported to maintainer
- **2026-04-23** Fixed in MooseFS 4.59.0 (commit `1274d1f`)
