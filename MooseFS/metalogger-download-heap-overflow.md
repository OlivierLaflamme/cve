# matomlserv: Pre-auth heap buffer overflow in matomlserv_download_request() via integer wrap

**Reporter**: Olivier Laflamme
**Pwno ID**: `PWNO-0047-M`
**Pwno index date**: 2026-05-15
**Pwno status**: Indexed at [bugs.pwno.io/diff](https://bugs.pwno.io/diff); public entry currently redacted

**Component**: mfsmaster (matomlserv.c)
**Severity**: Critical (pre-auth, heap overflow, single packet after DOWNLOAD_START)
**Tested against**: MooseFS commit `83142d5` (2026-04-08)
**Fixed in**: [`1274d1f`](https://github.com/moosefs/moosefs/commit/1274d1f) ("fixed some security issues")

---

The metalogger download handler computes a response packet size using `16 + leng` in `uint32_t` arithmetic, where `leng` is read directly from the network with no upper bound. Sending `leng = 0xFFFFFFF0` wraps the addition to zero, and `matomlserv_create_packet` allocates a 28-byte buffer (8 bytes of framing overhead + the wrapped payload size of 0). The subsequent `pread()` writes the contents of the metadata file — typically several kilobytes — into this undersized buffer, overflowing adjacent heap memory.

The attack requires two packets to the metalogger port (9419) and zero authentication. Both `ANTOMA_DOWNLOAD_START` and `ANTOMA_DOWNLOAD_REQUEST` are dispatched in `matomlserv_gotpacket` at line 782 without any registration or authentication check.

## Vulnerable code

In `mfsmaster/matomlserv.c`, `matomlserv_download_request` at line 659. The attacker first sends `ANTOMA_DOWNLOAD_START` to open the metadata file, then `ANTOMA_DOWNLOAD_REQUEST` with the crafted length:

```c
// matomlserv.c:676-682
offset = get64bit(&data);
leng = get32bit(&data);                                               // attacker-controlled
ptr = matomlserv_create_packet(eptr, MATOAN_DOWNLOAD_DATA, 16+leng);  // 16 + 0xFFFFFFF0 = 0
put64bit(&ptr, offset);                                               // writes past 28-byte buffer
put32bit(&ptr, leng);
put32bit(&ptr, 0);                                                    // crc placeholder
ret = pread(eptr->upload_meta_fd, ptr+4, leng, offset);              // writes filesize bytes
```

`matomlserv_create_packet` adds 8 bytes of framing overhead to the wrapped payload size of 0, calling `malloc(28)`. The `put64bit` at line 679 writes 8 bytes at offset 0 of the data section — exactly at the end of the 28-byte allocation — triggering the overflow immediately. The `pread` then writes the entire metadata file (often megabytes) into the same undersized buffer.

The error check comparing `pread`'s return against `leng` fires *after* the overflow. Setting `eptr->mode = KILL` does not undo the heap corruption.

## ASan output

```
=================================================================
==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xffffb4603ddc
    at pc 0xaaaadb8ceccc bp 0xffffef9dc0e0 sp 0xffffef9dc0d0
WRITE of size 8 at 0xffffb4603ddc thread T0
    #0 0xaaaadb8cecc8 in memcpy /usr/include/aarch64-linux-gnu/bits/string_fortified.h:29
    #1 0xaaaadb8cecc8 in put64bit ../mfscommon/datapack.h:49
    #2 0xaaaadb8cecc8 in matomlserv_download_request /build/moosefs/mfsmaster/matomlserv.c:679
    #3 0xaaaadb8cf210 in matomlserv_gotpacket /build/moosefs/mfsmaster/matomlserv.c:782
    #4 0xaaaadb8cfd54 in matomlserv_parse /build/moosefs/mfsmaster/matomlserv.c:916
    #5 0xaaaadb8d0d68 in matomlserv_serve /build/moosefs/mfsmaster/matomlserv.c:1150
    #6 0xaaaadb8db7e0 in mainloop ../mfscommon/main.c:682
    #7 0xaaaadb8dfdc0 in main ../mfscommon/main.c:1806
    #8 0xffffb78773fc in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #9 0xffffb78774d4 in __libc_start_main_impl ../csu/libc-start.c:392
    #10 0xaaaadb77c76c in _start (/usr/sbin/mfsmaster+0x4c76c)

0xffffb4603ddc is located 0 bytes to the right of 28-byte region [0xffffb4603dc0,0xffffb4603ddc)
allocated by thread T0 here:
    #0 0xffffb7aaf418 in __interceptor_malloc asan_malloc_linux.cpp:145
    #1 0xaaaadb8cc3b0 in matomlserv_create_packet /build/moosefs/mfsmaster/matomlserv.c:263
    #2 0xaaaadb8cead0 in matomlserv_download_request /build/moosefs/mfsmaster/matomlserv.c:678
    #3 0xaaaadb8cf210 in matomlserv_gotpacket /build/moosefs/mfsmaster/matomlserv.c:782
    #4 0xaaaadb8cfd54 in matomlserv_parse /build/moosefs/mfsmaster/matomlserv.c:916
    #5 0xaaaadb8d0d68 in matomlserv_serve /build/moosefs/mfsmaster/matomlserv.c:1150
    #6 0xaaaadb8db7e0 in mainloop ../mfscommon/main.c:682
    #7 0xaaaadb8dfdc0 in main ../mfscommon/main.c:1806
    #8 0xffffb78773fc in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #9 0xffffb78774d4 in __libc_start_main_impl ../csu/libc-start.c:392
    #10 0xaaaadb77c76c in _start (/usr/sbin/mfsmaster+0x4c76c)

SUMMARY: AddressSanitizer: heap-buffer-overflow /usr/include/aarch64-linux-gnu/bits/string_fortified.h:29 in memcpy
Shadow bytes around the buggy address:
  0x200ff68c0760: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x200ff68c0770: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x200ff68c0780: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x200ff68c0790: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x200ff68c07a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x200ff68c07b0: fa fa fa fa fa fa fa fa 00 00 00[04]fa fa 00 00
  0x200ff68c07c0: 00 04 fa fa fd fd fd fa fa fa fd fd fd fd fa fa
  0x200ff68c07d0: fd fd fd fa fa fa fd fd fd fd fa fa fd fd fd fa
  0x200ff68c07e0: fa fa fd fd fd fd fa fa fd fd fd fa fa fa fd fd
  0x200ff68c07f0: fd fd fa fa fd fd fd fa fa fa fd fd fd fd fa fa
  0x200ff68c0800: fd fd fd fa fa fa fd fd fd fd fa fa fd fd fd fa
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
  Shadow gap:              cc
==7==ABORTING
```

The shadow byte `[04]` at the crash address marks the end of the 28-byte allocation (28 = 3×8 + 4, so the last shadow byte is `04`). The surrounding `fa` bytes are heap redzones. The `fd` bytes below are freed heap regions from prior allocations.

## Patch

```diff
+#define ML_META_DL_BLOCK ((((MATOAN_MAXPACKETSIZE) - 1000) < 1000000) ? ((MATOAN_MAXPACKETSIZE) - 1000) : 1000000)

 void matomlserv_download_request(...) {
     // ...
     offset = get64bit(&data);
     leng = get32bit(&data);
+    if (leng>ML_META_DL_BLOCK) {
+        mfs_log(MFSLOG_SYSLOG,MFSLOG_WARNING,"ANTOMA_DOWNLOAD_REQUEST - bad length");
+        eptr->mode = KILL;
+        return;
+    }
     ptr = matomlserv_create_packet(eptr,MATOAN_DOWNLOAD_DATA,16+leng);
```

Caps `leng` to roughly 1 MB, ensuring `16 + leng` cannot overflow a `uint32_t`.

## Disclosure timeline

- **2026-04-08** Reported to maintainer
- **2026-04-23** Fixed in MooseFS 4.59.0 (commit `1274d1f`)
