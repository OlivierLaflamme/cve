# matoclserv: Integer overflow in matoclserv_fuse_setxattr() via avleng

**Reporter**: Olivier Laflamme
**Pwno ID**: `PWNO-0051-M`
**Pwno index date**: 2026-05-15
**Pwno status**: Indexed at [bugs.pwno.io/diff](https://bugs.pwno.io/diff); public entry currently redacted

**Component**: mfsmaster (matoclserv.c)
**Severity**: High (authenticated, single-packet DoS via OOB read)
**Tested against**: MooseFS commit `83142d5` (2026-04-08)
**Fixed in**: [`1274d1f`](https://github.com/moosefs/moosefs/commit/1274d1f) ("fixed some security issues")

---

The `CLTOMA_FUSE_SETXATTR` handler validates packet length with `23U + anleng + avleng`, where all operands are `uint32_t`. A client sends `avleng = 0xFFFFFFEA` to wrap the sum to a small value that matches a tiny packet. The check passes, and subsequent `get*bit` calls advance past the buffer into unmapped memory, crashing the master. Requires a FUSE session.

## Vulnerable code

In `mfsmaster/matoclserv.c`, `matoclserv_fuse_setxattr` at line 4729:

```c
// matoclserv.c:4766-4774
avleng = get32bit(&data);                    // attacker-controlled
if (length<23U+anleng+avleng) {              // line 4767: wraps for large avleng
    // ... KILL ...
}
attrvalue = data;
data += avleng;                              // advances pointer by 0xFFFFFFEA bytes
mode = get8bit(&data);                       // line 4774: reads from unmapped memory → SEGV
```

With `avleng = 0xFFFFFFEA` and `anleng = 0`:

```
23 + 0 + 0xFFFFFFEA = 0x100000001 → truncates to 0x1 (uint32_t)
```

A packet with `length >= 1` passes the check. The handler then uses `avleng` to advance the data pointer by ~4 GB, and the next `get8bit` reads from unmapped address space.

## ASan output

```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==7==ERROR: AddressSanitizer: SEGV on unknown address 0x201015c00072
    (pc 0xaaaae818a9f4 bp 0xffffeb4c22f0 sp 0xffffeb4c2240 T0)
==7==The signal is caused by a READ memory access.
    #0 0xaaaae818a9f4 in get8bit ../mfscommon/datapack.h:294
    #1 0xaaaae818a9f4 in matoclserv_fuse_setxattr /build/moosefs/mfsmaster/matoclserv.c:4774
    #2 0xaaaae819937c in matoclserv_gotpacket /build/moosefs/mfsmaster/matoclserv.c:6721
    #3 0xaaaae819a19c in matoclserv_parse /build/moosefs/mfsmaster/matoclserv.c:6985
    #4 0xaaaae819b1a8 in matoclserv_serve /build/moosefs/mfsmaster/matoclserv.c:7229
    #5 0xaaaae81ab7e0 in mainloop ../mfscommon/main.c:682
    #6 0xaaaae81afdc0 in main ../mfscommon/main.c:1806
    #7 0xffffb2c473fc in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #8 0xffffb2c474d4 in __libc_start_main_impl ../csu/libc-start.c:392
    #9 0xaaaae804c76c in _start (/usr/sbin/mfsmaster+0x4c76c)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV ../mfscommon/datapack.h:294 in get8bit
==7==ABORTING
```

ASan cannot provide shadow bytes because the access address (`0x201015c00072`) is far outside any mapped region — the data pointer was advanced by `avleng` (~4 GB) past the packet buffer.

## Patch

```diff
 avleng = get32bit(&data);
+if (avleng>MFS_XATTR_SIZE_MAX) {
+    mfs_log(MFSLOG_SYSLOG,MFSLOG_WARNING,"CLTOMA_FUSE_SETXATTR - xattr value too long");
+    eptr->mode = KILL;
+    return;
+}
 if (length<23U+anleng+avleng) {
```

`MFS_XATTR_SIZE_MAX` is 65536. With `avleng` capped to 64 KB, the addition `23 + anleng + avleng` cannot overflow a `uint32_t`.

## Disclosure timeline

- **2026-04-08** Reported to maintainer
- **2026-04-23** Fixed in MooseFS 4.59.0 (commit `1274d1f`)
