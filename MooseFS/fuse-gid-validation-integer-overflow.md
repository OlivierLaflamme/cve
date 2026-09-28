# matoclserv: Integer overflow in FUSE gids validation across 23 handlers

**Reporter**: Olivier Laflamme
**Pwno ID**: `PWNO-0054-M`
**Pwno index date**: 2026-05-15
**Pwno status**: Indexed at [bugs.pwno.io/diff](https://bugs.pwno.io/diff); public entry currently redacted

**Component**: mfsmaster (matoclserv.c)
**Severity**: Critical (authenticated, heap overflow on 32-bit / OOB read crash on 64-bit, 23 entry points)
**Tested against**: MooseFS commit `83142d5` (2026-04-08)
**Fixed in**: [`1274d1f`](https://github.com/moosefs/moosefs/commit/1274d1f) ("fixed some security issues")

---

Twenty-three FUSE request handlers in the master share an identical integer overflow: each validates packet length with `CONST + 4*gids` where `gids` is a `uint32_t` read from the network. The multiplication `4*gids` wraps in 32-bit arithmetic. With `gids = 0x40000001`, the product truncates to 4, the length check passes with a small packet, and the handler calls `matoclserv_gid_storage(gids)` requesting a buffer for 1,073,741,825 GIDs.

On 64-bit systems this is a ~4 GB allocation followed by an OOB read crash. On 32-bit systems the allocation itself wraps to 4 bytes, and the subsequent loop writes ~4 GB of attacker-controlled data into it — a heap overflow with RCE potential.

## Vulnerable code

The pattern, shown from the TRUNCATE handler at `matoclserv.c:2860`:

```c
// matoclserv.c:2856-2870
gids = get32bit(&data);
if (length != 25 + 4*gids) {     // 4 * 0x40000001 = 0x100000004 → truncates to 4 (uint32)
    // ... KILL ...               // 25 + 4 = 29 matches crafted packet → check passes
}
gid = matoclserv_gid_storage(gids);  // allocates for 0x40000001 GIDs
for (i=0 ; i<gids ; i++) {
    gid[i] = get32bit(&data);        // reads 1,073,741,825 times from 29-byte buffer
}
```

`matoclserv_gid_storage` at line 2361 allocates `sizeof(uint32_t) * gidleng` bytes. On 64-bit, this is ~4 GB (may succeed with overcommit). On 32-bit, `sizeof(uint32_t) * 0x40000001 = 0x100000004`, which wraps to `0x4` — a 4-byte buffer.

The same pattern exists at 23 locations: PATH_LOOKUP (2424), ACCESS (2519), LOOKUP (2581), SETATTR (2778), TRUNCATE (2860), SYMLINK (2953), MKNOD (3033), MKDIR (3110), UNLINK (3179), RMDIR (3243), RENAME (3321), LINK (3395), READDIR (3465), OPEN (3551), CREATE (3669), REPAIR (4054), GETXATTR (4681), SETXATTR (4789, 4852, 4869), APPEND_SLICE (4989), SNAPSHOT (5054), TRASH_RECOVER (6035).

## ASan output

```
=================================================================
==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xffffb60003bd
    at pc 0xaaaac94d2e40 bp 0xffffd06bbea0 sp 0xffffd06bbe90
READ of size 4 at 0xffffb60003bd thread T0
    #0 0xaaaac94d2e3c in matoclserv_fuse_truncate /build/moosefs/mfsmaster/matoclserv.c:2870
    #1 0xaaaac94e92fc in matoclserv_gotpacket /build/moosefs/mfsmaster/matoclserv.c:6697
    #2 0xaaaac94ea19c in matoclserv_parse /build/moosefs/mfsmaster/matoclserv.c:6985
    #3 0xaaaac94eb1a8 in matoclserv_serve /build/moosefs/mfsmaster/matoclserv.c:7229
    #4 0xaaaac94fb7e0 in mainloop ../mfscommon/main.c:682
    #5 0xaaaac94ffdc0 in main ../mfscommon/main.c:1806
    #6 0xffffbaa773fc in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #7 0xffffbaa774d4 in __libc_start_main_impl ../csu/libc-start.c:392
    #8 0xaaaac939c76c in _start (/usr/sbin/mfsmaster+0x4c76c)

0xffffb60003bd is located 0 bytes to the right of 45-byte region [0xffffb6000390,0xffffb60003bd)
allocated by thread T0 here:
    #0 0xffffbacaf418 in __interceptor_malloc asan_malloc_linux.cpp:145
    #1 0xaaaac94e9a48 in matoclserv_read /build/moosefs/mfsmaster/matoclserv.c:6941
    #2 0xaaaac94eb188 in matoclserv_serve /build/moosefs/mfsmaster/matoclserv.c:7223
    #3 0xaaaac94fb7e0 in mainloop ../mfscommon/main.c:682
    #4 0xaaaac94ffdc0 in main ../mfscommon/main.c:1806
    #5 0xffffbaa773fc in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #6 0xffffbaa774d4 in __libc_start_main_impl ../csu/libc-start.c:392
    #7 0xaaaac939c76c in _start (/usr/sbin/mfsmaster+0x4c76c)

SUMMARY: AddressSanitizer: heap-buffer-overflow /build/moosefs/mfsmaster/matoclserv.c:2870 in matoclserv_fuse_truncate
Shadow bytes around the buggy address:
  0x200ff6c00020: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x200ff6c00030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x200ff6c00040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x200ff6c00050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x200ff6c00060: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x200ff6c00070: fa fa 00 00 00 00 00[05]fa fa 00 00 00 00 07 fa
  0x200ff6c00080: fa fa fd fd fd fd fd fd fa fa 00 00 00 00 07 fa
  0x200ff6c00090: fa fa 00 00 00 00 00 00 fa fa 00 00 00 00 00 00
  0x200ff6c000a0: fa fa 00 00 00 00 00 fa fa fa 00 00 00 00 00 00
  0x200ff6c000b0: fa fa 00 00 00 00 06 fa fa fa 00 00 00 00 07 fa
  0x200ff6c000c0: fa fa 00 00 00 00 00 00 fa fa 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
```

The `[05]` shadow byte marks the tail of the 45-byte packet allocation (45 = 5×8 + 5). The `get32bit` loop reads 4 bytes starting at offset 45 — exactly at the boundary, immediately into the heap redzone.

## Patch

A `gids > MFS_GIDS_MAX` check is inserted before the multiplication in every affected handler:

```diff
 gids = get32bit(&data);
+if (gids>MFS_GIDS_MAX) {
+    mfs_log(MFSLOG_SYSLOG,MFSLOG_WARNING,"CLTOMA_FUSE_TRUNCATE - too many group ids");
+    eptr->mode = KILL;
+    return;
+}
 if (length!=25+4*gids) {
```

`MFS_GIDS_MAX` is 4096. With `gids` capped, `4*gids` stays within `uint32_t` range. The fix is applied to all 23 handlers.

## Disclosure timeline

- **2026-04-08** Reported to maintainer
- **2026-04-23** Fixed in MooseFS 4.59.0 (commit `1274d1f`)
