# matoclserv: Stack buffer overflow in matoclserv_sclass_create() via labelscnt

**Reporter**: Olivier Laflamme
**Pwno ID**: `PWNO-0048-M`
**Pwno index date**: 2026-05-15
**Pwno status**: Indexed at [bugs.pwno.io/diff](https://bugs.pwno.io/diff); public entry currently redacted

**Component**: mfsmaster (matoclserv.c)
**Severity**: Critical (authenticated, stack overflow with controlled content, potential RCE)
**Tested against**: MooseFS commit `83142d5` (2026-04-08)
**Fixed in**: [`1274d1f`](https://github.com/moosefs/moosefs/commit/1274d1f) ("fixed some security issues")

---

The `CLTOMA_FUSE_SCLASS_CREATE` and `CLTOMA_FUSE_SCLASS_CHANGE` handlers read a `labelscnt` value directly from the network as a `uint8_t` and use it to drive a `memcpy` loop copying 128-byte label expressions into a stack buffer sized for only 9 entries. Sending `labelscnt = 255` writes 32640 bytes into a 1152-byte stack allocation, destroying the saved frame pointer, return address, and adjacent stack frames.

The bounds check against `MAXLABELSCNT` exists — but in a downstream function called *after* the overflow has already occurred.

## Vulnerable code

In `mfsmaster/matoclserv.c`, `matoclserv_sclass_create` at line 5230. The stack struct `create` has `labelexpr[MAXLABELSCNT]` where `MAXLABELSCNT = 9` and each entry is `SCLASS_EXPR_MAX_SIZE = 128` bytes (total 1152 bytes):

```c
// matoclserv.c:5335-5348
create.labelscnt = get8bit(&data);   // 0-255 from network, no bounds check
keep.labelscnt = get8bit(&data);
arch.labelscnt = get8bit(&data);
// ... length check uses labelscnt in multiplication — passes for crafted packet ...
for (i=0 ; i<create.labelscnt ; i++) {
    memcpy(create.labelexpr[i], data, SCLASS_EXPR_MAX_SIZE);  // 128 bytes per iteration
    data += SCLASS_EXPR_MAX_SIZE;
}
```

With `labelscnt = 255`:

```
255 x 128 = 32640 bytes written into 1152 bytes → 31488 bytes of stack overflow
```

The same pattern exists in `matoclserv_sclass_change` at line 5399 (labelscnt read at line 5516, memcpy at line 5527).

## ASan output

```
==7==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xffffc379b924
    at pc 0xffffa3e3be04 bp 0xffffc379b2a0 sp 0xffffc379aa78
WRITE of size 128 at 0xffffc379b924 thread T0
    #0 0xffffa3e3be00 in __interceptor_memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:827
    #1 0xaaaac768feec in memcpy /usr/include/aarch64-linux-gnu/bits/string_fortified.h:29
    #2 0xaaaac768feec in matoclserv_sclass_create /build/moosefs/mfsmaster/matoclserv.c:5346
    #3 0xaaaac76993cc in matoclserv_gotpacket /build/moosefs/mfsmaster/matoclserv.c:6736
    #4 0xaaaac769a19c in matoclserv_parse /build/moosefs/mfsmaster/matoclserv.c:6985
    #5 0xaaaac769b1a8 in matoclserv_serve /build/moosefs/mfsmaster/matoclserv.c:7229
    #6 0xaaaac76ab7e0 in mainloop ../mfscommon/main.c:682
    #7 0xaaaac76afdc0 in main ../mfscommon/main.c:1806
    #8 0xffffa3c773fc in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #9 0xffffa3c774d4 in __libc_start_main_impl ../csu/libc-start.c:392
    #10 0xaaaac754c76c in _start (/usr/sbin/mfsmaster+0x4c76c)

Address 0xffffc379b924 is located in stack of thread T0 at offset 1444 in frame
    #0 0xaaaac768ee8c in matoclserv_sclass_create /build/moosefs/mfsmaster/matoclserv.c:5230

  This frame has 5 object(s):
    [48, 192) 'old_labelmasks' (line 5238)
    [256, 1444) 'create' (line 5237) <== Memory access at offset 1444 overflows this variable
    [1584, 2772) 'keep' (line 5237)
    [2912, 4100) 'arch' (line 5237)
    [4240, 5428) 'trash' (line 5237)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:827 in __interceptor_memcpy
Shadow bytes around the buggy address:
  0x200ff86f36d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff86f36e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff86f36f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff86f3700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff86f3710: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x200ff86f3720: 00 00 00 00[04]f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2
  0x200ff86f3730: f2 f2 f2 f2 f2 f2 00 00 00 00 00 00 00 00 00 00
  0x200ff86f3740: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff86f3750: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff86f3760: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x200ff86f3770: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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

The `[04]` byte at the crash address is the tail of the `create` variable (1188 bytes = 148×8 + 4). The `f2` bytes are stack mid-redzones separating `create` from `keep`. The overflow blasts through `keep`, `arch`, and `trash`, then into the caller's stack frame.

A nested crash follows as the corrupted stack unwinds:

```
==7==ERROR: AddressSanitizer: stack-overflow on address 0xffffc379e000
AddressSanitizer: nested bug in the same thread, aborting.
```

## Patch

```diff
 create.labelscnt = get8bit(&data);
 keep.labelscnt = get8bit(&data);
 arch.labelscnt = get8bit(&data);
 if (fver>=1) {
     trash.labelscnt = get8bit(&data);
+    if (create.labelscnt>MAXLABELSCNT || keep.labelscnt>MAXLABELSCNT || arch.labelscnt>MAXLABELSCNT || trash.labelscnt>MAXLABELSCNT) {
+        mfs_log(MFSLOG_SYSLOG,MFSLOG_WARNING,"CLTOMA_SCLASS_CREATE - wrong label count");
+        eptr->mode = KILL;
+        return;
+    }
```

And for the older protocol version (without `trash`):

```diff
 } else {
+    if (create.labelscnt>9 || keep.labelscnt>9 || arch.labelscnt>9) {
+        mfs_log(MFSLOG_SYSLOG,MFSLOG_WARNING,"CLTOMA_SCLASS_CREATE - wrong label count");
+        eptr->mode = KILL;
+        return;
+    }
```

The same fix is applied to `matoclserv_sclass_change`. `MAXLABELSCNT` is 9, matching the stack array size.

## Disclosure timeline

- **2026-04-08** Reported to maintainer
- **2026-04-23** Fixed in MooseFS 4.59.0 (commit `1274d1f`)
