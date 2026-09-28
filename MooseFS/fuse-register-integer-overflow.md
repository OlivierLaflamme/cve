# matoclserv: Pre-auth integer overflow in matoclserv_fuse_register() via ileng

**Reporter**: Olivier Laflamme
**Pwno ID**: `PWNO-0053-M`
**Pwno index date**: 2026-05-15
**Pwno status**: Indexed at [bugs.pwno.io/diff](https://bugs.pwno.io/diff); public entry currently redacted

**Component**: mfsmaster (matoclserv.c)
**Severity**: Critical (pre-auth, single-packet DoS, before password validation)
**Tested against**: MooseFS commit `83142d5` (2026-04-08)
**Fixed in**: [`1274d1f`](https://github.com/moosefs/moosefs/commit/1274d1f) ("fixed some security issues")

---

The `REGISTER_NEWSESSION` handler reads an `ileng` field as `uint32_t` from the registration packet and uses it in a bounds check: `if (length < 77 + ileng)`. With `ileng = 0xFFFFFFB3`, the addition wraps to zero in 32-bit arithmetic, and the check can never fail. The handler proceeds to `malloc(0xFFFFFFB3)` — a ~4 GB allocation that fails immediately, triggering `passert` (a fatal assertion macro) and killing the master process.

This occurs during the registration handshake, before password validation. One packet to port 9421, zero authentication.

## Vulnerable code

In `mfsmaster/matoclserv.c`, `matoclserv_fuse_register` at line 1741:

```c
// matoclserv.c:1741-1753
ileng = get32bit(&rptr);                    // attacker-controlled: 0xFFFFFFB3
if (length < 77 + ileng) {                  // 77 + 0xFFFFFFB3 = 0x00000000 (wraps)
    // ... kill ...                         // length > 0 always → check bypassed
}
// ...
eptr->info = malloc(ileng);                 // malloc(0xFFFFFFB3) ≈ 4 GB
passert(eptr->info);                        // malloc fails → abort()
memcpy(eptr->info, rptr, ileng);            // or: OOB read of ~4 GB if overcommit
```

The value `0xFFFFFFB3` is `UINT32_MAX - 76`, chosen so `77 + ileng` wraps to exactly zero. Since `length` is always positive, `length < 0` is always false, and execution continues.

On most systems, `malloc(0xFFFFFFB3)` returns NULL and `passert` calls `abort()`. On overcommit-enabled systems, `malloc` succeeds and the `memcpy` reads ~4 GB from a few-hundred-byte buffer, crashing with a SEGV or (as shown below) an ASan CHECK failure when the access falls outside shadow memory entirely.

## ASan output

```
==7==AddressSanitizer CHECK failed: ../../../../src/libsanitizer/asan/asan_descriptions.cpp:80
    "((0 && "Address is not in memory and not in shadow?")) != (0)" (0x0, 0x0)
    #0 0xffff96eb9454 in AsanCheckFailed asan_rtl.cpp:74
    #1 0xffff96edaa5c in __sanitizer::CheckFailed sanitizer_termination.cpp:78
    #2 0xffff96e2f05c in GetShadowKind asan_descriptions.cpp:80
    #3 0xffff96e2f05c in __asan::GetShadowAddressInformation asan_descriptions.cpp:96
    #4 0xffff96e2f05c in __asan::GetShadowAddressInformation asan_descriptions.cpp:93
    #5 0xffff96e30628 in __asan::AddressDescription::AddressDescription asan_descriptions.cpp:441
    #6 0xffff96e32c3c in __asan::ErrorGeneric::ErrorGeneric asan_errors.cpp:389
    #7 0xffff96eb8a58 in __asan::ReportGenericError asan_report.cpp:476
    #8 0xffff96e3bed8 in __interceptor_memcpy sanitizer_common_interceptors.inc:827
    #9 0xaaaad655eeac in memcpy /usr/include/aarch64-linux-gnu/bits/string_fortified.h:29
    #10 0xaaaad655eeac in matoclserv_fuse_register /build/moosefs/mfsmaster/matoclserv.c:1753
    #11 0xaaaad6588dac in matoclserv_gotpacket /build/moosefs/mfsmaster/matoclserv.c:6471
    #12 0xaaaad658a19c in matoclserv_parse /build/moosefs/mfsmaster/matoclserv.c:6985
    #13 0xaaaad658b1a8 in matoclserv_serve /build/moosefs/mfsmaster/matoclserv.c:7229
    #14 0xaaaad659b7e0 in mainloop ../mfscommon/main.c:682
    #15 0xaaaad659fdc0 in main ../mfscommon/main.c:1806
    #16 0xffff96c773fc in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #17 0xffff96c774d4 in __libc_start_main_impl ../csu/libc-start.c:392
    #18 0xaaaad643c76c in _start (/usr/sbin/mfsmaster+0x4c76c)
```

The ASan CHECK failure occurs because the ~4 GB `memcpy` reads so far out of bounds that the accessed address falls outside both the application memory and ASan's shadow memory mapping. ASan cannot even generate shadow byte information — the address is not in any known region.

## Patch

```diff
 ileng = get32bit(&rptr);
+if (ileng>MFS_PATH_MAX) {
+    mfs_log(MFSLOG_SYSLOG,MFSLOG_WARNING,"CLTOMA_FUSE_REGISTER/ACL.2 - info too long (%"PRIu32")",ileng);
+    eptr->mode = KILL;
+    return;
+}
 if (length<77+ileng) {
```

`MFS_PATH_MAX` is 1024. With `ileng` capped, `77 + ileng` stays within `uint32_t` range, and the allocation is bounded to a sane size.

## Disclosure timeline

- **2026-04-08** Reported to maintainer
- **2026-04-23** Fixed in MooseFS 4.59.0 (commit `1274d1f`)
