# matoclserv: Pre-auth NULL pointer dereference in matoclserv_node_info()

**Reporter**: Olivier Laflamme
**Pwno ID**: `PWNO-0050-M`
**Pwno index date**: 2026-05-15
**Pwno status**: Indexed at [bugs.pwno.io/diff](https://bugs.pwno.io/diff); public entry currently redacted

**Component**: mfsmaster (matoclserv.c)
**Severity**: High (pre-auth, single-packet DoS)
**Tested against**: MooseFS commit `83142d5` (2026-04-08)
**Fixed in**: [`1274d1f`](https://github.com/moosefs/moosefs/commit/1274d1f) ("fixed some security issues")

---

The master dispatches `CLTOMA_NODE_INFO` for unauthenticated connections. The handler dereferences `eptr->sesdata` to obtain the session's root inode, but `sesdata` is NULL for connections that haven't registered. One packet to port 9421 crashes the master with a NULL pointer read at offset `0x44`. No authentication, no timing window, no special preconditions.

## Vulnerable code

In `mfsmaster/matoclserv.c`, the `NOTREGISTERED` dispatch block at line 6455 even documents the invariant in a comment:

```c
// matoclserv.c:6455
if (eptr->registered==NOTREGISTERED) {  // unregistered clients - beware that in this context sesdata is NULL
    switch (type) {
        // ...
        case CLTOMA_NODE_INFO:                              // line 6539
            matoclserv_node_info(eptr,data,length);         // sesdata is NULL here
            break;
```

The handler at line 1319 immediately dereferences the NULL session pointer:

```c
// matoclserv.c:1319
ptr = matoclserv_create_packet(eptr,MATOCL_NODE_INFO,
    fs_node_info(sessions_get_rootinode(eptr->sesdata), ...));
```

`sessions_get_rootinode` in `sessions.c`:

```c
// sessions.c:983
uint32_t sessions_get_rootinode(void *vsesdata) {
    session *sesdata = (session*)vsesdata;
    return sesdata->rootinode;  // line 986: NULL + 0x44 → SEGV
}
```

## ASan output

```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==7==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000044
    (pc 0xaaaabd56b05c bp 0xffffe9d38980 sp 0xffffe9d38980 T0)
==7==The signal is caused by a READ memory access.
==7==Hint: address points to the zero page.
    #0 0xaaaabd56b05c in sessions_get_rootinode /build/moosefs/mfsmaster/sessions.c:986
    #1 0xaaaabd5aaf44 in matoclserv_node_info /build/moosefs/mfsmaster/matoclserv.c:1319
    #2 0xaaaabd5d8f1c in matoclserv_gotpacket /build/moosefs/mfsmaster/matoclserv.c:6540
    #3 0xaaaabd5da19c in matoclserv_parse /build/moosefs/mfsmaster/matoclserv.c:6985
    #4 0xaaaabd5db1a8 in matoclserv_serve /build/moosefs/mfsmaster/matoclserv.c:7229
    #5 0xaaaabd5eb7e0 in mainloop ../mfscommon/main.c:682
    #6 0xaaaabd5efdc0 in main ../mfscommon/main.c:1806
    #7 0xffffb94773fc in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #8 0xffffb94774d4 in __libc_start_main_impl ../csu/libc-start.c:392
    #9 0xaaaabd48c76c in _start (/usr/sbin/mfsmaster+0x4c76c)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /build/moosefs/mfsmaster/sessions.c:986 in sessions_get_rootinode
==7==ABORTING
```

The address `0x44` is the offset of `rootinode` within the `session` struct. ASan cannot provide shadow byte information because the access is to the zero page, not to a known heap or stack allocation.

## Patch

```diff
 if (eptr->registered==NOTREGISTERED) {
     switch (type) {
         // ...
-        case CLTOMA_NODE_INFO:
-            matoclserv_node_info(eptr,data,length);
-            break;
+//      case CLTOMA_NODE_INFO:
+//          matoclserv_node_info(eptr,data,length);
+//          break;
```

The command is now only reachable for registered connections that have a valid `sesdata`.

## Disclosure timeline

- **2026-04-08** Reported to maintainer
- **2026-04-23** Fixed in MooseFS 4.59.0 (commit `1274d1f`)
