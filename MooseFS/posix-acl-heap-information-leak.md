# posixacl: Heap information leak in posix_acl_set() via uint16 truncation

**Reporter**: Olivier Laflamme
**Pwno ID**: `PWNO-0049-M`
**Pwno index date**: 2026-05-15
**Pwno status**: Indexed at [bugs.pwno.io/diff](https://bugs.pwno.io/diff); public entry currently redacted

**Component**: mfsmaster (posixacl.c)
**Severity**: High (authenticated, silent heap info leak, repeatable)
**Tested against**: MooseFS commit `83142d5` (2026-04-08)
**Fixed in**: [`1274d1f`](https://github.com/moosefs/moosefs/commit/1274d1f) ("fixed some security issues")

---

A type truncation bug in the POSIX ACL subsystem causes hundreds of kilobytes of uninitialized heap memory to be sent to requesting clients. When a file has enough named ACL entries that `namedusers + namedgroups` exceeds 65535, the sum wraps in a `uint16_t` variable while the response buffer is sized using full `int` arithmetic. The mismatch means the server allocates a large buffer, writes a small number of entries into it, and sends the rest — uninitialized heap — to the client.

The server does not crash. ASan does not flag it — the allocation is large enough, the write is simply short. The leak is silent and repeatable.

## Vulnerable code

Three functions in `mfsmaster/posixacl.c` participate in the mismatch.

`posix_acl_set` at line 258 declares all loop and accumulation variables as `uint16_t`:

```c
// posixacl.c:258
void posix_acl_set(uint32_t inode, uint8_t acltype,
                   uint16_t userperm, uint16_t groupperm, uint16_t otherperm, uint16_t mask,
                   uint16_t namedusers, uint16_t namedgroups, const uint8_t *aclblob) {
    uint16_t i,acls;
    // ...
    acls = namedusers + namedgroups;  // line 273: 40000 + 40000 = 80000 → wraps to 14464
    // ...
    acn->acltab = malloc(sizeof(acl_entry)*acls);  // line 283: allocates for 14464 entries only
    // ...
    acn->namedusers = namedusers;  // line 289: stores full value 40000
    acn->namedgroups = namedgroups; // line 290: stores full value 40000
```

`posix_acl_get_blobsize` at line 299 computes the response size using integer promotion:

```c
// posixacl.c:307
return (acn->namedusers + acn->namedgroups) * 6;  // promoted to int: 80000 * 6 = 480000
```

`posix_acl_get_data` also declares `uint16_t i,acls`, so its serialization loop wraps to 14464 iterations — writing only `14464 * 6 = 86784` bytes of real ACL data into the 480000-byte response buffer.

The remaining 393216 bytes of uninitialized heap memory are transmitted to the client.

## Reproduction output

```
[+] Registered! sessionid=2, server_version=0x00043a08
[*] Setting ACL: namedusers=40000, namedgroups=40000
[*] uint16 wrap: acls = 80000 -> 14464
[*] Entries stored: 14464, but get_blobsize returns: 480000
[+] SETFACL succeeded
[+] GETFACL response: length=480016, namedusers=40000, namedgroups=40000
[+] ACL blob size: 480000 bytes
[+] Valid ACL data: 86784 bytes
[+] Leaked heap data: 393216 bytes of UNINITIALIZED memory
```

No ASan violation is triggered because the response buffer *is* allocated at 480000 bytes — the write is within bounds. The bug is that only 86784 bytes are initialized; the rest retains whatever the allocator returned. On long-running servers with jemalloc or tcmalloc, this region contains data from prior allocations: internal pointers, session state, authentication tokens, and filesystem metadata.

## Patch

```diff
 void posix_acl_set(...) {
-    uint16_t i,acls;
+    uint32_t i,acls;
     // ...
-    acls = namedusers + namedgroups;
+    acls = (uint32_t)namedusers + (uint32_t)namedgroups;

 int32_t posix_acl_get_blobsize(...) {
-    return (acn->namedusers+acn->namedgroups)*6;
+    return ((uint32_t)(acn->namedusers)+(uint32_t)(acn->namedgroups))*6;

 void posix_acl_get_data(...) {
-    uint16_t i,acls;
+    uint32_t i,acls;
-    acls = acn->namedusers+acn->namedgroups;
+    acls = (uint32_t)(acn->namedusers)+(uint32_t)(acn->namedgroups);
```

The same promotion is applied in `posix_acl_copydefaults`, `posix_acl_getall`, `posix_acl_check`, `posix_acl_copy`, `posix_acl_store`, `posix_acl_load`, and `fs_univ_set_additional_attributes` — 12+ locations total. This eliminates the truncation at every point where the sum is computed.

## Disclosure timeline

- **2026-04-08** Reported to maintainer
- **2026-04-23** Fixed in MooseFS 4.59.0 (commit `1274d1f`)
