# readdata: Heap buffer overflow in read_worker() via malicious chunkserver

**Reporter**: Olivier Laflamme
**Pwno ID**: `PWNO-0055-M`
**Pwno index date**: 2026-05-15
**Pwno status**: Indexed at [bugs.pwno.io/diff](https://bugs.pwno.io/diff); public entry currently redacted

**Component**: mfsmount / mfsclient (readdata.c)
**Severity**: Critical (client-side RCE, attacker-controlled heap overflow, mfsmount runs as root)
**Tested against**: MooseFS commit `83142d5` (2026-04-08)
**Fixed in**: [`1274d1f`](https://github.com/moosefs/moosefs/commit/1274d1f) ("fixed some security issues")

---

The MooseFS FUSE client (`mfsmount`) validates incoming chunkserver read data with `(recleng - 20) + currpos > endpos`, where all operands are `uint32_t`. A malicious chunkserver sends `recleng = 0xFFFFFFFF`, causing `recleng - 20` to underflow to `0xFFFFFFEB`. When added to a small `currpos`, the 32-bit sum wraps below `endpos`, and the bounds check passes. The client then calls `readv()` to write ~33 KB of attacker-controlled data past the end of a 4096-byte read buffer.

Since `mfsmount` typically runs as root (required for FUSE), this is a client-side RCE from any machine that can register as a chunkserver.

## Vulnerable code

In `mfsclient/readdata.c`, `read_worker` at line 1649:

```c
// readdata.c:1649-1657
if (datasrc[part].recleng<20) {
    // ... "got too short data packet" — handles underflow for recleng < 20
    status = EIO;
    break;
} else if ((datasrc[part].recleng-20) + datasrc[part].currpos > datasrc[part].endpos) {
    // BUG: recleng=0xFFFFFFFF passes the <20 check above,
    // then recleng-20 = 0xFFFFFFEB, and 0xFFFFFFEB + currpos(256) wraps to 0xEB
    // 0xEB < endpos(4096) → check passes
    status = EIO;
    break;
}
// ... later, at line 1718:
siov[1].iov_len = datasrc[part].recleng - 20;  // 0xFFFFFFEB bytes requested via readv()
```

With `recleng = 0xFFFFFFFF`:

```
recleng - 20 = 0xFFFFFFEB  (underflow: 4,294,967,275)
0xFFFFFFEB + currpos(256) = 0x1000000EB → truncates to 0xD7 (uint32_t)
0xEB < endpos(4096) → check passes
```

The `readv()` receives attacker-controlled data from the fake chunkserver, writing ~33 KB past the end of a 4096-byte heap allocation.

## Attack chain

The exploit requires registering as a fake chunkserver with the MooseFS master, which needs the `AUTH_CODE` from the master's configuration:

1. Leak `AUTH_CODE` via `ANTOAN_GET_CONFIG` on port 9419 (unauthenticated in the vulnerable version)
2. Register as a fake chunkserver with the master using `CSTOMA_REGISTER`
3. Wait for chunk assignment
4. When a client reads a file, serve a legitimate small `CSTOCL_READ_DATA` to advance `currpos`, then a malicious response with `recleng = 0xFFFFFFFF`
5. Client's `readv()` writes ~33 KB of attacker-controlled data past the 4096-byte buffer

## Reproduction output

```
=== Exploit Server Log ===
Starting V12 exploit (fake chunkserver)
[3] Waiting for chunk assignments and client connections
  chunk 0x0000000000000001 v1 created
  WRITE chunk=0x0000000000000001
  READ #1: chunk=0x0000000000000001 off=0 sz=4096
  sent 256B legit + overflow (36864B) + FIN
  33024B past 4096B allocation

=== V12 Readv Interceptor ===
[V12] readv iov[1]: base=0xffff98032380 len=0xffffffeb (underflow from recleng=0xFFFFFFFF)
```

The readv interceptor confirms `iov_len = 0xffffffeb` (the underflowed `recleng - 20`), targeting a 4096-byte buffer at `0xffff98032380`. The fake chunkserver sends 36864 bytes, of which 33024 overflow past the allocation boundary. Since `readv()` is a kernel syscall that writes directly to userspace memory, the overflow was captured via LD_PRELOAD interceptor rather than ASan instrumentation.

## Patch

```diff
 if (datasrc[part].recleng<20) {
     mfs_log(MFSLOG_SYSLOG,MFSLOG_WARNING,
         "readworker: got too short data packet from chunkserver (leng:%"PRIu32")",
         datasrc[part].recleng);
     status = EIO;
     resetpos = 1;
     break;
+} else if (datasrc[part].recleng>20+MFSCHUNKSIZE) {
+    mfs_log(MFSLOG_SYSLOG,MFSLOG_WARNING,
+        "readworker: got too long data packet from chunkserver (leng:%"PRIu32")",
+        datasrc[part].recleng);
+    status = EIO;
+    resetpos = 1;
+    break;
 } else if ((datasrc[part].recleng-20) + datasrc[part].currpos > datasrc[part].endpos) {
```

`MFSCHUNKSIZE` is 64 MB. No single read response should exceed `20 + MFSCHUNKSIZE` bytes. This rejects both the underflow case (`recleng < 20`, already handled) and the overflow case (`recleng` near `UINT32_MAX`) before the underflow-prone subtraction.

## Disclosure timeline

- **2026-04-08** Reported to maintainer
- **2026-04-23** Fixed in MooseFS 4.59.0 (commit `1274d1f`)
