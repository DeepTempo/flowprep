"""Benchmark flowprep throughput on a synthetic high-volume pcap.

Generates a 500k-packet capture across ~50k flows (cached in /tmp), then
times the binary end-to-end (pcap -> flow parquet). Requires
`pip install dpkt pyarrow`.
"""

import os
import struct
import subprocess
import time

import dpkt
import pyarrow.parquet as pq

PCAP_PATH = "/tmp/flowprep_bench.pcap"
N_PACKETS = 500_000

# Byte offsets in an Ethernet+IPv4+TCP frame
IP_SRC, IP_DST, TCP_SPORT, TCP_DPORT = 26, 30, 34, 36


def build_bench_pcap():
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x01\x02\x03\x04\x05",
        dst=b"\x06\x07\x08\x09\x0a\x0b",
        type=dpkt.ethernet.ETH_TYPE_IP,
    )
    ip = dpkt.ip.IP(src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02", p=6)
    tcp = dpkt.tcp.TCP(sport=40000, dport=443)
    tcp.data = b"x" * 200
    ip.data = tcp
    ip.len = len(bytes(ip))
    eth.data = ip
    template = bytearray(bytes(eth))

    base = 1750000000.0
    with open(PCAP_PATH, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        for i in range(N_PACKETS):
            # ~50k distinct flows, packets interleaved across them
            flow = i % 50_000
            struct.pack_into("!4s", template, IP_SRC, struct.pack("!I", 0x0A000000 + flow % 25_000))
            struct.pack_into("!4s", template, IP_DST, struct.pack("!I", 0xC0A80000 + flow % 500))
            struct.pack_into("!H", template, TCP_SPORT, 1024 + flow % 60_000)
            struct.pack_into("!H", template, TCP_DPORT, 443)
            writer.writepkt(bytes(template), ts=base + i * 0.0001)
    size_mb = os.path.getsize(PCAP_PATH) / 1e6
    print(f"Generated {PCAP_PATH}: {N_PACKETS} packets, {size_mb:.0f} MB")


def time_impl(name, binary):
    out = f"/tmp/flowprep_bench_{name}.parquet"
    start = time.perf_counter()
    r = subprocess.run([binary, "pcap", PCAP_PATH, out], capture_output=True, text=True)
    elapsed = time.perf_counter() - start
    assert r.returncode == 0, f"{name} failed: {r.stderr}"
    rows = pq.read_metadata(out).num_rows
    print(f"{name:>8}: {elapsed:6.2f}s  ({N_PACKETS / elapsed / 1000:.0f}k pkts/s, {rows} flows)")
    return elapsed, rows


def main():
    if not os.path.exists(PCAP_PATH):
        build_bench_pcap()

    here = os.path.dirname(os.path.abspath(__file__))
    default_bin = os.path.join(here, "..", "target", "release", "flowprep")
    time_impl("flowprep", os.environ.get("FLOWPREP_BIN", default_bin))


if __name__ == "__main__":
    main()
