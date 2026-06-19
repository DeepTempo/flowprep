"""End-to-end smoke test: synthetic pcap -> parquet, CICIDS-style CSV -> parquet.

Requires `pip install dpkt pyarrow` and a built binary (`cargo build
--release`). Set FLOWPREP_BIN to test an alternative binary; defaults to
the release build in this repo.
"""

import os
import subprocess
import sys

import pyarrow.parquet as pq

import dpkt

_DEFAULT_BIN = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "target", "release", "flowprep"
)
FLOWPREP_BIN = os.environ.get("FLOWPREP_BIN", _DEFAULT_BIN)


def build_test_pcap(path):
    """Write a pcap with a bidirectional TCP conversation and a UDP flow."""
    with open(path, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        base = 1750000000.0

        def packet(src, dst, sport, dport, proto_cls, payload):
            eth = dpkt.ethernet.Ethernet(
                src=b"\x00\x01\x02\x03\x04\x05", dst=b"\x06\x07\x08\x09\x0a\x0b"
            )
            ip = dpkt.ip.IP(
                src=bytes(map(int, src.split("."))),
                dst=bytes(map(int, dst.split("."))),
            )
            transport = proto_cls(sport=sport, dport=dport)
            transport.data = payload
            ip.data = transport
            ip.p = 6 if proto_cls is dpkt.tcp.TCP else 17
            ip.len = len(bytes(ip))
            eth.data = ip
            eth.type = dpkt.ethernet.ETH_TYPE_IP
            return bytes(eth)

        # TCP conversation: 3 packets out, 2 back
        for i in range(3):
            writer.writepkt(
                packet("10.0.0.1", "10.0.0.2", 44321, 443, dpkt.tcp.TCP, b"x" * 100),
                ts=base + i,
            )
        for i in range(2):
            writer.writepkt(
                packet("10.0.0.2", "10.0.0.1", 443, 44321, dpkt.tcp.TCP, b"y" * 500),
                ts=base + 0.5 + i,
            )
        # One-way UDP flow
        writer.writepkt(
            packet("10.0.0.3", "8.8.8.8", 5353, 53, dpkt.udp.UDP, b"z" * 60),
            ts=base + 10,
        )


def build_cicids_csv(path):
    """CSV with CICIDS-style headers: spaces, mixed case, ms durations."""
    rows = [
        "Source IP, Destination IP, Source Port, Destination Port, Flow Duration_Milliseconds, Total Fwd Bytes, Total Bwd Bytes, Protocol, Timestamp, Label",
        "192.168.1.5,10.9.9.9,51000,80,2500,1200,34000,tcp,1750000000,BENIGN",
        "192.168.1.6,10.9.9.9,51001,80,150,90,0,udp,1750000060,DDoS",
    ]
    with open(path, "w") as f:
        f.write("\n".join(rows))


def build_ocsf_ndjson(path):
    """OCSF Network Activity NDJSON: nested fields, ms units, a non-close event."""
    rows = [
        '{"activity_name":"Closed","time":1750000000000,"duration":2500,'
        '"src_endpoint":{"ip":"192.168.10.5","port":44321},'
        '"dst_endpoint":{"ip":"93.184.216.34","port":443},'
        '"traffic":{"bytes_in":1200,"bytes_out":34000,"packets_in":8,"packets_out":12},'
        '"connection_info":{"protocol_name":"tcp"}}',
        # Non-close event: must be dropped.
        '{"activity_name":"Opened","time":1750000003000,'
        '"src_endpoint":{"ip":"192.168.10.9","port":51000},'
        '"dst_endpoint":{"ip":"10.0.0.3","port":80}}',
        # activity_id 2 (close) with top-level bytes fallback and numeric protocol.
        '{"activity_id":2,"time":1750000010000,"elapsed_time":150,'
        '"src_endpoint":{"ip":"192.168.10.17","port":5353},'
        '"dst_endpoint":{"ip":"8.8.8.8","port":53},'
        '"bytes_from_client":90,"bytes_from_server":0,'
        '"connection_info":{"protocol_num":17}}',
    ]
    with open(path, "w") as f:
        f.write("\n".join(rows))


def main():
    build_test_pcap("/tmp/flowprep_test.pcap")
    build_cicids_csv("/tmp/flowprep_test.csv")
    build_ocsf_ndjson("/tmp/flowprep_test.ndjson")

    r = subprocess.run(
        [FLOWPREP_BIN, "pcap", "/tmp/flowprep_test.pcap", "/tmp/flowprep_pcap.parquet"],
        capture_output=True, text=True,
    )
    print(r.stdout.strip(), r.stderr.strip())
    assert r.returncode == 0, "pcap conversion failed"

    t = pq.read_table("/tmp/flowprep_pcap.parquet")
    print(t.to_pydict())
    assert t.num_rows == 2, f"expected 2 flows, got {t.num_rows}"
    tcp = [r for r in t.to_pylist() if r["protocol"] == 6][0]
    assert tcp["fwd_pkts"] == 3 and tcp["bwd_pkts"] == 2, "direction split wrong"
    assert tcp["flow_dur"] == 2.0, f"flow_dur wrong: {tcp['flow_dur']}"

    r = subprocess.run(
        [FLOWPREP_BIN, "canonicalize", "/tmp/flowprep_test.csv", "/tmp/flowprep_csv.parquet"],
        capture_output=True, text=True,
    )
    print(r.stdout.strip(), r.stderr.strip())
    assert r.returncode == 0, "canonicalize failed"

    t = pq.read_table("/tmp/flowprep_csv.parquet")
    print(t.to_pydict())
    rows = t.to_pylist()
    assert rows[0]["flow_dur"] == 2.5, f"ms->s conversion wrong: {rows[0]['flow_dur']}"
    assert rows[0]["protocol"] == 6 and rows[1]["protocol"] == 17, "protocol mapping wrong"
    assert rows[0]["timestamp"] == 1750000000_000000, "epoch-seconds detection wrong"
    assert rows[1]["timestamp"] == 1750000060_000000, "epoch-seconds detection wrong"
    assert rows[0]["label"] == "BENIGN", "label passthrough wrong"

    r = subprocess.run(
        [FLOWPREP_BIN, "ocsf", "/tmp/flowprep_test.ndjson", "/tmp/flowprep_ocsf.parquet"],
        capture_output=True, text=True,
    )
    print(r.stdout.strip(), r.stderr.strip())
    assert r.returncode == 0, "ocsf conversion failed"

    t = pq.read_table("/tmp/flowprep_ocsf.parquet")
    print(t.to_pydict())
    rows = t.to_pylist()
    assert t.num_rows == 2, f"expected 2 close events, got {t.num_rows}"
    assert rows[0]["timestamp"] == 1750000000_000000, "ms->us timestamp wrong"
    assert rows[0]["flow_dur"] == 2.5, f"duration ms->s wrong: {rows[0]['flow_dur']}"
    assert rows[0]["fwd_bytes"] == 1200 and rows[0]["bwd_bytes"] == 34000, "nested bytes wrong"
    assert rows[0]["fwd_pkts"] == 8 and rows[0]["bwd_pkts"] == 12, "nested packets wrong"
    assert rows[0]["protocol"] == 6, "protocol_name mapping wrong"
    assert rows[1]["flow_dur"] == 0.15, f"elapsed_time ms->s wrong: {rows[1]['flow_dur']}"
    assert rows[1]["fwd_bytes"] == 90, "top-level bytes fallback wrong"
    assert rows[1]["protocol"] == 17, "protocol_num passthrough wrong"

    print("ALL TESTS PASSED")


if __name__ == "__main__":
    sys.exit(main())
