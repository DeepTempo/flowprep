"""End-to-end smoke test: synthetic pcap/CSV/OCSF -> parquet, plus the bundled
nfcapd binary fixture -> parquet.

Requires `pip install dpkt pyarrow` and a built binary (`cargo build
--release`). Set FLOWPREP_BIN to test an alternative binary; defaults to
the release build in this repo. The nfcapd case reads the committed
`examples/sample.nfcapd` fixture natively — no `nfdump` CLI required.
"""

import os
import subprocess
import sys

import pyarrow.parquet as pq

import dpkt

_REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
_DEFAULT_BIN = os.path.join(_REPO, "target", "release", "flowprep")
FLOWPREP_BIN = os.environ.get("FLOWPREP_BIN", _DEFAULT_BIN)
EXAMPLES = os.path.join(_REPO, "examples")


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


def build_generic_flow_csv(path):
    """Generic aliased flow CSV: leading spaces in header names, an explicitly
    ms-named duration, and epoch-seconds timestamps. Not a real vendor format —
    it guards the alias/trim/unit machinery in isolation. Real CIC headers are
    covered by build_cic_csv below."""
    rows = [
        "Source IP, Destination IP, Source Port, Destination Port, Flow Duration_Milliseconds, Total Fwd Bytes, Total Bwd Bytes, Protocol, Timestamp, Label",
        "192.168.1.5,10.9.9.9,51000,80,2500,1200,34000,tcp,1750000000,BENIGN",
        "192.168.1.6,10.9.9.9,51001,80,150,90,0,udp,1750000060,DDoS",
    ]
    with open(path, "w") as f:
        f.write("\n".join(rows))


def build_cic_csv(path, variant):
    """Real CICFlowMeter headers, verbatim, in both spellings that exist in the
    wild. The previous fixture claimed to be "CICIDS-style" but invented
    `Total Fwd Bytes` and `Flow Duration_Milliseconds` — names no CIC export
    actually emits, which both happened to already resolve. That is why the real
    CIC gap went unnoticed.

    variant "A" = original CICIDS2017/2018 (`Source IP`, `Total Length of Fwd
    Packets`, M/D/Y date with a single-digit hour and no seconds).
    variant "B" = CICFlowMeter v4 (`Src IP`, `TotLen Fwd Pkts`, D/M/Y date that
    proves its own ordering because 20 > 12, float byte counts).

    Flow Duration is MICROSECONDS in both. By decision it is passed through as
    seconds, so flow_check catches the 10^6 inflation downstream — see the
    assertions, which pin that on purpose.
    """
    if variant == "A":
        rows = [
            "Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,Timestamp,Flow Duration,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Label",
            "x-1,104.16.207.165,443,192.168.10.5,54865,6,7/7/2017 3:30,3,2,0,12,0,BENIGN",
            "x-2,192.168.10.5,54865,104.16.207.165,443,6,7/7/2017 15:45:09,5000000,4,2,600,1200,DDoS",
        ]
    else:
        rows = [
            "Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,Label",
            "y-1,10.0.0.1,60602,10.0.1.2,5051,6,20/11/2020 09:50:19,38031,3,4,117.0,353.0,No Label",
            "y-2,10.0.0.2,443,10.0.1.3,51000,17,20/11/2020 09:50:20,120,1,0,64.0,0.0,Attack",
        ]
    with open(path, "w") as f:
        f.write("\n".join(rows))


def build_argus_binetflow(path):
    """Argus/CTU-13 `.binetflow`: verbatim real header, `YYYY/MM/DD` StartTime,
    only a *forward* byte counter (SrcBytes) alongside two totals, plus the two
    port shapes real Argus emits that are not numbers — hex ICMP type/code and
    an empty field for a protocol that carries no ports."""
    rows = [
        "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label",
        "2011/08/18 10:21:46.633335,1.060248,tcp,93.45.239.29,1611,   ->,147.32.84.118,6881,S_RA,0,0,4,252,132,flow=Background-TCP-Attempt",
        "2011/08/18 10:19:49.027650,279.349152,udp,62.240.166.118,1031,  <?>,147.32.84.229,13363,SRPA_PA,0,0,15,1318,955,flow=From-Botnet-V42-TCP",
        "2011/08/18 10:22:07.160628,0.000000,icmp,147.32.84.59,0x0303,  ->,147.32.80.9,0x4fa8,URP,0,0,1,70,70,flow=Background",
        "2011/08/18 10:23:01.000000,0.000000,arp,147.32.84.59,,  ->,147.32.85.1,,CON,0,0,1,42,42,flow=Background",
    ]
    with open(path, "w") as f:
        f.write("\n".join(rows))


def build_cidds_csv(path):
    """CIDDS-001/002 as emitted by nfdump: space-padded fields, `Date first seen`,
    a `class` label column (the OpenStack/ExternalServer captures use `class`, the
    traffic__week* ones use `label`), an nfdump magnitude suffix in Bytes, and an
    ICMP row that puts type.code in Dst Pt as a decimal."""
    rows = [
        "Date first seen,Duration,Proto,Src IP Addr,Src Pt,Dst IP Addr,Dst Pt,Packets,Bytes,Flows,Flags,Tos,class,attackType,attackID,attackDescription",
        "2017-08-02 00:00:00.419,    0.003,TCP  ,192.168.210.55, 44870,192.168.100.11,   445,       2,     174,    1,.AP...,  0,normal,---,---,---",
        "2017-08-02 00:00:01.000,   12.500,TCP  ,192.168.220.47, 55101,192.168.100.11,   445,    1500,     1.4 M,    1,.AP...,  0,attacker,dos,1,---",
        "2017-08-02 00:00:02.000,    0.000,ICMP ,192.168.220.16,     0,192.168.100.5,   8.0,       1,      92,    1,......,  0,victim,---,---,---",
    ]
    with open(path, "w") as f:
        f.write("\n".join(rows))


def build_zeek_conn_log(path):
    """Zeek `conn.log.labeled` (ctu-sme-11 shape): tab-separated, schema declared
    in a `#` preamble rather than a header row, `-` for fields Zeek did not
    measure, and dotted field names (`id.orig_h`) that normalization leaves
    intact. Row 2 is the unset case — 15% of real rows look like this, with
    packet counts present but duration and bytes absent."""
    rows = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#path\tconn",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\tlabel\tdetailedlabel",
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tcount\tcount\tstring\tstring",
        "1677110378.922531\tCUfDVH\t192.168.1.108\t138\t192.168.1.255\t138\tudp\t-\t2.5\t1200\t340\tSF\t8\t4\tBenign\tFrom_benign-To_benign",
        "1677110379.100000\tCAwxab\t192.168.1.108\t54517\t1.1.1.1\t53\tudp\tdns\t-\t-\t-\tS0\t1\t0\tMalicious\tFrom_malicious",
    ]
    with open(path, "w") as f:
        f.write("\n".join(rows) + "\n")


def build_tstat_tcp_csv(path):
    """tstat log_tcp_complete as scraped for AIT: every column carries a `:N`
    index suffix and the first is prefixed `#15#`. In tstat the client (`c_*`)
    initiates the connection, so it is the canonical source — the real rows
    corroborate this (`c_ip` equals the scraper's `ipv4_address_cli`). `durat`
    is milliseconds: in real rows it equals `last - first`, which are
    epoch-millisecond stamps."""
    rows = [
        "#15#c_ip:1,c_port:2,c_pkts_all:3,c_bytes_all:9,s_ip:15,s_port:16,"
        "s_pkts_all:17,s_bytes_all:23,first:29,last:30,durat:31,"
        "timestamp,role_cli,ipv4_address_cli,network_cli,role_serv,ipv4_address_serv,network_serv,label",
        "192.168.130.77,46950,509,494,91.189.88.142,80,568,1252657,"
        "1642209153960.206,1642209156148.560,2188.354,"
        "2022-01-15 01:12:33.960206,attacker_0,192.168.130.77,internet,external,91.189.88.142,external,browsing/update",
    ]
    with open(path, "w") as f:
        f.write("\n".join(rows))


def build_tstat_udp_csv(path):
    """tstat log_udp_complete (AIT fox_netflows shape): the first header column
    is prefixed with a bare `#` (no index, unlike log_tcp_complete's `#15#`),
    there is no flow-level `durat` — only the per-side millisecond `c_durat` —
    and byte/packet counters are per side, so client maps to forward."""
    rows = [
        "#c_ip:1,c_port:2,c_first_abs:3,c_durat:4,c_bytes_all:5,c_pkts_all:6,c_type:9,"
        "s_ip:10,s_port:11,s_durat:13,s_bytes_all:14,s_pkts_all:15,fqdn:19,"
        "timestamp,role_cli,ipv4_address_cli,role_serv,ipv4_address_serv,label",
        "192.168.255.254,32773,1642204803117.595,1.772,250,1,dns,"
        "192.168.130.77,53,1.100,269,1,intranet.company.com,"
        "2022-01-15 00:00:03.117595,client_0,192.168.255.254,dns_server,192.168.130.77,data exfiltration",
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
    build_generic_flow_csv("/tmp/flowprep_test.csv")
    build_argus_binetflow("/tmp/flowprep_test.binetflow")
    build_cidds_csv("/tmp/flowprep_cidds.csv")
    build_cic_csv("/tmp/flowprep_cic_a.csv", "A")
    build_cic_csv("/tmp/flowprep_cic_b.csv", "B")
    build_zeek_conn_log("/tmp/flowprep_zeek_conn.log")
    build_tstat_tcp_csv("/tmp/flowprep_tstat_tcp.csv")
    build_tstat_udp_csv("/tmp/flowprep_tstat_udp.csv")
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

    # Argus `.binetflow`: exercises content-based reader detection (the file is
    # comma-delimited text but is NOT named .csv), the YYYY/MM/DD StartTime
    # rewrite, and the deliberate choice to map only SrcBytes.
    r = subprocess.run(
        [FLOWPREP_BIN, "canonicalize", "/tmp/flowprep_test.binetflow", "/tmp/flowprep_argus.parquet"],
        capture_output=True, text=True,
    )
    print(r.stdout.strip(), r.stderr.strip())
    assert r.returncode == 0, f"binetflow conversion failed: {r.stderr.strip()}"

    t = pq.read_table("/tmp/flowprep_argus.parquet")
    print(t.to_pydict())
    rows = t.to_pylist()
    assert t.num_rows == 4, f"expected 4 flows, got {t.num_rows}"
    # StartTime "2011/08/18 10:21:46.633335" -> epoch us, sub-second preserved.
    assert rows[0]["timestamp"] == 1313662906633335, f"slash-date parse wrong: {rows[0]['timestamp']}"
    assert rows[0]["src_ip"] == "93.45.239.29" and rows[0]["dest_ip"] == "147.32.84.118"
    assert rows[0]["src_port"] == 1611 and rows[0]["dest_port"] == 6881
    assert rows[0]["flow_dur"] == 1.060248, f"Dur should be seconds: {rows[0]['flow_dur']}"
    assert rows[0]["protocol"] == 6 and rows[1]["protocol"] == 17, "Proto name mapping wrong"
    # Argus label values keep their `flow=` prefix; interpreting them is the
    # consumer's job, not flowprep's.
    assert rows[0]["label"] == "flow=Background-TCP-Attempt", "label passthrough wrong"
    # fwd_bytes comes from SrcBytes (132), NOT TotBytes (252). TotBytes/TotPkts
    # are totals, not directional, so they are deliberately unmapped: bwd_bytes
    # zero-fills and the packet counts stay null rather than carrying a wrong
    # value. Recovering backward bytes needs TotBytes - SrcBytes, which requires
    # a derived-field mechanism flowprep does not have.
    assert rows[0]["fwd_bytes"] == 132, f"fwd_bytes should be SrcBytes: {rows[0]['fwd_bytes']}"
    assert rows[0]["bwd_bytes"] == 0, "TotBytes must not be read as bwd_bytes"
    assert rows[0]["fwd_pkts"] is None, "TotPkts must not be read as fwd_pkts"
    assert rows[0]["bwd_pkts"] is None
    # Ports that are not numbers become 0 rather than failing the file: hex ICMP
    # type/code (row 3) and an empty field on a portless protocol (row 4).
    # canonical src_port/dest_port are non-nullable, so 0 is the sentinel — the
    # same one the nfcapd reader already emits for ICMP.
    assert rows[2]["src_port"] == 0 and rows[2]["dest_port"] == 0, "hex ICMP port should coerce to 0"
    assert rows[3]["src_port"] == 0 and rows[3]["dest_port"] == 0, "empty port should coerce to 0"
    assert all(r["src_port"] is not None for r in rows), "ports are non-nullable"

    # CIDDS: nfdump-style export. Exercises the 5 CIDDS aliases, the `class`
    # label passthrough, nfdump magnitude suffixes in Bytes, and a decimal
    # ICMP type.code in Dst Pt.
    r = subprocess.run(
        [FLOWPREP_BIN, "canonicalize", "/tmp/flowprep_cidds.csv", "/tmp/flowprep_cidds.parquet"],
        capture_output=True, text=True,
    )
    print(r.stdout.strip(), r.stderr.strip())
    assert r.returncode == 0, f"CIDDS conversion failed: {r.stderr.strip()}"

    t = pq.read_table("/tmp/flowprep_cidds.parquet")
    print(t.to_pydict())
    rows = t.to_pylist()
    assert t.num_rows == 3, f"expected 3 flows, got {t.num_rows}"
    assert rows[0]["timestamp"] == 1501632000419000, f"Date first seen wrong: {rows[0]['timestamp']}"
    assert rows[0]["src_ip"] == "192.168.210.55" and rows[0]["dest_ip"] == "192.168.100.11"
    assert rows[0]["src_port"] == 44870 and rows[0]["dest_port"] == 445, "Src Pt/Dst Pt wrong"
    assert rows[0]["flow_dur"] == 0.003, f"Duration should be seconds: {rows[0]['flow_dur']}"
    assert rows[0]["protocol"] == 6, "space-padded 'TCP  ' should map to 6"
    # CIDDS rows are unidirectional, so its single Bytes total IS that row's
    # forward volume; bwd zero-fills correctly.
    assert rows[0]["fwd_bytes"] == 174 and rows[0]["bwd_bytes"] == 0
    # nfdump magnitude suffix: "1.4 M" -> 1_400_000, not null.
    assert rows[1]["fwd_bytes"] == 1_400_000, f"suffix expansion wrong: {rows[1]['fwd_bytes']}"
    # ICMP type.code "8.0" in Dst Pt is not a port -> coerced to 0.
    assert rows[2]["dest_port"] == 0, "decimal ICMP type.code should coerce to 0"
    # `class` survives as ground truth.
    assert rows[0]["class"] == "normal" and rows[1]["class"] == "attacker"
    assert rows[1]["attacktype"] == "dos", "attackType should survive as attacktype"

    # CIC variant A — original CICIDS2017/2018 spelling. Date order cannot be
    # proven from the data (7/7/2017 has no component over 12), so it is assumed
    # M/D/Y and that assumption is logged.
    r = subprocess.run(
        [FLOWPREP_BIN, "canonicalize", "/tmp/flowprep_cic_a.csv", "/tmp/flowprep_cic_a.parquet"],
        capture_output=True, text=True,
    )
    print(r.stdout.strip(), r.stderr.strip())
    assert r.returncode == 0, f"CIC variant A failed: {r.stderr.strip()}"
    assert "ASSUMED M/D/YYYY" in r.stderr, "an unprovable date order must be logged as assumed"

    t = pq.read_table("/tmp/flowprep_cic_a.parquet")
    print(t.to_pydict())
    rows = t.to_pylist()
    assert rows[0]["src_ip"] == "104.16.207.165" and rows[0]["dest_port"] == 54865
    assert rows[0]["fwd_bytes"] == 12, "Total Length of Fwd Packets -> fwd_bytes"
    assert rows[1]["fwd_bytes"] == 600 and rows[1]["bwd_bytes"] == 1200
    assert rows[0]["fwd_pkts"] == 2, "Total Fwd Packets -> fwd_pkts"
    # 7/7/2017 3:30 read month-first, single-digit hour zero-padded, no seconds.
    assert rows[0]["timestamp"] == 1499398200000000, f"date rewrite wrong: {rows[0]['timestamp']}"
    assert rows[1]["timestamp"] == 1499442309000000, "HH:MM:SS form should parse too"
    # Flow Duration is MICROSECONDS but is deliberately passed through as
    # seconds; flow_check's duration.implausible_magnitude catches the 10^6
    # inflation downstream. This assertion pins that decision on purpose —
    # do NOT "fix" it to 5.0 without revisiting it.
    assert rows[1]["flow_dur"] == 5_000_000.0, f"duration must pass through: {rows[1]['flow_dur']}"
    assert rows[0]["label"] == "BENIGN"

    # CIC variant B — CICFlowMeter v4 spelling. 20/11/2020 proves D/M/Y.
    r = subprocess.run(
        [FLOWPREP_BIN, "canonicalize", "/tmp/flowprep_cic_b.csv", "/tmp/flowprep_cic_b.parquet"],
        capture_output=True, text=True,
    )
    print(r.stdout.strip(), r.stderr.strip())
    assert r.returncode == 0, f"CIC variant B failed: {r.stderr.strip()}"
    assert "D/M/YYYY (proven" in r.stderr, "20/11/2020 should prove day-first ordering"

    t = pq.read_table("/tmp/flowprep_cic_b.parquet")
    print(t.to_pydict())
    rows = t.to_pylist()
    assert rows[0]["src_ip"] == "10.0.0.1" and rows[0]["src_port"] == 60602
    # Float byte counts round to i64.
    assert rows[0]["fwd_bytes"] == 117 and rows[0]["bwd_bytes"] == 353
    assert rows[0]["fwd_pkts"] == 3 and rows[0]["bwd_pkts"] == 4, "Tot Fwd/Bwd Pkts"
    # 20 November 2020 09:50:19 UTC, NOT 11 August (which month-first would give).
    assert rows[0]["timestamp"] == 1605865819000000, f"D/M/Y parse wrong: {rows[0]['timestamp']}"
    assert rows[0]["label"] == "No Label"

    # Zeek conn.log.labeled: schema comes from the `#` preamble, not a header
    # row, and unset numeric fields ("-") are substituted with 0.
    r = subprocess.run(
        [FLOWPREP_BIN, "canonicalize", "/tmp/flowprep_zeek_conn.log", "/tmp/flowprep_zeek.parquet"],
        capture_output=True, text=True,
    )
    print(r.stdout.strip(), r.stderr.strip())
    assert r.returncode == 0, f"Zeek conn.log conversion failed: {r.stderr.strip()}"
    assert "substituted 0 for 3 unset" in r.stderr, "unset duration/orig_bytes/resp_bytes counted"

    t = pq.read_table("/tmp/flowprep_zeek.parquet")
    print(t.to_pydict())
    rows = t.to_pylist()
    assert t.num_rows == 2, f"expected 2 flows, got {t.num_rows}"
    # ts is an epoch double, so the magnitude path converts it to microseconds.
    assert rows[0]["timestamp"] == 1677110378922531, f"epoch ts wrong: {rows[0]['timestamp']}"
    # Dotted field names resolve literally: id.orig_h/id.resp_p etc.
    assert rows[0]["src_ip"] == "192.168.1.108" and rows[0]["dest_ip"] == "192.168.1.255"
    assert rows[0]["src_port"] == 138 and rows[0]["dest_port"] == 138
    assert rows[0]["flow_dur"] == 2.5, "Zeek duration is already seconds"
    assert rows[0]["fwd_bytes"] == 1200 and rows[0]["bwd_bytes"] == 340
    assert rows[0]["fwd_pkts"] == 8 and rows[0]["bwd_pkts"] == 4
    assert rows[0]["protocol"] == 17
    # Row 2: duration/orig_bytes/resp_bytes were "-" -> 0, packets still real.
    # That leaves zero bytes against non-zero packets, which is exactly what
    # flow_check's bytes.zero_with_packets reports — visible, not silent.
    assert rows[1]["flow_dur"] == 0.0 and rows[1]["fwd_bytes"] == 0
    assert rows[1]["fwd_pkts"] == 1, "packet counts must survive the substitution"
    # Both label columns come through.
    assert rows[1]["label"] == "Malicious"
    assert rows[0]["detailedlabel"] == "From_benign-To_benign"

    # tstat log_tcp_complete (AIT): `:N` suffixes and the `#15#` prefix are
    # stripped, the client (`c_*`) is the source/forward side, and `durat`
    # (milliseconds) converts to seconds.
    r = subprocess.run(
        [FLOWPREP_BIN, "canonicalize", "/tmp/flowprep_tstat_tcp.csv", "/tmp/flowprep_tstat_tcp.parquet"],
        capture_output=True, text=True,
    )
    print(r.stdout.strip(), r.stderr.strip())
    assert r.returncode == 0, f"tstat TCP conversion failed: {r.stderr.strip()}"

    t = pq.read_table("/tmp/flowprep_tstat_tcp.parquet")
    print(t.to_pydict())
    rows = t.to_pylist()
    assert t.num_rows == 1, f"expected 1 flow, got {t.num_rows}"
    # Client initiates, so c_ip is the source — matching ipv4_address_cli.
    assert rows[0]["src_ip"] == "192.168.130.77" and rows[0]["dest_ip"] == "91.189.88.142"
    assert rows[0]["src_port"] == 46950 and rows[0]["dest_port"] == 80
    assert rows[0]["fwd_bytes"] == 494 and rows[0]["bwd_bytes"] == 1252657
    assert rows[0]["fwd_pkts"] == 509 and rows[0]["bwd_pkts"] == 568
    # durat=2188.354 ms == last - first (epoch-ms stamps in the same row).
    assert rows[0]["flow_dur"] == 2.188354, f"durat ms->s wrong: {rows[0]['flow_dur']}"
    assert rows[0]["timestamp"] == 1642209153960206, f"timestamp wrong: {rows[0]['timestamp']}"
    assert rows[0]["label"] == "browsing/update"

    # tstat log_udp_complete (AIT): bare-`#` header prefix, and flow_dur comes
    # from the per-side millisecond `c_durat` (there is no flow-level durat).
    r = subprocess.run(
        [FLOWPREP_BIN, "canonicalize", "/tmp/flowprep_tstat_udp.csv", "/tmp/flowprep_tstat_udp.parquet"],
        capture_output=True, text=True,
    )
    print(r.stdout.strip(), r.stderr.strip())
    assert r.returncode == 0, f"tstat UDP conversion failed: {r.stderr.strip()}"

    t = pq.read_table("/tmp/flowprep_tstat_udp.parquet")
    print(t.to_pydict())
    rows = t.to_pylist()
    assert t.num_rows == 1, f"expected 1 flow, got {t.num_rows}"
    assert rows[0]["src_ip"] == "192.168.255.254" and rows[0]["dest_ip"] == "192.168.130.77"
    assert rows[0]["src_port"] == 32773 and rows[0]["dest_port"] == 53
    assert rows[0]["fwd_bytes"] == 250 and rows[0]["bwd_bytes"] == 269
    assert rows[0]["fwd_pkts"] == 1 and rows[0]["bwd_pkts"] == 1
    assert rows[0]["flow_dur"] == 0.001772, f"c_durat ms->s wrong: {rows[0]['flow_dur']}"
    assert rows[0]["label"] == "data exfiltration"

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

    # nfcapd: bundled binary fixture (5 NetFlow v5 records captured by nfdump),
    # read natively from nfdump's V2/V3 on-disk format.
    r = subprocess.run(
        [FLOWPREP_BIN, "nfcapd", os.path.join(EXAMPLES, "sample.nfcapd"), "/tmp/flowprep_nfcapd.parquet"],
        capture_output=True, text=True,
    )
    print(r.stdout.strip(), r.stderr.strip())
    assert r.returncode == 0, "nfcapd conversion failed"

    t = pq.read_table("/tmp/flowprep_nfcapd.parquet")
    print(t.to_pydict())
    assert t.num_rows == 5, f"expected 5 flows, got {t.num_rows}"
    by_key = {(x["src_ip"], x["dest_ip"], x["src_port"], x["dest_port"]): x for x in t.to_pylist()}
    tcp = by_key[("10.0.0.1", "10.0.0.2", 44321, 443)]
    assert tcp["protocol"] == 6 and tcp["fwd_bytes"] == 1200 and tcp["fwd_pkts"] == 8, "nfcapd tcp fields wrong"
    assert tcp["bwd_bytes"] == 0, "single-counter bwd should be zero-filled"
    assert tcp["timestamp"] == 1699999900_000000, "nfcapd ms->us timestamp wrong"
    assert tcp["flow_dur"] == 2.5, f"nfcapd duration wrong: {tcp['flow_dur']}"
    udp = by_key[("8.8.8.8", "192.168.1.10", 53, 51000)]
    assert udp["protocol"] == 17 and udp["fwd_bytes"] == 180, "nfcapd udp fields wrong"
    assert round(udp["flow_dur"], 3) == 0.001, f"nfcapd sub-ms duration wrong: {udp['flow_dur']}"

    print("ALL TESTS PASSED")


if __name__ == "__main__":
    sys.exit(main())
