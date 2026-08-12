"""Golden end-to-end test for passive Modbus/TCP PCAP decoding.

Requires ``dpkt`` and ``pyarrow`` plus a built flowprep binary. The fixture
exercises split and coalesced ADUs, a retransmission, MBAP resynchronization,
request/response pairing, an exception, missing/orphan halves, and FC 43/14
device identity extraction.
"""

import os
import subprocess
import sys
import tempfile

import dpkt
import pyarrow.parquet as pq


_REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
_DEFAULT_BIN = os.path.join(_REPO, "target", "release", "flowprep")
FLOWPREP_BIN = os.environ.get("FLOWPREP_BIN", _DEFAULT_BIN)


def modbus_adu(transaction_id, unit_id, pdu):
    length = 1 + len(pdu)
    return (
        transaction_id.to_bytes(2, "big")
        + b"\x00\x00"
        + length.to_bytes(2, "big")
        + bytes([unit_id])
        + pdu
    )


def identity_response(objects):
    pdu = bytes([43, 14, 1, 1, 0, 0, len(objects)])
    for object_id, value in objects:
        encoded = value.encode("utf-8")
        pdu += bytes([object_id, len(encoded)]) + encoded
    return pdu


def tcp_packet(src, dst, sport, dport, sequence, payload):
    ethernet = dpkt.ethernet.Ethernet(
        src=b"\x00\x01\x02\x03\x04\x05",
        dst=b"\x06\x07\x08\x09\x0a\x0b",
    )
    ip = dpkt.ip.IP(
        src=bytes(map(int, src.split("."))),
        dst=bytes(map(int, dst.split("."))),
        p=dpkt.ip.IP_PROTO_TCP,
    )
    tcp = dpkt.tcp.TCP(
        sport=sport,
        dport=dport,
        seq=sequence,
        flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
        data=payload,
    )
    ip.data = tcp
    ip.len = len(bytes(ip))
    ethernet.data = ip
    ethernet.type = dpkt.ethernet.ETH_TYPE_IP
    return bytes(ethernet)


def build_modbus_pcap(path):
    client = "10.20.0.10"
    server = "10.20.0.20"
    client_port = 40000
    server_port = 502
    client_sequence = 1000
    server_sequence = 5000
    base = 1_750_000_000.0

    read_request = modbus_adu(1, 1, bytes([3, 0, 0, 0, 2]))
    read_response = modbus_adu(1, 1, bytes([3, 4, 0, 10, 0, 20]))
    write_request = modbus_adu(2, 1, bytes([6, 0, 16, 0, 123]))
    write_response = modbus_adu(2, 1, bytes([6, 0, 16, 0, 123]))
    id_request = modbus_adu(3, 1, bytes([43, 14, 1, 0]))
    id_response = modbus_adu(
        3,
        1,
        identity_response(
            [
                (0, "Siemens"),
                (1, "S7-1500"),
                (2, "V3.1"),
                (4, "SIMATIC PLC"),
            ]
        ),
    )
    multi_write_request = modbus_adu(
        4, 1, bytes([16, 0, 100, 0, 2, 4, 0, 1, 0, 2])
    )
    exception_response = modbus_adu(4, 1, bytes([0x90, 2]))
    coil_write_request = modbus_adu(
        6, 1, bytes([15, 0, 32, 0, 10, 2, 0x55, 0x03])
    )
    coil_write_response = modbus_adu(6, 1, bytes([15, 0, 32, 0, 10]))
    missing_response_request = modbus_adu(5, 7, bytes([1, 0, 32, 0, 8]))
    orphan_response = modbus_adu(99, 1, bytes([3, 2, 0, 42]))

    with open(path, "wb") as capture:
        writer = dpkt.pcap.Writer(capture)

        # A request split across two TCP segments, followed by a full duplicate
        # of the second segment. Only one ADU should be emitted.
        first_part = read_request[:8]
        second_part = read_request[8:]
        writer.writepkt(
            tcp_packet(
                client,
                server,
                client_port,
                server_port,
                client_sequence,
                first_part,
            ),
            ts=base,
        )
        writer.writepkt(
            tcp_packet(
                client,
                server,
                client_port,
                server_port,
                client_sequence + len(first_part),
                second_part,
            ),
            ts=base + 0.001,
        )
        writer.writepkt(
            tcp_packet(
                client,
                server,
                client_port,
                server_port,
                client_sequence + len(first_part),
                second_part,
            ),
            ts=base + 0.002,
        )
        client_sequence += len(read_request)

        writer.writepkt(
            tcp_packet(
                server,
                client,
                server_port,
                client_port,
                server_sequence,
                read_response,
            ),
            ts=base + 0.003,
        )
        server_sequence += len(read_response)

        # Two complete requests and two responses coalesced into one segment in
        # each direction.
        coalesced_requests = write_request + id_request
        writer.writepkt(
            tcp_packet(
                client,
                server,
                client_port,
                server_port,
                client_sequence,
                coalesced_requests,
            ),
            ts=base + 0.004,
        )
        client_sequence += len(coalesced_requests)

        coalesced_responses = write_response + id_response
        writer.writepkt(
            tcp_packet(
                server,
                client,
                server_port,
                client_port,
                server_sequence,
                coalesced_responses,
            ),
            ts=base + 0.005,
        )
        server_sequence += len(coalesced_responses)

        # Malformed bytes before a valid request force a bounded MBAP resync;
        # the protocol exception still pairs with the recovered request.
        prefixed_request = b"\xff\xaa" + multi_write_request
        writer.writepkt(
            tcp_packet(
                client,
                server,
                client_port,
                server_port,
                client_sequence,
                prefixed_request,
            ),
            ts=base + 0.006,
        )
        client_sequence += len(prefixed_request)
        writer.writepkt(
            tcp_packet(
                server,
                client,
                server_port,
                client_port,
                server_sequence,
                exception_response,
            ),
            ts=base + 0.007,
        )
        server_sequence += len(exception_response)

        writer.writepkt(
            tcp_packet(
                client,
                server,
                client_port,
                server_port,
                client_sequence,
                coil_write_request,
            ),
            ts=base + 0.008,
        )
        client_sequence += len(coil_write_request)
        writer.writepkt(
            tcp_packet(
                server,
                client,
                server_port,
                client_port,
                server_sequence,
                coil_write_response,
            ),
            ts=base + 0.009,
        )
        server_sequence += len(coil_write_response)

        writer.writepkt(
            tcp_packet(
                client,
                server,
                client_port,
                server_port,
                client_sequence,
                missing_response_request,
            ),
            ts=base + 0.010,
        )
        writer.writepkt(
            tcp_packet(
                server,
                client,
                server_port,
                client_port,
                server_sequence,
                orphan_response,
            ),
            ts=base + 0.011,
        )


def build_malformed_only_pcap(path):
    with open(path, "wb") as capture:
        writer = dpkt.pcap.Writer(capture)
        writer.writepkt(
            tcp_packet(
                "10.20.0.10",
                "10.20.0.20",
                40000,
                502,
                1,
                b"\xff" * 32,
            ),
            ts=1_750_000_000.0,
        )


def main():
    with tempfile.TemporaryDirectory(prefix="flowprep_modbus_") as tempdir:
        capture = os.path.join(tempdir, "modbus.pcap")
        output = os.path.join(tempdir, "modbus.parquet")
        build_modbus_pcap(capture)
        result = subprocess.run(
            [FLOWPREP_BIN, "modbus", capture, output],
            capture_output=True,
            text=True,
        )
        print(result.stdout.strip(), result.stderr.strip())
        assert result.returncode == 0, f"Modbus conversion failed: {result.stderr}"
        assert "7 observations" in result.stdout
        assert "1 retransmissions" in result.stdout
        assert "2 malformed bytes skipped" in result.stdout

        table = pq.read_table(output)
        assert table.num_rows == 7
        assert table.schema.metadata[b"deeptempo.schema"] == b"modbus_observation/v1"
        assert table.schema.metadata[b"deeptempo.decoder"] == b"passive"
        assert "coil_values" in table.column_names
        assert "register_values" in table.column_names
        assert "raw_pdu" not in table.column_names

        rows = {row["transaction_id"]: row for row in table.to_pylist()}
        read = rows[1]
        assert read["function_name"] == "read_holding_registers"
        assert read["address"] == 0 and read["quantity"] == 2
        assert read["coil_values"] is None and read["register_values"] is None
        assert read["response_status"] == "ok"
        assert read["request_packet"] == 2 and read["response_packet"] == 4
        assert read["latency_usec"] == 2000

        write = rows[2]
        assert write["operation"] == "write" and write["address"] == 16
        assert write["register_values"] == [123]
        assert write["response_status"] == "ok"

        identity = rows[3]
        assert identity["operation"] == "device_identification"
        assert identity["vendor_name"] == "Siemens"
        assert identity["product_code"] == "S7-1500"
        assert identity["revision"] == "V3.1"
        assert identity["product_name"] == "SIMATIC PLC"

        exception = rows[4]
        assert exception["function_name"] == "write_multiple_registers"
        assert exception["register_values"] == [1, 2]
        assert exception["response_status"] == "exception"
        assert exception["exception_code"] == 2
        assert exception["exception_name"] == "illegal_data_address"
        assert "mbap_resynchronized" in exception["parser_warning"]

        coil_write = rows[6]
        assert coil_write["function_name"] == "write_multiple_coils"
        assert coil_write["address"] == 32 and coil_write["quantity"] == 10
        assert coil_write["coil_values"] == [
            True,
            False,
            True,
            False,
            True,
            False,
            True,
            False,
            True,
            True,
        ]
        assert coil_write["response_status"] == "ok"

        missing = rows[5]
        assert missing["request_seen"] is True and missing["response_seen"] is False
        assert missing["response_status"] == "missing_response"
        assert missing["unit_id"] == 7

        orphan = rows[99]
        assert orphan["request_seen"] is False and orphan["response_seen"] is True
        assert orphan["response_status"] == "orphan_response"

        malformed_capture = os.path.join(tempdir, "malformed.pcap")
        malformed_output = os.path.join(tempdir, "malformed.parquet")
        build_malformed_only_pcap(malformed_capture)
        malformed = subprocess.run(
            [FLOWPREP_BIN, "modbus", malformed_capture, malformed_output],
            capture_output=True,
            text=True,
        )
        print(malformed.stdout.strip(), malformed.stderr.strip())
        assert malformed.returncode != 0
        assert "no decodable Modbus/TCP observations" in malformed.stderr
        assert not os.path.exists(malformed_output)

    print("MODBUS E2E TEST PASSED")


if __name__ == "__main__":
    sys.exit(main())
