"""End-to-end proof for the low-latency, long-lived Modbus sensor path."""

import io
import json
import os
import select
import struct
import subprocess
import sys
import tempfile
import time

import dpkt

from test_modbus_e2e import modbus_adu, tcp_packet


_REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
_DEFAULT_BIN = os.path.join(_REPO, "target", "release", "flowprep")
FLOWPREP_BIN = os.environ.get("FLOWPREP_BIN", _DEFAULT_BIN)


def build_two_packet_capture():
    request = modbus_adu(42, 1, bytes([16, 0, 100, 0, 2, 4, 0, 1, 0, 2]))
    response = modbus_adu(42, 1, bytes([16, 0, 100, 0, 2]))
    capture = io.BytesIO()
    writer = dpkt.pcap.Writer(capture)
    writer.writepkt(
        tcp_packet("10.20.0.10", "10.20.0.20", 40000, 502, 1000, request),
        ts=1_750_000_000.0,
    )
    writer.writepkt(
        tcp_packet("10.20.0.20", "10.20.0.10", 502, 40000, 5000, response),
        ts=1_750_000_000.001,
    )
    return capture.getvalue()


def build_incremental_capture():
    """Build one warm-up transaction followed by the measured transaction."""
    warm_request = modbus_adu(41, 1, bytes([16, 0, 90, 0, 2, 4, 0, 1, 0, 2]))
    warm_response = modbus_adu(41, 1, bytes([16, 0, 90, 0, 2]))
    request = modbus_adu(42, 1, bytes([16, 0, 100, 0, 2, 4, 0, 1, 0, 2]))
    response = modbus_adu(42, 1, bytes([16, 0, 100, 0, 2]))
    capture = io.BytesIO()
    writer = dpkt.pcap.Writer(capture)
    writer.writepkt(
        tcp_packet("10.20.0.10", "10.20.0.20", 40000, 502, 1000, warm_request),
        ts=1_750_000_000.0,
    )
    writer.writepkt(
        tcp_packet("10.20.0.20", "10.20.0.10", 502, 40000, 5000, warm_response),
        ts=1_750_000_000.001,
    )
    writer.writepkt(
        tcp_packet(
            "10.20.0.10",
            "10.20.0.20",
            40000,
            502,
            1000 + len(warm_request),
            request,
        ),
        ts=1_750_000_000.002,
    )
    writer.writepkt(
        tcp_packet(
            "10.20.0.20",
            "10.20.0.10",
            502,
            40000,
            5000 + len(warm_response),
            response,
        ),
        ts=1_750_000_000.003,
    )
    return capture.getvalue()


def split_legacy_pcap(raw):
    magic = raw[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        byte_order = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        byte_order = ">"
    else:
        raise AssertionError(f"unexpected pcap magic: {magic.hex()}")

    header = raw[:24]
    records = []
    offset = 24
    while offset < len(raw):
        record_header = raw[offset : offset + 16]
        assert len(record_header) == 16
        _, _, captured_length, _ = struct.unpack(f"{byte_order}IIII", record_header)
        end = offset + 16 + captured_length
        records.append(raw[offset:end])
        offset = end
    return header, records


def read_event_with_deadline(process, timeout_seconds=1.0):
    readable, _, _ = select.select([process.stdout], [], [], timeout_seconds)
    assert readable, "sensor did not emit an event before the deadline"
    line = process.stdout.readline()
    assert line, "sensor stdout closed before an event was emitted"
    return json.loads(line)


def prove_incremental_emission():
    header, records = split_legacy_pcap(build_incremental_capture())
    assert len(records) == 4
    process = subprocess.Popen(
        [
            FLOWPREP_BIN,
            "modbus-stream",
            "--sensor-id",
            "stream-e2e",
            "--request-timeout-ms",
            "1000",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    startup_started = time.perf_counter_ns()
    process.stdin.write(header)
    process.stdin.write(records[0])
    process.stdin.flush()
    warm_request = read_event_with_deadline(process, timeout_seconds=2.0)
    startup_usec = (time.perf_counter_ns() - startup_started) // 1000
    assert warm_request["event_type"] == "request_observed"
    assert warm_request["event_sequence"] == 1

    # Complete one transaction as an explicit readiness handshake. The budget
    # below therefore measures packet-to-event latency in the already-running
    # background sensor, not one-time executable startup and dynamic linking.
    process.stdin.write(records[1])
    process.stdin.flush()
    warm_transaction = read_event_with_deadline(process)
    assert warm_transaction["event_type"] == "transaction_observed"
    assert warm_transaction["event_sequence"] == 2

    started = time.perf_counter_ns()
    process.stdin.write(records[2])
    process.stdin.flush()
    request = read_event_with_deadline(process)
    request_latency_usec = (time.perf_counter_ns() - started) // 1000

    assert request["schema_version"] == "modbus_stream_event/v1"
    assert request["observation_schema_version"] == "modbus_observation/v1"
    assert request["event_type"] == "request_observed"
    assert request["response_status"] == "pending"
    assert request["operation"] == "write"
    assert request["address"] == 100 and request["quantity"] == 2
    assert request["register_values"] == [1, 2]
    assert request["coil_values"] is None
    assert request["sensor_id"] == "stream-e2e"
    assert request["event_sequence"] == 3
    assert request["sensor_processing_usec"] < 50_000
    assert request_latency_usec < 50_000, (
        f"request event took {request_latency_usec}us; sensor budget is <50000us"
    )

    started = time.perf_counter_ns()
    process.stdin.write(records[3])
    process.stdin.flush()
    transaction = read_event_with_deadline(process)
    response_latency_usec = (time.perf_counter_ns() - started) // 1000

    assert transaction["event_type"] == "transaction_observed"
    assert transaction["response_status"] == "ok"
    assert transaction["request_seen"] is True
    assert transaction["response_seen"] is True
    assert transaction["register_values"] == [1, 2]
    assert transaction["latency_usec"] == 1000
    assert transaction["event_sequence"] == 4
    assert transaction["sensor_run_id"] == request["sensor_run_id"]
    assert transaction["sensor_processing_usec"] < 50_000
    assert response_latency_usec < 50_000, (
        f"transaction event took {response_latency_usec}us; sensor budget is <50000us"
    )

    process.stdin.close()
    return_code = process.wait(timeout=5)
    stderr = process.stderr.read().decode()
    assert return_code == 0, stderr
    assert "4 stream events" in stderr
    assert "2 immediate requests" in stderr
    return startup_usec, request_latency_usec, response_latency_usec


def prove_restart_safe_append():
    raw = build_two_packet_capture()
    with tempfile.TemporaryDirectory(prefix="flowprep_modbus_stream_") as tempdir:
        capture = os.path.join(tempdir, "input.pcap")
        output = os.path.join(tempdir, "events.ndjson")
        with open(capture, "wb") as handle:
            handle.write(raw)

        command = [
            FLOWPREP_BIN,
            "modbus-stream",
            "--input",
            capture,
            "--output",
            output,
            "--sensor-id",
            "restart-e2e",
        ]
        first = subprocess.run(command, capture_output=True, text=True)
        second = subprocess.run(command, capture_output=True, text=True)
        assert first.returncode == 0, first.stderr
        assert second.returncode == 0, second.stderr

        with open(output) as handle:
            events = [json.loads(line) for line in handle]
        assert len(events) == 4
        assert [event["event_sequence"] for event in events] == [1, 2, 1, 2]
        assert all(event["register_values"] == [1, 2] for event in events)
        first_run = {event["sensor_run_id"] for event in events[:2]}
        second_run = {event["sensor_run_id"] for event in events[2:]}
        assert len(first_run) == 1 and len(second_run) == 1
        assert first_run != second_run


def prove_pcapng_input():
    request = modbus_adu(77, 3, bytes([15, 0, 10, 0, 10, 2, 0x55, 0x03]))
    response = modbus_adu(77, 3, bytes([15, 0, 10, 0, 10]))
    with tempfile.TemporaryDirectory(prefix="flowprep_modbus_stream_pcapng_") as tempdir:
        capture = os.path.join(tempdir, "input.pcapng")
        with open(capture, "wb") as handle:
            writer = dpkt.pcapng.Writer(handle)
            writer.writepkt(
                tcp_packet("10.20.0.10", "10.20.0.20", 40000, 502, 1000, request),
                ts=1_750_000_000.0,
            )
            writer.writepkt(
                tcp_packet("10.20.0.20", "10.20.0.10", 502, 40000, 5000, response),
                ts=1_750_000_000.001,
            )

        result = subprocess.run(
            [FLOWPREP_BIN, "modbus-stream", "--input", capture],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        events = [json.loads(line) for line in result.stdout.splitlines()]
        assert [event["event_type"] for event in events] == [
            "request_observed",
            "transaction_observed",
        ]
        assert events[1]["transaction_id"] == 77
        assert events[1]["response_status"] == "ok"
        assert events[0]["coil_values"] == [
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
        assert events[1]["coil_values"] == events[0]["coil_values"]
        assert events[1]["register_values"] is None


def main():
    startup_usec, request_usec, response_usec = prove_incremental_emission()
    prove_restart_safe_append()
    prove_pcapng_input()
    print(
        "MODBUS STREAM E2E PASSED "
        f"(one-time startup {startup_usec}us; "
        f"request emission {request_usec}us, transaction emission {response_usec}us)"
    )


if __name__ == "__main__":
    sys.exit(main())
