"""Local throughput comparison for immediate-flush and small-batch stream modes."""

import io
import os
import subprocess
import sys
import time

import dpkt

from test_modbus_e2e import modbus_adu, tcp_packet


_REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
_DEFAULT_BIN = os.path.join(_REPO, "target", "release", "flowprep")
FLOWPREP_BIN = os.environ.get("FLOWPREP_BIN", _DEFAULT_BIN)
TRANSACTIONS = int(os.environ.get("MODBUS_BENCH_TRANSACTIONS", "5000"))


def build_capture(transaction_count):
    capture = io.BytesIO()
    writer = dpkt.pcap.Writer(capture)
    client_sequence = 1000
    server_sequence = 5000
    base = 1_750_000_000.0
    for index in range(transaction_count):
        transaction_id = index % 65536
        address = index % 65536
        request = modbus_adu(
            transaction_id,
            1,
            bytes(
                [
                    16,
                    (address >> 8) & 0xFF,
                    address & 0xFF,
                    0,
                    2,
                    4,
                    0,
                    10,
                    0,
                    20,
                ]
            ),
        )
        response = modbus_adu(
            transaction_id,
            1,
            bytes([16, (address >> 8) & 0xFF, address & 0xFF, 0, 2]),
        )
        writer.writepkt(
            tcp_packet(
                "10.20.0.10",
                "10.20.0.20",
                40000,
                502,
                client_sequence,
                request,
            ),
            ts=base + index / 1_000_000,
        )
        client_sequence += len(request)
        writer.writepkt(
            tcp_packet(
                "10.20.0.20",
                "10.20.0.10",
                502,
                40000,
                server_sequence,
                response,
            ),
            ts=base + index / 1_000_000 + 0.000001,
        )
        server_sequence += len(response)
    return capture.getvalue()


def run(raw, flush_every):
    started = time.perf_counter()
    result = subprocess.run(
        [
            FLOWPREP_BIN,
            "modbus-stream",
            "--sensor-id",
            "benchmark",
            "--flush-every",
            str(flush_every),
        ],
        input=raw,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    elapsed = time.perf_counter() - started
    assert result.returncode == 0, result.stderr.decode()
    events = TRANSACTIONS * 2
    return {
        "flush_every": flush_every,
        "elapsed_seconds": elapsed,
        "transactions_per_second": TRANSACTIONS / elapsed,
        "events_per_second": events / elapsed,
        "wall_usec_per_event": elapsed * 1_000_000 / events,
        "summary": result.stderr.decode().strip(),
    }


def main():
    raw = build_capture(TRANSACTIONS)
    print(f"capture transactions={TRANSACTIONS} bytes={len(raw)}")
    for flush_every in (1, 64):
        result = run(raw, flush_every)
        print(
            f"flush_every={flush_every} "
            f"transactions/s={result['transactions_per_second']:.0f} "
            f"events/s={result['events_per_second']:.0f} "
            f"wall_us/event={result['wall_usec_per_event']:.2f}"
        )
        print(result["summary"])


if __name__ == "__main__":
    sys.exit(main())
