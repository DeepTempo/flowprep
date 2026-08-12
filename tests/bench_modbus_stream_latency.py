"""Measure incremental packet-to-NDJSON latency for the long-lived sensor.

This intentionally feeds one complete PCAP record at a time and waits for its
event. The external measurement includes pipe scheduling, JSON serialization,
and the default per-event flush; ``sensor_processing_usec`` is also summarized
to separate the in-process parser path from transport/test-harness overhead.
"""

import json
import math
import os
import subprocess
import sys
import time

from bench_modbus_stream import FLOWPREP_BIN, build_capture
from test_modbus_stream_e2e import split_legacy_pcap


TRANSACTIONS = int(os.environ.get("MODBUS_LATENCY_TRANSACTIONS", "1000"))
WARMUP_TRANSACTIONS = int(os.environ.get("MODBUS_LATENCY_WARMUP", "10"))
BUDGET_USEC = int(os.environ.get("MODBUS_LATENCY_BUDGET_USEC", "50000"))


def percentile(values, percent):
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * percent / 100) - 1)
    return ordered[index]


def summarize(label, values):
    print(
        f"{label}: p50={percentile(values, 50)}us "
        f"p95={percentile(values, 95)}us "
        f"p99={percentile(values, 99)}us max={max(values)}us"
    )


def main():
    total_transactions = WARMUP_TRANSACTIONS + TRANSACTIONS
    header, records = split_legacy_pcap(build_capture(total_transactions))
    assert len(records) == total_transactions * 2

    process = subprocess.Popen(
        [FLOWPREP_BIN, "modbus-stream", "--sensor-id", "latency-benchmark"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    process.stdin.write(header)
    process.stdin.flush()

    external_usec = []
    internal_usec = []
    first_event_usec = None
    warmup_records = WARMUP_TRANSACTIONS * 2
    for index, record in enumerate(records):
        started = time.perf_counter_ns()
        process.stdin.write(record)
        process.stdin.flush()
        line = process.stdout.readline()
        elapsed_usec = (time.perf_counter_ns() - started) // 1000
        assert line, "sensor stdout closed before the expected event"
        event = json.loads(line)
        assert event["register_values"] == [10, 20]
        if index == 0:
            first_event_usec = elapsed_usec
        if index >= warmup_records:
            external_usec.append(elapsed_usec)
            internal_usec.append(event["sensor_processing_usec"])

    process.stdin.close()
    return_code = process.wait(timeout=5)
    stderr = process.stderr.read().decode().strip()
    assert return_code == 0, stderr
    assert len(external_usec) == TRANSACTIONS * 2

    print(
        f"transactions={TRANSACTIONS} events={len(external_usec)} "
        f"budget={BUDGET_USEC}us first_event_with_startup={first_event_usec}us"
    )
    summarize("external packet-to-flushed-NDJSON", external_usec)
    summarize("internal packet parse-to-record", internal_usec)
    print(stderr)

    p99 = percentile(external_usec, 99)
    if p99 >= BUDGET_USEC:
        print(f"LATENCY BUDGET FAILED: p99 {p99}us >= {BUDGET_USEC}us", file=sys.stderr)
        return 1
    print(f"LATENCY BUDGET PASSED: p99 {p99}us < {BUDGET_USEC}us")
    return 0


if __name__ == "__main__":
    sys.exit(main())
