#!/usr/bin/env bash
# flowprep end-to-end demo: builds the binary, converts the baked-in example
# pcap and a real CIC-2017 sample (aliased columns, typed timestamps, labels),
# and previews the canonical output. No Python required.
set -euo pipefail
cd "$(dirname "$0")"

cargo build --release --quiet
BIN=target/release/flowprep

echo "=== 1. pcap -> canonical flow parquet ==="
time $BIN pcap examples/sample.pcap /tmp/flowprep_demo_pcap.parquet
$BIN peek /tmp/flowprep_demo_pcap.parquet -n 5

echo
echo "=== 2. CIC-2017 (aliased columns: total_fwd_pkts, datetime timestamps) -> canonical ==="
time $BIN canonicalize examples/cic2017_sample.parquet /tmp/flowprep_demo_cic.parquet
$BIN peek /tmp/flowprep_demo_cic.parquet -n 5

echo
echo "Demo outputs: /tmp/flowprep_demo_pcap.parquet /tmp/flowprep_demo_cic.parquet"
