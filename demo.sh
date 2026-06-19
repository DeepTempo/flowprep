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
echo "=== 3. OCSF Network Activity (NDJSON, nested fields, ms units) -> canonical ==="
time $BIN ocsf examples/ocsf_sample.ndjson /tmp/flowprep_demo_ocsf.parquet
$BIN peek /tmp/flowprep_demo_ocsf.parquet -n 5

echo
echo "=== 4. nfdump/nfcapd binary flow file (V2/V3, no nfdump CLI) -> canonical ==="
time $BIN nfcapd examples/sample.nfcapd /tmp/flowprep_demo_nfcapd.parquet
$BIN peek /tmp/flowprep_demo_nfcapd.parquet -n 5

echo
echo "Demo outputs: /tmp/flowprep_demo_pcap.parquet /tmp/flowprep_demo_cic.parquet /tmp/flowprep_demo_ocsf.parquet /tmp/flowprep_demo_nfcapd.parquet"
