<p align="center">
  <img src="assets/deeptempo-logo.png" alt="DeepTempo" width="280">
</p>

<h1 align="center">flowprep</h1>

<p align="center">
  <strong>Network telemetry → ML-ready canonical NetFlow parquet.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://crates.io/crates/flowprep"><img src="https://img.shields.io/crates/v/flowprep.svg" alt="crates.io"></a>
  <img src="https://img.shields.io/badge/rust-stable-orange.svg" alt="Rust stable">
</p>

---

flowprep converts the network telemetry you actually have — packet captures,
flow CSVs, vendor exports — into a single, clean, typed, unit-normalized
parquet table that you can hand directly to a model, a notebook, or a data
pipeline.

It is built and maintained by [DeepTempo](https://deeptempo.ai), where it is
used in production as the ingestion front door for our **LogLM**: flow
telemetry arriving from many different sources and formats is normalized
through this same canonicalization layer, at scale, before it ever reaches
inference. We open-sourced it because everyone working with network flow
data ends up rebuilding this exact step, usually badly, usually more than
once.

## The problem

Every network-ML paper and every SOC data pipeline starts by solving the
same unglamorous problem. Flow data arrives as:

- raw **pcap/pcapng** captures,
- **CSV exports** from research datasets (CIC-IDS, UNSW-NB15, …),
- **nfdump/nfcapd** binaries, **Zeek** logs, **VPC flow logs**,
- and a long tail of vendor formats, each with its own column names,
  duration units, and timestamp encodings.

The same field might be called `src_ip`, `Source IP`, `srcaddr`,
`ipv4_src_addr`, or `client_ip`. A duration might be in seconds,
milliseconds, microseconds, or nanoseconds — and nothing tells you which. A
timestamp might be a datetime string, epoch seconds, or epoch nanoseconds.

Flow *collectors* (goflow2, nfdump) solve transport and storage, but they
stop at JSON, protobuf, or their own binary formats. Feature-extraction
tooling in the research world is fragmented and hard to reproduce. Nothing
hands you a clean parquet table with one schema, ready for training or
inference — including for the new generation of network foundation models.

flowprep is that missing step.

## Quick start

```bash
# install from crates.io (Rust stable, no system dependencies — no libpcap, no JVM)
cargo install flowprep

# or build from source
cargo build --release

# or just run the demo against the bundled examples
./demo.sh
```

Four subcommands:

```bash
# 1. Raw packet captures -> bidirectional flow records
flowprep pcap capture.pcap flows.parquet

# 2. Any aliased flow table (CSV or parquet) -> the canonical schema
flowprep canonicalize cic_export.csv flows.parquet

# 3. OCSF Network Activity events (JSON/NDJSON) -> the canonical schema
flowprep ocsf network_activity.ndjson flows.parquet

# 4. Inspect any parquet file from the terminal, no Python required
flowprep peek flows.parquet -n 20
```

The output is ordinary parquet. There are no bindings to install and no
client library to learn — pandas, polars, DuckDB, Spark, and Arrow in any
language read it natively. **The file format is the API.**

```python
import pandas as pd
df = pd.read_parquet("flows.parquet")   # that's the whole integration
```

## What it does

### Field alias resolution

flowprep knows 100+ column spellings observed in the wild — CICIDS's
`Total Fwd Bytes`, nfdump's `in_bytes`, IPFIX's `l4_src_port`, Zeek-style
names, and many vendor variants — and maps them all onto one canonical
schema. The alias map is not hard-coded: it is loaded at compile time from
a declarative schema file
([`schemas/netflow/v1/schema.json`](schemas/netflow/v1/schema.json)), the
same artifact DeepTempo's production ingestion uses. Adding support for a
new vendor's column names is a JSON edit, not a code change.

### Unit and encoding normalization

- **Durations** arrive in seconds, milliseconds, microseconds, or
  nanoseconds; the unit is inferred from the source column's name
  (`duration_ms`, `flow_duration_microseconds`, …) and everything lands as
  **float64 seconds**.
- **Timestamps** arrive as datetime strings, typed timestamps, or epoch
  values at any precision; epoch precision is inferred from magnitude and
  everything lands as **int64 epoch microseconds**.
- **Protocols** arrive as IANA numbers or names (`tcp`, `udp`, `icmp`);
  names are mapped to numbers.

### OCSF Network Activity events

OCSF (the Open Cybersecurity Schema Framework) is a standard, not a vendor
dialect, so flowprep reads its Network Activity events (`class_uid` 4001)
directly rather than through the alias map. Endpoints come from
`src_endpoint`/`dst_endpoint`, byte and packet counts from `traffic` (with a
top-level `bytes_from_client`/`bytes_from_server` fallback), and `time`/
`duration` are converted from the OCSF millisecond convention to the canonical
epoch-microsecond timestamp and float-second duration. Only flow-close events
(`activity_name` "Closed" or `activity_id` 2) are kept, since those carry the
final byte totals. Input may be NDJSON (one event per line), a JSON array, or a
single object. Events are deserialized into a typed view of the standard's
shape rather than navigated as loose JSON, and malformed records or close
events missing required fields are reported as errors rather than silently
dropped — partial or empty output never looks like success.

### Bidirectional flow aggregation (pcap)

Packets are grouped by a direction-normalized 5-tuple, so both halves of a
conversation aggregate into a single flow record with separate
forward/backward byte and packet counters. Flows split on a 60s idle
timeout and a 1h maximum duration. The reader streams pcap and pcapng,
keeps constant memory on the packet path, and is robust to the
slightly-out-of-order packets real captures contain.

### Label passthrough

Ground-truth columns (`label`, `attack`, `attack_type`, …) survive
canonicalization unchanged, so labeled research datasets stay labeled —
convert once, train immediately.

## Canonical schema

| field | type | notes |
|---|---|---|
| `timestamp` | int64 | flow start, epoch **microseconds** |
| `src_ip` / `dest_ip` | string | |
| `src_port` / `dest_port` | int32 | |
| `fwd_bytes` / `bwd_bytes` | int64 | `bwd` zero-filled for single-counter sources |
| `fwd_pkts` / `bwd_pkts` | int64 | nullable |
| `flow_dur` | float64 | **seconds** |
| `protocol` | int32 | IANA number; names auto-mapped |

Plus any passthrough label columns present in the source.

## Example: a real research dataset

The repo ships a ~100k-row slice of **CIC-IDS-2017** with its original
quirks intact — aliased packet columns (`total_fwd_pkts`), typed datetime
timestamps, and attack labels:

```text
$ flowprep canonicalize examples/cic2017_sample.parquet /tmp/cic.parquet
Wrote 101094 flows to /tmp/cic.parquet        # ~60 ms

$ flowprep peek /tmp/cic.parquet -n 3
+------------------+---------------+--------------+----------+-----------+-----------+-----------+----------+----------+----------+----------+--------+-------+
| timestamp        | src_ip        | dest_ip      | src_port | dest_port | fwd_bytes | bwd_bytes | fwd_pkts | bwd_pkts | flow_dur | protocol | attack | label |
+------------------+---------------+--------------+----------+-----------+-----------+-----------+----------+----------+----------+----------+--------+-------+
| 1488876958000000 | 8.254.250.126 | 192.168.10.5 | 80       | 49188     | 12        | 0         | 2        | 0        | 4e-6     |          | benign | 0     |
| 1488877019000000 | 192.168.10.9  | 192.168.10.3 | 1056     | 88        | 2812      | 2820      | 7        | 4        | 0.000655 |          | benign | 0     |
| 1488877062000000 | 192.168.10.17 | 192.168.10.3 | 35504    | 88        | 3150      | 3152      | 10       | 6        | 0.001122 |          | benign | 0     |
+------------------+---------------+--------------+----------+-----------+-----------+-----------+----------+----------+----------+----------+--------+-------+
```

## Performance

The per-packet decode path is exactly where interpreted languages pay the
serialization tax, and it's why flowprep is a compiled tool. On a 500k-packet
capture (Apple Silicon laptop, single thread):

| implementation | throughput | wall time |
|---|---|---|
| flowprep (Rust) | **~1.4M packets/s** | 0.35 s |
| equivalent Python (dpkt + pyarrow) | ~78k packets/s | 6.4 s |

That's an **18.5x** difference producing byte-identical flow output
(`tests/bench_pcap.py` reproduces the measurement). Canonicalizing the
101k-row CIC sample takes ~60 ms end to end, including parquet read and
zstd-compressed write.

## Design notes

- **Apache Arrow is the data plane.** flowprep is built on
  [`arrow-rs`](https://github.com/apache/arrow-rs) and the `parquet` crate;
  columnar data goes from reader to writer without detours through
  row-by-row object representations.
- **Schema as data, not code.** The canonical field set, alias mappings,
  and unit-detection rules live in one JSON artifact embedded at compile
  time. Tools and pipelines in other languages can consume the same file.
- **Single static binary.** No venv, no JVM, no libpcap, no runtime
  dependencies. `cargo build --release` produces one file you can copy to
  an air-gapped sensor box.

## Production use at DeepTempo

[DeepTempo](https://deeptempo.ai) builds LogLM — a log language model for
network security that turns flow telemetry into embeddings and incident
classifications. Customer flow data arrives in wildly different shapes
(cloud flow logs, IPFIX exporters, pcaps, SIEM exports), and this
canonicalization layer is how all of them converge to the one schema the
model consumes, at production scale, ahead of inference. flowprep is that
layer, maintained in the open: if it mangles a format you care about, the
fix benefits our pipeline and yours equally.

## Roadmap

- nfcapd (nfdump binary) reader
- Zeek `conn.log` reader
- IPv6 flow-tuple test coverage and pcapng per-interface timestamp resolutions
- Published canonical-parquet versions of common research datasets

Contributions welcome — especially "here is a flow export flowprep can't
parse" issues with a small sample attached.

## Development

```bash
cargo build --release

# end-to-end tests (python harness generates fixtures; needs dpkt + pyarrow)
python3 -m venv .venv && .venv/bin/pip install dpkt pyarrow
.venv/bin/python tests/test_e2e.py

# throughput benchmark
.venv/bin/python tests/bench_pcap.py
```

## Release

Releases are tag-driven. Pushing a `v*` tag builds Linux, macOS, and Windows
binaries, attaches them to a GitHub release, and publishes the crate to
crates.io using `CARGO_REGISTRY_TOKEN`.

## Acknowledgments

The bundled example slice derives from the CIC-IDS-2017 dataset:
Sharafaldin, Lashkari & Ghorbani, *"Toward Generating a New Intrusion
Detection Dataset and Intrusion Traffic Characterization"*, ICISSP 2018
(Canadian Institute for Cybersecurity, University of New Brunswick). It is
included solely as a small conversion example; for research use, obtain the
full dataset from [UNB CIC](https://www.unb.ca/cic/datasets/ids-2017.html)
and cite accordingly.

## License

[Apache-2.0](LICENSE) © DeepTempo
