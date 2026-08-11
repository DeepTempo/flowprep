# PCAP active/inactive timeout defaults (60s / 15s), CLI-overridable

Status: accepted

PCAP flow aggregation previously used a 60s idle split and a 1h max-duration
split, hardcoded and named unlike NetFlow exporter practice. We change the
defaults to an **active timeout** of 60s and an **inactive timeout** of 15s —
common exporter values — and expose both as integer-second CLI flags on
`flowprep pcap`, keeping strict `>` comparisons. This is an intentional
breaking change for default pcap→parquet cardinality (version bump to 0.4.0).

## Considered options

- **Keep 1h active / 60s inactive, hardcoded** — rejected; mismatches common
  NetFlow exporter timeouts and cannot be tuned per capture.
- **New defaults only, still hardcoded** — rejected; operators still cannot
  match a specific exporter profile without a rebuild.
- **Defaults 60s/15s + CLI overrides (chosen)** — matches exporter language and
  lets callers align with their collector without forking flowprep.

## Consequences

- Long or chatty conversations produce more flow records under defaults.
- `inactive > active` and non-positive timeouts are rejected at CLI parse/validate time.
- Other subcommands (`canonicalize`, `ocsf`, `nfcapd`) are unchanged — they
  ingest already-closed flow records.
