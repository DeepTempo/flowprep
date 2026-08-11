# Flowprep

Canonicalization of network telemetry into ML-ready NetFlow parquet.

## Language

**Active timeout**:
The maximum age of an open flow record before it is closed and a new record for the same key is started, even if packets are still arriving.
_Avoid_: max flow duration, max duration, flow lifetime

**Inactive timeout**:
The idle gap after the last packet on a flow key before that open record is closed.
_Avoid_: idle timeout, idle gap, silence timeout

**Flow key**:
The direction-normalized 5-tuple used to aggregate packets into one bidirectional flow record (src/dest IP and port ordered so both halves of a conversation share one key, plus protocol).
_Avoid_: connection, session, conversation (those may span multiple flow records after timeout splits)

**Flow record**:
One closed aggregation for a flow key over a contiguous packet window bounded by active and inactive timeouts (or end of capture).
_Avoid_: flow (alone — ambiguous between key, record, and session), biflow
