//! Map arbitrarily-named flow tables onto the canonical NetFlow schema.
//!
//! Handles the three things every vendor export gets differently: column
//! naming (alias map), duration units (inferred from the source column
//! name), and timestamp encoding (epoch s/ms/us/ns or string datetimes,
//! inferred from magnitude/type).

use std::borrow::Cow;
use std::fs::File;
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::sync::Arc;

use arrow::array::{Array, ArrayRef, Float64Array, Int32Array, Int64Array, StringArray};
use arrow::compute::{cast, concat_batches};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;

use crate::schema::{
    REQUIRED_FIELDS, canonical_schema, load_schema_spec, normalize_name, protocol_number,
};
use crate::writer::write_parquet;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn canonicalize_file(input: &str, output: &str) -> Result<usize> {
    let batch = read_table(input)?;
    let out = canonicalize(&batch)?;
    write_parquet(&out, output)?;
    Ok(out.num_rows())
}

/// Parquet's file magic, written at both the start and the end of the file.
const PARQUET_MAGIC: &[u8; 4] = b"PAR1";

/// Detect parquet from file content rather than from the file extension.
///
/// The extension is not a reliable signal for flow exports: Argus writes
/// `.binetflow`, plenty of flow CSVs arrive as `.txt` or with no extension at
/// all, and keying on `.csv` alone sent every one of them to the parquet reader
/// to fail on a confusing error. Both the leading and the trailing magic are
/// checked, so a delimited-text file whose first column happens to be named
/// `PAR1` cannot be mistaken for parquet.
fn is_parquet<R: Read + Seek>(reader: &mut R) -> Result<bool> {
    let magic_len = PARQUET_MAGIC.len();
    // A valid parquet file carries the magic twice, so it cannot be shorter.
    if reader.seek(SeekFrom::End(0))? < 2 * magic_len as u64 {
        return Ok(false);
    }
    let mut buf = [0u8; 4];
    reader.rewind()?;
    reader.read_exact(&mut buf)?;
    if &buf != PARQUET_MAGIC {
        return Ok(false);
    }
    reader.seek(SeekFrom::End(-(magic_len as i64)))?;
    reader.read_exact(&mut buf)?;
    Ok(&buf == PARQUET_MAGIC)
}

/// A Zeek log's `#`-prefixed preamble. Zeek keeps the column names and types
/// out of band, so without reading it the columns have no names to resolve
/// aliases against.
struct ZeekPreamble {
    separator: u8,
    fields: Vec<String>,
    types: Vec<String>,
    unset: String,
    empty: String,
}

/// Decode `#separator \x09` (the escape is written literally) into a byte.
fn decode_zeek_separator(line: &str) -> u8 {
    let spec = line.trim_end_matches(['\n', '\r']);
    // Strip the key, keeping any literal separator byte that follows it.
    let spec = spec
        .strip_prefix("#separator ")
        .or_else(|| spec.strip_prefix("#separator"))
        .unwrap_or("");
    if let Some(hex) = spec.strip_prefix("\\x") {
        // An escape that does not decode is not a literal backslash separator —
        // fall back to Zeek's default rather than picking up the '\'.
        return u8::from_str_radix(hex.trim(), 16).unwrap_or(b'\t');
    }
    spec.as_bytes().first().copied().unwrap_or(b'\t')
}

/// Read a Zeek log preamble, or `None` when the file is not a Zeek log.
///
/// Zeek writes its schema as directives before the data:
///   #separator \x09
///   #unset_field  -
///   #fields   ts  uid  id.orig_h  id.orig_p  ...
///   #types    time  string  addr  port  ...
fn read_zeek_preamble(path: &str) -> Result<Option<ZeekPreamble>> {
    let mut reader = std::io::BufReader::new(File::open(path)?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 || !line.starts_with("#separator") {
        return Ok(None);
    }
    let separator = decode_zeek_separator(&line);
    let mut preamble = ZeekPreamble {
        separator,
        fields: Vec::new(),
        types: Vec::new(),
        unset: "-".to_string(),
        empty: "(empty)".to_string(),
    };
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if !line.starts_with('#') {
            break;
        }
        let cleaned = line.trim_end_matches(['\n', '\r']);
        let mut parts = cleaned.split(separator as char);
        match parts.next().unwrap_or("") {
            "#fields" => preamble.fields = parts.map(str::to_string).collect(),
            "#types" => preamble.types = parts.map(str::to_string).collect(),
            "#unset_field" => {
                if let Some(v) = parts.next() {
                    preamble.unset = v.to_string();
                }
            }
            "#empty_field" => {
                if let Some(v) = parts.next() {
                    preamble.empty = v.to_string();
                }
            }
            _ => {}
        }
    }
    if preamble.fields.is_empty() {
        return Err("Zeek log has a #separator directive but no #fields line".into());
    }
    Ok(Some(preamble))
}

/// Map a Zeek type name to the arrow type it should become. `None` means leave
/// it as text (`string`, `addr`, `enum`, `bool`, `set[..]`, `vector[..]`).
fn zeek_arrow_type(declared: &str) -> Option<DataType> {
    match declared {
        "time" | "interval" | "double" => Some(DataType::Float64),
        "count" | "int" | "port" => Some(DataType::Int64),
        _ => None,
    }
}

/// Apply Zeek's declared types, substituting 0 for unset numeric values.
///
/// Zeek marks a field it did not measure with `-` (and an empty one with
/// `(empty)`). On roughly 15% of real conn.log rows that covers `duration`,
/// `orig_bytes` and `resp_bytes` together — connections it saw but did not fully
/// analyse — while the packet counts stay populated. `flow_dur` and `fwd_bytes`
/// are non-nullable canonically, so the alternative to a substitute is failing
/// every such file.
///
/// 0 is close to the truth for these rows (they are single-packet or unanalysed
/// connections) and, more importantly, it stays visible: `flow_check`'s
/// `bytes.zero_with_packets` check exists for exactly this signature — zero bytes
/// against non-zero packets — so the substituted rows get flagged rather than
/// passing silently. Scoped to the Zeek reader, so no other format's behaviour
/// changes.
fn apply_zeek_types(batch: &RecordBatch, preamble: &ZeekPreamble) -> Result<RecordBatch> {
    let mut substituted = 0usize;
    let mut fields: Vec<Field> = Vec::with_capacity(batch.num_columns());
    let mut columns: Vec<ArrayRef> = Vec::with_capacity(batch.num_columns());

    for (i, field) in batch.schema().fields().iter().enumerate() {
        let declared = preamble.types.get(i).map(String::as_str).unwrap_or("");
        let Some(target) = zeek_arrow_type(declared) else {
            fields.push(field.as_ref().clone());
            columns.push(batch.column(i).clone());
            continue;
        };
        let text = batch
            .column(i)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or("Zeek columns are read as text")?;
        let mut values: Vec<Option<&str>> = Vec::with_capacity(text.len());
        for value in text.iter() {
            match value {
                Some(s) if s == preamble.unset || s == preamble.empty => {
                    substituted += 1;
                    values.push(Some("0"));
                }
                other => values.push(other),
            }
        }
        let filled: ArrayRef = Arc::new(StringArray::from(values));
        fields.push(Field::new(field.name(), target.clone(), true));
        columns.push(cast(&filled, &target)?);
    }

    if substituted > 0 {
        eprintln!(
            "canonicalize: zeek — substituted 0 for {substituted} unset numeric value(s) \
             (Zeek writes '{}' where it did not measure a field; flow_check's \
             bytes.zero_with_packets surfaces the affected rows)",
            preamble.unset
        );
    }
    Ok(RecordBatch::try_new(
        Arc::new(Schema::new(fields)),
        columns,
    )?)
}

/// Read a Zeek TSV log into a batch, using its own declared schema.
fn read_zeek_table(path: &str, preamble: &ZeekPreamble) -> Result<RecordBatch> {
    // Every column is read as text first: Zeek's unset marker `-` sits in
    // numeric columns, and arrow's typed CSV parser rejects it outright.
    let schema = Arc::new(Schema::new(
        preamble
            .fields
            .iter()
            .map(|name| Field::new(name, DataType::Utf8, true))
            .collect::<Vec<_>>(),
    ));
    let format = arrow::csv::reader::Format::default()
        .with_header(false)
        .with_delimiter(preamble.separator)
        .with_comment(b'#');
    let reader = arrow::csv::ReaderBuilder::new(schema)
        .with_format(format)
        .build(File::open(path)?)?;
    let batches: Vec<RecordBatch> = reader.collect::<std::result::Result<_, _>>()?;
    if batches.is_empty() {
        return Err("input file contains no rows".into());
    }
    let batch = concat_batches(&batches[0].schema(), &batches)?;
    apply_zeek_types(&trim_text_columns(&batch)?, preamble)
}

fn read_table(path: &str) -> Result<RecordBatch> {
    let parquet = {
        let mut probe = File::open(path)?;
        is_parquet(&mut probe)?
    };
    // Zeek logs are delimited text but carry their schema in a `#` preamble, so
    // they need reading before the generic CSV path guesses at a header row.
    if !parquet {
        if let Some(preamble) = read_zeek_preamble(path)? {
            return read_zeek_table(path, &preamble);
        }
    }
    let batches: Vec<RecordBatch> = if parquet {
        let file = File::open(path)?;
        let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file)?
            .build()?;
        reader.collect::<std::result::Result<_, _>>()?
    } else {
        let mut file = File::open(path)?;
        let format = arrow::csv::reader::Format::default().with_header(true);
        // Infer over the WHOLE file, not a leading sample. Sampling the first N
        // rows makes the read fail outright when a column's type widens later:
        // a real CICFlowMeter export types column 75 as Int64 from its first
        // 1000 rows, then hits `4308037.666666667` at line 5130 and dies —
        // before canonicalize ever runs, on a column flowprep does not even use.
        // Costs one extra sequential pass, which is cheap next to being unable
        // to read the file at all.
        let (schema, _) = format.infer_schema(&mut file, None)?;
        let file = File::open(path)?;
        let reader = arrow::csv::ReaderBuilder::new(Arc::new(schema))
            .with_format(format)
            .build(file)?;
        reader.collect::<std::result::Result<_, _>>()?
    };
    if batches.is_empty() {
        return Err("input file contains no rows".into());
    }
    let batch = concat_batches(&batches[0].schema(), &batches)?;
    // Padding is a text-format artifact, so only delimited input needs it
    // stripped; parquet columns arrive already typed.
    if parquet {
        Ok(batch)
    } else {
        trim_text_columns(&batch)
    }
}

/// Strip surrounding whitespace from every text column.
///
/// nfdump-derived exports right-align their fields: CIDDS writes `Src Pt` as
/// `" 44870"`, `Duration` as `"    0.003"` and `Proto` as `"TCP  "`. Arrow's
/// casts do not trim, so `" 44870"` casts to null — and with `flow_dur`
/// non-nullable a padded duration fails the whole file.
///
/// Done once, centrally, rather than at each use site, because whitespace is
/// never meaningful in any canonical field. It matters for labels too: `"normal "`
/// and `"normal"` would otherwise count as two distinct classes downstream.
fn trim_text_columns(batch: &RecordBatch) -> Result<RecordBatch> {
    let columns: Vec<ArrayRef> = batch
        .columns()
        .iter()
        .map(
            |column| match column.as_any().downcast_ref::<StringArray>() {
                Some(strings) => Arc::new(
                    strings
                        .iter()
                        .map(|v| v.map(str::trim))
                        .collect::<StringArray>(),
                ) as ArrayRef,
                None => column.clone(),
            },
        )
        .collect();
    Ok(RecordBatch::try_new(batch.schema(), columns)?)
}

pub fn canonicalize(batch: &RecordBatch) -> Result<RecordBatch> {
    let spec = load_schema_spec();
    let source_names: Vec<String> = batch
        .schema()
        .fields()
        .iter()
        .map(|f| f.name().clone())
        .collect();
    let resolved = spec.resolve_columns(&source_names);

    let missing: Vec<&&str> = REQUIRED_FIELDS
        .iter()
        .filter(|f| !resolved.contains_key(**f))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "cannot resolve required fields {missing:?} from columns {source_names:?}"
        )
        .into());
    }

    let col = |canonical: &str| -> ArrayRef {
        batch
            .column_by_name(&resolved[canonical])
            .expect("resolved column exists")
            .clone()
    };
    let n = batch.num_rows();

    let (src_port, src_coerced) = port_to_i32(&col("src_port"))?;
    let (dest_port, dest_coerced) = port_to_i32(&col("dest_port"))?;
    if src_coerced + dest_coerced > 0 {
        eprintln!(
            "canonicalize: coerced {src_coerced} src_port and {dest_coerced} dest_port \
             value(s) to 0 — absent, or not a number (e.g. Argus writes hex ICMP \
             type/code such as 0x0303 into Sport/Dport)"
        );
    }

    let mut columns: Vec<ArrayRef> = vec![
        timestamp_to_micros(&col("timestamp"))?,
        cast(&col("src_ip"), &DataType::Utf8)?,
        cast(&col("dest_ip"), &DataType::Utf8)?,
        src_port,
        dest_port,
        to_rounded_i64(&col("fwd_bytes"))?,
    ];

    if resolved.contains_key("bwd_bytes") {
        columns.push(to_rounded_i64(&col("bwd_bytes"))?);
    } else {
        columns.push(Arc::new(Int64Array::from(vec![0i64; n])));
    }

    for pkts in ["fwd_pkts", "bwd_pkts"] {
        if resolved.contains_key(pkts) {
            // Same reader as bytes: nfdump suffixes packet counts too, and a
            // text column of "2.0"-style values must not silently become null.
            columns.push(to_rounded_i64(&col(pkts))?);
        } else {
            columns.push(Arc::new(Int64Array::from(vec![None::<i64>; n])));
        }
    }

    let dur_source = normalize_name(&resolved["flow_dur"]);
    let divisor = spec
        .duration_divisors
        .get(&dur_source)
        .copied()
        .unwrap_or(1.0);
    let dur = cast(&col("flow_dur"), &DataType::Float64)?;
    let dur = dur.as_any().downcast_ref::<Float64Array>().unwrap();
    columns.push(Arc::new(Float64Array::from_iter(
        dur.iter().map(|v| v.map(|x| x / divisor)),
    )));

    if resolved.contains_key("protocol") {
        columns.push(protocol_to_number(&col("protocol"))?);
    } else {
        columns.push(Arc::new(Int32Array::from(vec![None::<i32>; n])));
    }

    let mut fields: Vec<Field> = canonical_schema()
        .fields()
        .iter()
        .map(|f| f.as_ref().clone())
        .collect();

    // Ground-truth labels survive canonicalization.
    for label in &spec.passthrough {
        if let Some(source) = source_names.iter().find(|s| &normalize_name(s) == label) {
            if !fields.iter().any(|f| f.name() == label) {
                fields.push(Field::new(label, DataType::Utf8, true));
                columns.push(cast(
                    batch.column_by_name(source).unwrap(),
                    &DataType::Utf8,
                )?);
            }
        }
    }

    Ok(RecordBatch::try_new(
        Arc::new(Schema::new(fields)),
        columns,
    )?)
}

/// Rewrite a leading `YYYY/MM/DD` date as `YYYY-MM-DD`.
///
/// Argus writes `StartTime` as `2011/08/18 10:21:46.633335`. Arrow's
/// string→timestamp cast accepts only dash-separated dates, so the slash form
/// casts to null instead of erroring — and because `timestamp` is non-nullable
/// in the canonical schema the failure surfaces much later as a confusing
/// "declared as non-nullable but contains null values" write error.
///
/// Only the unambiguous `dddd/dd/dd` shape is rewritten. Day-first and
/// month-first slash formats (`18/08/2011`, `08/18/2011`) are left alone: they
/// cannot be told apart without external knowledge, so guessing would risk
/// silently transposing month and day.
fn normalize_slash_date(value: &str) -> Cow<'_, str> {
    let b = value.as_bytes();
    let is_ymd_slash = b.len() >= 10
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'/'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'/'
        && b[8..10].iter().all(u8::is_ascii_digit);
    if !is_ymd_slash {
        return Cow::Borrowed(value);
    }
    let mut owned = value.to_string();
    owned.replace_range(4..5, "-");
    owned.replace_range(7..8, "-");
    Cow::Owned(owned)
}

/// Which component of an `A/B/YYYY` date is the month.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlashDateOrder {
    MonthFirst,
    DayFirst,
}

/// Parse the leading `A/B/YYYY` of a value into `(a, b, year_and_remainder)`.
///
/// Returns `None` for anything else — including the `YYYY/MM/DD` shape, whose
/// first component is four digits, so that form stays with
/// `normalize_slash_date` where it is unambiguous.
fn slash_date_parts(value: &str) -> Option<(u32, u32, &str)> {
    let mut it = value.trim().splitn(3, '/');
    let a = it.next()?;
    let b = it.next()?;
    let tail = it.next()?;
    let two_digit = |s: &str| (1..=2).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_digit());
    if !two_digit(a) || !two_digit(b) || tail.len() < 4 {
        return None;
    }
    if !tail.as_bytes()[..4].iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some((a.parse().ok()?, b.parse().ok()?, tail))
}

/// Decide whether a column of `A/B/YYYY` dates is month-first or day-first.
///
/// Evidence beats assumption: a first component over 12 can only be a day, and a
/// second component over 12 can only be a day, so one such value anywhere in the
/// column proves the ordering. CICFlowMeter v4 writes `20/11/2020`, which proves
/// itself.
///
/// When nothing proves it the file is irreducibly ambiguous — a CICIDS2017
/// per-day export contains the single date `7/7/2017` and no more — and we assume
/// month-first, which is what CICIDS2017 and most CIC tooling emit. Either way
/// the decision is logged, so a wrong assumption is visible rather than silent.
///
/// `Ok(None)` means the column holds no such dates at all, so nothing is logged.
fn infer_slash_date_order(values: &StringArray) -> Result<Option<SlashDateOrder>> {
    let (mut seen, mut day_first, mut month_first) = (false, false, false);
    for value in values.iter().flatten() {
        if let Some((a, b, _)) = slash_date_parts(value) {
            seen = true;
            day_first |= a > 12;
            month_first |= b > 12;
        }
    }
    if !seen {
        return Ok(None);
    }
    match (day_first, month_first) {
        (true, true) => Err("timestamp column mixes D/M/YYYY and M/D/YYYY dates; \
                             no single ordering can be correct"
            .into()),
        (true, false) => {
            eprintln!("canonicalize: timestamp dates read as D/M/YYYY (proven: a day over 12)");
            Ok(Some(SlashDateOrder::DayFirst))
        }
        (false, true) => {
            eprintln!("canonicalize: timestamp dates read as M/D/YYYY (proven: a day over 12)");
            Ok(Some(SlashDateOrder::MonthFirst))
        }
        (false, false) => {
            eprintln!(
                "canonicalize: timestamp dates ASSUMED M/D/YYYY — no value in the column has a \
                 component over 12, so the ordering cannot be proven (CICIDS2017 per-day exports \
                 look like this). If this source is day-first, every date is wrong."
            );
            Ok(Some(SlashDateOrder::MonthFirst))
        }
    }
}

/// Rewrite `A/B/YYYY[ H:M[:S]]` as `YYYY-MM-DD HH:MM:SS`, which arrow can cast.
///
/// The time fragment is zero-padded because sources are inconsistent about it:
/// CICIDS2017 writes `7/7/2017 3:30` (single-digit hour, no seconds) while
/// CICFlowMeter v4 writes `20/11/2020 09:50:19`. Note CICIDS2017 omits AM/PM
/// entirely, so `3:30` is taken literally as 03:30 — a known flaw of that export,
/// not something this can recover.
fn rewrite_slash_date(value: &str, order: SlashDateOrder) -> Option<String> {
    let (a, b, tail) = slash_date_parts(value)?;
    let (month, day) = match order {
        SlashDateOrder::MonthFirst => (a, b),
        SlashDateOrder::DayFirst => (b, a),
    };
    let year = &tail[..4];
    let mut time = tail[4..].trim().split(':');
    let parse_or_zero = |part: Option<&str>| -> Option<u32> {
        match part.map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) => s.parse().ok(),
            None => Some(0),
        }
    };
    let hour = parse_or_zero(time.next())?;
    let minute = parse_or_zero(time.next())?;
    let second = time
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("00");
    Some(format!(
        "{year}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:0>2}"
    ))
}

/// Coerce a timestamp column to epoch microseconds (int64).
fn timestamp_to_micros(column: &ArrayRef) -> Result<ArrayRef> {
    match column.data_type() {
        DataType::Timestamp(_, _) => {
            let ts = cast(column, &DataType::Timestamp(TimeUnit::Microsecond, None))?;
            Ok(cast(&ts, &DataType::Int64)?)
        }
        DataType::Utf8 | DataType::LargeUtf8 => {
            let strings = cast(column, &DataType::Utf8)?;
            let strings = strings.as_any().downcast_ref::<StringArray>().unwrap();
            let order = infer_slash_date_order(strings)?;
            let normalized: ArrayRef = Arc::new(
                strings
                    .iter()
                    .map(|v| {
                        v.map(|s| match order.and_then(|o| rewrite_slash_date(s, o)) {
                            Some(rewritten) => rewritten,
                            None => normalize_slash_date(s).into_owned(),
                        })
                    })
                    .collect::<StringArray>(),
            );
            let ts = cast(
                &normalized,
                &DataType::Timestamp(TimeUnit::Microsecond, None),
            )?;
            Ok(cast(&ts, &DataType::Int64)?)
        }
        _ => {
            let floats = cast(column, &DataType::Float64)?;
            let floats = floats.as_any().downcast_ref::<Float64Array>().unwrap();
            let max = floats.iter().flatten().fold(0.0f64, f64::max);
            // Magnitude heuristic: epoch seconds ~1e9, ms ~1e12, us ~1e15, ns ~1e18.
            let factor = if max < 1e11 {
                1e6
            } else if max < 1e14 {
                1e3
            } else if max < 1e17 {
                1.0
            } else {
                1e-3
            };
            Ok(Arc::new(Int64Array::from_iter(
                floats.iter().map(|v| v.map(|x| (x * factor) as i64)),
            )))
        }
    }
}

/// Cast a port column to `Int32`, substituting 0 for anything that does not
/// parse. Returns the array plus how many values were substituted.
///
/// `src_port`/`dest_port` are non-nullable in the canonical schema, so the only
/// alternative to a sentinel is failing the whole file. Real exports routinely
/// have no usable port: protocols that carry none (arp, igmp, ipx/spx) leave the
/// field empty, and Argus packs ICMP type/code into it as hex (`0x0303`), which
/// is not a port at all. 0 is the sentinel flowprep's own nfcapd reader already
/// emits for ICMP, so this keeps the two readers consistent.
///
/// Note this applies to every `canonicalize` input, not just Argus. It is purely
/// additive: a file that converts today has no unparseable ports by definition,
/// so no existing behaviour changes. Downstream, a flood of zero ports is
/// visible rather than silent — `flow_check` has `structure.port_zero` and
/// `integrity.port_range` for exactly this.
fn port_to_i32(column: &ArrayRef) -> Result<(ArrayRef, usize)> {
    // arrow's default cast is safe: unparseable input becomes null, not an error.
    let ints = cast(column, &DataType::Int32)?;
    let coerced = ints.null_count();
    if coerced == 0 {
        return Ok((ints, coerced));
    }
    let typed = ints.as_any().downcast_ref::<Int32Array>().unwrap();
    let filled = Int32Array::from_iter_values(typed.iter().map(|v| v.unwrap_or(0)));
    Ok((Arc::new(filled), coerced))
}

/// Expand an nfdump-style magnitude suffix into a plain number.
///
/// nfdump writes large counters human-readably, and CIDDS — which is derived
/// from it — inherits that: a `Bytes` column holds plain integers and values
/// like `"1.4 M"` side by side. Arrow types such a column as Utf8 and casts the
/// suffixed entries to null, so with `fwd_bytes` non-nullable a single suffixed
/// row fails the entire file.
fn parse_magnitude(value: &str) -> Option<f64> {
    let trimmed = value.trim();
    // Slicing at len-1 is safe: we only do it when the last byte is ASCII,
    // which is always a char boundary.
    let (digits, multiplier) = match trimmed.as_bytes().last()?.to_ascii_uppercase() {
        b'K' => (&trimmed[..trimmed.len() - 1], 1e3),
        b'M' => (&trimmed[..trimmed.len() - 1], 1e6),
        b'G' => (&trimmed[..trimmed.len() - 1], 1e9),
        b'T' => (&trimmed[..trimmed.len() - 1], 1e12),
        _ => (trimmed, 1.0),
    };
    digits.trim().parse::<f64>().ok().map(|v| v * multiplier)
}

/// Cast a counter column (bytes, packets) to `Int64`, rounding, and expanding
/// nfdump magnitude suffixes when the column arrived as text.
///
/// Deliberately does NOT substitute a sentinel for unparseable input, unlike
/// `port_to_i32`: a byte or packet count of 0 is meaningful data, so quietly
/// inventing one would corrupt a measure rather than fill in a field the source
/// genuinely lacks. Truly unparseable counters stay null — which fails the file
/// for non-nullable `fwd_bytes`, loudly and on purpose.
fn to_rounded_i64(column: &ArrayRef) -> Result<ArrayRef> {
    if matches!(column.data_type(), DataType::Utf8 | DataType::LargeUtf8) {
        let strings = cast(column, &DataType::Utf8)?;
        let strings = strings.as_any().downcast_ref::<StringArray>().unwrap();
        return Ok(Arc::new(Int64Array::from_iter(
            strings
                .iter()
                .map(|v| v.and_then(parse_magnitude).map(|x| x.round() as i64)),
        )));
    }
    let floats = cast(column, &DataType::Float64)?;
    let floats = floats.as_any().downcast_ref::<Float64Array>().unwrap();
    Ok(Arc::new(Int64Array::from_iter(
        floats.iter().map(|v| v.map(|x| x.round() as i64)),
    )))
}

fn protocol_to_number(column: &ArrayRef) -> Result<ArrayRef> {
    if column.data_type().is_integer() {
        return Ok(cast(column, &DataType::Int32)?);
    }
    let strings = cast(column, &DataType::Utf8)?;
    let strings = strings.as_any().downcast_ref::<StringArray>().unwrap();
    Ok(Arc::new(Int32Array::from_iter(
        strings.iter().map(|v| v.and_then(protocol_number)),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sniff(bytes: &[u8]) -> bool {
        is_parquet(&mut Cursor::new(bytes.to_vec())).expect("sniff succeeds")
    }

    /// The Argus/CTU-13 header, verbatim. `.binetflow` files are comma-delimited
    /// text, so content detection must route them to the CSV reader.
    const ARGUS_HEADER: &str = "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,\
                                sTos,dTos,TotPkts,TotBytes,SrcBytes,Label";

    #[test]
    fn detects_parquet_by_magic_not_extension() {
        // Magic at both ends is parquet, whatever the file is called.
        assert!(sniff(b"PAR1....payload....PAR1"));
        // Argus text named `.binetflow` is not parquet.
        assert!(!sniff(ARGUS_HEADER.as_bytes()));
    }

    #[test]
    fn rejects_partial_parquet_magic() {
        // Leading magic only: a CSV whose first column is literally `PAR1`
        // must not be handed to the parquet reader.
        assert!(!sniff(b"PAR1,src_ip,dest_ip\n1,2,3\n"));
        // Trailing magic only.
        assert!(!sniff(b"not parquet at all PAR1"));
        // Too short to carry the magic twice.
        assert!(!sniff(b"PAR1"));
        assert!(!sniff(b""));
    }

    #[test]
    fn argus_header_resolves_every_required_field() {
        let names: Vec<String> = ARGUS_HEADER.split(',').map(|s| s.to_string()).collect();
        let resolved = load_schema_spec().resolve_columns(&names);

        for field in REQUIRED_FIELDS {
            assert!(
                resolved.contains_key(*field),
                "Argus header should resolve {field}, got {resolved:?}"
            );
        }
        assert_eq!(
            resolved.get("timestamp").map(String::as_str),
            Some("StartTime")
        );
        assert_eq!(resolved.get("flow_dur").map(String::as_str), Some("Dur"));
        assert_eq!(resolved.get("src_ip").map(String::as_str), Some("SrcAddr"));
        assert_eq!(resolved.get("dest_ip").map(String::as_str), Some("DstAddr"));
    }

    /// Argus `TotBytes`/`TotPkts` are *totals*, not directional measures.
    /// Mapping either onto a fwd_* field would inflate forward volume and
    /// corrupt downstream byte-conservation and direction checks, so
    /// `fwd_bytes` must come from `SrcBytes` and the packet counts must stay
    /// unresolved (canonicalize null-fills them) until a derived-field
    /// mechanism can compute `TotBytes - SrcBytes`.
    #[test]
    fn argus_totals_are_not_mistaken_for_directional_counts() {
        let names: Vec<String> = ARGUS_HEADER.split(',').map(|s| s.to_string()).collect();
        let resolved = load_schema_spec().resolve_columns(&names);

        assert_eq!(
            resolved.get("fwd_bytes").map(String::as_str),
            Some("SrcBytes")
        );
        assert!(
            !resolved.contains_key("bwd_bytes"),
            "TotBytes is not bwd_bytes"
        );
        assert!(
            !resolved.contains_key("fwd_pkts"),
            "TotPkts is not fwd_pkts"
        );
        assert!(!resolved.contains_key("bwd_pkts"));
    }

    /// `Dur` is seconds in Argus. Guard the divisor explicitly rather than
    /// relying on the unmatched-name fallback.
    #[test]
    fn argus_duration_is_seconds() {
        let spec = load_schema_spec();
        assert_eq!(spec.duration_divisors.get("dur").copied(), Some(1.0));
    }

    /// CIDDS-001/002, as produced by nfdump. Note the label column is named
    /// `class` in the OpenStack/ExternalServer captures and `label` in the
    /// `traffic__week*` ones — both must survive.
    const CIDDS_HEADER: &str = "Date first seen,Duration,Proto,Src IP Addr,Src Pt,Dst IP Addr,\
                                Dst Pt,Packets,Bytes,Flows,Flags,Tos,class,attackType,attackID,\
                                attackDescription";

    #[test]
    fn cidds_header_resolves_every_required_field() {
        let names: Vec<String> = CIDDS_HEADER.split(',').map(|s| s.to_string()).collect();
        let resolved = load_schema_spec().resolve_columns(&names);

        for field in REQUIRED_FIELDS {
            assert!(
                resolved.contains_key(*field),
                "CIDDS header should resolve {field}, got {resolved:?}"
            );
        }
        assert_eq!(
            resolved.get("timestamp").map(String::as_str),
            Some("Date first seen")
        );
        assert_eq!(
            resolved.get("src_ip").map(String::as_str),
            Some("Src IP Addr")
        );
        assert_eq!(resolved.get("src_port").map(String::as_str), Some("Src Pt"));
        assert_eq!(
            resolved.get("dest_port").map(String::as_str),
            Some("Dst Pt")
        );
        // CIDDS rows are unidirectional, so its single Bytes/Packets totals are
        // genuinely the forward direction for that row.
        assert_eq!(resolved.get("fwd_bytes").map(String::as_str), Some("Bytes"));
    }

    #[test]
    fn cidds_label_columns_are_passthrough() {
        let spec = load_schema_spec();
        for col in ["class", "attacktype", "label"] {
            assert!(
                spec.passthrough.iter().any(|p| p == col),
                "{col} should be preserved as a ground-truth label"
            );
        }
    }

    #[test]
    fn expands_nfdump_magnitude_suffixes() {
        // Real CIDDS shapes: 10,748 rows of one 1.09 GB file carry "<float> M".
        assert_eq!(parse_magnitude("1.4 M"), Some(1_400_000.0));
        assert_eq!(parse_magnitude("999.9 M"), Some(999_900_000.0));
        assert_eq!(parse_magnitude("2 K"), Some(2_000.0));
        assert_eq!(parse_magnitude("1.5G"), Some(1_500_000_000.0));
        assert_eq!(parse_magnitude("3 T"), Some(3e12));
        // Plain numbers are untouched.
        assert_eq!(parse_magnitude("174"), Some(174.0));
        assert_eq!(parse_magnitude("  46  "), Some(46.0));
        assert_eq!(parse_magnitude("8.0"), Some(8.0));
        // Junk yields None rather than a wrong number.
        assert_eq!(parse_magnitude(""), None);
        assert_eq!(parse_magnitude("---"), None);
        assert_eq!(parse_magnitude("M"), None);
    }

    #[test]
    fn counter_columns_expand_suffixes_but_keep_junk_null() {
        let raw: ArrayRef = Arc::new(StringArray::from(vec![
            Some("174"),
            Some("1.4 M"),
            Some("---"),
            None,
        ]));
        let out = to_rounded_i64(&raw).expect("counter cast succeeds");
        let out = out.as_any().downcast_ref::<Int64Array>().unwrap();
        assert_eq!(out.value(0), 174);
        assert_eq!(out.value(1), 1_400_000);
        // A byte count of 0 is meaningful data, so junk must NOT become 0 —
        // it stays null and fails the file loudly for non-nullable fwd_bytes.
        assert!(out.is_null(2) && out.is_null(3));
    }

    #[test]
    fn decodes_zeek_separator_directive() {
        // Zeek writes the escape literally, as four characters.
        assert_eq!(decode_zeek_separator("#separator \\x09\n"), b'\t');
        assert_eq!(decode_zeek_separator("#separator \\x2c"), b',');
        // A writer that emits the literal byte instead.
        assert_eq!(decode_zeek_separator("#separator\t"), b'\t');
        // Nothing usable falls back to tab, Zeek's default.
        assert_eq!(decode_zeek_separator("#separator"), b'\t');
        assert_eq!(decode_zeek_separator("#separator \\xZZ"), b'\t');
    }

    #[test]
    fn maps_zeek_declared_types() {
        // Numeric: these are the ones an unset `-` must be substituted in.
        assert_eq!(zeek_arrow_type("time"), Some(DataType::Float64));
        assert_eq!(zeek_arrow_type("interval"), Some(DataType::Float64));
        assert_eq!(zeek_arrow_type("double"), Some(DataType::Float64));
        assert_eq!(zeek_arrow_type("count"), Some(DataType::Int64));
        assert_eq!(zeek_arrow_type("port"), Some(DataType::Int64));
        assert_eq!(zeek_arrow_type("int"), Some(DataType::Int64));
        // Text: addr stays a string so IPv4 and IPv6 both survive.
        assert_eq!(zeek_arrow_type("addr"), None);
        assert_eq!(zeek_arrow_type("string"), None);
        assert_eq!(zeek_arrow_type("enum"), None);
        assert_eq!(zeek_arrow_type("bool"), None);
        assert_eq!(zeek_arrow_type("set[string]"), None);
        assert_eq!(zeek_arrow_type("vector[interval]"), None);
    }

    /// The real ctu-sme-11 `conn.log.labeled` field list, verbatim.
    const ZEEK_CONN_FIELDS: &str = "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,service,\
                                    duration,orig_bytes,resp_bytes,conn_state,local_orig,\
                                    local_resp,missed_bytes,history,orig_pkts,orig_ip_bytes,\
                                    resp_pkts,resp_ip_bytes,tunnel_parents,label,detailedlabel";

    #[test]
    fn zeek_conn_log_resolves_every_required_field() {
        let names: Vec<String> = ZEEK_CONN_FIELDS.split(',').map(|s| s.to_string()).collect();
        let resolved = load_schema_spec().resolve_columns(&names);
        for field in REQUIRED_FIELDS {
            assert!(
                resolved.contains_key(*field),
                "Zeek conn.log should resolve {field}, got {resolved:?}"
            );
        }
        // Dots are not normalized away, so these aliases must match literally.
        assert_eq!(
            resolved.get("src_ip").map(String::as_str),
            Some("id.orig_h")
        );
        assert_eq!(
            resolved.get("dest_ip").map(String::as_str),
            Some("id.resp_h")
        );
        assert_eq!(
            resolved.get("src_port").map(String::as_str),
            Some("id.orig_p")
        );
        assert_eq!(
            resolved.get("dest_port").map(String::as_str),
            Some("id.resp_p")
        );
        // orig_bytes/resp_bytes are payload counts and genuinely directional.
        assert_eq!(
            resolved.get("fwd_bytes").map(String::as_str),
            Some("orig_bytes")
        );
        assert_eq!(
            resolved.get("bwd_bytes").map(String::as_str),
            Some("resp_bytes")
        );
        assert_eq!(
            resolved.get("fwd_pkts").map(String::as_str),
            Some("orig_pkts")
        );
    }

    /// The sibling Zeek logs (dns, ssl, x509, weird, …) carry no bytes, packets
    /// or duration. 168 of the 181 `.labeled` files in the corpus are these, and
    /// they must reject rather than convert into junk flows.
    #[test]
    fn zeek_non_conn_logs_lack_required_fields() {
        let dns = "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,trans_id,rtt,query,\
                   qclass,qclass_name,qtype,qtype_name,rcode,rcode_name,AA,TC,RD,RA,Z,answers,\
                   TTLs,rejected,label,detailedlabel";
        let names: Vec<String> = dns.split(',').map(|s| s.to_string()).collect();
        let resolved = load_schema_spec().resolve_columns(&names);
        let missing: Vec<&&str> = REQUIRED_FIELDS
            .iter()
            .filter(|f| !resolved.contains_key(**f))
            .collect();
        assert_eq!(
            missing,
            vec![&"fwd_bytes", &"flow_dur"],
            "a Zeek dns.log must be rejected for want of byte and duration columns"
        );
    }

    #[test]
    fn zeek_detailedlabel_is_passthrough() {
        assert!(
            load_schema_spec()
                .passthrough
                .iter()
                .any(|p| p == "detailedlabel")
        );
    }

    #[test]
    fn coerces_unusable_ports_to_zero_and_counts_them() {
        // Argus reality: hex ICMP type/code, an empty field for a protocol with
        // no ports, and ordinary numeric ports side by side.
        let raw: ArrayRef = Arc::new(StringArray::from(vec![
            Some("1611"),
            Some("0x0303"),
            Some(""),
            None,
            Some("443"),
        ]));
        let (ports, coerced) = port_to_i32(&raw).expect("port cast succeeds");
        let ports = ports.as_any().downcast_ref::<Int32Array>().unwrap();

        assert_eq!(coerced, 3, "0x0303, empty and null should all be coerced");
        assert_eq!(ports.values(), &[1611, 0, 0, 0, 443]);
        assert_eq!(ports.null_count(), 0, "canonical ports are non-nullable");
    }

    #[test]
    fn leaves_clean_port_columns_untouched() {
        let raw: ArrayRef = Arc::new(StringArray::from(vec!["1611", "443", "0"]));
        let (ports, coerced) = port_to_i32(&raw).expect("port cast succeeds");
        assert_eq!(coerced, 0, "nothing to coerce means no reported coercions");
        let ports = ports.as_any().downcast_ref::<Int32Array>().unwrap();
        assert_eq!(ports.values(), &[1611, 443, 0]);
    }

    /// Real CIC headers, both spellings. Only the columns that must resolve.
    const CIC_A_HEADER: &str = "Flow ID,Source IP,Source Port,Destination IP,Destination Port,\
                                Protocol,Timestamp,Flow Duration,Total Fwd Packets,\
                                Total Backward Packets,Total Length of Fwd Packets,\
                                Total Length of Bwd Packets,Label";
    const CIC_B_HEADER: &str = "Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,\
                                Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,\
                                TotLen Bwd Pkts,Label";

    #[test]
    fn both_cic_header_variants_resolve_every_required_field() {
        for (name, header) in [("variant A", CIC_A_HEADER), ("variant B", CIC_B_HEADER)] {
            let names: Vec<String> = header.split(',').map(|s| s.to_string()).collect();
            let resolved = load_schema_spec().resolve_columns(&names);
            for field in REQUIRED_FIELDS {
                assert!(
                    resolved.contains_key(*field),
                    "CIC {name} should resolve {field}, got {resolved:?}"
                );
            }
        }
    }

    #[test]
    fn cic_byte_and_packet_columns_map_directionally() {
        let a: Vec<String> = CIC_A_HEADER.split(',').map(|s| s.to_string()).collect();
        let a = load_schema_spec().resolve_columns(&a);
        assert_eq!(
            a.get("fwd_bytes").map(String::as_str),
            Some("Total Length of Fwd Packets")
        );
        assert_eq!(
            a.get("bwd_bytes").map(String::as_str),
            Some("Total Length of Bwd Packets")
        );

        let b: Vec<String> = CIC_B_HEADER.split(',').map(|s| s.to_string()).collect();
        let b = load_schema_spec().resolve_columns(&b);
        assert_eq!(
            b.get("fwd_bytes").map(String::as_str),
            Some("TotLen Fwd Pkts")
        );
        assert_eq!(
            b.get("bwd_bytes").map(String::as_str),
            Some("TotLen Bwd Pkts")
        );
        assert_eq!(b.get("fwd_pkts").map(String::as_str), Some("Tot Fwd Pkts"));
        assert_eq!(b.get("bwd_pkts").map(String::as_str), Some("Tot Bwd Pkts"));
    }

    /// Variant A spells the packet counts `Total Fwd Packets` and `Total
    /// Backward Packets` — *Backward*, not *Bwd*. Missing the second one left
    /// every bwd_pkts null across 225,745 real rows. That resolves to a null
    /// column rather than an error, so only inspecting converted data catches it.
    #[test]
    fn cic_variant_a_resolves_both_packet_directions() {
        let names: Vec<String> = CIC_A_HEADER.split(',').map(|s| s.to_string()).collect();
        let resolved = load_schema_spec().resolve_columns(&names);
        assert_eq!(
            resolved.get("fwd_pkts").map(String::as_str),
            Some("Total Fwd Packets")
        );
        assert_eq!(
            resolved.get("bwd_pkts").map(String::as_str),
            Some("Total Backward Packets")
        );
    }

    /// `Flow Duration` is microseconds in CIC, but by decision it resolves as
    /// seconds and `flow_check` catches the 10^6 inflation downstream. Pinning it
    /// here so the behaviour is deliberate rather than incidental.
    #[test]
    fn cic_flow_duration_is_intentionally_treated_as_seconds() {
        let spec = load_schema_spec();
        assert_eq!(
            spec.duration_divisors.get("flow_duration").copied(),
            Some(1.0),
            "CIC Flow Duration is microseconds; treating it as seconds is a \
             deliberate decision, with flow_check's duration.implausible_magnitude \
             as the safety net"
        );
    }

    fn order_of(values: &[&str]) -> Result<Option<SlashDateOrder>> {
        infer_slash_date_order(&StringArray::from(values.to_vec()))
    }

    #[test]
    fn proves_slash_date_order_from_evidence() {
        // 20 > 12 can only be a day -> day-first.
        assert_eq!(
            order_of(&["20/11/2020 09:50:19"]).unwrap(),
            Some(SlashDateOrder::DayFirst)
        );
        // 31 in the second position can only be a day -> month-first.
        assert_eq!(
            order_of(&["7/31/2017 3:30"]).unwrap(),
            Some(SlashDateOrder::MonthFirst)
        );
        // Evidence anywhere in the column settles the whole column.
        assert_eq!(
            order_of(&["1/2/2020", "3/4/2020", "20/5/2020"]).unwrap(),
            Some(SlashDateOrder::DayFirst)
        );
    }

    #[test]
    fn assumes_month_first_only_when_unprovable() {
        // A CICIDS2017 per-day export: one date, nothing over 12.
        assert_eq!(
            order_of(&["7/7/2017 3:30", "7/7/2017 15:45:09"]).unwrap(),
            Some(SlashDateOrder::MonthFirst)
        );
        // No slash dates at all -> nothing inferred, nothing logged.
        assert_eq!(
            order_of(&["1750000000", "2011-08-18 10:00:00"]).unwrap(),
            None
        );
        // Contradictory evidence is an error, not a coin flip.
        assert!(order_of(&["20/11/2020", "7/31/2017"]).is_err());
    }

    #[test]
    fn rewrites_ambiguous_slash_dates_with_padding() {
        use SlashDateOrder::{DayFirst, MonthFirst};
        // Single-digit hour, no seconds (CICIDS2017).
        assert_eq!(
            rewrite_slash_date("7/7/2017 3:30", MonthFirst).unwrap(),
            "2017-07-07 03:30:00"
        );
        // Full time (CICFlowMeter v4), day-first.
        assert_eq!(
            rewrite_slash_date("20/11/2020 09:50:19", DayFirst).unwrap(),
            "2020-11-20 09:50:19"
        );
        // The same string under the two orderings must differ.
        assert_eq!(
            rewrite_slash_date("7/5/2017", MonthFirst).unwrap(),
            "2017-07-05 00:00:00"
        );
        assert_eq!(
            rewrite_slash_date("7/5/2017", DayFirst).unwrap(),
            "2017-05-07 00:00:00"
        );
        // Year-first is NOT claimed here — normalize_slash_date owns that shape.
        assert!(rewrite_slash_date("2011/08/18 10:21:46.633335", MonthFirst).is_none());
        assert!(rewrite_slash_date("1750000000", MonthFirst).is_none());
    }

    #[test]
    fn rewrites_year_first_slash_dates() {
        // Argus StartTime, microsecond precision preserved.
        assert_eq!(
            normalize_slash_date("2011/08/18 10:21:46.633335"),
            "2011-08-18 10:21:46.633335"
        );
        assert_eq!(normalize_slash_date("2011/08/18"), "2011-08-18");
    }

    #[test]
    fn leaves_ambiguous_and_already_valid_dates_alone() {
        // Already dash-separated.
        assert_eq!(
            normalize_slash_date("2011-08-18 10:21:46"),
            "2011-08-18 10:21:46"
        );
        // RFC3339.
        assert_eq!(
            normalize_slash_date("2011-08-18T10:21:46Z"),
            "2011-08-18T10:21:46Z"
        );
        // Day-first / month-first are ambiguous — must not be rewritten, or we
        // would risk silently transposing month and day.
        assert_eq!(normalize_slash_date("18/08/2011"), "18/08/2011");
        assert_eq!(normalize_slash_date("08/18/2011"), "08/18/2011");
        // Epoch strings and junk pass through untouched.
        assert_eq!(normalize_slash_date("1750000000"), "1750000000");
        assert_eq!(normalize_slash_date(""), "");
        assert_eq!(normalize_slash_date("2011/8/1"), "2011/8/1");
    }
}
