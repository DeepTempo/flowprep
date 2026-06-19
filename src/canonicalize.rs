//! Map arbitrarily-named flow tables onto the canonical NetFlow schema.
//!
//! Handles the three things every vendor export gets differently: column
//! naming (alias map), duration units (inferred from the source column
//! name), and timestamp encoding (epoch s/ms/us/ns or string datetimes,
//! inferred from magnitude/type).

use std::fs::File;
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

fn read_table(path: &str) -> Result<RecordBatch> {
    let batches: Vec<RecordBatch> = if path.ends_with(".csv") {
        let mut file = File::open(path)?;
        let format = arrow::csv::reader::Format::default().with_header(true);
        let (schema, _) = format.infer_schema(&mut file, Some(1000))?;
        let file = File::open(path)?;
        let reader = arrow::csv::ReaderBuilder::new(Arc::new(schema))
            .with_format(format)
            .build(file)?;
        reader.collect::<std::result::Result<_, _>>()?
    } else {
        let file = File::open(path)?;
        let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file)?
            .build()?;
        reader.collect::<std::result::Result<_, _>>()?
    };
    if batches.is_empty() {
        return Err("input file contains no rows".into());
    }
    Ok(concat_batches(&batches[0].schema(), &batches)?)
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
    let mut columns: Vec<ArrayRef> = vec![
        timestamp_to_micros(&col("timestamp"))?,
        cast(&col("src_ip"), &DataType::Utf8)?,
        cast(&col("dest_ip"), &DataType::Utf8)?,
        cast(&col("src_port"), &DataType::Int32)?,
        cast(&col("dest_port"), &DataType::Int32)?,
        to_rounded_i64(&col("fwd_bytes"))?,
    ];

    if resolved.contains_key("bwd_bytes") {
        columns.push(to_rounded_i64(&col("bwd_bytes"))?);
    } else {
        columns.push(Arc::new(Int64Array::from(vec![0i64; n])));
    }

    for pkts in ["fwd_pkts", "bwd_pkts"] {
        if resolved.contains_key(pkts) {
            columns.push(cast(&col(pkts), &DataType::Int64)?);
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

/// Coerce a timestamp column to epoch microseconds (int64).
fn timestamp_to_micros(column: &ArrayRef) -> Result<ArrayRef> {
    match column.data_type() {
        DataType::Timestamp(_, _) | DataType::Utf8 | DataType::LargeUtf8 => {
            let ts = cast(column, &DataType::Timestamp(TimeUnit::Microsecond, None))?;
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

fn to_rounded_i64(column: &ArrayRef) -> Result<ArrayRef> {
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
