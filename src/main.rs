mod canonicalize;
mod modbus;
mod nfcapd;
mod nfdump;
mod ocsf;
mod pcap;
mod schema;
mod writer;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "flowprep",
    about = "Convert network telemetry into ML-ready flow and protocol observations"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// pcap/pcapng -> canonical flow parquet
    Pcap { input: String, output: String },
    /// passively decode Modbus/TCP from pcap/pcapng -> protocol observations
    Modbus {
        input: String,
        output: String,
        /// TCP port used by Modbus servers in this capture
        #[arg(long, default_value_t = 502)]
        server_port: u16,
    },
    /// continuously decode a PCAP stream -> low-latency NDJSON events
    ModbusStream {
        /// PCAP/PCAPNG input path, or '-' for stdin
        #[arg(long, default_value = "-")]
        input: String,
        /// NDJSON output path (append mode), or '-' for stdout
        #[arg(long, default_value = "-")]
        output: String,
        /// TCP port used by Modbus servers in this capture
        #[arg(long, default_value_t = 502)]
        server_port: u16,
        /// Stable deployment identity attached to every event
        #[arg(long, default_value = "flowprep-local")]
        sensor_id: String,
        /// Time before an unmatched request becomes a terminal event
        #[arg(long, default_value_t = 5000)]
        request_timeout_ms: u64,
        /// Flush NDJSON after this many events; 1 minimizes latency
        #[arg(long, default_value_t = 1)]
        flush_every: usize,
    },
    /// aliased parquet/CSV flow table -> canonical parquet
    Canonicalize { input: String, output: String },
    /// OCSF Network Activity JSON/NDJSON -> canonical parquet
    Ocsf { input: String, output: String },
    /// nfdump/nfcapd binary flow file -> canonical parquet
    Nfcapd { input: String, output: String },
    /// print the first rows of a parquet file
    Peek {
        input: String,
        #[arg(short = 'n', long, default_value_t = 10)]
        rows: usize,
    },
}

fn peek(input: &str, rows: usize) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::File::open(input)?;
    let mut reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file)?
        .with_batch_size(rows)
        .build()?;
    if let Some(batch) = reader.next() {
        arrow::util::pretty::print_batches(&[batch?])?;
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Pcap { input, output } => {
            pcap::pcap_to_parquet(input, output).map(|n| println!("Wrote {n} flows to {output}"))
        }
        Command::Modbus {
            input,
            output,
            server_port,
        } => modbus::modbus_to_parquet(input, output, *server_port)
            .map(|summary| println!("Wrote Modbus {summary} to {output}")),
        Command::ModbusStream {
            input,
            output,
            server_port,
            sensor_id,
            request_timeout_ms,
            flush_every,
        } => modbus::modbus_stream_to_ndjson(
            input,
            output,
            *server_port,
            sensor_id,
            *request_timeout_ms,
            *flush_every,
        )
        .map(|summary| eprintln!("Modbus stream finished: {summary}")),
        Command::Canonicalize { input, output } => canonicalize::canonicalize_file(input, output)
            .map(|n| println!("Wrote {n} flows to {output}")),
        Command::Ocsf { input, output } => {
            ocsf::ocsf_to_parquet(input, output).map(|n| println!("Wrote {n} flows to {output}"))
        }
        Command::Nfcapd { input, output } => nfcapd::nfcapd_to_parquet(input, output)
            .map(|n| println!("Wrote {n} flows to {output}")),
        Command::Peek { input, rows } => peek(input, *rows),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
