mod canonicalize;
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
    about = "Convert network telemetry into ML-ready canonical NetFlow parquet"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// pcap/pcapng -> canonical flow parquet
    Pcap {
        input: String,
        output: String,
        /// Max age of an open flow record before it is closed (seconds).
        #[arg(long, default_value_t = pcap::DEFAULT_ACTIVE_TIMEOUT_SECS)]
        active_timeout: u64,
        /// Idle gap after the last packet before a flow record is closed (seconds).
        #[arg(long, default_value_t = pcap::DEFAULT_INACTIVE_TIMEOUT_SECS)]
        inactive_timeout: u64,
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
        Command::Pcap {
            input,
            output,
            active_timeout,
            inactive_timeout,
        } => match pcap::FlowTimeouts::from_secs(*active_timeout, *inactive_timeout) {
            Ok(timeouts) => pcap::pcap_to_parquet(input, output, timeouts)
                .map(|n| println!("Wrote {n} flows to {output}")),
            Err(e) => Err(e),
        },
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
