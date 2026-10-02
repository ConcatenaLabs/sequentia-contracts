//! `seqc`: the command line of the Sequentia contracts toolchain.
//!
//!     seqc version                 print the pinned SimplicityHL version
//!     seqc lint <file>...          lint SimplicityHL sources; exit 1 on any finding

use std::process::ExitCode;

use sequentia_contracts::{lint, COMPILER_VERSION};

fn usage() -> ExitCode {
    eprintln!("usage: seqc version | seqc lint <file>...");
    ExitCode::from(2)
}

fn cmd_lint(paths: &[String]) -> ExitCode {
    if paths.is_empty() {
        return usage();
    }
    let mut failed = false;
    for path in paths {
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{path}: {e}");
                failed = true;
                continue;
            }
        };
        let report = lint::lint_source(&source);
        if report.is_clean() {
            let how = if report.compiled {
                "source and compiled program"
            } else {
                "source only (does not compile)"
            };
            println!("{path}: ok ({how})");
        } else {
            failed = true;
            for f in &report.findings {
                println!("{path}: {f}");
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("version") => {
            println!("simplicityhl {COMPILER_VERSION}");
            ExitCode::SUCCESS
        }
        Some("lint") => cmd_lint(&args[1..]),
        _ => usage(),
    }
}
