//! `seqc`: the command line of the Sequentia contracts toolchain.
//!
//!     seqc version                 print the pinned SimplicityHL version
//!     seqc lint <file>...          lint SimplicityHL sources; exit 1 on any finding
//!     seqc run                     one JSON request on stdin, one JSON reply on stdout
//!
//! `seqc run` request fields:
//!
//!   source         SimplicityHL text
//!   args           {NAME: {"value": "...", "type": "..."}}      (optional)
//!   witness        {NAME: {"value": "...", "type": "..."}}      (optional; absent = compile only)
//!   tx             raw transaction hex, Elements encoding        (optional)
//!   utxos          [hex of each spent TxOut], one per input      (with tx)
//!   index          input index                                   (with tx)
//!   control_block  hex                                           (with tx)
//!   genesis        genesis block hash, display hex               (with tx)
//!   annex          hex WITHOUT the 0x50 tag                      (optional; placed in the
//!                  input's witness so sig_all_hash commits to it, as the node does)
//!   prune          bool (default: true when tx is given)
//!   allow_banned_jets  bool (default false). Only the regtest demonstration of the
//!                  broken timelock jets sets it; every other request is linted and
//!                  refused on any finding.
//!
//! Reply: compiler_version, cmr, commit_program_hex/bytes (no witness); with a
//! witness: program_hex/bytes, witness_hex/bytes, redeem_cmr, cost_milli,
//! extra_cells, extra_frames, and with a tx also executed, exec_error and
//! sighash_all. On failure: {"error": "..."}.

use std::io::Read;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;

use sequentia_contracts::simplicityhl::elements::encode::deserialize;
use sequentia_contracts::simplicityhl::elements::hashes::Hash;
use sequentia_contracts::simplicityhl::elements::taproot::ControlBlock;
use sequentia_contracts::simplicityhl::elements::{BlockHash, Transaction, TxOut};
use sequentia_contracts::simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use sequentia_contracts::simplicityhl::simplicity::BitMachine;
use sequentia_contracts::simplicityhl::{Arguments, WitnessValues};
use sequentia_contracts::{hex, lint, COMPILER_VERSION};

use serde_json::{json, Map, Value};

fn usage() -> ExitCode {
    eprintln!("usage: seqc version | seqc lint <file>... | seqc run < request.json");
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

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn from_json<T: for<'de> serde::Deserialize<'de>>(v: &Value) -> Result<T, String> {
    // The compiler's value types deserialize from borrowed strings, which
    // `from_value` cannot lend; go through the text form.
    serde_json::from_str(&v.to_string()).map_err(|e| format!("arguments/witness: {e}"))
}

/// The static cost bound in milli weight units. `Cost` keeps its field
/// private; its `Debug` form is `Cost(n)`.
fn cost_milli(cost: impl std::fmt::Debug) -> u64 {
    format!("{cost:?}")
        .trim_start_matches("Cost(")
        .trim_end_matches(')')
        .parse()
        .expect("Cost debug format")
}

fn run(req: &Value) -> Result<Value, String> {
    let source = req["source"].as_str().ok_or("source missing")?;
    let allow_banned = req
        .get("allow_banned_jets")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut out = Map::new();
    out.insert("compiler_version".into(), COMPILER_VERSION.into());

    let findings = lint::scan_source(source);
    let empty = json!({});
    let args: Arguments = from_json(req.get("args").unwrap_or(&empty))?;
    let program = sequentia_contracts::compile(source, args)?;
    let commit = program.commit();
    let mut all = findings;
    all.extend(lint::scan_compiled(&commit));
    if !all.is_empty() {
        if !allow_banned {
            let text: Vec<String> = all.iter().map(|f| f.to_string()).collect();
            return Err(format!("lint: {}", text.join("; ")));
        }
        out.insert(
            "banned_jets_allowed".into(),
            all.iter()
                .map(|f| f.name.clone())
                .collect::<Vec<_>>()
                .into(),
        );
    }

    let cmr = commit.cmr();
    out.insert("cmr".into(), hex(cmr.as_ref()).into());
    let commit_bytes = commit.to_vec_without_witness();
    out.insert("commit_program_bytes".into(), commit_bytes.len().into());
    out.insert("commit_program_hex".into(), hex(&commit_bytes).into());

    let env = if let Some(txhex) = req.get("tx").and_then(Value::as_str) {
        let mut tx: Transaction = deserialize(&unhex(txhex)?).map_err(|e| format!("tx: {e}"))?;
        let mut utxos = Vec::new();
        for u in req["utxos"].as_array().ok_or("utxos missing")? {
            let o: TxOut = deserialize(&unhex(u.as_str().ok_or("utxo not a string")?)?)
                .map_err(|e| format!("utxo: {e}"))?;
            utxos.push(ElementsUtxo::from(o));
        }
        let index = req["index"].as_u64().ok_or("index missing")? as u32;
        let cb = ControlBlock::from_slice(&unhex(
            req["control_block"]
                .as_str()
                .ok_or("control_block missing")?,
        )?)
        .map_err(|e| format!("control block: {e}"))?;
        let genesis = BlockHash::from_str(req["genesis"].as_str().ok_or("genesis missing")?)
            .map_err(|e| format!("genesis: {e}"))?;
        let annex = match req.get("annex").and_then(Value::as_str) {
            Some(a) => Some(unhex(a)?),
            None => None,
        };
        if let Some(a) = &annex {
            // The library reads the annex from the input's witness, as the node
            // does; the stack items before it do not enter the environment.
            let input = tx
                .input
                .get_mut(index as usize)
                .ok_or("index out of range")?;
            let mut item = vec![0x50u8];
            item.extend_from_slice(a);
            input.witness.script_witness = vec![item];
        }
        let env = ElementsEnv::new(Arc::new(tx), utxos, index, cmr, cb, annex, genesis);
        out.insert(
            "sighash_all".into(),
            hex(&env.c_tx_env().sighash_all().to_byte_array()).into(),
        );
        Some(env)
    } else {
        None
    };

    if let Some(w) = req.get("witness") {
        let wv: WitnessValues = from_json(w)?;
        let prune = req
            .get("prune")
            .and_then(Value::as_bool)
            .unwrap_or(env.is_some());
        let satisfied = program.satisfy_with_env(wv, if prune { env.as_ref() } else { None })?;
        let node = satisfied.redeem().clone();
        let (pb, wb) = node.to_vec_with_witness();
        let bounds = node.bounds();
        out.insert("pruned".into(), prune.into());
        out.insert("program_hex".into(), hex(&pb).into());
        out.insert("program_bytes".into(), pb.len().into());
        out.insert("witness_hex".into(), hex(&wb).into());
        out.insert("witness_bytes".into(), wb.len().into());
        out.insert("redeem_cmr".into(), hex(node.cmr().as_ref()).into());
        out.insert("cost_milli".into(), cost_milli(bounds.cost).into());
        out.insert("extra_cells".into(), bounds.extra_cells.into());
        out.insert("extra_frames".into(), bounds.extra_frames.into());
        if let Some(env) = env.as_ref() {
            let exec = BitMachine::for_program(&node)
                .map_err(|e| format!("bit machine: {e}"))
                .and_then(|mut mac| mac.exec(&node, env).map(|_| ()).map_err(|e| format!("{e}")));
            match exec {
                Ok(()) => {
                    out.insert("executed".into(), true.into());
                }
                Err(e) => {
                    out.insert("executed".into(), false.into());
                    out.insert("exec_error".into(), e.into());
                }
            }
        }
    }
    Ok(Value::Object(out))
}

fn cmd_run() -> ExitCode {
    let mut text = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut text) {
        eprintln!("stdin: {e}");
        return ExitCode::from(2);
    }
    let reply = match serde_json::from_str::<Value>(&text) {
        Ok(req) => run(&req).unwrap_or_else(|e| json!({ "error": e })),
        Err(e) => json!({ "error": format!("bad request: {e}") }),
    };
    println!("{reply}");
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("version") => {
            println!("simplicityhl {COMPILER_VERSION}");
            ExitCode::SUCCESS
        }
        Some("lint") => cmd_lint(&args[1..]),
        Some("run") => cmd_run(),
        _ => usage(),
    }
}
