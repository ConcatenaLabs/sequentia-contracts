//! `seqc`: the command line of the Sequentia contracts toolchain.
//!
//!     seqc version                 print the pinned SimplicityHL version
//!     seqc lint <file>...          lint SimplicityHL sources; exit 1 on any finding,
//!                                  and on a source that does not compile
//!         --source-only            accept a source that does not compile on the
//!                                  source scan alone (helpers, templates)
//!         --dep <name>=<dir>       compile with this dependency, as Simplex does
//!         --root <dir>             the package root the dependencies hang from
//!                                  (default: the file's directory)
//!         --project <dir>          lint every program of a Simplex project, with
//!                                  the dependency map its Simplex.toml gives
//!     seqc run                     one JSON request on stdin, one JSON reply on stdout
//!     seqc expand <file>           print a source with its helper includes resolved
//!     seqc descriptor seal <dir>   fill in the source hash, root and template hash
//!     seqc descriptor check <dir>...   validate descriptors and their golden vectors
//!     seqc descriptor vectors <dir>    rewrite the derived fields of the golden vectors
//!     seqc descriptor as-v2 <dir>      print a version 1 template as the version 2
//!                                  template of the same tree
//!
//! A template directory holds `descriptor.json`, the program sources it names,
//! and `vectors.json`. Descriptors of version 1 and 2 are both read; each
//! version has its own vector format.
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
    eprintln!(
        "usage: seqc version | seqc lint [options] <file>... | seqc run < request.json | seqc expand <file>\n       \
         seqc descriptor (seal | check | vectors | as-v2) <template dir>..."
    );
    ExitCode::from(2)
}

/// Print a lint report for one program; true when it passed.
fn print_report(path: &str, report: &lint::Report, source_only: bool) -> bool {
    if !report.is_clean() {
        for f in &report.findings {
            println!("{path}: {f}");
        }
        if let Some(cmr) = &report.cmr {
            println!("{path}: refused (compiled root {cmr})");
        }
        return false;
    }
    if report.compiled {
        println!(
            "{path}: ok (source and compiled program, root {})",
            report.cmr.as_deref().unwrap_or("?")
        );
        return true;
    }
    let why = report.compile_error.as_deref().unwrap_or("unknown error");
    if source_only {
        println!(
            "{path}: ok (source only, as --source-only asks; it does not compile: {})",
            why.lines().next().unwrap_or("")
        );
        true
    } else {
        println!(
            "{path}: FAILED: it does not compile, so the compiled layer did not run, and a jet \
             reached through an import or a renaming would go unseen.\n{why}\n\
             Lint a program that imports with `use` as it is built (--project <dir> or \
             --dep <name>=<dir>); lint a fragment that is not a program with --source-only."
        );
        false
    }
}

const LINT_USAGE: &str = "usage: seqc lint [--source-only] <file>...\n       \
     seqc lint [--source-only] [--root <dir>] --dep <name>=<dir> [--dep ...] <file>...\n       \
     seqc lint [--source-only] --project <dir>";

fn cmd_lint(args: &[String]) -> ExitCode {
    use sequentia_contracts::simplicityhl::resolution::DependencyMapBuilder;
    use sequentia_contracts::simplicityhl::source::CanonPath;

    let mut source_only = false;
    let mut project: Option<String> = None;
    let mut root: Option<String> = None;
    let mut deps: Vec<(String, String)> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--source-only" => source_only = true,
            "--project" | "--root" | "--dep" => {
                let Some(v) = it.next() else {
                    eprintln!("{LINT_USAGE}");
                    return ExitCode::from(2);
                };
                match a.as_str() {
                    "--project" => project = Some(v.clone()),
                    "--root" => root = Some(v.clone()),
                    _ => match v.split_once('=') {
                        Some((n, d)) => deps.push((n.to_string(), d.to_string())),
                        None => {
                            eprintln!("--dep wants <name>=<dir>, got {v}");
                            return ExitCode::from(2);
                        }
                    },
                }
            }
            s if s.starts_with("--") => {
                eprintln!("unknown option {s}\n{LINT_USAGE}");
                return ExitCode::from(2);
            }
            _ => paths.push(a.clone()),
        }
    }

    let mut failed = false;
    if let Some(dir) = project {
        if !paths.is_empty() || !deps.is_empty() || root.is_some() {
            eprintln!("--project takes no files, --dep or --root\n{LINT_USAGE}");
            return ExitCode::from(2);
        }
        let p = match sequentia_contracts::simplex::project(std::path::Path::new(&dir)) {
            Ok(p) => p,
            Err(e) => {
                println!("{dir}: FAILED: {e}");
                return ExitCode::FAILURE;
            }
        };
        if p.entries.is_empty() {
            println!(
                "{dir}: FAILED: no program (a .simf file declaring fn main) under {}",
                p.src_dir.display()
            );
            return ExitCode::FAILURE;
        }
        for entry in &p.entries {
            let report = lint::lint_with_deps(entry, &p.deps);
            failed |= !print_report(&entry.display().to_string(), &report, source_only);
        }
    } else if paths.is_empty() {
        eprintln!("{LINT_USAGE}");
        return ExitCode::from(2);
    } else if !deps.is_empty() || root.is_some() {
        for path in &paths {
            let root_dir = match &root {
                Some(r) => std::path::PathBuf::from(r),
                None => std::path::Path::new(path)
                    .parent()
                    .map(|p| {
                        if p.as_os_str().is_empty() {
                            std::path::Path::new(".")
                        } else {
                            p
                        }
                    })
                    .unwrap_or(std::path::Path::new("."))
                    .to_path_buf(),
            };
            let map = (|| -> Result<_, String> {
                let root = CanonPath::canonicalize(&root_dir)
                    .map_err(|e| format!("{}: {e}", root_dir.display()))?;
                let mut b = DependencyMapBuilder::new();
                for (name, dir) in &deps {
                    let target = CanonPath::canonicalize(std::path::Path::new(dir))
                        .map_err(|e| format!("{dir}: {e}"))?;
                    b.add_dependency(root.clone(), name.clone(), target);
                }
                b.build(root).map_err(|e| e.to_string())
            })();
            match map {
                Ok(map) => {
                    let report = lint::lint_with_deps(std::path::Path::new(path), &map);
                    failed |= !print_report(path, &report, source_only);
                }
                Err(e) => {
                    println!("{path}: FAILED: {e}");
                    failed = true;
                }
            }
        }
    } else {
        for path in &paths {
            match std::fs::read_to_string(path) {
                Ok(source) => {
                    let report = lint::lint_source(&source);
                    failed |= !print_report(path, &report, source_only);
                }
                Err(e) => {
                    eprintln!("{path}: {e}");
                    failed = true;
                }
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

    let findings = lint::scan_source(&sequentia_contracts::expand(source)?);
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

fn write_json(path: &std::path::Path, value: &impl serde::Serialize) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())? + "\n";
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Fills in, for every Simplicity leaf of a version 2 tree, the source hash,
/// root, compiler and cost bound its source compiles to.
fn seal_tree(node: &mut Value, dir: &std::path::Path) -> Result<(), String> {
    use sequentia_contracts::simplicityhl::elements::hashes::{sha256, Hash};
    let obj = node.as_object_mut().ok_or("a tree node is not an object")?;
    if let Some(children) = obj.get_mut("branch") {
        for child in children.as_array_mut().ok_or("a branch is not an array")? {
            seal_tree(child, dir)?;
        }
        return Ok(());
    }
    if let Some(leaf) = obj.get_mut("simplicity") {
        let source = leaf["source"]
            .as_str()
            .ok_or("a Simplicity leaf has no source")?;
        let spath = dir.join(source);
        let raw =
            std::fs::read_to_string(&spath).map_err(|e| format!("{}: {e}", spath.display()))?;
        let text = sequentia_contracts::expand(&raw)?;
        let program = sequentia_contracts::compile(&text, Default::default())?;
        leaf["source_sha256"] = hex(sha256::Hash::hash(text.as_bytes()).as_ref()).into();
        leaf["cmr"] = sequentia_contracts::cmr_hex(&program).into();
        leaf["compiler"] = json!({"name": "simplicityhl", "version": COMPILER_VERSION});
        leaf["max_cost_wu"] = sequentia_contracts::descriptor::max_cost_wu(&program)?.into();
    }
    Ok(())
}

fn vectors_version(path: &std::path::Path) -> Result<u64, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let v = sequentia_contracts::descriptor::parse_json(&text)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    v["vectors"]
        .as_u64()
        .ok_or_else(|| format!("{}: no vectors version", path.display()))
}

fn descriptor_one(cmd: &str, dir: &std::path::Path) -> Result<String, String> {
    use sequentia_contracts::descriptor::{template_hash, Descriptor, Vectors, VectorsV2};
    use sequentia_contracts::simplicityhl::elements::hashes::{sha256, Hash};

    let dpath = dir.join("descriptor.json");
    let vpath = dir.join("vectors.json");
    let mut d = Descriptor::load(&dpath)?;
    // Each descriptor version has its vector version.
    let regenerate = |d: &Descriptor| -> Result<(Value, Value, usize), String> {
        if d.descriptor == 1 {
            let v = Vectors::load(&vpath)?;
            let r = v.regenerate(d)?;
            let n = r.addresses.len();
            Ok((json!(v), json!(r), n))
        } else {
            if vectors_version(&vpath)? != 2 {
                return Err(format!(
                    "{}: a version 2 descriptor has version 2 vectors",
                    vpath.display()
                ));
            }
            let v = VectorsV2::load(&vpath)?;
            let r = v.regenerate(d)?;
            let n = r.addresses.len();
            Ok((json!(v), json!(r), n))
        }
    };
    match cmd {
        "seal" => {
            if d.descriptor == 1 {
                let t = d.typed()?;
                let spath = dir.join(&t.program.source);
                let raw = std::fs::read_to_string(&spath)
                    .map_err(|e| format!("{}: {e}", spath.display()))?;
                let text = sequentia_contracts::expand(&raw)?;
                let program = sequentia_contracts::compile(&text, Default::default())?;
                let program_v = d
                    .template
                    .get_mut("program")
                    .ok_or("template has no program")?;
                program_v["source_sha256"] =
                    hex(sha256::Hash::hash(text.as_bytes()).as_ref()).into();
                program_v["cmr"] = sequentia_contracts::cmr_hex(&program).into();
                program_v["compiler"] =
                    json!({"name": "simplicityhl", "version": COMPILER_VERSION});
            } else {
                seal_tree(
                    d.template.get_mut("tree").ok_or("template has no tree")?,
                    dir,
                )?;
            }
            d.template_hash = template_hash(&d.template);
            d.validate(dir)?;
            write_json(&dpath, &d)?;
            Ok(format!("sealed, template_hash {}", d.template_hash))
        }
        "check" => {
            d.validate(dir)?;
            let (v, r, n) = regenerate(&d)?;
            if r != v {
                return Err(format!(
                    "{} differs from what the descriptor derives",
                    vpath.display()
                ));
            }
            Ok(format!(
                "ok: descriptor version {}, {n} address vectors, template_hash {}",
                d.descriptor, d.template_hash
            ))
        }
        "vectors" => {
            d.validate(dir)?;
            let (_, r, n) = regenerate(&d)?;
            write_json(&vpath, &r)?;
            Ok(format!("wrote {n} address vectors"))
        }
        "as-v2" => {
            let v2 = d.as_v2(dir)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&v2).map_err(|e| e.to_string())?
            );
            Ok("printed the version 2 template".into())
        }
        _ => Err(format!("unknown descriptor command {cmd}")),
    }
}

fn cmd_descriptor(args: &[String]) -> ExitCode {
    let Some((cmd, dirs)) = args.split_first() else {
        return usage();
    };
    if dirs.is_empty() {
        return usage();
    }
    let mut failed = false;
    for dir in dirs {
        match descriptor_one(cmd, std::path::Path::new(dir)) {
            Ok(msg) => println!("{dir}: {msg}"),
            Err(e) => {
                println!("{dir}: {e}");
                failed = true;
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
        Some("run") => cmd_run(),
        Some("descriptor") => cmd_descriptor(&args[1..]),
        Some("expand") if args.len() == 2 => match std::fs::read_to_string(&args[1])
            .map_err(|e| e.to_string())
            .and_then(|s| sequentia_contracts::expand(&s))
        {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{}: {e}", args[1]);
                ExitCode::FAILURE
            }
        },
        _ => usage(),
    }
}
