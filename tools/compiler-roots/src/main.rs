//! Compile each program of a request under SimplicityHL 0.4.1 and under the
//! pinned compiler, and report both commitment roots.
//!
//! Request on stdin: {"programs": [{"id", "source", "args", "debug"}]}, where
//! `args` uses the typed form {"NAME": {"value": "...", "type": "..."}}. An
//! argument value "@cmr:<id>" is replaced by the root of the earlier program
//! <id> under the same compiler, so a program that commits to another's root
//! is compared under one compiler at a time.
//!
//! Reply on stdout: {"compilers": {...}, "programs": [{"id", "v0_4_1": {...},
//! "pinned": {...}}]}, each side {"cmr", "program_bytes"} or {"error"}; the
//! pinned side also carries the lint findings.

use std::collections::HashMap;
use std::io::Read;

use sequentia_contracts::{hex, lint, COMPILER_VERSION};
use serde_json::{json, Map, Value};

fn resolve(args: &Value, roots: &HashMap<String, String>) -> Result<String, String> {
    let mut args = args.clone();
    if let Some(map) = args.as_object_mut() {
        for (_, v) in map.iter_mut() {
            let reference = v
                .get("value")
                .and_then(Value::as_str)
                .and_then(|s| s.strip_prefix("@cmr:"))
                .map(str::to_string);
            if let Some(id) = reference {
                let cmr = roots
                    .get(&id)
                    .ok_or_else(|| format!("no root for {id} under this compiler"))?;
                v["value"] = Value::String(format!("0x{cmr}"));
            }
        }
    }
    Ok(args.to_string())
}

fn compile_041(source: &str, args: &str, debug: bool) -> Result<(String, usize), String> {
    let arguments: simplicityhl041::Arguments =
        serde_json::from_str(args).map_err(|e| format!("arguments: {e}"))?;
    let program = simplicityhl041::CompiledProgram::new(source, arguments, debug)?;
    let commit = program.commit();
    Ok((hex(commit.cmr().as_ref()), commit.to_vec_without_witness().len()))
}

fn compile_pinned(source: &str, args: &str, debug: bool) -> Result<(String, usize), String> {
    let arguments: sequentia_contracts::simplicityhl::Arguments =
        serde_json::from_str(args).map_err(|e| format!("arguments: {e}"))?;
    let program = sequentia_contracts::template(source)?.instantiate(arguments, debug)?;
    let commit = program.commit();
    Ok((hex(commit.cmr().as_ref()), commit.to_vec_without_witness().len()))
}

fn side(r: Result<(String, usize), String>) -> Value {
    match r {
        Ok((cmr, n)) => json!({"cmr": cmr, "program_bytes": n}),
        Err(e) => json!({"error": e}),
    }
}

fn main() {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text).expect("stdin");
    let req: Value = serde_json::from_str(&text).expect("request JSON");
    let mut roots_041: HashMap<String, String> = HashMap::new();
    let mut roots_pinned: HashMap<String, String> = HashMap::new();
    let mut out = Vec::new();
    for p in req["programs"].as_array().expect("programs") {
        let id = p["id"].as_str().expect("id").to_string();
        let source = p["source"].as_str().expect("source");
        let debug = p.get("debug").and_then(Value::as_bool).unwrap_or(false);
        let empty = json!({});
        let args = p.get("args").unwrap_or(&empty);

        let old = resolve(args, &roots_041).and_then(|a| compile_041(source, &a, debug));
        let new = resolve(args, &roots_pinned).and_then(|a| compile_pinned(source, &a, debug));
        if let Ok((cmr, _)) = &old {
            roots_041.insert(id.clone(), cmr.clone());
        }
        if let Ok((cmr, _)) = &new {
            roots_pinned.insert(id.clone(), cmr.clone());
        }
        let mut pinned = side(new);
        let findings: Vec<String> = lint::lint_source(source)
            .findings
            .iter()
            .map(|f| f.to_string())
            .collect();
        if let Some(m) = pinned.as_object_mut() {
            m.insert("lint".into(), findings.into());
        }
        let mut entry = Map::new();
        entry.insert("id".into(), id.into());
        entry.insert("v0_4_1".into(), side(old));
        entry.insert("pinned".into(), pinned);
        out.push(Value::Object(entry));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "compilers": {"v0_4_1": "0.4.1", "pinned": COMPILER_VERSION},
            "programs": out,
        }))
        .unwrap()
    );
}
