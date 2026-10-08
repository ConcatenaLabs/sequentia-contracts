//! Every template's descriptor validates (each source compiles to its recorded
//! root and cost bound under the pinned compiler), and its golden vectors are
//! exactly what the descriptor derives. Every refusal in
//! `mirrors/fixtures/refusals.json` is made, for its reason. The Python,
//! JavaScript and Go mirrors check the same vectors and the same refusals, so
//! all four implementations agree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sequentia_contracts::descriptor::{
    template_hash, Descriptor, Node, TreeVector, Vectors, VectorsV2,
};
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every template, and every fixture that is a descriptor.
fn descriptor_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for base in ["templates", "mirrors/fixtures"] {
        for e in std::fs::read_dir(root().join(base)).unwrap() {
            let p = e.unwrap().path();
            if p.join("descriptor.json").is_file() {
                dirs.push(p);
            }
        }
    }
    dirs.sort();
    assert!(dirs.iter().any(|d| d.ends_with("one_key_exit")));
    dirs
}

#[test]
fn every_template_validates_and_matches_its_vectors() {
    for dir in descriptor_dirs() {
        let d = Descriptor::load(&dir.join("descriptor.json")).unwrap();
        d.validate(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        if d.descriptor == 1 {
            let v = Vectors::load(&dir.join("vectors.json")).unwrap();
            assert!(!v.addresses.is_empty(), "{}", dir.display());
            assert_eq!(v.regenerate(&d).unwrap(), v, "{}", dir.display());
        } else {
            let v = VectorsV2::load(&dir.join("vectors.json")).unwrap();
            assert!(!v.addresses.is_empty(), "{}", dir.display());
            assert_eq!(v.regenerate(&d).unwrap(), v, "{}", dir.display());
        }
    }
}

fn load(dir: &str) -> (PathBuf, Descriptor) {
    let dir = root().join(dir);
    let d = Descriptor::load(&dir.join("descriptor.json")).unwrap();
    (dir, d)
}

#[test]
fn a_version_1_template_is_the_version_2_fixture() {
    // The fixture is one_key written out as a version 2 tree. The reader's
    // own reading of version 1 gives exactly its template, and the two sets
    // of vectors give the same addresses.
    let (dir, d) = load("templates/one_key");
    let (fdir, f) = load("mirrors/fixtures/one_key_as_v2");
    assert_eq!(d.as_v2(&dir).unwrap(), f.template);
    assert_eq!(
        std::fs::read(dir.join("one_key.simf")).unwrap(),
        std::fs::read(fdir.join("one_key.simf")).unwrap()
    );
    let a = Vectors::load(&dir.join("vectors.json")).unwrap();
    let b = VectorsV2::load(&fdir.join("vectors.json")).unwrap();
    assert_eq!(a.addresses.len(), b.addresses.len());
    for (x, y) in a.addresses.iter().zip(&b.addresses) {
        assert_eq!(x.params, y.params);
        assert_eq!(x.address, y.address);
        assert_eq!(x.data_leaf, y.leaves["params"].hash);
        assert_eq!(x.program_leaf, y.leaves["program"].hash);
        assert_eq!(Some(&x.param_bytes), y.leaves["params"].data.as_ref());
    }
}

fn edit(doc: &mut Value, op: &Value) {
    let at = op["at"].as_array().unwrap();
    let mut target = doc;
    for k in &at[..at.len() - 1] {
        target = match k {
            Value::String(s) => target.get_mut(s.as_str()).unwrap(),
            Value::Number(n) => target.get_mut(n.as_u64().unwrap() as usize).unwrap(),
            _ => panic!("bad path"),
        };
    }
    let last = &at[at.len() - 1];
    let o = op.as_object().unwrap();
    if let Some(v) = o.get("set") {
        match last {
            Value::String(s) => {
                target[s.as_str()] = v.clone();
            }
            Value::Number(n) => target[n.as_u64().unwrap() as usize] = v.clone(),
            _ => panic!("bad path"),
        }
    } else if o.contains_key("delete") {
        match last {
            Value::String(s) => {
                target.as_object_mut().unwrap().remove(s.as_str());
            }
            Value::Number(n) => {
                target
                    .as_array_mut()
                    .unwrap()
                    .remove(n.as_u64().unwrap() as usize);
            }
            _ => panic!("bad path"),
        }
    } else if let Some(v) = o.get("append") {
        target[last.as_str().unwrap()]
            .as_array_mut()
            .unwrap()
            .push(v.clone());
    } else if let Some(v) = o.get("suffix") {
        let k = last.as_str().unwrap();
        let s = format!("{}{}", target[k].as_str().unwrap(), v.as_str().unwrap());
        target[k] = s.into();
    } else {
        panic!("unknown edit {op}");
    }
}

fn refusal_text(case: &Value) -> String {
    let base = root().join(case["base"].as_str().unwrap());
    let mut text = std::fs::read_to_string(base.join("descriptor.json")).unwrap();
    if let Some(replacements) = case.get("text") {
        for r in replacements.as_array().unwrap() {
            let (from, to) = (r[0].as_str().unwrap(), r[1].as_str().unwrap());
            assert!(text.contains(from), "{}: {from}", case["name"]);
            text = text.replacen(from, to, 1);
        }
        return text;
    }
    let mut doc = sequentia_contracts::descriptor::parse_json(&text).unwrap();
    for op in case["edit"].as_array().unwrap() {
        edit(&mut doc, op);
    }
    if case.get("reseal").and_then(Value::as_bool) != Some(false) {
        doc["template_hash"] = template_hash(&doc["template"]).into();
    }
    serde_json::to_string_pretty(&doc).unwrap()
}

fn strings(v: &Value) -> BTreeMap<String, String> {
    v.as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect()
}

#[test]
fn every_refusal_is_made_for_its_reason() {
    let text = std::fs::read_to_string(root().join("mirrors/fixtures/refusals.json")).unwrap();
    // The corpus nests a tree deeper than serde_json's default limit allows.
    let doc = sequentia_contracts::descriptor::parse_json(&text).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() > 50);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let base = root().join(case["base"].as_str().unwrap());
        let text = refusal_text(case);
        let read = Descriptor::parse(&text).and_then(|d| d.validate(&base).map(|()| d));
        if case.get("accept").and_then(Value::as_bool) == Some(true) {
            read.unwrap_or_else(|e| panic!("{name}: refused: {e}"));
            continue;
        }
        let err = match (read, case.get("derive")) {
            (Ok(d), Some(v)) => d
                .model()
                .unwrap()
                .derive(&strings(&v["params"]), &strings(&v["slots"]))
                .map(|_| ())
                .expect_err(name),
            (Ok(_), None) => panic!("{name}: ACCEPTED"),
            (Err(e), Some(_)) => panic!("{name}: the descriptor is refused: {e}"),
            (Err(e), None) => e,
        };
        let expect = case["expect"].as_str().unwrap();
        assert!(
            err.contains(expect),
            "{name}: refused, but not for {expect:?}: {err}"
        );
    }
}

#[test]
fn an_edit_to_a_leaf_source_or_its_root_fails_validation() {
    let (dir, mut d) = load("templates/one_key_exit");
    fn leaf(d: &mut Descriptor) -> &mut Value {
        &mut d.template["tree"]["branch"][0]["branch"][0]["simplicity"]
    }
    leaf(&mut d)["cmr"] = "00".repeat(32).into();
    d.template_hash = template_hash(&d.template);
    assert!(d.validate(&dir).unwrap_err().contains("compiles to"));

    let (_, mut d) = load("templates/one_key_exit");
    leaf(&mut d)["max_cost_wu"] = 71.into();
    d.template_hash = template_hash(&d.template);
    assert!(d.validate(&dir).unwrap_err().contains("cost bound is 72"));

    let (_, mut d) = load("templates/one_key_exit");
    leaf(&mut d)["witness"][1]["name"] = "SIGNATURE".into();
    d.template_hash = template_hash(&d.template);
    assert!(d
        .validate(&dir)
        .unwrap_err()
        .contains("the program declares"));

    let (_, mut d) = load("templates/one_key_exit");
    leaf(&mut d)["compiler"]["version"] = "0.4.1".into();
    d.template_hash = template_hash(&d.template);
    assert!(d.validate(&dir).unwrap_err().contains("pins simplicityhl"));

    let (_, mut d) = load("templates/one_key_exit");
    d.template["budget"]["per_witness_byte"] = 1.into();
    d.template_hash = template_hash(&d.template);
    assert!(d
        .validate(&dir)
        .unwrap_err()
        .contains("rule a Sequentia node applies"));
}

#[test]
fn version_1_parameters_must_be_complete_and_of_their_width() {
    let (_, d) = load("templates/one_key");
    let short: BTreeMap<String, String> = [("PK".to_string(), "00".repeat(31))].into();
    assert!(d.param_bytes(&short).unwrap_err().contains("is 31 bytes"));
    assert!(d.param_bytes(&BTreeMap::new()).is_err());
    let upper: BTreeMap<String, String> = [("PK".to_string(), "AB".repeat(32))].into();
    assert!(d.param_bytes(&upper).unwrap_err().contains("lowercase hex"));
}

/// Whether the vector puts each branch's first child's hash below its
/// second's, branch by branch, depth first.
fn orders(node: &Node, v: &TreeVector, out: &mut Vec<bool>) -> String {
    match node {
        Node::Branch(a, b) => {
            let (ha, hb) = (orders(a, v, out), orders(b, v, out));
            out.push(ha < hb);
            use sequentia_contracts::simplicityhl::elements::hashes::{sha256, Hash, HashEngine};
            let tag = sha256::Hash::hash(b"TapBranch/elements");
            let mut e = sha256::Hash::engine();
            e.input(tag.as_ref());
            e.input(tag.as_ref());
            let (lo, hi) = if ha < hb { (&ha, &hb) } else { (&hb, &ha) };
            e.input(&hex_bytes(lo));
            e.input(&hex_bytes(hi));
            sequentia_contracts::hex(sha256::Hash::from_engine(e).as_ref())
        }
        leaf => v.leaves[leaf.name().unwrap()].hash.clone(),
    }
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn vectors_cover_every_order_of_every_branch_with_both_parities() {
    for dir in descriptor_dirs() {
        let d = Descriptor::load(&dir.join("descriptor.json")).unwrap();
        let model = d.model().unwrap();
        let branches = model.tree.branches();
        assert!(
            branches <= 3,
            "{}: list the combinations to cover",
            dir.display()
        );
        let mut seen = std::collections::BTreeSet::new();
        if d.descriptor == 1 {
            let v = Vectors::load(&dir.join("vectors.json")).unwrap();
            for a in &v.addresses {
                seen.insert((vec![a.program_leaf < a.data_leaf], a.output_key_parity));
            }
        } else {
            let v = VectorsV2::load(&dir.join("vectors.json")).unwrap();
            for a in &v.addresses {
                let mut o = Vec::new();
                let root = orders(&model.tree, a, &mut o);
                assert_eq!(root, a.merkle_root, "{}", dir.display());
                seen.insert((o, a.output_key_parity));
            }
        }
        let want = 1usize << (branches + 1);
        assert_eq!(
            seen.len(),
            want,
            "{}: the vectors cover {} of the {want} combinations of branch order and parity",
            dir.display(),
            seen.len()
        );
    }
}

/// Each Simplicity leaf's source, with its includes resolved, by source name:
/// what a wallet is handed alongside a descriptor.
fn expanded_sources(dir: &Path, d: &Descriptor) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (leaf, _) in d.model().unwrap().tree.leaves() {
        if let Node::Simplicity { program, .. } = leaf {
            let raw = std::fs::read_to_string(dir.join(&program.source)).unwrap();
            out.insert(
                program.source.clone(),
                sequentia_contracts::expand(&raw).unwrap(),
            );
        }
    }
    out
}

#[test]
fn every_template_validates_from_its_sources_as_text() {
    for dir in descriptor_dirs() {
        let d = Descriptor::load(&dir.join("descriptor.json")).unwrap();
        let sources = expanded_sources(&dir, &d);
        assert!(!sources.is_empty(), "{}", dir.display());
        d.validate_sources(&sources)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    }
}

#[test]
fn validating_from_text_refuses_what_validating_from_files_refuses() {
    let (dir, d) = load("templates/faucet_drip");
    let good = expanded_sources(&dir, &d);
    let name = "faucet_drip.simf".to_string();

    let e = d.validate_sources(&BTreeMap::new()).unwrap_err();
    assert!(
        e.contains("no text given for the source faucet_drip.simf"),
        "{e}"
    );

    // The source as stored, its includes not resolved: not the text the hash names.
    let raw = std::fs::read_to_string(dir.join(&name)).unwrap();
    let e = d
        .validate_sources(&BTreeMap::from([(name.clone(), raw)]))
        .unwrap_err();
    assert!(
        e.contains("the source with its includes resolved hashes to"),
        "{e}"
    );

    // One changed byte.
    let edited = good[&name].replacen("assert!(jet::eq_32(jet::current_index(), 0));", "", 1);
    assert_ne!(edited, good[&name]);
    let e = d
        .validate_sources(&BTreeMap::from([(name.clone(), edited)]))
        .unwrap_err();
    assert!(e.contains("source_sha256 is f6b1bc9c"), "{e}");

    // A descriptor whose root is not what the text compiles to, resealed.
    let mut text = std::fs::read_to_string(dir.join("descriptor.json")).unwrap();
    text = text.replace(
        "5251ec00d9799dbcdb31da4534f25ef9960321f195e2e24ef7125c46f24b972a",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let mut forged = Descriptor::parse(&text).unwrap();
    forged.template_hash = template_hash(&forged.template);
    let e = forged.validate_sources(&good).unwrap_err();
    assert!(e.contains("the source compiles to 5251ec00"), "{e}");
}

#[test]
fn a_resolved_source_compiles_without_a_file_system() {
    let e = sequentia_contracts::compile_expanded(
        "// include output_reader\nfn main() {}\n",
        simplicityhl::Arguments::default(),
    )
    .unwrap_err();
    assert!(
        e.contains("the source still includes a helper (// include output_reader)"),
        "{e}"
    );
    let p =
        sequentia_contracts::compile_expanded("fn main() {}\n", simplicityhl::Arguments::default())
            .unwrap();
    assert_eq!(
        sequentia_contracts::cmr_hex(&p),
        sequentia_contracts::cmr_hex(
            &sequentia_contracts::compile("fn main() {}\n", simplicityhl::Arguments::default())
                .unwrap()
        )
    );
}
