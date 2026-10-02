//! Every template's descriptor validates (the source compiles to its recorded
//! root under the pinned compiler), and its golden vectors are exactly what the
//! descriptor derives. The Python, JavaScript and Go mirrors check the same
//! vectors, so all four implementations agree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sequentia_contracts::descriptor::{template_hash, Descriptor, Vectors};

fn templates() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("descriptor.json").is_file())
        .collect();
    dirs.sort();
    assert!(!dirs.is_empty());
    dirs
}

#[test]
fn every_template_validates_and_matches_its_vectors() {
    for dir in templates() {
        let d = Descriptor::load(&dir.join("descriptor.json")).unwrap();
        d.validate(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        let v = Vectors::load(&dir.join("vectors.json")).unwrap();
        assert!(!v.addresses.is_empty(), "{}", dir.display());
        assert_eq!(v.regenerate(&d).unwrap(), v, "{}", dir.display());
    }
}

fn one_key() -> (PathBuf, Descriptor) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates/one_key");
    let d = Descriptor::load(&dir.join("descriptor.json")).unwrap();
    (dir, d)
}

#[test]
fn any_change_to_the_template_changes_its_hash_and_fails_validation() {
    let (dir, mut d) = one_key();
    d.template["params"][0]["role"] = "asset".into();
    assert_ne!(template_hash(&d.template), d.template_hash);
    assert!(d.validate(&dir).unwrap_err().contains("template_hash"));
}

#[test]
fn a_recorded_root_the_source_does_not_compile_to_is_refused() {
    let (dir, mut d) = one_key();
    d.template["program"]["cmr"] = "00".repeat(32).into();
    d.template_hash = template_hash(&d.template);
    assert!(d.validate(&dir).unwrap_err().contains("compiles to"));
}

#[test]
fn another_compiler_is_refused() {
    let (dir, mut d) = one_key();
    d.template["program"]["compiler"]["version"] = "0.4.1".into();
    d.template_hash = template_hash(&d.template);
    assert!(d.validate(&dir).unwrap_err().contains("pins simplicityhl"));
}

#[test]
fn parameters_must_be_complete_and_of_their_width() {
    let (_, d) = one_key();
    let short: BTreeMap<String, String> = [("PK".to_string(), "00".repeat(31))].into();
    assert!(d.param_bytes(&short).unwrap_err().contains("is 31 bytes"));
    assert!(d.param_bytes(&BTreeMap::new()).is_err());
    let upper: BTreeMap<String, String> = [("PK".to_string(), "AB".repeat(32))].into();
    assert!(d.param_bytes(&upper).unwrap_err().contains("lowercase hex"));
}

fn resealed(mut d: Descriptor, edit: impl FnOnce(&mut serde_json::Value)) -> Descriptor {
    edit(&mut d.template);
    d.template_hash = template_hash(&d.template);
    d
}

const X_OF_G: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

#[test]
fn a_key_path_is_refused_unless_the_template_declares_it() {
    let (dir, d) = one_key();
    // x(G): secret key 1. A key path anyone who knows that key can take.
    let undeclared = resealed(d.clone(), |t| t["internal_key"] = X_OF_G.into());
    let e = undeclared.validate(&dir).unwrap_err();
    assert!(e.contains("key path"), "{e}");
    // Declared in the template and described in `paths`: accepted.
    let declared = resealed(d.clone(), |t| {
        t["internal_key"] = X_OF_G.into();
        t["key_path"] = "cooperative".into();
        t["paths"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"name": "cooperative", "who": "the holder of the internal key",
                                     "effect": "Spends the output into any transaction that key signs."}));
    });
    declared.validate(&dir).unwrap();
    // Named in the template but not described in `paths`.
    let unnamed = resealed(d.clone(), |t| {
        t["internal_key"] = X_OF_G.into();
        t["key_path"] = "cooperative".into();
    });
    assert!(unnamed.validate(&dir).unwrap_err().contains("paths"));
    // The NUMS key with a key path declared: a contradiction.
    let nums = resealed(d, |t| t["key_path"] = "spend".into());
    assert!(nums.validate(&dir).unwrap_err().contains("NUMS"));
}

#[test]
fn unknown_fields_are_refused() {
    let (dir, d) = one_key();
    for edit in [
        (|t: &mut serde_json::Value| t["expiry"] = 5.into()) as fn(&mut serde_json::Value),
        |t| t["program"]["note"] = "x".into(),
        |t| t["params"][0]["default"] = "00".into(),
        |t| t["paths"][0]["key"] = "00".into(),
    ] {
        let e = resealed(d.clone(), edit).validate(&dir).unwrap_err();
        assert!(e.contains("unknown field"), "{e}");
    }
}

#[test]
fn integers_of_2_pow_53_or_more_are_refused() {
    let (dir, d) = one_key();
    let ok = resealed(d.clone(), |t| t["version"] = ((1u64 << 53) - 1).into());
    ok.validate(&dir).unwrap();
    let big = resealed(d.clone(), |t| t["version"] = (1u64 << 53).into());
    assert!(big.validate(&dir).unwrap_err().contains("2^53"));
    let float = resealed(d, |t| t["version"] = serde_json::json!(1.0));
    assert!(float.validate(&dir).unwrap_err().contains("2^53"));
    // The reader refuses such a number anywhere in the file.
    let text = std::fs::read_to_string(dir.join("descriptor.json")).unwrap();
    let tmp = std::env::temp_dir().join(format!("seqc-desc-{}.json", std::process::id()));
    std::fs::write(
        &tmp,
        text.replacen("\"descriptor\": 1", "\"descriptor\": 9007199254740993", 1),
    )
    .unwrap();
    let e = Descriptor::load(&tmp).unwrap_err();
    std::fs::remove_file(&tmp).unwrap();
    assert!(e.contains("2^53"), "{e}");
}

#[test]
fn vectors_cover_both_leaf_orders_and_both_parities() {
    for dir in templates() {
        let v = Vectors::load(&dir.join("vectors.json")).unwrap();
        let has = |f: &dyn Fn(&sequentia_contracts::descriptor::AddressVector) -> bool| {
            v.addresses.iter().any(f)
        };
        assert!(
            has(&|a| a.data_leaf < a.program_leaf),
            "{}: no data leaf below the program leaf",
            dir.display()
        );
        assert!(
            has(&|a| a.data_leaf > a.program_leaf),
            "{}: no data leaf above the program leaf",
            dir.display()
        );
        for order in [true, false] {
            for parity in [0, 1] {
                assert!(
                    has(&|a| (a.data_leaf > a.program_leaf) == order
                        && a.output_key_parity == parity),
                    "{}: no vector with data leaf above={order} and parity {parity}",
                    dir.display()
                );
            }
        }
    }
}
