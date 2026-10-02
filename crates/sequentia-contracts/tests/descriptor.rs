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
