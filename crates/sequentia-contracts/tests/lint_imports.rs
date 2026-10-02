//! A banned jet reached through an import. Simplex compiles a program with
//! its dependency map and every unstable feature enabled; the lint must see
//! the program Simplex builds, and must not pass a program it cannot compile.

use std::path::{Path, PathBuf};

use sequentia_contracts::lint::{lint_source, lint_with_deps, Layer};
use sequentia_contracts::simplex;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../lints/fixtures")
        .canonicalize()
        .unwrap()
}

#[test]
fn a_program_that_does_not_compile_has_not_passed() {
    let entry = fixtures().join("reject/import/simf/native_asset.simf");
    let report = lint_source(&std::fs::read_to_string(&entry).unwrap());
    // The source scan alone finds nothing: the jet is in the dependency.
    assert!(report.is_clean(), "{:?}", report.findings);
    assert!(!report.compiled);
    assert!(
        !report.passed(false),
        "a program the lint could not compile passed it"
    );
    assert!(report.passed(true));
}

#[test]
fn the_project_is_compiled_with_its_dependency_map_and_refused() {
    let p = simplex::project(&fixtures().join("reject/import")).unwrap();
    let names: Vec<_> = p
        .entries
        .iter()
        .map(|e| e.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert_eq!(names, ["lock_distance.simf", "native_asset.simf"]);
    for (entry, jet) in p
        .entries
        .iter()
        .zip(["broken_do_not_use_check_lock_distance", "lbtc_asset"])
    {
        let report = lint_with_deps(entry, &p.deps);
        assert!(
            report.compiled,
            "{}: {:?}",
            entry.display(),
            report.compile_error
        );
        assert!(!report.passed(false) && !report.passed(true));
        for layer in [Layer::Compiled, Layer::Flattened] {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|f| f.layer == layer && f.name == jet),
                "{}: {layer:?} layer did not find {jet}: {:?}",
                entry.display(),
                report.findings
            );
        }
        // The entry file itself names no banned jet.
        assert!(report.findings.iter().all(|f| f.layer != Layer::Source));
    }
}

#[test]
fn a_clean_import_passes_with_the_compiled_layer() {
    let p = simplex::project(&fixtures().join("accept/import")).unwrap();
    assert_eq!(p.entries.len(), 1);
    let report = lint_with_deps(&p.entries[0], &p.deps);
    assert!(report.compiled, "{:?}", report.compile_error);
    assert!(report.passed(false), "{:?}", report.findings);
    assert!(report.cmr.is_some());
}
