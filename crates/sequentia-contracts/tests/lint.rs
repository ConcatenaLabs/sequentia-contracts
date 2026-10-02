//! The lints refuse every banned-jet fixture, pass the safe ones, and pass
//! every other SimplicityHL program in the repository.

use std::path::{Path, PathBuf};

use sequentia_contracts::lint::{lint_source, Layer};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn simf_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if path.is_dir() {
            if name == "target" || name.starts_with('.') {
                continue;
            }
            simf_files(&path, out);
        } else if name.ends_with(".simf") || name.ends_with(".simf.in") {
            out.push(path);
        }
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn every_reject_fixture_fails_the_lint() {
    let dir = repo_root().join("lints/fixtures/reject");
    let mut files = Vec::new();
    simf_files(&dir, &mut files);
    assert!(files.len() >= 7, "fixtures missing: {files:?}");
    for path in files {
        let report = lint_source(&read(&path));
        assert!(!report.is_clean(), "{} passed the lint", path.display());
        for f in &report.findings {
            println!("{}: {f}", path.file_name().unwrap().to_string_lossy());
        }
    }
}

#[test]
fn compiled_layer_finds_the_jet_itself() {
    // Each of these compiles under the pinned compiler, so the compiled layer
    // must find the jet in the program, independent of how the source spells it.
    let dir = repo_root().join("lints/fixtures/reject");
    for (file, jet) in [
        ("lbtc_asset.simf", "lbtc_asset"),
        (
            "broken_check_lock_distance.simf",
            "broken_do_not_use_check_lock_distance",
        ),
        (
            "broken_check_lock_duration.simf",
            "broken_do_not_use_check_lock_duration",
        ),
        (
            "broken_lock_probe.simf",
            "broken_do_not_use_tx_lock_distance",
        ),
        (
            "broken_lock_probe.simf",
            "broken_do_not_use_tx_lock_duration",
        ),
    ] {
        let report = lint_source(&read(&dir.join(file)));
        assert!(report.compiled, "{file}: {:?}", report.compile_error);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.layer == Layer::Compiled && f.name == jet),
            "{file}: compiled layer did not find {jet}: {:?}",
            report.findings
        );
    }
}

#[test]
fn source_layer_catches_what_the_compiler_cannot_see() {
    let dir = repo_root().join("lints/fixtures/reject");
    // Pre-0.6.0 spelling: the pinned compiler rejects the name, so only the
    // source layer can report it.
    let r = lint_source(&read(&dir.join("plain_name_check_lock_distance.simf")));
    assert!(!r.compiled);
    assert!(r
        .findings
        .iter()
        .any(|f| f.layer == Layer::Source && f.name == "check_lock_distance"));
    // A banned jet in a function main never calls is not in the compiled program.
    let r = lint_source(&read(&dir.join("lbtc_asset_in_unused_function.simf")));
    assert!(r.compiled, "{:?}", r.compile_error);
    assert!(r.findings.iter().all(|f| f.layer == Layer::Source));
    assert!(!r.findings.is_empty());
}

#[test]
fn every_other_program_in_the_repository_passes_the_lint() {
    let root = repo_root();
    let reject = root.join("lints/fixtures/reject");
    let mut files = Vec::new();
    simf_files(&root, &mut files);
    let mut checked = 0;
    for path in files.into_iter().filter(|p| !p.starts_with(&reject)) {
        let report = lint_source(&read(&path));
        assert!(
            report.is_clean(),
            "{}:\n{}",
            path.display(),
            report
                .findings
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        );
        checked += 1;
    }
    assert!(checked >= 2);
}
