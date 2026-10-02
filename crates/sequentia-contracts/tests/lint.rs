//! The lints refuse every banned-jet fixture, pass the safe ones, and pass
//! every other SimplicityHL program in the repository. A program passes only
//! when it compiled, so that the compiled layer ran; helpers and templates
//! with placeholders, which are not programs, pass on the source scan alone.

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
        assert!(!report.passed(false), "{} passed the lint", path.display());
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

/// A fragment that is not a program on its own: a helper, spliced in by
/// `// include`, or a template whose placeholders the harness fills in.
fn is_fragment(root: &Path, path: &Path) -> bool {
    path.starts_with(root.join("helpers")) || path.to_string_lossy().ends_with(".simf.in")
}

/// The Simplex project a file belongs to, if any.
fn simplex_project(root: &Path, path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .skip(1)
        .take_while(|d| d.starts_with(root) && *d != root)
        .filter(|d| d.join("Simplex.toml").exists())
        .last()
        .map(Path::to_path_buf)
}

#[test]
fn every_other_program_in_the_repository_passes_the_lint() {
    let root = repo_root();
    let reject = root.join("lints/fixtures/reject");
    let mut files = Vec::new();
    simf_files(&root, &mut files);
    let mut checked = 0;
    let mut compiled = 0;
    let mut projects = std::collections::BTreeSet::new();
    for path in files.into_iter().filter(|p| !p.starts_with(&reject)) {
        if let Some(project) = simplex_project(&root, &path) {
            projects.insert(project);
            continue;
        }
        let fragment = is_fragment(&root, &path);
        let report = lint_source(&read(&path));
        assert!(
            report.passed(fragment),
            "{}: compiled={} {:?}\n{}",
            path.display(),
            report.compiled,
            report.compile_error,
            report
                .findings
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        );
        checked += 1;
        compiled += report.compiled as usize;
    }
    for project in &projects {
        let p = sequentia_contracts::simplex::project(project).unwrap();
        assert!(!p.entries.is_empty(), "{}", project.display());
        for entry in &p.entries {
            let report = sequentia_contracts::lint::lint_with_deps(entry, &p.deps);
            assert!(
                report.passed(false),
                "{}: {:?} {:?}",
                entry.display(),
                report.compile_error,
                report.findings
            );
            checked += 1;
            compiled += 1;
        }
    }
    assert!(checked >= 2 && compiled >= 2);
}
