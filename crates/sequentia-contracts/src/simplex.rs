//! A Simplex project, read the way Simplex's `build` reads it, so that its
//! programs can be linted exactly as Simplex compiles them.
//!
//! A project is a directory holding `Simplex.toml`. Its `[build]` table names
//! the source directory (`src_dir`, default `simf`), and its `[dependencies]`
//! table names other projects, each by `path` (relative to the project that
//! names it) or by `git` (installed by `simplex install` under `deps/` in the
//! root project). Every dependency is registered under the source directory
//! of the project that names it, and its own dependencies are followed in
//! turn, so the [`DependencyMap`] built here is the one Simplex builds.
//!
//! Simplex builds the `.simf` files of the source directory that its
//! `simf_files` patterns select and that declare `fn main`. The patterns are
//! not read here: every `.simf` file under the source directory that declares
//! `fn main` is an entry, which is the set Simplex builds or a larger one.

use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};

use simplicityhl::parse::{self, ParseFromStr};
use simplicityhl::resolution::{DependencyMap, DependencyMapBuilder};
use simplicityhl::source::CanonPath;
use simplicityhl::str::FunctionName;

/// The file that makes a directory a Simplex project.
pub const CONFIG_FILENAME: &str = "Simplex.toml";
/// The source directory when `[build] src_dir` is not given.
pub const DEFAULT_SRC_DIR: &str = "simf";
/// Where `simplex install` puts git dependencies, relative to the root project.
pub const DEPENDENCY_DIR: &str = "deps";

/// A project's programs and the dependency map they are built with.
pub struct Project {
    /// The canonical source directory.
    pub src_dir: PathBuf,
    /// Every `.simf` file under the source directory that declares `fn main`.
    pub entries: Vec<PathBuf>,
    /// The dependency map Simplex compiles these entries with.
    pub deps: DependencyMap,
}

enum Dep {
    Path(String),
    Git { url: String, reference: String },
}

struct Config {
    src_dir: String,
    deps: Vec<(String, Dep)>,
}

fn read_config(project: &Path) -> Result<Config, String> {
    let path = project.join(CONFIG_FILENAME);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let table: toml::Table = text
        .parse()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let src_dir = match table.get("build").and_then(|b| b.get("src_dir")) {
        None => DEFAULT_SRC_DIR.to_string(),
        Some(v) => v
            .as_str()
            .ok_or_else(|| format!("{}: build.src_dir is not a string", path.display()))?
            .to_string(),
    };
    let mut deps = Vec::new();
    if let Some(section) = table.get("dependencies") {
        let section = section
            .as_table()
            .ok_or_else(|| format!("{}: [dependencies] is not a table", path.display()))?;
        for (name, spec) in section {
            let spec = spec
                .as_table()
                .ok_or_else(|| format!("{}: dependency {name} is not a table", path.display()))?;
            let get = |k: &str| spec.get(k).and_then(|v| v.as_str()).map(str::to_string);
            for key in spec.keys() {
                if !["path", "git", "rev", "tag", "branch"].contains(&key.as_str()) {
                    return Err(format!(
                        "{}: dependency {name}: unknown field {key}",
                        path.display()
                    ));
                }
            }
            let dep = match (get("path"), get("git")) {
                (Some(p), None) => Dep::Path(p),
                (None, Some(url)) => {
                    let reference = match (get("rev"), get("tag"), get("branch")) {
                        (Some(r), None, None) => format!("rev={r}"),
                        (None, Some(t), None) => format!("tag={t}"),
                        (None, None, Some(b)) => format!("branch={b}"),
                        (None, None, None) => "HEAD".to_string(),
                        _ => {
                            return Err(format!(
                                "{}: dependency {name} names more than one of rev, tag and branch",
                                path.display()
                            ))
                        }
                    };
                    Dep::Git { url, reference }
                }
                _ => {
                    return Err(format!(
                        "{}: dependency {name} must name exactly one of path and git",
                        path.display()
                    ))
                }
            };
            deps.push((name.clone(), dep));
        }
    }
    Ok(Config { src_dir, deps })
}

/// The directory `simplex install` gives a git dependency: the repository's
/// name and a 16-digit hash of `<url>@<reference>`, as Simplex computes it.
pub fn git_dependency_dir(url: &str, reference: &str) -> Option<String> {
    let clean = url.strip_suffix(".git").unwrap_or(url);
    let name = clean.split('/').next_back().filter(|n| !n.is_empty())?;
    let mut hasher = DefaultHasher::new();
    format!("{url}@{reference}").hash(&mut hasher);
    Some(format!("{name}-{:016x}", hasher.finish()))
}

fn canon(path: &Path) -> Result<CanonPath, String> {
    CanonPath::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn collect(
    builder: &mut DependencyMapBuilder,
    visited: &mut HashSet<PathBuf>,
    deps_dir: &Path,
    config: &Config,
    package: &Path,
    simf_dir: &CanonPath,
) -> Result<(), String> {
    for (name, dep) in &config.deps {
        let dep_root = match dep {
            Dep::Path(p) => package.join(p),
            Dep::Git { url, reference } => deps_dir.join(
                git_dependency_dir(url, reference)
                    .ok_or_else(|| format!("dependency {name}: bad git url {url}"))?,
            ),
        };
        let dep_root = canon(&dep_root)?.as_path().to_path_buf();
        let dep_config = read_config(&dep_root)?;
        let dep_simf = canon(&dep_root.join(&dep_config.src_dir))?;
        builder.add_dependency(simf_dir.clone(), name.clone(), dep_simf.clone());
        if visited.insert(dep_root.clone()) {
            collect(
                builder,
                visited,
                deps_dir,
                &dep_config,
                &dep_root,
                &dep_simf,
            )?;
        }
    }
    Ok(())
}

fn declares_main(items: &[parse::Item], main: &FunctionName) -> bool {
    items.iter().any(|item| match item {
        parse::Item::Function(f) => f.name() == main,
        parse::Item::Module(m) => declares_main(m.items(), main),
        _ => false,
    })
}

fn simf_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in rd {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            simf_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "simf") {
            out.push(path);
        }
    }
    Ok(())
}

/// Read the Simplex project in `dir`.
pub fn project(dir: &Path) -> Result<Project, String> {
    let root = canon(dir)?.as_path().to_path_buf();
    let config = read_config(&root)?;
    let src_dir = canon(&root.join(&config.src_dir))?;
    let mut builder = DependencyMapBuilder::new();
    let mut visited = HashSet::from([root.clone()]);
    collect(
        &mut builder,
        &mut visited,
        &root.join(DEPENDENCY_DIR),
        &config,
        &root,
        &src_dir,
    )?;
    let deps = builder.build(src_dir.clone()).map_err(|e| e.to_string())?;

    let mut files = Vec::new();
    simf_files(src_dir.as_path(), &mut files)?;
    files.sort();
    let main = FunctionName::main();
    let mut entries = Vec::new();
    for path in files {
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if let Ok(program) = parse::Program::parse_from_str(&text) {
            if declares_main(program.items(), &main) {
                entries.push(path);
            }
        }
    }
    Ok(Project {
        src_dir: src_dir.as_path().to_path_buf(),
        entries,
        deps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_dependency_dir_is_named_like_simplex_names_it() {
        let d = git_dependency_dir("https://example.org/a/lib.git", "tag=v1").unwrap();
        assert!(d.starts_with("lib-") && d.len() == "lib-".len() + 16, "{d}");
        assert_ne!(
            d,
            git_dependency_dir("https://example.org/a/lib.git", "HEAD").unwrap()
        );
        assert!(git_dependency_dir("", "HEAD").is_none());
    }
}
