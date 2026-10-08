//! The Simplicity toolchain for Sequentia contracts.
//!
//! This crate pins one SimplicityHL compiler and re-exports it. A program's
//! commitment Merkle root, and therefore its address, depends on the compiler
//! that built it, so every repository that compiles a Sequentia contract
//! depends on this crate instead of naming `simplicityhl` itself.
//!
//! It also carries the lints that refuse the jets which are wrong on this
//! chain (see [`lint`]).

pub mod attestation;
pub mod descriptor;
pub mod lint;
pub mod simplex;

use std::collections::HashMap;
use std::sync::Arc;

pub use simplicityhl;
pub use simplicityhl::elements;
pub use simplicityhl::simplicity;

use simplicityhl::ast::ElementsJetHinter;
use simplicityhl::str::WitnessName;
use simplicityhl::types::StructuralType;
use simplicityhl::value::StructuralValue;
use simplicityhl::{Arguments, CompiledProgram, TemplateProgram, Value};

/// The exact SimplicityHL version this repository compiles with.
///
/// `Cargo.toml` pins the same version with `=`; a unit test fails if the two
/// ever disagree.
pub const COMPILER_VERSION: &str = "0.7.2";

/// The line that includes a helper: `// include <name>` splices in
/// `helpers/<name>.simf`.
pub const INCLUDE_DIRECTIVE: &str = "// include ";

/// The directory helpers are included from: `SEQC_HELPERS` when set, else the
/// `helpers` directory of this repository.
pub fn helpers_dir() -> std::path::PathBuf {
    match std::env::var_os("SEQC_HELPERS") {
        Some(dir) => dir.into(),
        None => std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../helpers"),
    }
}

/// Resolve the helper includes of a source.
///
/// SimplicityHL's own imports are behind an unstable compiler flag, so shared
/// helpers are spliced in as text. A line that is exactly
/// `// include <name>` is replaced by the contents of `helpers/<name>.simf`,
/// whose own includes are resolved in turn; a helper is included once however
/// often it is named. A source with no include is returned unchanged. The
/// compiled program, and so its commitment root, depends only on the text this
/// returns.
pub fn expand(source: &str) -> Result<String, String> {
    let mut seen = std::collections::BTreeSet::new();
    expand_in(source, &helpers_dir(), &mut seen)
}

fn expand_in(
    source: &str,
    dir: &std::path::Path,
    seen: &mut std::collections::BTreeSet<String>,
) -> Result<String, String> {
    if !source
        .lines()
        .any(|l| l.trim_end().starts_with(INCLUDE_DIRECTIVE))
    {
        return Ok(source.to_string());
    }
    let mut out = String::new();
    for line in source.lines() {
        match line.trim_end().strip_prefix(INCLUDE_DIRECTIVE) {
            Some(name) => {
                let name = name.trim();
                if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return Err(format!("include: bad helper name {name:?}"));
                }
                if seen.insert(name.to_string()) {
                    let path = dir.join(format!("{name}.simf"));
                    let text = std::fs::read_to_string(&path)
                        .map_err(|e| format!("include {name}: {}: {e}", path.display()))?;
                    out.push_str(&expand_in(&text, dir, seen)?);
                    if !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
            }
            None => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    Ok(out)
}

/// Parse a SimplicityHL source, with its helper includes resolved, into a
/// template for the Elements jet set.
pub fn template(source: &str) -> Result<TemplateProgram, String> {
    let source = expand(source)?;
    TemplateProgram::new(source.as_str(), Box::new(ElementsJetHinter::new()))
        .map_err(|d| d.to_string())
}

/// Compile a SimplicityHL source with the given arguments, without debug
/// symbols, for the Elements jet set.
pub fn compile(source: &str, arguments: Arguments) -> Result<CompiledProgram, String> {
    template(source)?.instantiate(arguments, false)
}

/// Arguments that give every parameter of `template` its all-zero value.
///
/// The jets a program calls do not depend on its parameter values, so a
/// template instantiated with these arguments is enough to inspect which jets
/// it uses without knowing a real instance.
pub fn zero_arguments(template: &TemplateProgram) -> Arguments {
    let mut map: HashMap<WitnessName, Value> = HashMap::new();
    for (name, ty) in template.parameters().iter() {
        let structural = StructuralType::from(ty);
        let zero = simplicity::Value::zero(structural.as_ref());
        let value = Value::reconstruct(&StructuralValue::from(zero), ty)
            .expect("an all-zero value exists for every parameter type");
        map.insert(name.shallow_clone(), value);
    }
    Arguments::from(map)
}

/// The commitment Merkle root of a compiled program, as lowercase hex.
pub fn cmr_hex(program: &CompiledProgram) -> String {
    hex(program.commit().cmr().as_ref())
}

/// Lowercase hex encoding.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Shared handle to a compiled program's commitment node.
pub type CommitNode = Arc<simplicity::CommitNode>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_compiler_is_the_declared_one() {
        let program = compile("fn main() {}", Arguments::default()).unwrap();
        assert_eq!(program.compiler_version(), COMPILER_VERSION);
    }

    #[test]
    fn includes_are_spliced_once_and_a_source_without_one_is_unchanged() {
        let plain = "fn main() {}\n";
        assert_eq!(expand(plain).unwrap(), plain);
        let src = "// include fee_cap\n// include fee_cap\nfn main() {}\n";
        let text = expand(src).unwrap();
        assert_eq!(text.matches("fn fee_cap_require").count(), 1);
        assert!(expand("// include ../secret\nfn main() {}").is_err());
        assert!(expand("// include no_such_helper\nfn main() {}").is_err());
    }

    #[test]
    fn zero_arguments_instantiate_a_parameterised_template() {
        let source = "fn main() { assert!(jet::eq_32(param::N, 0)); \
                      jet::bip_0340_verify((param::PK, jet::sig_all_hash()), witness::SIG) }";
        let t = template(source).unwrap();
        let args = zero_arguments(&t);
        assert!(t.instantiate(args, false).is_ok());
    }
}
