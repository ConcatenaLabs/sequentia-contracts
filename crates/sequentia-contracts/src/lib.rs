//! The Simplicity toolchain for Sequentia contracts.
//!
//! This crate pins one SimplicityHL compiler and re-exports it. A program's
//! commitment Merkle root, and therefore its address, depends on the compiler
//! that built it, so every repository that compiles a Sequentia contract
//! depends on this crate instead of naming `simplicityhl` itself.
//!
//! It also carries the lints that refuse the jets which are wrong on this
//! chain (see [`lint`]).

pub mod descriptor;
pub mod lint;

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

/// Parse a SimplicityHL source into a template for the Elements jet set.
pub fn template(source: &str) -> Result<TemplateProgram, String> {
    TemplateProgram::new(source, Box::new(ElementsJetHinter::new())).map_err(|d| d.to_string())
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
    fn zero_arguments_instantiate_a_parameterised_template() {
        let source = "fn main() { assert!(jet::eq_32(param::N, 0)); \
                      jet::bip_0340_verify((param::PK, jet::sig_all_hash()), witness::SIG) }";
        let t = template(source).unwrap();
        let args = zero_arguments(&t);
        assert!(t.instantiate(args, false).is_ok());
    }
}
