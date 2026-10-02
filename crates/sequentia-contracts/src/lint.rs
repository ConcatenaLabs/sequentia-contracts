//! Lints that refuse jets which are wrong on Sequentia.
//!
//! - `lbtc_asset` returns a constant: Liquid's L-BTC asset id. On Sequentia it
//!   names no asset at all, so a program that uses it to mean "the fee asset"
//!   or "the native coin" is wrong here.
//! - `check_lock_distance`, `check_lock_duration`, `tx_lock_distance` and
//!   `tx_lock_duration` (called `broken_do_not_use_*` from SimplicityHL 0.6.0
//!   on) read the largest relative lock over every input of the transaction,
//!   not the input being spent. A spender defeats a lock built on them by
//!   adding an old coin of their own. A correct relative lock requires
//!   `version() >= 2` and reads `parse_sequence(current_sequence())`.
//!
//! Two layers run on every program:
//!
//! 1. A source scan, after comments are removed, for any identifier that names
//!    one of these jets under either spelling. It works on any text, including
//!    templates that do not compile and programs written for older compilers.
//! 2. When the source compiles under the pinned compiler, a walk over every
//!    jet node of the compiled program. This catches the jet whatever it was
//!    called in the source, because it inspects the jet itself.
//!
//! The second layer is the one that cannot be fooled, so a program the lint
//! could not compile has not passed it: [`Report::compiled`] says whether the
//! layer ran, and `seqc lint` fails when it did not unless the caller asked
//! for the source scan alone.
//!
//! A program that imports other files with `use` compiles only against the
//! dependency map it is built with. [`lint_with_deps`] compiles it the way
//! Simplex builds it (the same map, every unstable feature enabled), and scans
//! the flattened program Simplex embeds and compiles at run time.

use simplicityhl::simplicity::dag::{DagLike, InternalSharing};
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::node::Inner;

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use simplicityhl::ast::ElementsJetHinter;
use simplicityhl::resolution::DependencyMap;
use simplicityhl::source::{CanonPath, CanonSourceFile};
use simplicityhl::{TemplateProgram, UnstableFeatures};

/// A jet the lints refuse, with the reason given to the author.
pub struct BannedJet {
    pub jet: Elements,
    /// Every spelling under which a SimplicityHL source can name the jet.
    pub names: &'static [&'static str],
    pub reason: &'static str,
}

const LBTC: &str = "returns Liquid's L-BTC asset id, which names no asset on Sequentia";
const LOCK: &str = "reads the largest relative lock of ANY input, so a spender bypasses it \
                    with an old coin of their own; require version() >= 2 and read \
                    parse_sequence(current_sequence()) instead";

/// The jets no Sequentia program may use.
pub const BANNED_JETS: &[BannedJet] = &[
    BannedJet {
        jet: Elements::LbtcAsset,
        names: &["lbtc_asset"],
        reason: LBTC,
    },
    BannedJet {
        jet: Elements::BrokenDoNotUseCheckLockDistance,
        names: &[
            "check_lock_distance",
            "broken_do_not_use_check_lock_distance",
        ],
        reason: LOCK,
    },
    BannedJet {
        jet: Elements::BrokenDoNotUseCheckLockDuration,
        names: &[
            "check_lock_duration",
            "broken_do_not_use_check_lock_duration",
        ],
        reason: LOCK,
    },
    BannedJet {
        jet: Elements::BrokenDoNotUseTxLockDistance,
        names: &["tx_lock_distance", "broken_do_not_use_tx_lock_distance"],
        reason: LOCK,
    },
    BannedJet {
        jet: Elements::BrokenDoNotUseTxLockDuration,
        names: &["tx_lock_duration", "broken_do_not_use_tx_lock_duration"],
        reason: LOCK,
    },
];

/// How a finding was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    /// The identifier appears in the source text.
    Source,
    /// The identifier appears in the flattened program: the entry file with
    /// every file it imports resolved into it.
    Flattened,
    /// The jet appears in the compiled program.
    Compiled,
}

/// One use of a banned jet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub layer: Layer,
    /// The name found in the source, or the jet's canonical name.
    pub name: String,
    /// 1-based line in the source, for source findings.
    pub line: Option<usize>,
    pub reason: &'static str,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.layer, self.line) {
            (Layer::Source, Some(line)) => {
                write!(f, "line {line}: `{}` {}", self.name, self.reason)
            }
            (Layer::Flattened, Some(line)) => write!(
                f,
                "flattened program, line {line}: `{}` {}",
                self.name, self.reason
            ),
            _ => write!(
                f,
                "compiled program uses jet `{}`: {}",
                self.name, self.reason
            ),
        }
    }
}

/// The result of linting one program.
#[derive(Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    /// Whether the source compiled under the pinned compiler, so that the
    /// compiled layer ran.
    pub compiled: bool,
    /// Why the source did not compile, when it did not.
    pub compile_error: Option<String>,
    /// The commitment root of the compiled program, as lowercase hex, when
    /// it compiled (with every parameter at zero).
    pub cmr: Option<String>,
}

impl Report {
    /// No banned jet was found by the layers that ran.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// The program passed the lint: no finding, and the compiled layer ran.
    /// With `source_only`, a source that does not compile passes on the
    /// source scan alone; only fragments that are not programs (helpers,
    /// templates with placeholders) should be linted that way.
    pub fn passed(&self, source_only: bool) -> bool {
        self.is_clean() && (self.compiled || source_only)
    }
}

/// Lint a SimplicityHL source with both layers.
pub fn lint_source(source: &str) -> Report {
    let expanded = crate::expand(source).unwrap_or_else(|_| source.to_string());
    let mut report = Report {
        findings: scan_source(&expanded),
        ..Report::default()
    };
    match crate::template(source) {
        Ok(template) => {
            let args = crate::zero_arguments(&template);
            match template.instantiate(args, false) {
                Ok(program) => {
                    report.compiled = true;
                    report.cmr = Some(crate::cmr_hex(&program));
                    report.findings.extend(scan_compiled(&program.commit()));
                }
                Err(e) => report.compile_error = Some(e),
            }
        }
        Err(e) => report.compile_error = Some(e),
    }
    report
}

/// Lint one program the way Simplex builds it.
///
/// `entry` is compiled with `deps` and every unstable feature enabled, as
/// Simplex's build does, and flattened into the single source Simplex embeds
/// and compiles at run time. The source layer scans the entry file and the
/// flattened text; the compiled layer scans the program compiled from the
/// flattened text. The compiled layer counts as run only when that program
/// has the same commitment root as the one compiled from the dependency map,
/// so the scanned program is the one that will be deployed.
pub fn lint_with_deps(entry: &Path, deps: &DependencyMap) -> Report {
    let mut report = Report::default();
    let text = match std::fs::read_to_string(entry) {
        Ok(t) => t,
        Err(e) => {
            report.compile_error = Some(format!("{}: {e}", entry.display()));
            return report;
        }
    };
    report.findings = scan_source(&text);
    let canon = match CanonPath::canonicalize(entry) {
        Ok(c) => c,
        Err(e) => {
            report.compile_error = Some(format!("{}: {e}", entry.display()));
            return report;
        }
    };
    let file = CanonSourceFile::new(canon, Arc::from(text.as_str()));
    let features = UnstableFeatures::all();

    let flattened = match TemplateProgram::flatten(file.clone(), deps, &features) {
        Ok(f) => f,
        Err(d) => {
            report.compile_error = Some(d.to_string());
            return report;
        }
    };
    for mut f in scan_source(&flattened) {
        f.layer = Layer::Flattened;
        report.findings.push(f);
    }

    let built = TemplateProgram::new_with_dep(file, deps, &features, Box::new(ElementsJetHinter))
        .map_err(|d| d.to_string())
        .and_then(|t| t.instantiate(crate::zero_arguments(&t), false));
    let deployed = TemplateProgram::new_with_unstable(
        flattened.as_str(),
        &features,
        Box::new(ElementsJetHinter),
    )
    .map_err(|d| d.to_string())
    .and_then(|t| t.instantiate(crate::zero_arguments(&t), false));
    match (built, deployed) {
        (Ok(built), Ok(deployed)) => {
            let (a, b) = (crate::cmr_hex(&built), crate::cmr_hex(&deployed));
            if a != b {
                report.compile_error = Some(format!(
                    "the program compiled from the dependency map (root {a}) differs from \
                     the flattened program (root {b})"
                ));
                return report;
            }
            report.compiled = true;
            report.cmr = Some(b);
            report.findings.extend(scan_compiled(&deployed.commit()));
            // The jets are the same in both when the roots are; scan both anyway,
            // so a difference in how either is built cannot hide one.
            for f in scan_compiled(&built.commit()) {
                if !report
                    .findings
                    .iter()
                    .any(|g| g.layer == Layer::Compiled && g.name == f.name)
                {
                    report.findings.push(f);
                }
            }
        }
        (Err(e), _) | (_, Err(e)) => report.compile_error = Some(e),
    }
    report
}

/// Layer 1: banned identifiers in the source text, comments removed.
pub fn scan_source(source: &str) -> Vec<Finding> {
    let text = strip_comments(source);
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        for token in line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            if token.is_empty() {
                continue;
            }
            if let Some(b) = BANNED_JETS.iter().find(|b| b.names.contains(&token)) {
                out.push(Finding {
                    layer: Layer::Source,
                    name: token.to_string(),
                    line: Some(i + 1),
                    reason: b.reason,
                });
            }
        }
    }
    out
}

/// Layer 2: banned jets anywhere in a compiled program, every branch included.
pub fn scan_compiled(program: &crate::CommitNode) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for node in program.as_ref().post_order_iter::<InternalSharing>() {
        if let Inner::Jet(jet) = node.node.inner() {
            if let Some(elements) = jet.as_any().downcast_ref::<Elements>() {
                if let Some(b) = BANNED_JETS.iter().find(|b| b.jet == *elements) {
                    let name = elements.to_string();
                    if !out.iter().any(|f| f.name == name) {
                        out.push(Finding {
                            layer: Layer::Compiled,
                            name,
                            line: None,
                            reason: b.reason,
                        });
                    }
                }
            }
        }
    }
    out
}

/// Replace `//` and `/* */` comments with spaces, keeping line breaks so line
/// numbers stay right. SimplicityHL has no string literals, so no quoting
/// needs handling.
fn strip_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i < bytes.len()
                && !(bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/')
            {
                out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                i += 1;
            }
            i += 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_do_not_trigger_the_source_layer() {
        let src =
            "// lbtc_asset is banned\n/* check_lock_distance\n tx_lock_duration */\nfn main() {}";
        let r = lint_source(src);
        assert!(r.is_clean(), "{:?}", r.findings);
        assert!(r.compiled);
    }

    #[test]
    fn a_clean_safe_lock_passes() {
        let src = "fn main() {\n\
                   assert!(jet::le_32(2, jet::version()));\n\
                   let d: u16 = match unwrap(jet::parse_sequence(jet::current_sequence())) {\n\
                       Left(blocks: u16) => blocks,\n\
                       Right(units: u16) => panic!(),\n\
                   };\n\
                   assert!(jet::le_16(10, d));\n\
                   }";
        let r = lint_source(src);
        assert!(r.compiled, "{:?}", r.compile_error);
        assert!(r.is_clean(), "{:?}", r.findings);
    }

    #[test]
    fn line_numbers_survive_block_comments() {
        let src = "/*\n\n*/\nfn main() { let a: u256 = jet::lbtc_asset(); }";
        let f = scan_source(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].line, Some(4));
    }
}
