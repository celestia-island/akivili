//! Inter-plugin dependencies: the `[[dependencies]]` manifest section and
//! the semver constraint matcher every consumer shares.
//!
//! Design (media-editor program W-A, 2026-11-10): plugins may declare that
//! they require other plugins at specific versions. The DECLARATION lives
//! here (parse + validate + match); ENFORCEMENT lives with the installer
//! (chest's store ops consult `matches` before install and refuse with the
//! gap named; uninstall consults the reverse edge and refuses while a
//! dependent is installed). Old manifests without the section are
//! unaffected — the field is additive with an empty default.
//!
//! Constraint grammar (kept deliberately small — every operator is one
//! that a store UI can render as a sentence):
//!
//! ```text
//! "*"        any version
//! "0.3.2"    exactly this version
//! "^0.3"     compatible: same major, and if major is 0 same minor
//! "~0.3.2"   patch-level: same major.minor
//! ">=0.3"  ">0.3"  "<=0.4"  "<0.4"   one-sided bounds
//! ```
//!
//! Comparisons follow semver precedence: numeric core fields, then
//! prerelease (a prerelease sorts BEFORE its release; identifiers compare
//! numerically when numeric, lexically otherwise, shorter prefix first).
//! Build metadata is ignored, as semver mandates. The one-sided bounds
//! (`>=` `>` `<` `<=`) therefore admit prerelease candidates by pure
//! precedence (e.g. `>=0.3` matches `0.4.0-rc.1`) — the family-range
//! prerelease restriction below applies to `^` and `~` only.

use crate::RegistryResult;
use crate::error::RegistryError;

/// One `[[dependencies]]` row: the required plugin's registry id and a
/// version constraint string (see the module docs for the grammar).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyEntry {
    /// Required plugin id, same shape as a manifest id.
    pub id: String,
    /// Version constraint (e.g. `"^0.3"`). `"*"` means any.
    pub version: String,
}

/// A parsed version constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionConstraint {
    Any,
    Exact(Version),
    /// The bool records whether the base named its PATCH explicitly:
    /// npm pins the patch for `^0.0.z` but ranges the minor for `^0.0`.
    Caret(Version, bool),
    Tilde(Version),
    Gte(Version),
    Gt(Version),
    Lte(Version),
    Lt(Version),
}

/// A parsed semver version: three numeric core fields plus an optional
/// prerelease split into dot-separated identifiers. Build metadata is
/// parsed (for validity) and then ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Option<Vec<String>>,
}

impl Version {
    /// Parse a full semver string (`MAJOR.MINOR.PATCH[-pre][+build]`).
    /// Returns `None` on any non-conforming input — callers treat that as
    /// invalid data, never as zero.
    pub fn parse(raw: &str) -> Option<Self> {
        let (core_pre, build) = match raw.split_once('+') {
            Some((head, tail)) => (head, Some(tail)),
            None => (raw, None),
        };
        let (core, pre) = match core_pre.split_once('-') {
            Some((head, tail)) => (head, Some(tail)),
            None => (core_pre, None),
        };
        let mut fields = core.split('.');
        let mut next_num = || -> Option<u64> {
            let seg = fields.next()?;
            if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            // Leading zeros are forbidden by semver for numeric fields.
            if seg.len() > 1 && seg.starts_with('0') {
                return None;
            }
            seg.parse().ok()
        };
        let major = next_num()?;
        let minor = next_num()?;
        let patch = next_num()?;
        if fields.next().is_some() {
            return None;
        }
        let pre = pre.map(|p| p.split('.').map(|s| s.to_string()).collect::<Vec<String>>());
        if let Some(pre_ids) = &pre {
            if pre_ids.iter().any(|s| s.is_empty()) {
                return None;
            }
            // Prerelease identifiers: alphanumerics and hyphens only,
            // and digits-only identifiers carry no leading zeros (semver
            // §9 — the same rule the crate's own is_valid_semver enforces
            // for manifest versions; the two parsers must agree).
            for seg in pre_ids {
                if !seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                    return None;
                }
                let digits_only = !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit());
                if digits_only && seg.len() > 1 && seg.starts_with('0') {
                    return None;
                }
            }
        }
        let build_ok = build.is_none_or(|build| {
            !build.is_empty()
                && build.split('.').all(|s| {
                    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        });
        if !build_ok {
            return None;
        }
        Some(Version {
            major,
            minor,
            patch,
            pre,
        })
    }
}

/// semver precedence: core fields numerically; then a version WITHOUT a
/// prerelease is GREATER than the same version with one; prerelease
/// identifiers compare pairwise (numeric < alphanumeric, numeric
/// numerically, alphanumeric lexically), shorter list is SMALLER when the
/// shared prefix is equal.
fn compare(a: &Version, b: &Version) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let core = a
        .major
        .cmp(&b.major)
        .then(a.minor.cmp(&b.minor))
        .then(a.patch.cmp(&b.patch));
    if core != Ordering::Equal {
        return core;
    }
    match (&a.pre, &b.pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(pa), Some(pb)) => {
            for (x, y) in pa.iter().zip(pb.iter()) {
                let ord = match (is_numeric(x), is_numeric(y)) {
                    // Digit-only identifiers compare by magnitude
                    // WITHOUT a u64 roundtrip: (length, then lexical) is
                    // exact for canonical digit strings of any length — a
                    // u64 parse would collapse to Equal at 2^64 and break
                    // exact pins in both directions.
                    (true, true) => x.len().cmp(&y.len()).then_with(|| x.cmp(y)),
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    (false, false) => x.cmp(y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            pa.len().cmp(&pb.len())
        }
    }
}

fn is_numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Parse an operator constraint's BASE: a partial version where missing
/// trailing fields default to zero (`"0.3"` → 0.3.0). Prerelease and
/// build still follow full semver shape when present. Exact constraints
/// do NOT use this — a bare version must be complete.
/// Returns the base plus whether the PATCH was named explicitly.
fn parse_base(raw: &str) -> Option<(Version, bool)> {
    if let Some(v) = Version::parse(raw) {
        return Some((v, true));
    }
    // Partial: exactly two numeric fields.
    let mut fields = raw.split('.');
    let mut next_num = || -> Option<u64> {
        let seg = fields.next()?;
        if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if seg.len() > 1 && seg.starts_with('0') {
            return None;
        }
        seg.parse().ok()
    };
    let major = next_num()?;
    let minor = next_num()?;
    if fields.next().is_some() {
        return None;
    }
    Some((
        Version {
            major,
            minor,
            patch: 0,
            pre: None,
        },
        false,
    ))
}

impl VersionConstraint {
    /// Parse a constraint string. The empty string is rejected — a
    /// dependency row must SAY something (use `"*"` for any). Operator
    /// bases may be partial (`^0.3` = `^0.3.0`); a bare exact version
    /// must be complete (`0.3` alone does not parse).
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        if raw == "*" {
            return Some(VersionConstraint::Any);
        }
        if let Some(rest) = raw.strip_prefix('^') {
            return parse_base(rest)
                .map(|(v, patch_explicit)| VersionConstraint::Caret(v, patch_explicit));
        }
        if let Some(rest) = raw.strip_prefix('~') {
            return parse_base(rest).map(|(v, _)| VersionConstraint::Tilde(v));
        }
        if let Some(rest) = raw.strip_prefix(">=") {
            return parse_base(rest).map(|(v, _)| VersionConstraint::Gte(v));
        }
        if let Some(rest) = raw.strip_prefix('>') {
            return parse_base(rest).map(|(v, _)| VersionConstraint::Gt(v));
        }
        if let Some(rest) = raw.strip_prefix("<=") {
            return parse_base(rest).map(|(v, _)| VersionConstraint::Lte(v));
        }
        if let Some(rest) = raw.strip_prefix('<') {
            return parse_base(rest).map(|(v, _)| VersionConstraint::Lt(v));
        }
        Version::parse(raw).map(VersionConstraint::Exact)
    }

    /// Whether `version` (a full semver string) satisfies this constraint.
    /// An unparseable version simply does not match — the caller names the
    /// gap; it never guesses a pass.
    pub fn matches(&self, version: &str) -> bool {
        let Some(v) = Version::parse(version) else {
            return false;
        };
        use std::cmp::Ordering;
        match self {
            VersionConstraint::Any => true,
            VersionConstraint::Exact(e) => compare(&v, e) == Ordering::Equal,
            VersionConstraint::Gte(b) => compare(&v, b) != Ordering::Less,
            VersionConstraint::Gt(b) => compare(&v, b) == Ordering::Greater,
            VersionConstraint::Lte(b) => compare(&v, b) != Ordering::Greater,
            VersionConstraint::Lt(b) => compare(&v, b) == Ordering::Less,
            VersionConstraint::Caret(b, patch_explicit) => {
                // Compatible: >=b and < the next incompatible boundary.
                // Semver's compat rule: for 0.x the minor plays the major's
                // role (0.3 and 0.4 are incompatible).
                if compare(&v, b) == Ordering::Less {
                    return false;
                }
                let same_family = match (b.major, b.minor) {
                    // 0.0.x: the patch plays the major's role (npm caret)
                    // — but only when the base NAMED its patch: `^0.0`
                    // (patch defaulted) ranges the minor like npm does.
                    (0, 0) => {
                        v.major == 0 && v.minor == 0 && (!patch_explicit || v.patch == b.patch)
                    }
                    // 0.x (nonzero minor): the minor plays the major's role.
                    (0, _) => v.major == 0 && v.minor == b.minor,
                    _ => v.major == b.major,
                };
                same_family && caret_pre_ok(&v, b)
            }
            VersionConstraint::Tilde(b) => {
                if compare(&v, b) == Ordering::Less {
                    return false;
                }
                v.major == b.major && v.minor == b.minor && caret_pre_ok(&v, b)
            }
        }
    }
}

/// Within a family range (^ or ~), a PRERELEASE candidate satisfies only
/// when the range's base itself carries a prerelease (the semver range
/// rule, kept in its simple form: plain `^0.3` does not admit `0.3.4-rc.1`).
fn caret_pre_ok(v: &Version, b: &Version) -> bool {
    !(v.pre.is_some() && b.pre.is_none())
}

/// Validate one `[[dependencies]]` row (id shape + constraint parse).
/// Exposed for the manifest validator; enforcement is the installer's.
pub fn validate_entry(entry: &DependencyEntry, self_id: &str) -> RegistryResult<()> {
    let id = &entry.id;
    let shape_ok = !id.is_empty()
        && id
            .chars()
            .next()
            .map(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            .unwrap_or(false)
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !shape_ok {
        return Err(RegistryError::InvalidManifest(format!(
            "dependency id '{id}' must match ^[a-z0-9][a-z0-9-]*$ (same shape as a plugin id)"
        )));
    }
    if id == self_id {
        return Err(RegistryError::InvalidManifest(format!(
            "plugin '{self_id}' declares a dependency on itself"
        )));
    }
    if VersionConstraint::parse(&entry.version).is_none() {
        return Err(RegistryError::InvalidManifest(format!(
            "dependency '{id}' version constraint {:?} does not parse (*, exact, ^, ~, >=, >, <=, < over full semver)",
            entry.version
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parse_accepts_semver_and_rejects_garbage() {
        assert!(Version::parse("0.3.2").is_some());
        assert!(Version::parse("1.2.3-alpha.1").is_some());
        assert!(Version::parse("1.2.3-alpha.1+build.5").is_some());
        assert!(Version::parse("0.3").is_none());
        assert!(Version::parse("0.3.2.1").is_none());
        assert!(Version::parse("01.2.3").is_none(), "leading zeros rejected");
        assert!(Version::parse("").is_none());
        assert!(
            Version::parse("1.2.3-").is_none(),
            "empty prerelease rejected"
        );
        assert!(
            Version::parse("1.2.3+a..b").is_none(),
            "empty build segment rejected"
        );
        // semver §9: digits-only prerelease identifiers carry no leading
        // zeros — the same rule the crate's is_valid_semver enforces.
        assert!(
            Version::parse("1.2.3-01").is_none(),
            "numeric prerelease leading zero"
        );
        assert!(
            Version::parse("1.2.3-rc.007").is_none(),
            "embedded numeric leading zero"
        );
        assert!(Version::parse("1.2.3-0").is_some(), "plain zero is legal");
    }

    #[test]
    fn precedence_follows_semver() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert_eq!(compare(&v("1.0.0"), &v("1.0.0")), std::cmp::Ordering::Equal);
        assert_eq!(compare(&v("1.0.0"), &v("1.2.0")), std::cmp::Ordering::Less);
        // Prerelease sorts before its release.
        assert_eq!(
            compare(&v("1.0.0-alpha"), &v("1.0.0")),
            std::cmp::Ordering::Less
        );
        // Numeric identifiers compare numerically.
        assert_eq!(
            compare(&v("1.0.0-alpha.2"), &v("1.0.0-alpha.10")),
            std::cmp::Ordering::Less
        );
        // Numeric < alphanumeric.
        assert_eq!(
            compare(&v("1.0.0-1"), &v("1.0.0-alpha")),
            std::cmp::Ordering::Less
        );
        // Shorter prerelease list is smaller on equal prefix.
        assert_eq!(
            compare(&v("1.0.0-alpha"), &v("1.0.0-alpha.1")),
            std::cmp::Ordering::Less
        );
        // 2^64-scale digit identifiers compare by magnitude, not by a
        // u64 parse that would collapse to Equal (the exact-pin bypass).
        let huge = "18446744073709551616"; // 2^64
        assert_eq!(
            compare(&v("1.0.0-5"), &v(&format!("1.0.0-{huge}"))),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare(&v(&format!("1.0.0-{huge}")), &v("1.0.0-5")),
            std::cmp::Ordering::Greater
        );
        assert!(
            !VersionConstraint::parse(&format!("1.0.0-{huge}"))
                .unwrap()
                .matches("1.0.0-5")
        );
        assert!(
            !VersionConstraint::parse("1.0.0-5")
                .unwrap()
                .matches(&format!("1.0.0-{huge}"))
        );
    }

    #[test]
    fn constraint_grammar_parses_and_rejects() {
        assert_eq!(VersionConstraint::parse("*"), Some(VersionConstraint::Any));
        assert!(matches!(
            VersionConstraint::parse("^0.3"),
            Some(VersionConstraint::Caret(..))
        ));
        assert!(matches!(
            VersionConstraint::parse("~0.3.2"),
            Some(VersionConstraint::Tilde(_))
        ));
        assert!(matches!(
            VersionConstraint::parse(">=0.3"),
            Some(VersionConstraint::Gte(_))
        ));
        assert!(matches!(
            VersionConstraint::parse(">0.3"),
            Some(VersionConstraint::Gt(_))
        ));
        assert!(matches!(
            VersionConstraint::parse("<=0.4"),
            Some(VersionConstraint::Lte(_))
        ));
        assert!(matches!(
            VersionConstraint::parse("<0.4"),
            Some(VersionConstraint::Lt(_))
        ));
        assert!(matches!(
            VersionConstraint::parse("0.3.2"),
            Some(VersionConstraint::Exact(_))
        ));
        // Operator bases may be partial (two fields), exact may not.
        assert!(matches!(
            VersionConstraint::parse("^0.3"),
            Some(VersionConstraint::Caret(..))
        ));
        assert!(matches!(
            VersionConstraint::parse(">=0.3"),
            Some(VersionConstraint::Gte(_))
        ));
        assert!(
            VersionConstraint::parse("0.3").is_none(),
            "bare exact needs full semver"
        );
        assert!(VersionConstraint::parse("").is_none());
        assert!(VersionConstraint::parse("^0.3.2.1").is_none());
        assert!(VersionConstraint::parse(">=").is_none());
    }

    #[test]
    fn matching_is_exact_where_said_and_families_where_said() {
        let c = |s: &str| VersionConstraint::parse(s).unwrap();
        // Exact means exact.
        assert!(c("0.3.2").matches("0.3.2"));
        assert!(!c("0.3.2").matches("0.3.3"));
        // Caret at 0.x: same minor.
        assert!(c("^0.3").matches("0.3.0"));
        assert!(c("^0.3").matches("0.3.9"));
        assert!(!c("^0.3").matches("0.4.0"));
        // Caret at 1.x: same major.
        assert!(c("^1.2").matches("1.9.9"));
        assert!(!c("^1.2").matches("2.0.0"));
        // Caret at 0.0.x with an EXPLICIT patch: pinned (npm).
        assert!(c("^0.0.3").matches("0.0.3"));
        assert!(!c("^0.0.3").matches("0.0.4"));
        // Caret at 0.0 with the patch DEFAULTED: minor ranges (npm).
        assert!(c("^0.0").matches("0.0.9"));
        assert!(!c("^0.0").matches("0.1.0"));
        // Tilde: same major.minor.
        assert!(c("~0.3.2").matches("0.3.5"));
        assert!(!c("~0.3.2").matches("0.4.0"));
        // One-sided bounds.
        assert!(c(">=0.3").matches("0.3.0"));
        assert!(!c(">0.3.0").matches("0.3.0"));
        assert!(c("<0.4").matches("0.3.99"));
        assert!(c("<=0.4.0").matches("0.4.0"));
        // Any matches anything parseable.
        assert!(c("*").matches("9.9.9-rc.1"));
        // Unparseable candidate never matches.
        assert!(!c("*").matches("not-a-version"));
        // Build metadata is ignored.
        assert!(c("0.3.2").matches("0.3.2+build.7"));
        // Prerelease candidates need a prerelease base in family ranges.
        assert!(!c("^0.3").matches("0.3.4-rc.1"), "plain ^0.3 admits no rc");
        assert!(
            c("^0.3.0-rc.1").matches("0.3.0-rc.2"),
            "rc base admits later rc"
        );
        assert!(
            !c("~0.3.2").matches("0.3.3-beta"),
            "tilde admits no bare beta"
        );
    }

    #[test]
    fn entry_validation_shapes_and_self_reference() {
        let entry = |id: &str, version: &str| DependencyEntry {
            id: id.into(),
            version: version.into(),
        };
        assert!(validate_entry(&entry("celestia-agent-arona", "^0.1"), "celestia-video").is_ok());
        assert!(validate_entry(&entry("Bad_Id", "*"), "x").is_err());
        assert!(
            validate_entry(&entry("celestia-video", "*"), "celestia-video").is_err(),
            "self-dep refused"
        );
        assert!(
            validate_entry(&entry("celestia-video", ""), "x").is_err(),
            "empty constraint refused"
        );
        assert!(validate_entry(&entry("celestia-video", "^1.2.3.4"), "x").is_err());
    }
}
