//! Command-line surface for humans and ops (`akivili-plugin`).
//!
//! The logic lives in these library functions so tests exercise it without
//! spawning processes; the `akivili-plugin` binary is a thin argument
//! shell. Commands:
//!
//! ```text
//! akivili-plugin [--store <dir>] [--audit <path>] list
//! akivili-plugin [--store <dir>] [--audit <path>] check
//! akivili-plugin [--store <dir>] [--audit <path>] enable <id>
//! akivili-plugin [--store <dir>] [--audit <path>] disable <id>
//! akivili-plugin [--store <dir>] [--audit <path>] audit [N]
//! akivili-plugin validate <manifest-path>
//! akivili-plugin pack <package-dir> [--out <dir>] [--insecure-dev-key]
//! ```
//!
//! `--store` defaults to `./plugins`; `--audit` defaults to
//! `<store>/registry-audit.jsonl`. `check` exits non-zero exactly when the
//! scan produced rejections. `list` opens the registry quietly (no scan
//! replay into the audit log); `check`/`enable`/`disable` keep the full
//! open, so management actions leave their scan trail. `audit` reads the
//! log directly and never opens the registry at all. `pack` seals a
//! package directory into a store-installable bundle (see
//! [`crate::pack`]); it needs no store — the signing key comes from the
//! `AKIVILI_SIGNING_KEY` env var (64 hex chars) or, for local seeding
//! only, the loudly-marked `--insecure-dev-key` escape hatch.

use std::path::{Path, PathBuf};

use crate::error::RegistryResult;
use crate::pack::SIGNING_KEY_ENV;
use crate::registry::Registry;
use crate::store::PluginRecord;

/// Default plugin store directory (relative to the working directory).
pub const DEFAULT_STORE_DIR: &str = "plugins";
/// Default audit file name, resolved inside the store directory.
pub const DEFAULT_AUDIT_FILE: &str = "registry-audit.jsonl";
/// Default number of trailing audit lines shown by `audit`.
pub const DEFAULT_AUDIT_TAIL: usize = 20;
/// Default output directory for `pack` bundles (relative to the working
/// directory); the bundle lands in `<out>/<plugin-id>/`.
pub const DEFAULT_PACK_OUT_DIR: &str = "dist";

/// Resolved CLI paths.
#[derive(Debug, Clone, PartialEq)]
pub struct CliPaths {
    pub store_dir: PathBuf,
    pub audit_path: PathBuf,
}

/// Default audit path for a store directory.
pub fn default_audit_path(store_dir: &Path) -> PathBuf {
    store_dir.join(DEFAULT_AUDIT_FILE)
}

/// Splits `--store`/`--audit` flags out of the argument list, applying
/// defaults for the rest. Returns the remaining positional arguments.
pub fn parse_paths(args: &[String]) -> Result<(CliPaths, Vec<String>), String> {
    let mut store_dir: Option<PathBuf> = None;
    let mut audit_path: Option<PathBuf> = None;
    let mut positional = Vec::new();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--store" => {
                let value = iter.next().ok_or("--store requires a value")?;
                store_dir = Some(PathBuf::from(value));
            }
            "--audit" => {
                let value = iter.next().ok_or("--audit requires a value")?;
                audit_path = Some(PathBuf::from(value));
            }
            _ => positional.push(arg.clone()),
        }
    }

    let store_dir = store_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_STORE_DIR));
    let audit_path = audit_path.unwrap_or_else(|| default_audit_path(&store_dir));
    Ok((
        CliPaths {
            store_dir,
            audit_path,
        },
        positional,
    ))
}

/// Renders the `list` table: id / version / provider / enabled / resources.
pub fn format_plugin_table(records: &[PluginRecord]) -> String {
    let header = ["ID", "VERSION", "PROVIDER", "ENABLED", "RESOURCES"];
    let rows: Vec<[String; 5]> = records
        .iter()
        .map(|record| {
            [
                record.manifest.id.clone(),
                record.manifest.version.clone(),
                record.manifest.provider.clone(),
                if record.enabled { "yes" } else { "no" }.to_string(),
                record.manifest.resources.len().to_string(),
            ]
        })
        .collect();

    let mut widths = header.map(|h| h.len());
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    let mut out = String::new();
    let push_row = |out: &mut String, cells: [String; 5]| {
        for (i, cell) in cells.iter().enumerate() {
            if i > 0 {
                out.push_str("  ");
            }
            out.push_str(&format!("{cell:<width$}", width = widths[i]));
        }
        out.push('\n');
    };

    push_row(&mut out, header.map(str::to_string));
    let separator: String = {
        let gaps = 2 * (widths.len().saturating_sub(1));
        "-".repeat(widths.iter().sum::<usize>() + gaps)
    };
    out.push_str(&separator);
    out.push('\n');
    for row in rows {
        push_row(&mut out, row);
    }
    out
}

/// Renders the `check` report: one line per accepted plugin, one line per
/// rejection (with reason).
pub fn format_check_report(registry: &Registry) -> String {
    let mut out = String::new();
    for record in registry.plugins() {
        out.push_str(&format!(
            "ok    {} {} (provider {}, {} resource(s))\n",
            record.manifest.id,
            record.manifest.version,
            record.manifest.provider,
            record.manifest.resources.len()
        ));
    }
    for rejection in registry.rejections() {
        match &rejection.plugin_id {
            Some(id) => out.push_str(&format!(
                "FAIL  {} [{}]: {}\n",
                id,
                rejection.dir.display(),
                rejection.reason
            )),
            None => out.push_str(&format!(
                "FAIL  [{}]: {}\n",
                rejection.dir.display(),
                rejection.reason
            )),
        }
    }
    out.push_str(&format!(
        "\n{} plugin(s) accepted, {} rejected\n",
        registry.plugins().len(),
        registry.rejections().len()
    ));
    out
}

/// Whether `check` should exit non-zero (any rejection).
pub fn check_has_failures(registry: &Registry) -> bool {
    !registry.rejections().is_empty()
}

/// The resolved arguments of a `pack` invocation.
#[derive(Debug, Clone, PartialEq)]
pub struct PackArgs {
    /// The package directory to pack (an `akivili.plugin.toml` inside).
    pub package_dir: PathBuf,
    /// Where the bundle directory is created (`<out>/<plugin-id>/`).
    pub out_dir: PathBuf,
    /// Whether `--insecure-dev-key` was passed (ephemeral local-seeding
    /// key when no `AKIVILI_SIGNING_KEY` is set).
    pub insecure_dev_key: bool,
}

/// Parses the positional tail of a `pack` command:
/// `<package-dir> [--out <dir>] [--insecure-dev-key]`.
pub fn parse_pack_args(positional: &[String]) -> Result<PackArgs, String> {
    let package_dir = positional
        .first()
        .ok_or_else(|| "pack requires a package directory".to_string())?;
    let mut out_dir: Option<PathBuf> = None;
    let mut insecure_dev_key = false;
    let mut iter = positional[1..].iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--out" => {
                let value = iter.next().ok_or("--out requires a value")?;
                out_dir = Some(PathBuf::from(value));
            }
            "--insecure-dev-key" => insecure_dev_key = true,
            other => return Err(format!("unknown pack argument '{other}'")),
        }
    }
    Ok(PackArgs {
        package_dir: PathBuf::from(package_dir),
        out_dir: out_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_PACK_OUT_DIR)),
        insecure_dev_key,
    })
}

/// Runs one `pack` invocation with an explicit environment value (the
/// process env is read by the caller, so tests stay pure). Prints the
/// report on success; returns the process exit code.
pub fn run_pack(args: &PackArgs, env_value: Option<&str>) -> i32 {
    let resolved = match crate::pack::resolve_signing_key(env_value, args.insecure_dev_key) {
        Ok(resolved) => resolved,
        Err(e) => {
            eprintln!("akivili-plugin: pack: {e}");
            return 2;
        }
    };
    let report = if resolved.insecure_dev {
        match crate::pack::pack_dev_key(&args.package_dir, &args.out_dir) {
            Ok((report, dev_key)) => {
                // The ephemeral seed is announced once for local
                // re-seeding — loudly marked, never persisted anywhere.
                eprintln!(
                    "!! INSECURE-DEV-KEY seed (hex, save to re-sign, NEVER production): {}",
                    hex_seed(&dev_key.to_bytes())
                );
                report
            }
            Err(e) => {
                eprintln!("akivili-plugin: pack: {e}");
                return 2;
            }
        }
    } else {
        match crate::pack::pack(&args.package_dir, &args.out_dir, &resolved.key) {
            Ok(report) => report,
            Err(e) => {
                eprintln!("akivili-plugin: pack: {e}");
                return 2;
            }
        }
    };
    print!("{}", report.summary());
    0
}

/// Hex-encodes a 32-byte Ed25519 seed (the `AKIVILI_SIGNING_KEY` shape).
fn hex_seed(seed: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in seed {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Returns the last `n` audit lines (each a JSON object), oldest first.
pub fn audit_tail(path: &Path, n: usize) -> RegistryResult<String> {
    let text = std::fs::read_to_string(path)?;
    let lines: Vec<&str> = {
        let all: Vec<&str> = if text.is_empty() {
            Vec::new()
        } else {
            text.strip_suffix('\n').unwrap_or(&text).lines().collect()
        };
        if all.len() <= n {
            all
        } else {
            all[all.len() - n..].to_vec()
        }
    };
    Ok(lines.join("\n") + if lines.is_empty() { "" } else { "\n" })
}

/// Usage text.
pub fn usage() -> String {
    format!(
        "usage: akivili-plugin [--store <dir>] [--audit <path>] <command> [args]\n\n\
         commands:\n  \
         list                 list discovered plugins\n  \
         check                scan and validate the store (non-zero exit on rejections)\n  \
         enable <id>          enable a plugin\n  \
         disable <id>         disable a plugin\n  \
         audit [N]            show the last N audit events (default {DEFAULT_AUDIT_TAIL})\n  \
         validate <path>      parse and validate one manifest file (no store needed)\n  \
         pack <dir> [--out <dir>] [--insecure-dev-key]\n  \
         seal a package directory into a store-installable signed bundle\n\n\
         defaults: --store ./{DEFAULT_STORE_DIR}  --audit <store>/{DEFAULT_AUDIT_FILE}\n  \
         pack: --out ./{DEFAULT_PACK_OUT_DIR}  key from {SIGNING_KEY_ENV} (64 hex chars)\n"
    )
}

/// Runs the CLI against `args` (without the program name), printing to
/// stdout/stderr and returning the process exit code.
pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("akivili-plugin: {message}");
            eprintln!();
            eprint!("{}", usage());
            2
        }
    }
}

fn run_inner(args: &[String]) -> Result<i32, String> {
    let (paths, positional) = parse_paths(args)?;

    let command = positional
        .first()
        .ok_or_else(|| "missing command".to_string())?;
    match command.as_str() {
        "validate" => {
            // Single-manifest validation for plugin authors: no store, no
            // audit trail — parse the file and run the same schema
            // validation the store scanner applies (schema generations,
            // form gating, capability vocabulary, contract refs).
            let path = positional
                .get(1)
                .ok_or_else(|| "validate requires a manifest path".to_string())?;
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("cannot read '{path}': {e}"))?;
            let manifest: crate::manifest::PluginManifest =
                toml::from_str(&text).map_err(|e| format!("parse error: {e}"))?;
            manifest.validate().map_err(|e| e.to_string())?;
            println!(
                "ok: {} v{} (schema {}, form {})",
                manifest.id,
                manifest.version,
                manifest.schema,
                manifest
                    .form
                    .map(|f| f.to_string())
                    .unwrap_or_else(|| "missing".to_string())
            );
            Ok(0)
        }
        "list" => {
            // Read-only: quiet open scans without replaying scan events
            // into the audit log, so listing does not grow the trail.
            let registry = Registry::open_quiet(&paths.store_dir, &paths.audit_path)
                .map_err(|e| e.to_string())?;
            print!("{}", format_plugin_table(registry.plugins()));
            Ok(0)
        }
        "check" => {
            let registry =
                Registry::open(&paths.store_dir, &paths.audit_path).map_err(|e| e.to_string())?;
            print!("{}", format_check_report(&registry));
            Ok(u8::from(check_has_failures(&registry)) as i32)
        }
        "enable" | "disable" => {
            let id = positional
                .get(1)
                .ok_or_else(|| format!("{command} requires a plugin id"))?;
            let mut registry =
                Registry::open(&paths.store_dir, &paths.audit_path).map_err(|e| e.to_string())?;
            let enabled = command == "enable";
            registry
                .set_enabled(id, enabled)
                .map_err(|e| e.to_string())?;
            println!(
                "{}d plugin {id}",
                if enabled { "enable" } else { "disable" }
            );
            Ok(0)
        }
        "audit" => {
            let n = match positional.get(1) {
                None => DEFAULT_AUDIT_TAIL,
                Some(raw) => raw
                    .parse::<usize>()
                    .map_err(|_| format!("invalid count '{raw}'"))?,
            };
            match audit_tail(&paths.audit_path, n) {
                Ok(tail) => {
                    print!("{tail}");
                    Ok(0)
                }
                Err(e) => Err(format!("cannot read audit log: {e}")),
            }
        }
        "pack" => {
            // No store, no audit: the packer works off the package
            // directory alone. The env value is threaded in so the
            // logic stays testable without touching process state.
            let pack_args = parse_pack_args(&positional[1..])?;
            let env_value = std::env::var(crate::pack::SIGNING_KEY_ENV).ok();
            Ok(run_pack(&pack_args, env_value.as_deref()))
        }
        other => Err(format!("unknown command '{other}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Registry;
    use crate::manifest::MANIFEST_FILE;

    struct Fixture {
        root: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                root: tempfile::tempdir().unwrap(),
            }
        }

        fn store_dir(&self) -> PathBuf {
            self.root.path().join("plugins")
        }

        fn audit_path(&self) -> PathBuf {
            self.root.path().join("audit.jsonl")
        }

        fn add_plugin(&self, name: &str, manifest: &str) {
            let dir = self.store_dir().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(MANIFEST_FILE), manifest).unwrap();
        }

        fn open(&self) -> Registry {
            Registry::open(&self.store_dir(), &self.audit_path()).unwrap()
        }
    }

    const GOOD: &str = r##"
id = "acmetheme"
version = "1.4.0"
provider = "acme"
form = "web.resource"

[[resources]]
kind = "webui.theme"
name = "dark"
order = 1

[resources.payload.Inline]
primary = "#181825"
"##;

    #[test]
    fn parse_paths_defaults_and_overrides() {
        let (paths, positional) = parse_paths(&["list".to_string()]).expect("defaults must parse");
        assert_eq!(paths.store_dir, PathBuf::from("plugins"));
        assert_eq!(
            paths.audit_path,
            PathBuf::from("plugins/registry-audit.jsonl")
        );
        assert_eq!(positional, ["list"]);

        let (paths, positional) = parse_paths(&[
            "--store".into(),
            "/srv/plugins".into(),
            "audit".into(),
            "5".into(),
        ])
        .expect("flags must parse");
        assert_eq!(paths.store_dir, PathBuf::from("/srv/plugins"));
        assert_eq!(
            paths.audit_path,
            PathBuf::from("/srv/plugins/registry-audit.jsonl")
        );
        assert_eq!(positional, ["audit", "5"]);

        let (paths, _) = parse_paths(&[
            "--store".into(),
            "/s".into(),
            "--audit".into(),
            "/a.jsonl".into(),
            "list".into(),
        ])
        .unwrap();
        assert_eq!(paths.audit_path, PathBuf::from("/a.jsonl"));

        assert!(
            parse_paths(&["--store".to_string()]).is_err(),
            "dangling flag"
        );
    }

    #[test]
    fn list_table_shows_all_columns() {
        let fixture = Fixture::new();
        fixture.add_plugin("acmetheme", GOOD);
        let registry = fixture.open();

        let table = format_plugin_table(registry.plugins());
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 3, "header + separator + row: {table}");
        assert!(lines[0].contains("ID") && lines[0].contains("VERSION"));
        assert!(lines[0].contains("PROVIDER") && lines[0].contains("ENABLED"));
        assert!(lines[0].contains("RESOURCES"));
        assert!(lines[2].contains("acmetheme"));
        assert!(lines[2].contains("1.4.0"));
        assert!(lines[2].contains("acme"));
        assert!(lines[2].contains("yes"));
        assert!(lines[2].contains('1'));
    }

    #[test]
    fn check_report_and_exit_condition() {
        let fixture = Fixture::new();
        fixture.add_plugin("acmetheme", GOOD);
        fixture.add_plugin(
            "broken",
            "id = \"NOPE\"\nversion = \"1\"\nprovider = \"x\"\n",
        );

        let registry = fixture.open();
        assert!(check_has_failures(&registry));

        let report = format_check_report(&registry);
        assert!(report.contains("ok    acmetheme 1.4.0"));
        assert!(report.contains("FAIL  NOPE"));
        assert!(report.contains("1 plugin(s) accepted, 1 rejected"));
    }

    #[test]
    fn check_exit_zero_on_clean_store() {
        let fixture = Fixture::new();
        fixture.add_plugin("acmetheme", GOOD);
        let registry = fixture.open();
        assert!(!check_has_failures(&registry));
    }

    #[test]
    fn run_list_and_check_exit_codes() {
        let fixture = Fixture::new();
        fixture.add_plugin("acmetheme", GOOD);
        fixture.add_plugin("broken", "garbage = true\n");

        let store = fixture.store_dir();
        let audit = fixture.audit_path();
        let args = |cmd: &[&str]| -> Vec<String> {
            let mut v = vec![
                "--store".to_string(),
                store.display().to_string(),
                "--audit".to_string(),
                audit.display().to_string(),
            ];
            v.extend(cmd.iter().map(|s| s.to_string()));
            v
        };

        assert_eq!(run(&args(&["list"])), 0);
        assert_eq!(run(&args(&["check"])), 1, "rejections must exit non-zero");

        // enable/disable round trip at the CLI level
        assert_eq!(run(&args(&["disable", "acmetheme"])), 0);
        let registry = fixture.open();
        assert!(
            !registry
                .plugins()
                .iter()
                .find(|r| r.manifest.id == "acmetheme")
                .unwrap()
                .enabled
        );
        assert_eq!(run(&args(&["enable", "acmetheme"])), 0);
        let registry = fixture.open();
        assert!(
            registry
                .plugins()
                .iter()
                .find(|r| r.manifest.id == "acmetheme")
                .unwrap()
                .enabled
        );

        // unknown id fails
        assert_eq!(run(&args(&["disable", "ghost"])), 2);
        // unknown command / missing command are usage errors
        assert_eq!(run(&args(&["frobnicate"])), 2);
        assert_eq!(run(&args(&[])), 2);
    }

    #[test]
    fn run_list_is_read_only_on_the_audit_log() {
        let fixture = Fixture::new();
        fixture.add_plugin("acmetheme", GOOD);

        let args = vec![
            "--store".to_string(),
            fixture.store_dir().display().to_string(),
            "--audit".to_string(),
            fixture.audit_path().display().to_string(),
            "list".to_string(),
        ];
        assert_eq!(run(&args), 0);

        let text = std::fs::read_to_string(fixture.audit_path()).unwrap_or_default();
        assert!(text.is_empty(), "list must not write audit events: {text}");
    }

    #[test]
    fn run_audit_tail() {
        let fixture = Fixture::new();
        fixture.add_plugin("acmetheme", GOOD);
        let _registry = fixture.open(); // writes discovered+validated

        let args = |cmd: &[&str]| -> Vec<String> {
            let mut v = vec![
                "--store".to_string(),
                fixture.store_dir().display().to_string(),
                "--audit".to_string(),
                fixture.audit_path().display().to_string(),
            ];
            v.extend(cmd.iter().map(|s| s.to_string()));
            v
        };

        assert_eq!(run(&args(&["audit"])), 0);
        assert_eq!(run(&args(&["audit", "1"])), 0);
        assert_eq!(run(&args(&["audit", "not-a-number"])), 2);

        // Library-level: the tail is a prefix-consistent slice of the file.
        let text = std::fs::read_to_string(fixture.audit_path()).unwrap();
        let total = text.lines().count();
        let tail = audit_tail(&fixture.audit_path(), 1).unwrap();
        assert_eq!(tail.lines().count(), 1);
        assert_eq!(tail.trim_end(), text.lines().last().unwrap().to_string());
        let all = audit_tail(&fixture.audit_path(), total + 10).unwrap();
        assert_eq!(all.lines().count(), total);
    }

    #[test]
    fn usage_lists_every_command() {
        let text = usage();
        for command in [
            "list", "check", "enable", "disable", "audit", "validate", "pack",
        ] {
            assert!(text.contains(command), "usage must mention {command}");
        }
        assert!(
            text.contains(SIGNING_KEY_ENV),
            "usage must name the signing-key env var"
        );
    }

    #[test]
    fn parse_pack_args_defaults_and_flags() {
        let args = parse_pack_args(&["pkg".to_string()]).expect("positional-only parses");
        assert_eq!(args.package_dir, PathBuf::from("pkg"));
        assert_eq!(args.out_dir, PathBuf::from(DEFAULT_PACK_OUT_DIR));
        assert!(!args.insecure_dev_key);

        let args = parse_pack_args(&[
            "pkg".to_string(),
            "--out".to_string(),
            "/tmp/o".to_string(),
            "--insecure-dev-key".to_string(),
        ])
        .expect("flags parse");
        assert_eq!(args.out_dir, PathBuf::from("/tmp/o"));
        assert!(args.insecure_dev_key);

        assert!(parse_pack_args(&[]).is_err(), "package dir is required");
        assert!(
            parse_pack_args(&["p".to_string(), "--out".to_string()]).is_err(),
            "dangling --out"
        );
        assert!(
            parse_pack_args(&["p".to_string(), "--wat".to_string()]).is_err(),
            "unknown flag"
        );
    }

    /// A minimal packable package for the CLI-level tests.
    fn pack_fixture(dir: &std::path::Path) -> PathBuf {
        let pkg = dir.join("clipack");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join(crate::manifest::MANIFEST_FILE),
            r#"schema = 1
id = "clipack"
version = "1.0.0"
provider = "official"
form = "web.resource"

[[resources]]
kind = "webui.style"
[resources.payload.File]
path = "style.css"
"#,
        )
        .unwrap();
        std::fs::write(pkg.join("style.css"), b"body {}").unwrap();
        pkg
    }

    #[test]
    fn run_pack_without_a_key_refuses() {
        let root = tempfile::tempdir().unwrap();
        let pkg = pack_fixture(root.path());
        let args = PackArgs {
            package_dir: pkg,
            out_dir: root.path().join("dist"),
            insecure_dev_key: false,
        };
        assert_eq!(run_pack(&args, None), 2, "missing key must refuse");
        assert!(
            !args.out_dir.join("clipack").exists(),
            "no bundle on refusal"
        );
    }

    #[test]
    fn run_pack_with_an_env_key_or_dev_key_succeeds() {
        let root = tempfile::tempdir().unwrap();
        let pkg = pack_fixture(root.path());

        // Env key lane.
        let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut hex_seed = String::new();
        for byte in signing.to_bytes() {
            use std::fmt::Write as _;
            let _ = write!(hex_seed, "{byte:02x}");
        }
        let args = PackArgs {
            package_dir: pkg.clone(),
            out_dir: root.path().join("dist"),
            insecure_dev_key: false,
        };
        assert_eq!(run_pack(&args, Some(&hex_seed)), 0, "env key packs");
        assert!(args.out_dir.join("clipack").exists());
        // The env lane is not dev-marked.
        assert_eq!(
            run_pack(
                &PackArgs {
                    package_dir: pkg.clone(),
                    out_dir: root.path().join("dist2"),
                    insecure_dev_key: false,
                },
                Some(&hex_seed)
            ),
            0
        );

        // Dev key lane.
        let dev_args = PackArgs {
            package_dir: pkg,
            out_dir: root.path().join("dist3"),
            insecure_dev_key: true,
        };
        assert_eq!(run_pack(&dev_args, None), 0, "dev key packs");
        assert!(dev_args.out_dir.join("clipack").exists());
    }

    #[test]
    fn validate_accepts_a_schema_2_manifest_without_a_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MANIFEST_FILE);
        std::fs::write(
            &path,
            r##"
schema = 1
id = "celestia-kanban"
version = "1.2.0"
provider = "official"
form = "web.vue-module"
capabilities = ["kv.read", "mesh.call:celestia-reports"]
requires-contract = ["celestia:panel/host@0.1"]
"##,
        )
        .unwrap();
        let args = vec!["validate".to_string(), path.display().to_string()];
        assert_eq!(run(&args), 0, "a valid fabric manifest must pass");
    }

    #[test]
    fn validate_rejects_bad_manifests_with_exit_2() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MANIFEST_FILE);

        // A non-SemVer version is rejected.
        std::fs::write(
            &path,
            r#"
id = "acme"
version = "1"
provider = "acme"
form = "script.ts"
"#,
        )
        .unwrap();
        let args = vec!["validate".to_string(), path.display().to_string()];
        assert_eq!(run(&args), 2, "non-SemVer version must be rejected");

        // A capability outside the closed vocabulary.
        std::fs::write(
            &path,
            r#"
schema = 1
id = "acme"
version = "1.0.0"
provider = "acme"
form = "script.ts"
capabilities = ["fs.read"]
"#,
        )
        .unwrap();
        assert_eq!(
            run(&args),
            2,
            "out-of-vocabulary capabilities must be rejected"
        );

        // missing path argument
        assert_eq!(run(&["validate".to_string()]), 2);

        // unreadable path
        let missing = dir.path().join("nope.toml");
        assert_eq!(
            run(&["validate".to_string(), missing.display().to_string()]),
            2
        );
    }
}
