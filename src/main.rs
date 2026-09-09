mod config;
mod diff;
mod engine;
mod git;
mod hook;
mod report;
mod rules;

use crate::config::{Config, FailOn};
use crate::diff::AddedLine;
use crate::git::PushUpdate;
use std::io::{self, Cursor, IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            print_error(&err);
            ExitCode::from(2)
        }
    }
}

fn print_error(err: &str) {
    if io::stderr().is_terminal() {
        eprintln!("\x1b[31;1mverify:\x1b[0m {err}");
    } else {
        eprintln!("verify: {err}");
    }
}

fn run() -> Result<ExitCode, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stdin = if io::stdin().is_terminal() {
        StdinSrc::Terminal
    } else {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| e.to_string())?;
        StdinSrc::Piped(buf)
    };
    dispatch(&args, stdin)
}

#[derive(Debug, Clone)]
enum StdinSrc {
    Terminal,
    Piped(String),
}

fn dispatch(args: &[String], stdin: StdinSrc) -> Result<ExitCode, String> {
    let cli = parse_cli(args)?;
    match cli.cmd.as_str() {
        "init" => {
            hook::init_config(cli.force)?;
            Ok(ExitCode::SUCCESS)
        }
        "install" => {
            hook::install(cli.force)?;
            Ok(ExitCode::SUCCESS)
        }
        "uninstall" => {
            hook::uninstall()?;
            Ok(ExitCode::SUCCESS)
        }
        "rules" => {
            rules::print_catalog();
            Ok(ExitCode::SUCCESS)
        }
        "scan" => scan_cmd(&cli, stdin),
        "hook-run" => hook_run(&cli, stdin),
        "" => match stdin {
            StdinSrc::Terminal => {
                print_help();
                Ok(ExitCode::SUCCESS)
            }
            StdinSrc::Piped(buf) => match classify_stdin(&buf) {
                StdinClass::PrePush => hook_run(&cli, StdinSrc::Piped(buf)),
                StdinClass::Diff => {
                    let mut scan = cli;
                    scan.as_diff = true;
                    scan_cmd(&scan, StdinSrc::Piped(buf))
                }
                StdinClass::Unknown => Err(
                    "piped stdin is neither a pre-push protocol nor a unified diff; use `verify scan --diff` or `verify hook-run`"
                        .into(),
                ),
            },
        },
        other => Err(format!("unknown command '{other}'. Try --help.")),
    }
}

#[derive(Debug, Clone)]
struct Cli {
    cmd: String,
    show_secrets: bool,
    config_path: Option<PathBuf>,
    fail_on: Option<FailOn>,
    force: bool,
    as_diff: bool,
    paths: Vec<PathBuf>,
    remote: Option<String>,
    url: Option<String>,
}

fn parse_cli(args: &[String]) -> Result<Cli, String> {
    let mut show_secrets = false;
    let mut config_path = None;
    let mut fail_on = None;
    let mut force = false;
    let mut as_diff = false;
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--" => {
                positional.extend(args[i + 1..].iter().cloned());
                break;
            }
            "--show-secrets" => show_secrets = true,
            "-c" | "--config" => {
                i += 1;
                let path = args.get(i).ok_or("--config requires a path")?;
                config_path = Some(PathBuf::from(path));
            }
            "--fail-on" => {
                i += 1;
                let v = args.get(i).ok_or("--fail-on requires any|high")?;
                fail_on = Some(parse_fail_on(v)?);
            }
            "--diff" => as_diff = true,
            "--force" => force = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("verify {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            s if s.starts_with('-') => {
                return Err(format!("unknown option '{s}'. Try --help."));
            }
            _ => positional.push(args[i].clone()),
        }
        i += 1;
    }

    let cmd = positional.first().cloned().unwrap_or_default();
    let rest = if positional.is_empty() {
        Vec::new()
    } else {
        positional[1..].to_vec()
    };
    let (remote, url) = if cmd == "hook-run" {
        (rest.first().cloned(), rest.get(1).cloned())
    } else {
        (None, None)
    };
    let paths = if cmd == "scan" {
        rest.into_iter()
            .filter(|a| a != "--diff" && a != "--force")
            .map(PathBuf::from)
            .collect()
    } else {
        Vec::new()
    };

    Ok(Cli {
        cmd,
        show_secrets,
        config_path,
        fail_on,
        force,
        as_diff,
        paths,
        remote,
        url,
    })
}

fn parse_fail_on(s: &str) -> Result<FailOn, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "any" => Ok(FailOn::Any),
        "high" => Ok(FailOn::High),
        other => Err(format!("invalid --fail-on '{other}' (want any|high)")),
    }
}

fn apply_fail_on(cfg: &mut Config, cli: &Cli) {
    if let Some(v) = cli.fail_on {
        cfg.fail_on = v;
        return;
    }
    if let Ok(v) = std::env::var("VERIFY_FAIL_ON") {
        if let Ok(parsed) = parse_fail_on(&v) {
            cfg.fail_on = parsed;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdinClass {
    PrePush,
    Diff,
    Unknown,
}

fn classify_stdin(buf: &str) -> StdinClass {
    let line = buf.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let t = line.trim();
    if t.starts_with("diff --git ") || t.starts_with("--- ") || t.starts_with("+++ ") {
        return StdinClass::Diff;
    }
    let parts: Vec<&str> = t.split_whitespace().collect();
    if parts.len() == 4 && looks_like_oid(parts[1]) && looks_like_oid(parts[3]) {
        return StdinClass::PrePush;
    }
    StdinClass::Unknown
}

fn looks_like_oid(s: &str) -> bool {
    s.len() >= 7 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hook_run(cli: &Cli, stdin: StdinSrc) -> Result<ExitCode, String> {
    let repo = git::repo_root().ok_or("not inside a git repository")?;
    let mut cfg = config::load(cli.config_path.as_deref(), &repo)?;
    apply_fail_on(&mut cfg, cli);

    let updates = match stdin {
        StdinSrc::Terminal => {
            return Err("pre-push stdin is a terminal — hook is not receiving Git updates".into());
        }
        StdinSrc::Piped(buf) => git::parse_pre_push_lines(Cursor::new(buf))?,
    };
    match hook_plan(&updates)? {
        HookPlan::DeleteOnly => {
            eprintln!("verify: delete-only push — nothing to scan");
            return Ok(ExitCode::SUCCESS);
        }
        HookPlan::Scan(active) => {
            let mut all_added = Vec::new();
            for update in active {
                all_added.extend(git::added_lines_for_update(update, cli.remote.as_deref())?);
            }
            finish_scan(&cfg, cli.show_secrets, &all_added, cli.remote.as_deref(), cli.url.as_deref(), report::Mode::Hook)
        }
    }
}

#[derive(Debug)]
enum HookPlan<'a> {
    DeleteOnly,
    Scan(Vec<&'a PushUpdate>),
}

fn hook_plan(updates: &[PushUpdate]) -> Result<HookPlan<'_>, String> {
    if updates.is_empty() {
        return Err("pre-push sent no ref updates".into());
    }
    let active: Vec<&PushUpdate> = updates.iter().filter(|u| !u.is_delete()).collect();
    if active.is_empty() {
        Ok(HookPlan::DeleteOnly)
    } else {
        Ok(HookPlan::Scan(active))
    }
}

fn scan_cmd(cli: &Cli, stdin: StdinSrc) -> Result<ExitCode, String> {
    if cli.as_diff && !cli.paths.is_empty() {
        return Err("--diff cannot be combined with file paths".into());
    }
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let repo = git::repo_root().unwrap_or(cwd);
    let mut cfg = config::load(cli.config_path.as_deref(), &repo)?;
    apply_fail_on(&mut cfg, cli);

    let added = if cli.as_diff {
        let buf = match stdin {
            StdinSrc::Piped(b) => b,
            StdinSrc::Terminal => {
                return Err("scan --diff requires a unified diff on stdin".into());
            }
        };
        crate::diff::parse_unified_diff(&buf)?
    } else if !cli.paths.is_empty() {
        engine::read_files_as_added(&cli.paths, cfg.max_file_bytes)?
    } else if matches!(&stdin, StdinSrc::Piped(b) if !b.is_empty()) {
        let StdinSrc::Piped(buf) = stdin else { unreachable!() };
        crate::diff::parse_unified_diff(&buf)?
    } else if git::repo_root().is_some() {
        scan_unpushed_and_worktree()?
    } else {
        return Err("nothing to scan — pass files, pipe a diff, or run inside a git repo".into());
    };

    finish_scan(&cfg, cli.show_secrets, &added, None, None, report::Mode::Scan)
}

fn scan_unpushed_and_worktree() -> Result<Vec<AddedLine>, String> {
    let unpushed = git::added_lines_unpushed();
    let worktree = git::added_lines_vs_head();
    match (unpushed, worktree) {
        (Ok(mut a), Ok(b)) => {
            a.extend(b);
            Ok(a)
        }
        (Ok(a), Err(_)) => Ok(a),
        (Err(_), Ok(b)) => Ok(b),
        (Err(e), Err(_)) => Err(e),
    }
}

fn finish_scan(
    cfg: &Config,
    show_secrets: bool,
    added: &[AddedLine],
    remote: Option<&str>,
    url: Option<&str>,
    mode: report::Mode,
) -> Result<ExitCode, String> {
    let engine = engine::Engine::new(cfg)?;
    let findings = engine.scan_added_lines(added);
    report::print_verdict(
        &findings,
        show_secrets || !cfg.redact,
        remote,
        url,
        cfg,
        mode,
    );
    if findings.iter().any(|f| f.blocks(cfg)) {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn print_help() {
    print!(
        "\
verify {ver} — local Git pre-push secret auditor

USAGE:
    verify <COMMAND> [OPTIONS]

COMMANDS:
    init                 Write verify.toml in the repo root (does not install the hook)
    install              Install the pre-push hook where Git will run it
    uninstall            Remove the Verify hook
    scan [FILES]         Scan files, a piped diff, unpushed commits and the working tree
    hook-run             Entry point used by the Git hook
    rules                List built-in detection rules

OPTIONS:
    -c, --config PATH    Path to verify.toml
        --fail-on any|high   Override fail_on from config / VERIFY_FAIL_ON
        --show-secrets   Print matched values instead of redacting
        --diff           Treat stdin as a unified diff (scan)
        --force          Overwrite existing files (init/install)
    -h, --help
    -V, --version
",
        ver = env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::{PushUpdate, ZERO_OID};

    #[test]
    fn empty_hook_updates_are_an_error() {
        let err = hook_plan(&[]).unwrap_err();
        assert!(err.contains("no ref updates"), "{err}");
    }

    #[test]
    fn delete_only_is_noop() {
        let u = PushUpdate {
            local_ref: "(delete)".into(),
            local_sha: ZERO_OID.into(),
            remote_ref: "refs/heads/gone".into(),
            remote_sha: "abc1110000000000000000000000000000000001".into(),
        };
        assert!(matches!(hook_plan(&[u]).unwrap(), HookPlan::DeleteOnly));
    }

    #[test]
    fn classify_diff_and_pre_push() {
        assert_eq!(
            classify_stdin("diff --git a/x b/x\n+++ b/x\n"),
            StdinClass::Diff
        );
        assert_eq!(
            classify_stdin("+++ b/foo.rs\n+hi\n"),
            StdinClass::Diff
        );
        let line = format!(
            "refs/heads/main abc1110000000000000000000000000000000001 refs/heads/main {ZERO_OID}\n"
        );
        assert_eq!(classify_stdin(&line), StdinClass::PrePush);
        assert_eq!(classify_stdin("hello world\n"), StdinClass::Unknown);
    }

    #[test]
    fn diff_plus_paths_is_an_error() {
        let cli = parse_cli(&["scan".into(), "--diff".into(), "src/a.rs".into()]).unwrap();
        let err = scan_cmd(&cli, StdinSrc::Piped("diff --git a/x b/x\n".into())).unwrap_err();
        assert!(err.contains("--diff cannot"), "{err}");
    }

    #[test]
    fn config_flag_requires_path() {
        let err = parse_cli(&["-c".into()]).unwrap_err();
        assert!(err.contains("--config requires"), "{err}");
    }

    #[test]
    fn unknown_command() {
        let err = dispatch(&["nope".into()], StdinSrc::Terminal).unwrap_err();
        assert!(err.contains("unknown command"), "{err}");
    }

    #[test]
    fn fail_on_override_parses() {
        let cli = parse_cli(&["scan".into(), "--fail-on".into(), "any".into()]).unwrap();
        assert_eq!(cli.fail_on, Some(FailOn::Any));
        assert!(parse_fail_on("nope").is_err());
    }

    #[test]
    fn double_dash_keeps_dash_paths() {
        let cli = parse_cli(&["scan".into(), "--".into(), "-weird".into()]).unwrap();
        assert_eq!(cli.paths, vec![PathBuf::from("-weird")]);
    }

    #[test]
    fn hook_run_empty_pipe_errors() {
        let cli = parse_cli(&["hook-run".into(), "origin".into(), "url".into()]).unwrap();
        match hook_plan_from_stdin(&cli, StdinSrc::Piped(String::new())) {
            Ok(_) => panic!("expected error"),
            Err(e) => assert!(e.contains("no ref updates") || e.contains("git repository"), "{e}"),
        }
    }

    fn hook_plan_from_stdin(cli: &Cli, stdin: StdinSrc) -> Result<String, String> {
        let _ = cli;
        let updates = match stdin {
            StdinSrc::Terminal => return Err("terminal".into()),
            StdinSrc::Piped(buf) => git::parse_pre_push_lines(Cursor::new(buf))?,
        };
        hook_plan(&updates)?;
        Ok("ok".into())
    }
}