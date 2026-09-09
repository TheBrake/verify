mod config;
mod diff;
mod engine;
mod git;
mod hook;
mod report;
mod rules;

use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("\x1b[31;1mverify:\x1b[0m {err}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut show_secrets = false;
    let mut config_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--show-secrets" => {
                show_secrets = true;
                args.remove(i);
            }
            "-c" | "--config" => {
                if i + 1 >= args.len() {
                    return Err("--config requires a path".into());
                }
                config_path = Some(PathBuf::from(&args[i + 1]));
                args.remove(i);
                args.remove(i);
            }
            "-h" | "--help" => {
                print_help();
                return Ok(ExitCode::SUCCESS);
            }
            "-V" | "--version" => {
                println!("verify {}", env!("CARGO_PKG_VERSION"));
                return Ok(ExitCode::SUCCESS);
            }
            _ => i += 1,
        }
    }

    let cmd = args.first().map(String::as_str).unwrap_or("");
    match cmd {
        "init" => {
            hook::init_config(args.iter().any(|a| a == "--force"))?;
            Ok(ExitCode::SUCCESS)
        }
        "install" => {
            hook::install(args.iter().any(|a| a == "--force"))?;
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
        "scan" => {
            let as_diff = args.iter().any(|a| a == "--diff");
            let paths: Vec<PathBuf> = args
                .iter()
                .skip(1)
                .filter(|a| !a.starts_with('-'))
                .map(PathBuf::from)
                .collect();
            scan_cmd(config_path, show_secrets, paths, as_diff)
        }
        "hook-run" => {
            let remote = args.get(1).cloned();
            let url = args.get(2).cloned();
            hook_run(config_path, show_secrets, remote, url)
        }
        "" => {
            if !io::stdin().is_terminal() {
                hook_run(config_path, show_secrets, None, None)
            } else {
                print_help();
                Ok(ExitCode::SUCCESS)
            }
        }
        other => Err(format!("unknown command '{other}'. Try --help.")),
    }
}

fn print_help() {
    print!(
        "\
verify {ver} — local Git pre-push secret auditor

USAGE:
    verify <COMMAND> [OPTIONS]

COMMANDS:
    init                 Write verify.toml in the repo root
    install              Install .git/hooks/pre-push
    uninstall            Remove the Verify hook
    scan [FILES]         Scan files, a piped diff, or unpushed commits
    hook-run             Entry point used by the Git hook
    rules                List built-in detection rules

OPTIONS:
    -c, --config PATH    Path to verify.toml
        --show-secrets   Print matched values instead of redacting
        --diff           Treat stdin as a unified diff (scan)
        --force          Overwrite existing files (init/install)
    -h, --help
    -V, --version
",
        ver = env!("CARGO_PKG_VERSION")
    );
}

fn hook_run(
    config_path: Option<PathBuf>,
    show_secrets: bool,
    remote: Option<String>,
    url: Option<String>,
) -> Result<ExitCode, String> {
    let repo = git::repo_root().ok_or("not inside a git repository")?;
    let cfg = config::load(config_path.as_deref(), &repo)?;
    let updates = git::read_pre_push_updates()?;

    if updates.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }

    let mut all_added = Vec::new();
    for update in &updates {
        if update.is_delete() {
            continue;
        }
        all_added.extend(git::added_lines_for_update(update, remote.as_deref())?);
    }

    let engine = engine::Engine::new(&cfg)?;
    let findings = engine.scan_added_lines(&all_added);
    report::print_verdict(
        &findings,
        show_secrets || !cfg.redact,
        remote.as_deref(),
        url.as_deref(),
        &cfg,
        report::Mode::Hook,
    );
    if findings.iter().any(|f| f.blocks(&cfg)) {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn scan_cmd(
    config_path: Option<PathBuf>,
    show_secrets: bool,
    paths: Vec<PathBuf>,
    as_diff: bool,
) -> Result<ExitCode, String> {
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let repo = git::repo_root().unwrap_or(cwd);
    let cfg = config::load(config_path.as_deref(), &repo)?;
    let engine = engine::Engine::new(&cfg)?;

    let added = if as_diff || (!io::stdin().is_terminal() && paths.is_empty()) {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| e.to_string())?;
        crate::diff::parse_unified_diff(&buf)?
    } else if !paths.is_empty() {
        engine::read_files_as_added(&paths, cfg.max_file_bytes)?
    } else if git::repo_root().is_some() {
        git::added_lines_unpushed().or_else(|_| git::added_lines_vs_head())?
    } else {
        return Err(
            "nothing to scan — pass files, pipe a diff, or run inside a git repo".into(),
        );
    };

    let findings = engine.scan_added_lines(&added);
    report::print_verdict(&findings, show_secrets || !cfg.redact, None, None, &cfg, report::Mode::Scan);
    if findings.iter().any(|f| f.blocks(&cfg)) {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}