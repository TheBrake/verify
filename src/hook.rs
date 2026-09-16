use crate::config;
use crate::git;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const HOOK_MARKER_LINE: &str = "# Managed by Verify";

pub fn init_config(force: bool) -> Result<(), String> {
    let repo = git::repo_root().ok_or("run `verify init` from inside a git repository")?;
    let path = repo.join("verify.toml");
    if path.exists() && !force {
        return Err(format!(
            "{} already exists (pass --force to overwrite)",
            path.display()
        ));
    }
    if path.exists() && force {
        let bak = repo.join("verify.toml.bak");
        fs::copy(&path, &bak).map_err(|e| format!("failed to backup {}: {e}", path.display()))?;
        println!(
            "\x1b[33mverify\x1b[0m  backed up {} → {}",
            path.display(),
            bak.display()
        );
    }
    fs::write(&path, config::STARTER_TOML).map_err(|e| e.to_string())?;
    println!("\x1b[32;1mok\x1b[0m wrote {}", path.display());
    println!("  this only writes config — run `verify install` to enable pre-commit and pre-push");
    Ok(())
}

const MANAGED_HOOKS: &[(&str, &str)] = &[("pre-commit", "commit-run"), ("pre-push", "hook-run")];

pub fn install(force: bool) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot resolve verify binary: {e}"))?;
    install_exe(&exe, force)
}

pub fn update() -> Result<(), String> {
    let exe = match find_verify_source() {
        Some(src) => {
            println!("\x1b[32;1mok\x1b[0m source   {}", src.display());
            cargo_install(&src)?;
            let installed = cargo_bin_verify().ok_or_else(|| {
                "cargo install finished but ~/.cargo/bin/verify is missing — check CARGO_HOME"
                    .to_string()
            })?;
            println!("\x1b[32;1mok\x1b[0m binary   {}", installed.display());
            installed
        }
        None => {
            let exe = std::env::current_exe()
                .map_err(|e| format!("cannot resolve verify binary: {e}"))?;
            println!(
                "\x1b[33mverify\x1b[0m  cwd is not the Verify source — hooks will keep this binary"
            );
            println!("  {}", exe.display());
            println!("  to rebuild after a pull: cd into the Verify clone, then verify update");
            exe
        }
    };
    install_exe(&exe, true)
}

fn install_exe(exe: &Path, force: bool) -> Result<(), String> {
    if !exe.exists() {
        return Err(format!(
            "verify binary is not resolvable at {} — install a stable binary before `verify install`",
            exe.display()
        ));
    }
    probe_exe(exe)?;

    for (name, cmd) in MANAGED_HOOKS {
        install_one(name, cmd, exe, force)?;
    }

    print_install_footer(exe);
    if git::repo_root()
        .map(|r| !r.join("verify.toml").exists() && !r.join(".verify.toml").exists())
        .unwrap_or(false)
    {
        println!(
            "  no verify.toml yet — `verify init` writes config only; the hooks are already active"
        );
    }
    Ok(())
}

pub fn find_verify_source() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    cwd.ancestors().find_map(|dir| {
        if is_verify_source(dir) {
            Some(dir.to_path_buf())
        } else {
            None
        }
    })
}

pub fn is_verify_source(dir: &Path) -> bool {
    let cargo = dir.join("Cargo.toml");
    let Ok(text) = fs::read_to_string(&cargo) else {
        return false;
    };
    let named = text.lines().any(|l| {
        let l = l.trim();
        l == "name = \"sverify\"" || l == "name = \"verify\""
    });
    named && dir.join("src").join("main.rs").is_file()
}

fn cargo_install(src: &Path) -> Result<(), String> {
    let cargo = cargo_bin();
    println!(
        "  running {cargo} install --path {} --locked --force",
        src.display()
    );
    let status = Command::new(&cargo)
        .args(["install", "--path"])
        .arg(src)
        .args(["--locked", "--force"])
        .status()
        .map_err(|e| format!("failed to spawn {cargo}: {e}"))?;
    if !status.success() {
        return Err(format!(
            "{cargo} install failed with {status} — fix the build, then retry verify update"
        ));
    }
    Ok(())
}

fn cargo_bin() -> String {
    std::env::var("CARGO")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "cargo".into())
}

fn cargo_bin_verify() -> Option<PathBuf> {
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))?;
    let p = home.join("bin").join("verify");
    if p.is_file() {
        Some(p)
    } else {
        None
    }
}

fn install_one(name: &str, cmd: &str, exe: &Path, force: bool) -> Result<(), String> {
    let hook = hook_path_named(name)?;
    if hook.exists() {
        let existing = fs::read_to_string(&hook).unwrap_or_default();
        if !is_managed_hook(&existing) && !force {
            return Err(format!(
                "{} already exists and was not created by Verify (pass --force to replace it; the previous hook is not chained)",
                hook.display()
            ));
        }
    }
    let script = render_hook_script_cmd(exe, cmd);
    atomic_write_hook(&hook, script.as_bytes())?;
    print!("{}", format_install_line(name, cmd, &hook, exe));
    Ok(())
}

pub fn format_install_line(name: &str, cmd: &str, hook: &Path, exe: &Path) -> String {
    let quoted = sh_single_quote(&exe.display().to_string());
    let when = match name {
        "pre-commit" => "git commit  →  scans the index (new and modified files)",
        "pre-push" => "git push    →  scans the outgoing range",
        _ => "git hook",
    };
    format!(
        "\x1b[32;1mok\x1b[0m installed {name}\n  path     {}\n  runs     {quoted} {cmd} \"$@\"\n  when     {when}\n",
        hook.display()
    )
}

fn print_install_footer(exe: &Path) {
    println!("  binary   {}", exe.display());
    println!("  git commit is the lock; git push is the second net");
    println!("  secrets already on a remote are not deleted by these hooks — rotate them");
    println!("  after a new binary: verify update");
}

pub fn uninstall() -> Result<(), String> {
    let mut removed = 0usize;
    for (name, _) in MANAGED_HOOKS {
        let hook = hook_path_named(name)?;
        if !hook.exists() {
            continue;
        }
        let existing = fs::read_to_string(&hook).unwrap_or_default();
        if !is_managed_hook(&existing) {
            return Err(format!(
                "{} exists but was not created by Verify — remove it by hand",
                hook.display()
            ));
        }
        fs::remove_file(&hook).map_err(|e| e.to_string())?;
        println!("\x1b[32;1mok\x1b[0m removed {}", hook.display());
        removed += 1;
    }
    if removed == 0 {
        println!("\x1b[32;1mok\x1b[0m no hook installed");
    }
    Ok(())
}

pub fn hook_path() -> Result<PathBuf, String> {
    hook_path_named("pre-push")
}

pub fn hook_path_named(name: &str) -> Result<PathBuf, String> {
    Ok(hooks_dir()?.join(name))
}

fn hooks_dir() -> Result<PathBuf, String> {
    let out = git::git_stdout(&["rev-parse", "--git-path", "hooks"])?;
    if out.is_empty() {
        return Err("git rev-parse --git-path hooks returned empty".into());
    }
    let p = PathBuf::from(&out);
    if p.is_absolute() {
        Ok(p)
    } else {
        Ok(std::env::current_dir().map_err(|e| e.to_string())?.join(p))
    }
}

pub fn is_managed_hook(contents: &str) -> bool {
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "#!/bin/sh" || line == "#!/bin/bash" || line.starts_with("#!") {
            continue;
        }
        return line == HOOK_MARKER_LINE || line.starts_with("# Managed by Verify");
    }
    false
}

pub fn render_hook_script(exe: &Path) -> String {
    render_hook_script_cmd(exe, "hook-run")
}

pub fn render_commit_hook_script(exe: &Path) -> String {
    render_hook_script_cmd(exe, "commit-run")
}

fn render_hook_script_cmd(exe: &Path, cmd: &str) -> String {
    let quoted = sh_single_quote(&exe.display().to_string());
    format!(
        "#!/bin/sh\n{HOOK_MARKER_LINE}\n# Reinstall with: verify update\nexec {quoted} {cmd} \"$@\"\n"
    )
}

pub fn sh_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn probe_exe(exe: &Path) -> Result<(), String> {
    let out = Command::new(exe)
        .arg("--version")
        .output()
        .map_err(|e| format!("installed binary cannot start ({}): {e}", exe.display()))?;
    if !out.status.success() {
        return Err(format!(
            "installed binary {} --version failed with status {}",
            exe.display(),
            out.status
        ));
    }
    Ok(())
}

fn atomic_write_hook(hook: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = hook.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp_name = format!(
        "{}.verify.tmp",
        hook.file_name().unwrap_or_default().to_string_lossy()
    );
    let tmp = hook.with_file_name(tmp_name);
    let write_result = (|| {
        let mut f = fs::File::create(&tmp).map_err(|e| e.to_string())?;
        f.write_all(bytes).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        let mut perms = fs::metadata(&tmp).map_err(|e| e.to_string())?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tmp, perms).map_err(|e| e.to_string())?;
        fs::rename(&tmp, hook).map_err(|e| e.to_string())?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_single_quotes_in_exe_path() {
        assert_eq!(
            sh_single_quote("/opt/o'reilly/verify"),
            "'/opt/o'\\''reilly/verify'"
        );
    }

    #[test]
    fn install_line_names_path_and_command() {
        let text = format_install_line(
            "pre-commit",
            "commit-run",
            Path::new("/repo/.git/hooks/pre-commit"),
            Path::new("/usr/bin/verify"),
        );
        assert!(text.contains("/repo/.git/hooks/pre-commit"), "{text}");
        assert!(text.contains("commit-run"), "{text}");
        assert!(text.contains("'/usr/bin/verify'"), "{text}");
        assert!(text.contains("git commit"), "{text}");

        let push = format_install_line(
            "pre-push",
            "hook-run",
            Path::new("/repo/.git/hooks/pre-push"),
            Path::new("/usr/bin/verify"),
        );
        assert!(push.contains("/repo/.git/hooks/pre-push"), "{push}");
        assert!(push.contains("hook-run"), "{push}");
        assert!(push.contains("git push"), "{push}");
    }

    #[test]
    fn script_execs_hook_run_and_keeps_stdin() {
        let script = render_hook_script(Path::new("/usr/bin/verify"));
        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(script.contains(HOOK_MARKER_LINE));
        assert!(script.contains("exec '/usr/bin/verify' hook-run \"$@\""));
        assert!(!script.contains("cat "));
        assert!(!script.contains("read "));
        assert!(is_managed_hook(&script));
    }

    #[test]
    fn commit_script_execs_commit_run() {
        let script = render_commit_hook_script(Path::new("/usr/bin/verify"));
        assert!(script.contains("exec '/usr/bin/verify' commit-run \"$@\""));
        assert!(is_managed_hook(&script));
    }

    #[test]
    fn marker_must_be_the_first_comment_not_a_substring() {
        assert!(!is_managed_hook(
            "#!/bin/sh\n# husky\n# mention Managed by Verify in passing\nexit 0\n"
        ));
        assert!(is_managed_hook(
            "#!/bin/sh\n# Managed by Verify\nexec true\n"
        ));
        assert!(is_managed_hook(
            "# Managed by Verify — do not edit by hand\n"
        ));
        assert!(!is_managed_hook(""));
    }

    #[test]
    fn uninstall_rejects_foreign_hook_text() {
        assert!(!is_managed_hook(
            "#!/bin/sh\nlefthook run pre-push \"$@\"\n"
        ));
    }

    #[test]
    fn atomic_write_replaces_and_sets_executable() {
        let dir = std::env::temp_dir().join(format!("verify-hook-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let hook = dir.join("pre-push");
        fs::write(&hook, b"old\n").unwrap();
        atomic_write_hook(&hook, b"#!/bin/sh\n# Managed by Verify\nexec true\n").unwrap();
        let body = fs::read_to_string(&hook).unwrap();
        assert!(body.starts_with("#!/bin/sh"));
        let mode = fs::metadata(&hook).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111);
        assert!(!dir.join("pre-push.verify.tmp").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn source_tree_needs_sverify_manifest_and_main() {
        let dir = std::env::temp_dir().join(format!("verify-src-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/main.rs"), "fn main() {}\n").unwrap();
        assert!(!is_verify_source(&dir));
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"sverify\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        assert!(is_verify_source(&dir));
        let other = dir.join("app");
        fs::create_dir_all(&other).unwrap();
        assert!(!is_verify_source(&other));
        let _ = fs::remove_dir_all(&dir);
    }
}
