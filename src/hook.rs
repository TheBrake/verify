use crate::config;
use crate::git;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// First comment line of a Verify-managed hook. Ownership is this line, not a
/// substring anywhere in the file.
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
        println!("\x1b[33mverify\x1b[0m  backed up {} → {}", path.display(), bak.display());
    }
    fs::write(&path, config::STARTER_TOML).map_err(|e| e.to_string())?;
    println!("\x1b[32;1mok\x1b[0m wrote {}", path.display());
    println!("  this only writes config — run `verify install` to enable the pre-push hook");
    Ok(())
}

pub fn install(force: bool) -> Result<(), String> {
    let hook = hook_path()?;
    if hook.exists() {
        let existing = fs::read_to_string(&hook).unwrap_or_default();
        if !is_managed_hook(&existing) && !force {
            return Err(format!(
                "{} already exists and was not created by Verify (pass --force to replace it; the previous hook is not chained)",
                hook.display()
            ));
        }
    }

    let exe = std::env::current_exe().map_err(|e| format!("cannot resolve verify binary: {e}"))?;
    if !exe.exists() {
        return Err(format!(
            "verify binary is not resolvable at {} — install a stable binary before `verify install`",
            exe.display()
        ));
    }
    probe_exe(&exe)?;

    let script = render_hook_script(&exe);
    atomic_write_hook(&hook, script.as_bytes())?;

    println!(
        "\x1b[32;1mok\x1b[0m installed pre-push hook → {}",
        hook.display()
    );
    println!("  git push will now pause and run Verify on the outgoing diff");
    if git::repo_root().map(|r| !r.join("verify.toml").exists() && !r.join(".verify.toml").exists()).unwrap_or(false) {
        println!("  no verify.toml yet — `verify init` writes config only; the hook is already active");
    }
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let hook = hook_path()?;
    if !hook.exists() {
        println!("\x1b[32;1mok\x1b[0m no hook installed");
        return Ok(());
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
    Ok(())
}

pub fn hook_path() -> Result<PathBuf, String> {
    Ok(hooks_dir()?.join("pre-push"))
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
        Ok(std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(p))
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
    let quoted = sh_single_quote(&exe.display().to_string());
    format!(
        "#!/bin/sh\n{HOOK_MARKER_LINE}\n# Reinstall with: verify install --force\nexec {quoted} hook-run \"$@\"\n"
    )
}

pub fn sh_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn probe_exe(exe: &Path) -> Result<(), String> {
    let out = Command::new(exe)
        .arg("-V")
        .output()
        .map_err(|e| format!("installed binary cannot start ({}): {e}", exe.display()))?;
    if !out.status.success() {
        return Err(format!(
            "installed binary {} -V failed with status {}",
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
    let tmp = hook.with_file_name("pre-push.verify.tmp");
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
        assert_eq!(sh_single_quote("/opt/o'reilly/verify"), "'/opt/o'\\''reilly/verify'");
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
    fn marker_must_be_the_first_comment_not_a_substring() {
        assert!(!is_managed_hook("#!/bin/sh\n# husky\n# mention Managed by Verify in passing\nexit 0\n"));
        assert!(is_managed_hook("#!/bin/sh\n# Managed by Verify\nexec true\n"));
        assert!(is_managed_hook("# Managed by Verify — do not edit by hand\n"));
        assert!(!is_managed_hook(""));
    }

    #[test]
    fn uninstall_rejects_foreign_hook_text() {
        assert!(!is_managed_hook("#!/bin/sh\nlefthook run pre-push \"$@\"\n"));
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
}