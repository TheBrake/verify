use crate::config;
use crate::git;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const HOOK_MARKER: &str = "Managed by Verify";

pub fn init_config(force: bool) -> Result<(), String> {
    let repo = git::repo_root().ok_or("run `verify init` from inside a git repository")?;
    let path = repo.join("verify.toml");
    if path.exists() && !force {
        return Err(format!(
            "{} already exists (pass --force to overwrite)",
            path.display()
        ));
    }
    fs::write(&path, config::STARTER_TOML).map_err(|e| e.to_string())?;
    println!("\x1b[32;1mok\x1b[0m wrote {}", path.display());
    Ok(())
}

pub fn install(force: bool) -> Result<(), String> {
    let hook = hook_path()?;
    if hook.exists() {
        let existing = fs::read_to_string(&hook).unwrap_or_default();
        if !existing.contains(HOOK_MARKER) && !force {
            return Err(format!(
                "{} already exists and was not created by Verify (pass --force to replace it)",
                hook.display()
            ));
        }
    }

    let exe = std::env::current_exe().map_err(|e| format!("cannot resolve verify binary: {e}"))?;
    let exe = exe.display().to_string().replace('\'', "'\\''");

    let script = format!(
        "#!/bin/sh\n# {HOOK_MARKER} — do not edit by hand\n# Reinstall with: verify install --force\nexec '{exe}' hook-run \"$@\"\n"
    );

    if let Some(parent) = hook.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    {
        let mut f = fs::File::create(&hook).map_err(|e| e.to_string())?;
        f.write_all(script.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    let mut perms = fs::metadata(&hook).map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&hook, perms).map_err(|e| e.to_string())?;

    println!(
        "\x1b[32;1mok\x1b[0m installed pre-push hook → {}",
        hook.display()
    );
    println!("  git push will now pause and run Verify on the outgoing diff");
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let hook = hook_path()?;
    if !hook.exists() {
        println!("\x1b[32;1mok\x1b[0m no hook installed");
        return Ok(());
    }
    let existing = fs::read_to_string(&hook).unwrap_or_default();
    if !existing.contains(HOOK_MARKER) {
        return Err(format!(
            "{} exists but was not created by Verify — remove it by hand",
            hook.display()
        ));
    }
    fs::remove_file(&hook).map_err(|e| e.to_string())?;
    println!("\x1b[32;1mok\x1b[0m removed {}", hook.display());
    Ok(())
}

fn hook_path() -> Result<PathBuf, String> {
    Ok(git::git_dir()?.join("hooks").join("pre-push"))
}
