use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_verify"))
}

fn scratch() -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "verify-p1-{}-{}-{}",
        std::process::id(),
        n,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn git(repo: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("HOME", repo)
        .env("XDG_CONFIG_HOME", repo.join(".xdg"))
        .env("GIT_AUTHOR_NAME", "Verify Phase1")
        .env("GIT_AUTHOR_EMAIL", "phase1@verify.local")
        .env("GIT_COMMITTER_NAME", "Verify Phase1")
        .env("GIT_COMMITTER_EMAIL", "phase1@verify.local")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("spawn git")
}

fn git_ok(repo: &Path, args: &[&str]) {
    let out = git(repo, args);
    assert!(
        out.status.success(),
        "git {} failed\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn init_repo() -> PathBuf {
    let dir = scratch();
    git_ok(&dir, &["init", "-b", "main"]);
    git_ok(&dir, &["config", "user.name", "Verify Phase1"]);
    git_ok(&dir, &["config", "user.email", "phase1@verify.local"]);
    git_ok(&dir, &["config", "commit.gpgsign", "false"]);
    dir
}

fn verify(repo: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(repo)
        .env("HOME", repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("spawn verify")
}

fn hooks_dir(repo: &Path) -> PathBuf {
    let hooks = git(repo, &["rev-parse", "--git-path", "hooks"]);
    assert!(hooks.status.success());
    let raw = String::from_utf8_lossy(&hooks.stdout).trim().to_string();
    let p = PathBuf::from(&raw);
    if p.is_absolute() {
        p
    } else {
        repo.join(p)
    }
}

#[test]
fn version_identifies_verify_repo_not_a_foreign_crate() {
    let repo = init_repo();
    let out = verify(&repo, &["-v"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "verify -v failed:\n{stderr}");
    assert!(
        stdout.starts_with("verify "),
        "product name must be verify:\n{stdout}"
    );
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "semver missing:\n{stdout}"
    );
    assert!(
        stdout.contains("github.com/TheBrake/verify"),
        "-v must point at TheBrake/verify, not another crate:\n{stdout}"
    );
    assert!(
        !stdout.to_ascii_lowercase().contains("colprotect"),
        "-v must not look like colprotect_backend:\n{stdout}"
    );
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn help_separates_use_from_build_and_documents_contract() {
    let repo = init_repo();
    let out = verify(&repo, &["--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("Cargo/Rust are not required to *use*")
            || stdout.contains("not required to *use*"),
        "help must say Cargo is not required to use:\n{stdout}"
    );
    assert!(
        stdout.contains("USE (any Git repo") || stdout.contains("verify install"),
        "{stdout}"
    );
    assert!(
        stdout.contains("BUILD") && stdout.contains("cargo install"),
        "help must isolate cargo install as build, not use:\n{stdout}"
    );
    assert!(stdout.contains("EXIT CODES:"), "{stdout}");
    assert!(stdout.contains("git commit --no-verify"), "{stdout}");
    assert!(
        stdout.contains("do not delete secrets already on a remote")
            || stdout.contains("rotate those credentials"),
        "{stdout}"
    );
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn install_prints_both_hook_paths_and_the_command_each_runs() {
    let repo = init_repo();
    let out = verify(&repo, &["install"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "install failed:\n{stderr}\n{stdout}");

    let dir = hooks_dir(&repo);
    let pre_commit = dir.join("pre-commit");
    let pre_push = dir.join("pre-push");
    assert!(pre_commit.is_file(), "{}", pre_commit.display());
    assert!(pre_push.is_file(), "{}", pre_push.display());

    assert!(
        stdout.contains(pre_commit.to_string_lossy().as_ref()),
        "install must print pre-commit path {}:\n{stdout}",
        pre_commit.display()
    );
    assert!(
        stdout.contains(pre_push.to_string_lossy().as_ref()),
        "install must print pre-push path {}:\n{stdout}",
        pre_push.display()
    );
    assert!(
        stdout.contains("commit-run"),
        "install must name the pre-commit command:\n{stdout}"
    );
    assert!(
        stdout.contains("hook-run"),
        "install must name the pre-push command:\n{stdout}"
    );
    assert!(
        stdout.contains("rotate"),
        "install should warn that already-pushed secrets must be rotated:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&repo);
}
