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
        "verify-p0-{}-{}-{}",
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
        .env("GIT_AUTHOR_NAME", "Verify Phase0")
        .env("GIT_AUTHOR_EMAIL", "phase0@verify.local")
        .env("GIT_COMMITTER_NAME", "Verify Phase0")
        .env("GIT_COMMITTER_EMAIL", "phase0@verify.local")
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
    git_ok(&dir, &["config", "user.name", "Verify Phase0"]);
    git_ok(&dir, &["config", "user.email", "phase0@verify.local"]);
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

fn head_exists(repo: &Path) -> bool {
    git(repo, &["rev-parse", "--verify", "HEAD"]).status.success()
}

#[test]
fn commit_run_blocks_staged_new_env() {
    let repo = init_repo();
    fs::write(repo.join(".env"), "PASSWORD=rotated-secret-99\n").unwrap();
    git_ok(&repo, &["add", "--", ".env"]);

    let out = verify(&repo, &["commit-run"]);
    let code = out.status.code().unwrap_or(255);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(code, 1, "expected exit 1, got {code}\n{err}");
    assert!(
        err.contains("env-file") || err.contains("commit blocked"),
        "stderr should mention env-file / commit blocked:\n{err}"
    );
    assert!(!head_exists(&repo), "commit-run must not create a commit");
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn commit_run_blocks_modified_env() {
    let repo = init_repo();
    fs::write(repo.join("README"), "ok\n").unwrap();
    git_ok(&repo, &["add", "--", "README"]);
    git_ok(&repo, &["commit", "-m", "seed"]);
    // No hooks yet, so the first .env can be committed. Fase 0 cares
    // about the *modified* index entry afterwards.
    fs::write(repo.join(".env"), "FOO=1\n").unwrap();
    git_ok(&repo, &["add", "--", ".env"]);
    git_ok(&repo, &["commit", "-m", "plant env"]);

    fs::write(repo.join(".env"), "PASSWORD=rotated-secret-99\n").unwrap();
    git_ok(&repo, &["add", "--", ".env"]);

    let out = verify(&repo, &["commit-run"]);
    let code = out.status.code().unwrap_or(255);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(code, 1, "modified .env must block, got {code}\n{err}");
    assert!(
        err.contains("env-file") || err.contains("commit blocked"),
        "{err}"
    );
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn install_writes_both_managed_hooks_and_git_commit_does_not_create() {
    let repo = init_repo();
    let inst = verify(&repo, &["install"]);
    assert!(
        inst.status.success(),
        "install failed:\n{}",
        String::from_utf8_lossy(&inst.stderr)
    );

    let hooks = git(&repo, &["rev-parse", "--git-path", "hooks"]);
    assert!(hooks.status.success());
    let hooks_dir = {
        let raw = String::from_utf8_lossy(&hooks.stdout).trim().to_string();
        let p = PathBuf::from(&raw);
        if p.is_absolute() {
            p
        } else {
            repo.join(p)
        }
    };
    let pre_commit = fs::read_to_string(hooks_dir.join("pre-commit")).unwrap();
    let pre_push = fs::read_to_string(hooks_dir.join("pre-push")).unwrap();
    assert!(
        pre_commit.contains("# Managed by Verify"),
        "{pre_commit}"
    );
    assert!(pre_commit.contains("commit-run"), "{pre_commit}");
    assert!(pre_push.contains("# Managed by Verify"), "{pre_push}");
    assert!(pre_push.contains("hook-run"), "{pre_push}");

    fs::write(repo.join(".env"), "PASSWORD=rotated-secret-99\n").unwrap();
    git_ok(&repo, &["add", "--", ".env"]);

    let commit = git(&repo, &["commit", "-m", "should not exist"]);
    let code = commit.status.code().unwrap_or(255);
    assert_eq!(
        code, 1,
        "git commit must fail with 1\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&commit.stdout),
        String::from_utf8_lossy(&commit.stderr)
    );
    assert!(
        !head_exists(&repo),
        "a blocked pre-commit must not create HEAD"
    );
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn env_example_is_not_an_env_file_finding_on_commit_run() {
    let repo = init_repo();
    fs::write(repo.join(".env.example"), "FOO=1\n").unwrap();
    git_ok(&repo, &["add", "--", ".env.example"]);
    let out = verify(&repo, &["commit-run"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("env-file"),
        ".env.example must not emit env-file:\n{err}"
    );
    // Content is harmless; commit-run should allow (exit 0).
    assert_eq!(out.status.code().unwrap_or(255), 0, "{err}");
    let _ = fs::remove_dir_all(&repo);
}