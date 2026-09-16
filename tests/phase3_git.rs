use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_verify"))
}

fn scratch() -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "verify-p3-{}-{}-{}",
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
        .env("GIT_AUTHOR_NAME", "Verify Phase3")
        .env("GIT_AUTHOR_EMAIL", "phase3@verify.local")
        .env("GIT_COMMITTER_NAME", "Verify Phase3")
        .env("GIT_COMMITTER_EMAIL", "phase3@verify.local")
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

fn git_stdout(repo: &Path, args: &[&str]) -> String {
    let out = git(repo, args);
    assert!(
        out.status.success(),
        "git {} failed\n{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn init_repo() -> PathBuf {
    let dir = scratch();
    git_ok(&dir, &["init", "-b", "main"]);
    git_ok(&dir, &["config", "user.name", "Verify Phase3"]);
    git_ok(&dir, &["config", "user.email", "phase3@verify.local"]);
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

fn verify_stdin(repo: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .current_dir(repo)
        .env("HOME", repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn verify");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait verify")
}

fn head_sha(repo: &Path) -> String {
    git_stdout(repo, &["rev-parse", "HEAD"])
}

fn hooks_dir(repo: &Path) -> PathBuf {
    let raw = git_stdout(repo, &["rev-parse", "--git-path", "hooks"]);
    let p = PathBuf::from(&raw);
    if p.is_absolute() {
        p
    } else {
        repo.join(p)
    }
}

fn pre_push_line(local_sha: &str, remote_sha: &str) -> String {
    format!("refs/heads/main {local_sha} refs/heads/main {remote_sha}\n")
}

const ZERO_OID: &str = "0000000000000000000000000000000000000000";
const LEAK: &str = "PASSWORD=rotated-secret-99\n";

#[test]
fn commit_run_blocks_staged_new_env() {
    let repo = init_repo();
    fs::write(repo.join(".env"), LEAK).unwrap();
    git_ok(&repo, &["add", "--", ".env"]);

    let cached = git_stdout(&repo, &["diff", "--cached", "--", ".env"]);
    assert!(
        cached.contains("new file mode"),
        "control: a brand-new .env must show new file mode:\n{cached}"
    );

    let out = verify(&repo, &["commit-run"]);
    let code = out.status.code().unwrap_or(255);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(code, 1, "expected exit 1, got {code}\n{err}");
    assert!(
        err.contains("env-file") || err.contains("commit blocked"),
        "stderr should mention env-file / commit blocked:\n{err}"
    );
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn commit_run_blocks_modified_env_without_new_file_mode() {
    let repo = init_repo();
    fs::write(repo.join(".env"), "FOO=1\n").unwrap();
    git_ok(&repo, &["add", "--", ".env"]);
    git_ok(&repo, &["commit", "-m", "plant env"]);

    fs::write(repo.join(".env"), LEAK).unwrap();
    git_ok(&repo, &["add", "--", ".env"]);

    let cached = git_stdout(&repo, &["diff", "--cached", "--unified=0", "--", ".env"]);
    assert!(
        !cached.contains("new file mode"),
        "this case is the modified path, not a new file:\n{cached}"
    );
    assert!(
        cached.contains("+PASSWORD=rotated-secret-99"),
        "index must expose the added leak line:\n{cached}"
    );

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
    assert_eq!(out.status.code().unwrap_or(255), 0, "{err}");
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn install_writes_both_managed_hooks() {
    let repo = init_repo();
    let inst = verify(&repo, &["install"]);
    assert!(
        inst.status.success(),
        "install failed:\n{}",
        String::from_utf8_lossy(&inst.stderr)
    );

    let dir = hooks_dir(&repo);
    let pre_commit = fs::read_to_string(dir.join("pre-commit")).unwrap();
    let pre_push = fs::read_to_string(dir.join("pre-push")).unwrap();
    assert!(pre_commit.contains("# Managed by Verify"), "{pre_commit}");
    assert!(pre_commit.contains("commit-run"), "{pre_commit}");
    assert!(pre_push.contains("# Managed by Verify"), "{pre_push}");
    assert!(pre_push.contains("hook-run"), "{pre_push}");
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn hook_run_sees_secret_in_commit_range_not_after_double_dash() {
    let repo = init_repo();
    fs::write(repo.join("README"), "ok\n").unwrap();
    git_ok(&repo, &["add", "--", "README"]);
    git_ok(&repo, &["commit", "-m", "seed"]);
    let remote_sha = head_sha(&repo);

    fs::write(repo.join(".env"), LEAK).unwrap();
    git_ok(&repo, &["add", "--", ".env"]);
    git_ok(&repo, &["commit", "-m", "leak"]);
    let local_sha = head_sha(&repo);

    let wrong = git(
        &repo,
        &[
            "-c",
            "core.quotepath=false",
            "diff",
            "--unified=0",
            "--diff-filter=ACMR",
            "--no-ext-diff",
            "--no-color",
            "--",
            &remote_sha,
            &local_sha,
        ],
    );
    let wrong_txt = String::from_utf8_lossy(&wrong.stdout);
    assert!(
        !wrong_txt.contains("+PASSWORD=rotated-secret-99"),
        "regresión documentada: `git diff -- SHA SHA` no debe mostrar el secreto:\n{wrong_txt}"
    );

    let right = git(
        &repo,
        &[
            "-c",
            "core.quotepath=false",
            "diff",
            "--unified=0",
            "--diff-filter=ACMR",
            "--no-ext-diff",
            "--no-color",
            &remote_sha,
            &local_sha,
            "--",
        ],
    );
    let right_txt = String::from_utf8_lossy(&right.stdout);
    assert!(
        right.status.success(),
        "git diff SHA SHA -- failed:\n{}",
        String::from_utf8_lossy(&right.stderr)
    );
    assert!(
        right_txt.contains("+PASSWORD=rotated-secret-99"),
        "revisiones *antes* de `--` tienen que exponer la línea +:\n{right_txt}"
    );

    let out = verify_stdin(
        &repo,
        &["hook-run", "origin", "https://example.invalid/repo.git"],
        &pre_push_line(&local_sha, &remote_sha),
    );
    let code = out.status.code().unwrap_or(255);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        code,
        1,
        "hook-run must see the range leak, got {code}\nstderr:\n{err}\nstdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        err.contains("env-file")
            || err.contains("push blocked")
            || err.contains("blocked")
            || err.contains("PASSWORD"),
        "hook-run should report the leak, not an empty-diff pass:\n{err}"
    );
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn hook_run_ignores_secret_already_on_the_remote_side() {
    let repo = init_repo();
    fs::write(repo.join("README"), "ok\n").unwrap();
    git_ok(&repo, &["add", "--", "README"]);
    git_ok(&repo, &["commit", "-m", "seed"]);

    fs::write(repo.join(".env"), LEAK).unwrap();
    git_ok(&repo, &["add", "--", ".env"]);
    git_ok(&repo, &["commit", "-m", "already pushed leak"]);
    let remote_sha = head_sha(&repo);

    fs::write(repo.join("README"), "ok\nmore\n").unwrap();
    git_ok(&repo, &["add", "--", "README"]);
    git_ok(&repo, &["commit", "-m", "clean follow-up"]);
    let local_sha = head_sha(&repo);

    let out = verify_stdin(
        &repo,
        &["hook-run", "origin", "https://example.invalid/repo.git"],
        &pre_push_line(&local_sha, &remote_sha),
    );
    let code = out.status.code().unwrap_or(255);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        code, 0,
        "range after the leak must be clean, got {code}\n{err}"
    );
    assert!(!err.contains("env-file"), "{err}");
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn hook_run_blocks_new_branch_that_introduces_env() {
    let repo = init_repo();
    fs::write(repo.join(".env"), LEAK).unwrap();
    git_ok(&repo, &["add", "--", ".env"]);
    git_ok(&repo, &["commit", "-m", "first commit is the leak"]);
    let local_sha = head_sha(&repo);

    let out = verify_stdin(
        &repo,
        &["hook-run", "origin", "https://example.invalid/repo.git"],
        &pre_push_line(&local_sha, ZERO_OID),
    );
    let code = out.status.code().unwrap_or(255);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        code, 1,
        "new-branch push that carries .env must block, got {code}\n{err}"
    );
    assert!(err.contains("env-file") || err.contains("blocked"), "{err}");
    let _ = fs::remove_dir_all(&repo);
}
