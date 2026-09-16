use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_verify"))
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn scratch() -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "verify-p4-{}-{}-{}",
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
        .env("GIT_AUTHOR_NAME", "Verify Phase4")
        .env("GIT_AUTHOR_EMAIL", "phase4@verify.local")
        .env("GIT_COMMITTER_NAME", "Verify Phase4")
        .env("GIT_COMMITTER_EMAIL", "phase4@verify.local")
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

fn verify(repo: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(repo)
        .env("HOME", repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("PATH", {
            let dir = bin().parent().unwrap().to_path_buf();
            format!("{}:/usr/bin:/bin", dir.display())
        })
        .output()
        .expect("spawn verify")
}

fn hooks_dir(repo: &Path) -> PathBuf {
    let out = git(repo, &["rev-parse", "--git-path", "hooks"]);
    assert!(out.status.success());
    let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let p = PathBuf::from(&raw);
    if p.is_absolute() {
        p
    } else {
        repo.join(p)
    }
}

fn head_exists(repo: &Path) -> bool {
    git(repo, &["rev-parse", "--verify", "HEAD"])
        .status
        .success()
}

#[test]
fn version_is_v1_cut() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "1.0.0");
    let repo = scratch();
    git_ok(&repo, &["init", "-b", "main"]);
    let out = verify(&repo, &["-V"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.starts_with("verify 1.0.0"),
        "cut version missing:\n{stdout}"
    );
    assert!(stdout.contains("github.com/TheBrake/verify"), "{stdout}");
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn changelog_names_the_v1_surface() {
    let text = fs::read_to_string(crate_root().join("CHANGELOG.md"))
        .expect("CHANGELOG.md must exist at the crate root for the v1 cut");
    let lower = text.to_ascii_lowercase();
    assert!(
        text.contains("1.0.0"),
        "CHANGELOG must record the cut:\n{text}"
    );
    assert!(
        lower.contains("pre-commit") && lower.contains("pre-push"),
        "CHANGELOG must name both hooks:\n{text}"
    );
    assert!(
        lower.contains(".env") && (lower.contains("modific") || lower.contains("modified")),
        "CHANGELOG must mention modified .env:\n{text}"
    );
    assert!(
        lower.contains("musl")
            || lower.contains("release")
            || lower.contains("binario")
            || lower.contains("binary"),
        "CHANGELOG must mention binary distribution:\n{text}"
    );
}

#[test]
fn release_note_in_ci_reproduces_the_fourth_proof() {
    let wf = fs::read_to_string(crate_root().join(".github/ci.yml")).expect(".github/ci.yml");
    assert!(
        wf.contains("PASSWORD=rotated-secret-99"),
        "release body must include the epic's .env proof:\n{wf}"
    );
    assert!(
        wf.contains("git commit -m x") || wf.contains("git commit -m"),
        "release body must show the commit that has to fail:\n{wf}"
    );
    assert!(
        wf.contains("install -m 755"),
        "canonical install line missing from the release body:\n{wf}"
    );
    assert!(
        wf.contains("verify-x86_64-unknown-linux-musl.sha256"),
        "checksum file must keep its artifact name so sha256sum -c works:\n{wf}"
    );
    let low = wf.to_ascii_lowercase();
    assert!(
        low.contains("--no-verify") && (low.contains("rotar") || low.contains("rotate")),
        "known limits missing from the release body:\n{wf}"
    );
    assert!(
        low.contains("límites conocidos") || low.contains("limites conocidos"),
        "release body must title the known limits:\n{wf}"
    );
    assert!(
        !wf.contains("brew install")
            && !wf.contains("cargo publish")
            && !wf.contains("pip install"),
        "V1.1 install channels must stay out of the v1.0.0 note:\n{wf}"
    );
}

#[test]
fn fourth_proof_in_a_python_repo_without_verify_source() {
    let repo = scratch();
    git_ok(&repo, &["init", "-b", "main"]);
    git_ok(&repo, &["config", "user.name", "Verify Phase4"]);
    git_ok(&repo, &["config", "user.email", "phase4@verify.local"]);
    git_ok(&repo, &["config", "commit.gpgsign", "false"]);

    fs::write(
        repo.join("app.py"),
        "def main():\n    print('colprotect')\n",
    )
    .unwrap();
    fs::write(repo.join("requirements.txt"), "flask==3.0.0\n").unwrap();
    assert!(
        !repo.join("Cargo.toml").exists(),
        "the protected repo must not look like the Verify source"
    );

    let inst = verify(&repo, &["install"]);
    assert!(
        inst.status.success(),
        "install failed:\n{}",
        String::from_utf8_lossy(&inst.stderr)
    );
    let dir = hooks_dir(&repo);
    assert!(dir.join("pre-commit").is_file());
    assert!(dir.join("pre-push").is_file());

    fs::write(repo.join(".env"), "PASSWORD=rotated-secret-99\n").unwrap();
    git_ok(&repo, &["add", "--", ".env"]);

    let commit = git(&repo, &["commit", "-m", "x"]);
    let code = commit.status.code().unwrap_or(255);
    assert_eq!(
        code,
        1,
        "git commit must fail with 1 in a non-Rust repo\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&commit.stdout),
        String::from_utf8_lossy(&commit.stderr)
    );
    assert!(!head_exists(&repo), "the blocked commit must not exist");
    let _ = fs::remove_dir_all(&repo);
}
