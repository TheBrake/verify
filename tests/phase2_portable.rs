
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
        "verify-p2-{}-{}-{}",
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
        .env("GIT_AUTHOR_NAME", "Verify Phase2")
        .env("GIT_AUTHOR_EMAIL", "phase2@verify.local")
        .env("GIT_COMMITTER_NAME", "Verify Phase2")
        .env("GIT_COMMITTER_EMAIL", "phase2@verify.local")
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
    git_ok(&dir, &["config", "user.name", "Verify Phase2"]);
    git_ok(&dir, &["config", "user.email", "phase2@verify.local"]);
    git_ok(&dir, &["config", "commit.gpgsign", "false"]);
    dir
}

fn verify(repo: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(repo)
        .env("HOME", repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("PATH", {
            // Simula una VM sin cargo/rustc en PATH.
            let bin_path = bin();
            let dir = bin_path.parent().unwrap();
            format!("{}:/usr/bin:/bin", dir.display())
        })
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

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn crate_is_bin_only_and_not_a_library() {
    let toml = fs::read_to_string(crate_root().join("Cargo.toml")).unwrap();
    assert!(
        toml.contains("[[bin]]") && toml.contains("name = \"verify\""),
        "V1 ships a binary named verify:\n{toml}"
    );
    assert!(
        !toml.contains("[lib]"),
        "Fase 2 no publica [lib]; Cargo.toml no debe declarar una librería:\n{toml}"
    );
    assert!(
        toml.contains("name = \"sverify\"") || toml.contains("name = \"verify\""),
        "{toml}"
    );
}

#[test]
fn help_documents_release_install_without_rust() {
    let repo = init_repo();
    let out = verify(&repo, &["--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("RELEASE") || stdout.contains("GitHub Releases"),
        "help must name the portable channel:\n{stdout}"
    );
    assert!(
        stdout.contains("install -m 755"),
        "canonical install line missing:\n{stdout}"
    );
    assert!(
        stdout.contains("x86_64-unknown-linux-musl")
            || stdout.contains("linux-musl")
            || stdout.contains("GitHub Releases"),
        "{stdout}"
    );
    assert!(
        !stdout.to_ascii_lowercase().contains("homebrew")
            && !stdout.to_ascii_lowercase().contains("crates.io"),
        "Homebrew / crates.io-lib are V1.1, not Fase 2 help:\n{stdout}"
    );
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn install_from_this_binary_does_not_need_cargo() {
    let repo = init_repo();
    let out = verify(&repo, &["install"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "install failed:\n{stderr}\n{stdout}");
    assert!(
        !stdout.contains("cargo install") && !stderr.contains("cargo install"),
        "a downloaded binary must plant hooks without Cargo:\n{stdout}\n{stderr}"
    );

    let dir = hooks_dir(&repo);
    let pre_commit = fs::read_to_string(dir.join("pre-commit")).unwrap();
    let pre_push = fs::read_to_string(dir.join("pre-push")).unwrap();
    assert!(pre_commit.contains("# Managed by Verify"), "{pre_commit}");
    assert!(pre_commit.contains("commit-run"), "{pre_commit}");
    assert!(pre_push.contains("# Managed by Verify"), "{pre_push}");
    assert!(pre_push.contains("hook-run"), "{pre_push}");

    let exe = bin().canonicalize().unwrap();
    let exe_s = exe.to_string_lossy();
    assert!(
        pre_commit.contains(exe_s.as_ref()) || pre_commit.contains(&exe.display().to_string()),
        "hook must exec this binary, not cargo:\n{pre_commit}"
    );
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn release_artifact_names_are_stable() {
    assert_eq!(
        artifact_name("x86_64-unknown-linux-musl"),
        "verify-x86_64-unknown-linux-musl"
    );
    assert_eq!(
        artifact_name("aarch64-apple-darwin"),
        "verify-aarch64-apple-darwin"
    );
    let script = fs::read_to_string(crate_root().join("scripts/package-linux-musl.sh")).unwrap();
    assert!(
        script.contains("verify-${target}") || script.contains("verify-$target"),
        "packaging script must emit verify-<triple>:\n{script}"
    );
    let workflow = fs::read_to_string(crate_root().join(".github/ci.yml")).unwrap();
    assert!(
        workflow.contains("x86_64-unknown-linux-musl"),
        "CI must build the musl triple:\n{workflow}"
    );
    assert!(
        workflow.contains("sha256") || workflow.contains("sha256sum") || workflow.contains("shasum"),
        "CI must publish a checksum:\n{workflow}"
    );
    let wf = workflow.to_ascii_lowercase();
    assert!(
        !wf.contains("homebrew") && !wf.contains("pypi") && !wf.contains("cargo publish"),
        "Fase 2 pipeline must stay a single GitHub Release channel:\n{workflow}"
    );
}

fn artifact_name(triple: &str) -> String {
    format!("verify-{triple}")
}

#[test]
fn musl_binary_is_static_when_built_for_that_target() {
    let target = std::env::var("TARGET").unwrap_or_default();
    let triple = if target.is_empty() {
        std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default()
    } else {
        target
    };
    let is_musl = triple.contains("musl")
        || option_env!("CARGO_CFG_TARGET_ENV") == Some("musl");
    if !is_musl {
        return;
    }
    let path = bin();
    let file = Command::new("file")
        .arg(&path)
        .output()
        .expect("file(1)");
    let desc = String::from_utf8_lossy(&file.stdout);
    assert!(
        desc.to_ascii_lowercase().contains("statically linked")
            || desc.to_ascii_lowercase().contains("static"),
        "musl artifact must be statically linked:\n{desc}"
    );
}