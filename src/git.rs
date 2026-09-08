use crate::diff::{self, AddedLine};
use std::io::{self, BufRead, IsTerminal};
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub const ZERO_OID: &str = "0000000000000000000000000000000000000000";
pub const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

#[derive(Debug, Clone)]
pub struct PushUpdate {
    pub local_ref: String,
    pub local_sha: String,
    pub remote_ref: String,
    pub remote_sha: String,
}

impl PushUpdate {
    pub fn is_delete(&self) -> bool {
        self.local_sha == ZERO_OID || self.local_ref == "(delete)"
    }

    pub fn is_new_branch(&self) -> bool {
        self.remote_sha == ZERO_OID
    }
}

pub fn repo_root() -> Option<PathBuf> {
    git_stdout(&["rev-parse", "--show-toplevel"])
        .ok()
        .map(PathBuf::from)
}

pub fn git_dir() -> Result<PathBuf, String> {
    let out = git_stdout(&["rev-parse", "--git-dir"])?;
    let p = PathBuf::from(&out);
    if p.is_absolute() {
        Ok(p)
    } else {
        Ok(std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(p))
    }
}

pub fn read_pre_push_updates() -> Result<Vec<PushUpdate>, String> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Ok(Vec::new());
    }
    parse_pre_push_lines(stdin.lock())
}

pub fn parse_pre_push_lines<R: BufRead>(reader: R) -> Result<Vec<PushUpdate>, String> {
    let mut updates = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| e.to_string())?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let local_ref = parts.next().unwrap_or("").to_string();
        let local_sha = parts.next().unwrap_or("").to_string();
        let remote_ref = parts.next().unwrap_or("").to_string();
        let remote_sha = parts.next().unwrap_or("").to_string();
        if local_sha.is_empty() {
            continue;
        }
        updates.push(PushUpdate {
            local_ref,
            local_sha,
            remote_ref,
            remote_sha,
        });
    }
    Ok(updates)
}

pub fn added_lines_for_update(update: &PushUpdate) -> Result<Vec<AddedLine>, String> {
    let from = if update.is_new_branch() {
        merge_base_or_empty(&update.local_sha)
    } else {
        update.remote_sha.clone()
    };
    diff_range(&from, &update.local_sha)
}

pub fn added_lines_unpushed() -> Result<Vec<AddedLine>, String> {
    let local = git_stdout(&["rev-parse", "HEAD"])?;
    let from = merge_base_or_empty(&local);
    diff_range(&from, &local)
}

pub fn added_lines_vs_head() -> Result<Vec<AddedLine>, String> {
    let raw = git_stdout(&["diff", "--unified=0", "--diff-filter=ACMR", "HEAD"])?;
    Ok(diff::parse_unified_diff(&raw))
}

fn merge_base_or_empty(local_sha: &str) -> String {
    for cand in [
        "@{upstream}",
        "refs/remotes/origin/HEAD",
        "origin/HEAD",
        "origin/main",
        "origin/master",
    ] {
        if let Ok(base) = git_stdout(&["merge-base", local_sha, cand]) {
            if !base.is_empty() {
                return base;
            }
        }
    }
    EMPTY_TREE.to_string()
}

fn diff_range(from: &str, to: &str) -> Result<Vec<AddedLine>, String> {
    let raw = git_stdout(&[
        "diff",
        "--unified=0",
        "--diff-filter=ACMR",
        "--no-ext-diff",
        "--no-color",
        from,
        to,
    ])?;
    Ok(diff::parse_unified_diff(&raw))
}

pub fn git_stdout(args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("failed to spawn git: {e}"))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git {} failed: {}", args.join(" "), err.trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
