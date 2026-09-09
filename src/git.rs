use crate::diff::{self, AddedLine};
use std::io::{self, BufRead, IsTerminal};
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub const ZERO_OID: &str = "0000000000000000000000000000000000000000";
pub const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

const DIFF_FLAGS: &[&str] = &[
    "-c",
    "core.quotepath=false",
    "diff",
    "--unified=0",
    "--diff-filter=ACMR",
    "--no-ext-diff",
    "--no-color",
];

#[derive(Debug, Clone)]
pub struct PushUpdate {
    pub local_ref: String,
    pub local_sha: String,
    pub remote_ref: String,
    pub remote_sha: String,
}

impl PushUpdate {
    pub fn is_delete(&self) -> bool {
        is_zero_oid(&self.local_sha) || self.local_ref == "(delete)"
    }

    pub fn is_new_branch(&self) -> bool {
        is_zero_oid(&self.remote_sha)
    }
}

pub fn is_zero_oid(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b == b'0')
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
        return Err("pre-push stdin is a terminal — hook is not receiving Git updates".into());
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
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 4 {
            return Err(format!(
                "invalid pre-push line (want local_ref local_sha remote_ref remote_sha): {line}"
            ));
        }
        let local_ref = parts[0].to_string();
        let local_sha = parts[1].to_string();
        let remote_ref = parts[2].to_string();
        let remote_sha = parts[3].to_string();
        if local_sha.is_empty() || remote_sha.is_empty() {
            return Err(format!("invalid pre-push line (empty sha): {line}"));
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

pub fn added_lines_for_update(
    update: &PushUpdate,
    remote: Option<&str>,
) -> Result<Vec<AddedLine>, String> {
    if update.is_delete() {
        return Ok(Vec::new());
    }
    let to = peel_commit(&update.local_sha)?;
    let from = if update.is_new_branch() {
        merge_base_or_empty(&to, remote)
    } else {
        peel_commit(&update.remote_sha).unwrap_or_else(|_| update.remote_sha.clone())
    };
    diff_range(&from, &to)
}

pub fn added_lines_unpushed() -> Result<Vec<AddedLine>, String> {
    let local = git_stdout(&["rev-parse", "HEAD"])?;
    let from = merge_base_or_empty(&local, None);
    diff_range(&from, &local)
}

pub fn added_lines_vs_head() -> Result<Vec<AddedLine>, String> {
    let raw = git_diff_text(&{
        let mut args: Vec<&str> = DIFF_FLAGS.to_vec();
        args.extend(["--", "HEAD"]);
        args
    })?;
    diff::parse_unified_diff(&raw)
}

/// Candidates for merge-base when the remote side is a new branch.
/// Anchored to the push remote first. `@{upstream}` of HEAD is last, not first.
pub fn merge_base_candidates(remote: Option<&str>) -> Vec<String> {
    let mut cands = Vec::new();
    if let Some(r) = remote {
        let r = r.trim();
        if !r.is_empty() && r != "origin" {
            cands.push(format!("refs/remotes/{r}/HEAD"));
            cands.push(format!("refs/remotes/{r}/main"));
            cands.push(format!("refs/remotes/{r}/master"));
            cands.push(format!("{r}/HEAD"));
            cands.push(format!("{r}/main"));
            cands.push(format!("{r}/master"));
        }
    }
    cands.push("refs/remotes/origin/HEAD".into());
    cands.push("refs/remotes/origin/main".into());
    cands.push("refs/remotes/origin/master".into());
    cands.push("origin/HEAD".into());
    cands.push("origin/main".into());
    cands.push("origin/master".into());
    cands.push("@{upstream}".into());
    cands
}

pub fn merge_base_or_empty(local_sha: &str, remote: Option<&str>) -> String {
    for cand in merge_base_candidates(remote) {
        if let Ok(base) = git_stdout(&["merge-base", local_sha, &cand]) {
            if !base.is_empty() {
                return base;
            }
        }
    }
    empty_tree()
}

fn empty_tree() -> String {
    git_stdout(&["hash-object", "-t", "tree", "/dev/null"]).unwrap_or_else(|_| EMPTY_TREE.to_string())
}

fn peel_commit(sha: &str) -> Result<String, String> {
    let spec = format!("{sha}^{{commit}}");
    git_stdout(&["rev-parse", "--verify", spec.as_str()]).or_else(|_| Ok(sha.to_string()))
}

fn diff_range(from: &str, to: &str) -> Result<Vec<AddedLine>, String> {
    let raw = git_diff_text(&[
        DIFF_FLAGS[0],
        DIFF_FLAGS[1],
        DIFF_FLAGS[2],
        DIFF_FLAGS[3],
        DIFF_FLAGS[4],
        DIFF_FLAGS[5],
        DIFF_FLAGS[6],
        "--",
        from,
        to,
    ])?;
    diff::parse_unified_diff(&raw)
}

/// Trimmed UTF-8 for refs / SHAs / single-line answers.
pub fn git_stdout(args: &[&str]) -> Result<String, String> {
    let raw = git_output(args)?;
    Ok(String::from_utf8_lossy(&raw).trim().to_string())
}

/// Untrimmed patch text. Valid UTF-8 is kept as-is; invalid lines are lossy.
fn git_diff_text(args: &[&str]) -> Result<String, String> {
    let raw = git_output(args)?;
    Ok(bytes_to_diff(&raw))
}

fn bytes_to_diff(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.split_inclusive(|&b| b == b'\n') {
        match std::str::from_utf8(chunk) {
            Ok(s) => out.push_str(s),
            Err(_) => out.push_str(&String::from_utf8_lossy(chunk)),
        }
    }
    out
}

fn git_output(args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("failed to spawn git: {e}"))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git {} failed: {}", args.join(" "), err.trim()));
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(s: &str) -> Vec<PushUpdate> {
        parse_pre_push_lines(Cursor::new(s)).unwrap()
    }

    #[test]
    fn four_fields() {
        let u = parse(
            "refs/heads/feat abc1110000000000000000000000000000000001 refs/heads/feat def2220000000000000000000000000000000002\n",
        );
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].local_ref, "refs/heads/feat");
        assert_eq!(u[0].local_sha, "abc1110000000000000000000000000000000001");
        assert!(!u[0].is_delete());
        assert!(!u[0].is_new_branch());
    }

    #[test]
    fn delete_is_local_zero() {
        let line = format!("(delete) {ZERO_OID} refs/heads/gone abc1110000000000000000000000000000000001\n");
        let u = parse(&line);
        assert!(u[0].is_delete());
        assert_eq!(added_lines_for_update(&u[0], Some("origin")).unwrap().len(), 0);
    }

    #[test]
    fn new_branch_is_remote_zero() {
        let line = format!(
            "refs/heads/feat abc1110000000000000000000000000000000001 refs/heads/feat {ZERO_OID}\n"
        );
        let u = parse(&line);
        assert!(u[0].is_new_branch());
        assert!(!u[0].is_delete());
    }

    #[test]
    fn two_tokens_is_an_error() {
        let err = parse_pre_push_lines(Cursor::new("refs/heads/feat abc\n")).unwrap_err();
        assert!(err.contains("invalid pre-push"), "{err}");
    }

    #[test]
    fn empty_lines_ignored_two_updates() {
        let u = parse(
            "\nrefs/heads/a aaa1110000000000000000000000000000000001 refs/heads/a bbb1110000000000000000000000000000000001\n\nrefs/heads/b ccc1110000000000000000000000000000000001 refs/heads/b ddd1110000000000000000000000000000000001\n",
        );
        assert_eq!(u.len(), 2);
    }

    #[test]
    fn merge_base_candidates_anchor_to_push_remote() {
        let c = merge_base_candidates(Some("upstream"));
        assert_eq!(c[0], "refs/remotes/upstream/HEAD");
        assert!(c.contains(&"@{upstream}".into()));
        assert_ne!(c[0], "@{upstream}");
        let origin = merge_base_candidates(Some("origin"));
        assert_eq!(origin[0], "refs/remotes/origin/HEAD");
    }

    #[test]
    fn zero_oid_accepts_sha256_zeros() {
        assert!(is_zero_oid(ZERO_OID));
        assert!(is_zero_oid(&"0".repeat(64)));
        assert!(!is_zero_oid("abc"));
        assert!(!is_zero_oid(""));
    }

    #[test]
    fn bytes_to_diff_does_not_trim() {
        let raw = b"+SECRET=1\n";
        assert_eq!(bytes_to_diff(raw), "+SECRET=1\n");
    }
}