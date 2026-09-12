use crate::config::Config;
use crate::diff::AddedLine;
use crate::rules::{self, CompiledRule, Severity};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// Stop walking the rest of the diff once this many blocking findings exist.
const MAX_BLOCKING_FINDINGS: usize = 64;

pub struct Engine {
    rules: Vec<CompiledRule>,
    cfg: Config,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub description: String,
    pub severity: Severity,
    pub path: String,
    pub line_no: usize,
    pub snippet: String,
    pub fingerprint: String,
}

impl Finding {
    pub fn blocks(&self, cfg: &Config) -> bool {
        match cfg.fail_on {
            crate::config::FailOn::Any => true,
            crate::config::FailOn::High => {
                self.severity == Severity::High || self.severity == Severity::Critical
            }
        }
    }
}

impl Engine {
    pub fn new(cfg: &Config) -> Result<Self, String> {
        Ok(Self {
            rules: rules::compile_all(&cfg.custom_rules)?,
            cfg: cfg.clone(),
        })
    }

    pub fn scan_added_lines(&self, lines: &[AddedLine]) -> Vec<Finding> {
        let oversized = oversized_paths(lines, self.cfg.max_file_bytes);
        let mut findings = Vec::new();
        let mut seen = HashSet::<String>::new();
        let mut blocking = 0usize;

        for line in lines {
            if blocking >= MAX_BLOCKING_FINDINGS {
                break;
            }
            if line.path.is_empty() {
                continue;
            }
            if self.cfg.is_excluded(&line.path) {
                continue;
            }
            if oversized.contains(&line.path) {
                continue;
            }

            let allow = line_allow(&line.text);

            // New *or* modified: an env file in the diff is leaving Git.
            // Fingerprint is per path, so many + lines collapse to one finding.
            if self.cfg.block_env_files && is_env_file(&line.path) {
                if !allow.skips("env-file") {
                    let f = self.make_finding(
                        "env-file",
                        "Environment file staged or in outgoing diff (likely contains secrets)",
                        Severity::Critical,
                        line,
                        &line.path,
                    );
                    if !self.is_allowed(&f, line) && seen.insert(f.fingerprint.clone()) {
                        if f.blocks(&self.cfg) {
                            blocking += 1;
                        }
                        findings.push(f);
                    }
                }
            }

            let before = findings.len();
            for rule in &self.rules {
                if allow.skips(&rule.id) {
                    continue;
                }
                for matched in rules::match_line(rule, &line.text, &line.path) {
                    if is_doc_secret(&matched) {
                        continue;
                    }
                    if matches!(
                        rule.id.as_str(),
                        "generic-api-key" | "password-assign" | "generic-db-url"
                    ) && looks_like_placeholder(&matched)
                    {
                        continue;
                    }

                    let f = self.make_finding(
                        &rule.id,
                        &rule.description,
                        rule.severity,
                        line,
                        &matched,
                    );
                    if self.is_allowed(&f, line) {
                        continue;
                    }
                    if seen.insert(f.fingerprint.clone()) {
                        if f.blocks(&self.cfg) {
                            blocking += 1;
                        }
                        findings.push(f);
                    }
                }
            }
            let line_had_rule = findings.len() > before;

            if self.cfg.entropy_enabled && !line_had_rule && !allow.skips("high-entropy") {
                for token in high_entropy_tokens(
                    &line.text,
                    self.cfg.entropy_min_length,
                    self.cfg.entropy_threshold,
                ) {
                    if is_doc_secret(&token) || looks_like_placeholder(&token) {
                        continue;
                    }
                    let f = self.make_finding(
                        "high-entropy",
                        "High-entropy token (possible unknown secret)",
                        Severity::Medium,
                        line,
                        &token,
                    );
                    if self.is_allowed(&f, line) {
                        continue;
                    }
                    if seen.insert(f.fingerprint.clone()) {
                        if f.blocks(&self.cfg) {
                            blocking += 1;
                        }
                        findings.push(f);
                    }
                }
            }
        }

        findings
    }

    fn make_finding(
        &self,
        rule_id: &str,
        description: &str,
        severity: Severity,
        line: &AddedLine,
        matched: &str,
    ) -> Finding {
        let snippet = normalize_secret(matched);
        Finding {
            fingerprint: fingerprint(rule_id, &snippet),
            rule_id: rule_id.to_string(),
            description: description.to_string(),
            severity,
            path: line.path.clone(),
            line_no: line.line_no,
            snippet,
        }
    }

    fn is_allowed(&self, finding: &Finding, line: &AddedLine) -> bool {
        self.cfg.allow.iter().any(|a| {
            a.matches(
                &finding.rule_id,
                &finding.path,
                &finding.snippet,
                &line.text,
                &finding.fingerprint,
            )
        })
    }
}

fn oversized_paths(lines: &[AddedLine], max_file_bytes: usize) -> HashSet<String> {
    let mut sizes: HashMap<&str, usize> = HashMap::new();
    for line in lines {
        if line.path.is_empty() {
            continue;
        }
        *sizes.entry(line.path.as_str()).or_insert(0) += line.text.len().saturating_add(1);
    }
    sizes
        .into_iter()
        .filter(|(_, n)| *n > max_file_bytes)
        .map(|(p, _)| p.to_string())
        .collect()
}

/// Read paths as if they were newly added files.
/// I/O errors surface. Files larger than `max_file_bytes` are omitted (no findings).
pub fn read_files_as_added(
    paths: &[PathBuf],
    max_file_bytes: usize,
) -> Result<Vec<AddedLine>, String> {
    let mut out = Vec::new();
    for path in paths {
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        if meta.len() as usize > max_file_bytes {
            continue;
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        let display = path.display().to_string();
        let env = is_env_file(&display);
        for (i, line) in text.lines().enumerate() {
            out.push(AddedLine {
                path: display.clone(),
                line_no: i + 1,
                text: line.to_string(),
                // File scan treats the whole file as leaving the machine.
                // Env-file policy no longer depends on is_new_file (new and
                // modified env paths are both blocked when block_env_files).
                is_new_file: env,
            });
        }
    }
    Ok(out)
}

pub fn is_env_file(path: &str) -> bool {
    let raw = path.replace('\\', "/");
    let name = raw.rsplit('/').next().unwrap_or(raw.as_str());
    let name = name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        ".env.example" | ".env.sample" | ".env.template" | ".env.test"
    ) {
        return false;
    }
    name == ".env" || name.starts_with(".env.")
}

#[derive(Debug, PartialEq, Eq)]
enum LineAllow {
    None,
    All,
    Rule(String),
}

impl LineAllow {
    fn skips(&self, rule_id: &str) -> bool {
        match self {
            Self::None => false,
            Self::All => true,
            Self::Rule(id) => id.eq_ignore_ascii_case(rule_id),
        }
    }
}

/// Only a real trailing comment can silence the line.
/// `verify:allow` / `verify:ignore` / `verify-ignore`; optional `:rule_id`.
fn line_allow(line: &str) -> LineAllow {
    let Some(body) = trailing_comment(line) else {
        return LineAllow::None;
    };
    let lower = body.to_ascii_lowercase();
    for marker in ["verify:allow", "verify:ignore", "verify-ignore"] {
        if let Some(idx) = lower.find(marker) {
            let after = lower[idx + marker.len()..].trim_start();
            if let Some(rest) = after.strip_prefix(':') {
                let id: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                    .collect();
                if !id.is_empty() {
                    return LineAllow::Rule(id);
                }
            }
            return LineAllow::All;
        }
    }
    LineAllow::None
}

fn trailing_comment(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && (in_single || in_double) && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if c == b'"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if c == b'\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if in_single || in_double {
            i += 1;
            continue;
        }
        if c == b'#' {
            return Some(&line[i + 1..]);
        }
        if c == b'/' && i + 1 < bytes.len() && (bytes[i + 1] == b'/' || bytes[i + 1] == b'*') {
            return Some(&line[i + 2..]);
        }
        if c == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            return Some(&line[i + 2..]);
        }
        i += 1;
    }
    None
}

fn looks_like_placeholder(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "your_",
        "changeme",
        "placeholder",
        "xxx",
        "todo",
        "insert_",
        "<secret",
        "${",
        "{{",
        "dummy",
        "fake_",
        "sample",
        "redacted",
        "not_a_real",
        "replace_me",
    ];
    MARKERS.iter().any(|m| l.contains(m))
}

/// Exact documentation / fixture secrets. Not a substring filter.
fn is_doc_secret(secret: &str) -> bool {
    const DOCS: &[&str] = &[
        "AKIAIOSFODNN7EXAMPLE",
        "ASIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ];
    let norm = normalize_secret(secret);
    DOCS.iter().any(|d| d.eq_ignore_ascii_case(&norm))
}

pub fn normalize_secret(secret: &str) -> String {
    secret
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .trim()
        .to_string()
}

/// 128-bit FNV-1a of rule_id || 0 || normalized secret. Path is not mixed in:
/// an Allow.fingerprint silences that secret everywhere.
pub fn fingerprint(rule_id: &str, secret: &str) -> String {
    let secret = normalize_secret(secret);
    let mut h0: u64 = 0xcbf29ce484222325;
    let mut h1: u64 = 0x6c62272e07bb0142;
    for (i, b) in rule_id
        .bytes()
        .chain(std::iter::once(0))
        .chain(secret.bytes())
        .enumerate()
    {
        if i % 2 == 0 {
            h0 ^= b as u64;
            h0 = h0.wrapping_mul(0x100000001b3);
        } else {
            h1 ^= b as u64;
            h1 = h1.wrapping_mul(0x100000001b3);
        }
    }
    format!("vf_{h0:016x}{h1:016x}")
}

fn high_entropy_tokens(line: &str, min_len: usize, threshold: f64) -> Vec<String> {
    let mut out = Vec::new();
    for token in tokenize(line) {
        if token.len() < min_len {
            continue;
        }
        if token.starts_with("http://") || token.starts_with("https://") {
            continue;
        }
        if !looks_secretish(token) {
            continue;
        }
        if rules::shannon_entropy(token) >= threshold {
            let n = normalize_secret(token);
            if !out.iter().any(|t| t == &n) {
                out.push(n);
            }
        }
    }
    out
}

fn tokenize(line: &str) -> impl Iterator<Item = &str> {
    line.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '`' | ',' | ';' | '|' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
            )
    })
    .map(|t| t.trim_matches(|c: char| matches!(c, '=' | ':' | '\\' | '/')))
    .filter(|t| !t.is_empty())
}

fn looks_secretish(token: &str) -> bool {
    let has_alpha = token.bytes().any(|b| b.is_ascii_alphabetic());
    let has_digit = token.bytes().any(|b| b.is_ascii_digit());
    has_alpha
        && has_digit
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/' | '=' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, FailOn};

    fn scan_on(path: &str, text: &str, new_file: bool) -> Vec<Finding> {
        let engine = Engine::new(&Config::default()).unwrap();
        engine.scan_added_lines(&[AddedLine {
            path: path.into(),
            line_no: 1,
            text: text.into(),
            is_new_file: new_file,
        }])
    }

    fn scan_line(text: &str) -> Vec<Finding> {
        scan_on("src/main.rs", text, false)
    }

    fn real_aws() -> &'static str {
        "AKIAAAAAAAAAAAAAAAAA"
    }

    #[test]
    fn catches_aws_key() {
        let f = scan_line(&format!(r#"const K: &str = "{}";"#, real_aws()));
        assert!(f.iter().any(|x| x.rule_id == "aws-access-key"), "{f:?}");
    }

    #[test]
    fn doc_aws_example_is_denylisted() {
        let f = scan_line(r#"const K: &str = "AKIAIOSFODNN7EXAMPLE";"#);
        assert!(
            f.iter().all(|x| x.rule_id != "aws-access-key"),
            "docs key must not block: {f:?}"
        );
    }

    #[test]
    fn catches_postgres() {
        let f = scan_line("url = postgres://admin:hunter2secret@prod-db.internal:5432/app");
        assert!(f.iter().any(|x| x.rule_id == "postgres-conn"), "{f:?}");
    }

    #[test]
    fn allow_comment_skips() {
        let f = scan_line(&format!(r#"password = "supersecret12" // verify:allow"#));
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn allow_in_string_value_does_not_skip() {
        let f = scan_line(r#"password = "supersecret12 verify:allow""#);
        assert!(
            f.iter().any(|x| x.rule_id == "password-assign"),
            "payload must not silence the hook: {f:?}"
        );
    }

    #[test]
    fn allow_one_rule_only() {
        let line = format!(r#"{} // verify:allow:aws-access-key"#, real_aws());
        let f = scan_line(&line);
        assert!(f.iter().all(|x| x.rule_id != "aws-access-key"), "{f:?}");
    }

    #[test]
    fn entropy_of_random_is_high() {
        let e = rules::shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        assert!(e > 4.0, "entropy={e}");
    }

    #[test]
    fn entropy_not_emitted_when_rule_already_hit() {
        let f = scan_line(&format!(r#"key = "{}";"#, real_aws()));
        assert!(f.iter().any(|x| x.rule_id == "aws-access-key"), "{f:?}");
        assert!(
            f.iter().all(|x| x.rule_id != "high-entropy"),
            "entropy is fallback, not a second opinion: {f:?}"
        );
    }

    #[test]
    fn entropy_returns_every_token_over_threshold() {
        let a = "wJalrXUtnFEMI7MDENGbPxRfiC";
        let b = "n4mQ8vL2pR9sT6wY3uA7cD1eH";
        assert!(
            rules::shannon_entropy(a) >= 4.5,
            "{}",
            rules::shannon_entropy(a)
        );
        assert!(
            rules::shannon_entropy(b) >= 4.5,
            "{}",
            rules::shannon_entropy(b)
        );
        let f = scan_line(&format!("{a} {b}"));
        let ent: Vec<_> = f.iter().filter(|x| x.rule_id == "high-entropy").collect();
        assert!(ent.len() >= 2, "expected both tokens, got {f:?}");
    }

    #[test]
    fn exclude_drops_path() {
        let engine = Engine::new(&Config::default()).unwrap();
        let f = engine.scan_added_lines(&[AddedLine {
            path: "README.md".into(),
            line_no: 1,
            text: format!(r#"k = "{}""#, real_aws()),
            is_new_file: false,
        }]);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn block_env_file_on_file_scan_semantics() {
        let engine = Engine::new(&Config::default()).unwrap();
        let f = engine.scan_added_lines(&[AddedLine {
            path: ".ENV.production".into(),
            line_no: 1,
            text: "FOO=1".into(),
            is_new_file: true,
        }]);
        assert!(f.iter().any(|x| x.rule_id == "env-file"), "{f:?}");
    }

    #[test]
    fn block_env_file_when_modified_not_new() {
        let engine = Engine::new(&Config::default()).unwrap();
        let f = engine.scan_added_lines(&[AddedLine {
            path: ".env".into(),
            line_no: 4,
            text: "PASSWORD=rotated-secret-99".into(),
            is_new_file: false,
        }]);
        assert!(
            f.iter().any(|x| x.rule_id == "env-file"),
            "modified env files must block, got {f:?}"
        );
        assert_eq!(
            f.iter().filter(|x| x.rule_id == "env-file").count(),
            1,
            "one env-file finding per path: {f:?}"
        );
    }

    #[test]
    fn env_example_is_not_blocked() {
        let f = scan_on(".env.example", "FOO=1", true);
        assert!(f.iter().all(|x| x.rule_id != "env-file"), "{f:?}");
    }

    #[test]
    fn max_file_bytes_applies_to_whole_path() {
        let mut cfg = Config::default();
        cfg.max_file_bytes = 32;
        let engine = Engine::new(&cfg).unwrap();
        let lines = vec![
            AddedLine {
                path: "src/big.rs".into(),
                line_no: 1,
                text: "a".repeat(20),
                is_new_file: false,
            },
            AddedLine {
                path: "src/big.rs".into(),
                line_no: 2,
                text: format!("k={}", real_aws()),
                is_new_file: false,
            },
        ];
        let f = engine.scan_added_lines(&lines);
        assert!(f.is_empty(), "oversized path must be skipped: {f:?}");
    }

    #[test]
    fn fail_on_high_ignores_medium() {
        let mut cfg = Config::default();
        cfg.fail_on = FailOn::High;
        cfg.entropy_enabled = true;
        let engine = Engine::new(&cfg).unwrap();
        let token = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4";
        let f = engine.scan_added_lines(&[AddedLine {
            path: "src/main.rs".into(),
            line_no: 1,
            text: token.into(),
            is_new_file: false,
        }]);
        assert!(f.iter().any(|x| x.rule_id == "high-entropy"), "{f:?}");
        assert!(f.iter().all(|x| !x.blocks(&cfg)), "{f:?}");
    }

    #[test]
    fn fingerprint_stable_across_trim_and_quotes() {
        let a = fingerprint("aws-access-key", real_aws());
        let b = fingerprint("aws-access-key", &format!("  \"{}\"  ", real_aws()));
        assert_eq!(a, b);
        assert!(a.starts_with("vf_"));
        assert_eq!(a.len(), 3 + 32, "{a}");
    }

    #[test]
    fn read_files_errors_on_missing_path() {
        let err =
            read_files_as_added(&[PathBuf::from("/no/such/verify-file-xyz")], 1024).unwrap_err();
        assert!(err.contains("failed to read"), "{err}");
    }

    #[test]
    fn read_files_marks_env_as_new() {
        let dir = std::env::temp_dir().join(format!("verify-eng-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let envp = dir.join(".env");
        std::fs::write(&envp, "FOO=1\n").unwrap();
        let lines = read_files_as_added(&[envp.clone()], 1024).unwrap();
        assert!(lines.iter().all(|l| l.is_new_file));
        let engine = Engine::new(&Config::default()).unwrap();
        let f = engine.scan_added_lines(&lines);
        assert!(f.iter().any(|x| x.rule_id == "env-file"), "{f:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
