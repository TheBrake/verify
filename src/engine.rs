use crate::config::{self, Config};
use crate::diff::AddedLine;
use crate::rules::{self, CompiledRule, Kind, Severity};
use std::path::PathBuf;

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
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::<String>::new();

        for line in lines {
            if line.path.is_empty() {
                continue;
            }
            if self.cfg.is_excluded(&line.path) {
                continue;
            }
            if line.text.len() > self.cfg.max_file_bytes {
                continue;
            }
            if is_allow_comment(&line.text) {
                continue;
            }

            if self.cfg.block_env_files && line.is_new_file && is_env_file(&line.path) {
                let f = self.make_finding(
                    "env-file",
                    "Newly added environment file (likely contains secrets)",
                    Severity::Critical,
                    line,
                    &line.path,
                );
                if !self.is_allowed(&f, line) && seen.insert(f.fingerprint.clone()) {
                    findings.push(f);
                }
            }

            for rule in &self.rules {
                let matched = match &rule.kind {
                    Kind::Builtin(f) => f(&line.text),
                    Kind::Regex {
                        regex,
                        secret_group,
                        keywords,
                        path_matcher,
                        entropy,
                    } => match_custom_rule(
                        line,
                        regex,
                        *secret_group,
                        keywords,
                        path_matcher.as_ref(),
                        *entropy,
                    ),
                };
                let Some(matched) = matched else { continue };

                if matches!(
                    rule.id.as_str(),
                    "generic-api-key" | "password-assign" | "generic-db-url"
                ) && (looks_like_placeholder(&matched) || looks_like_placeholder(&line.text))
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
                if seen.insert(format!("{}:{}:{}", f.path, f.line_no, f.rule_id)) {
                    findings.push(f);
                }
            }

            if self.cfg.entropy_enabled {
                if let Some(token) = high_entropy_token(
                    &line.text,
                    self.cfg.entropy_min_length,
                    self.cfg.entropy_threshold,
                ) {
                    if !looks_like_placeholder(&token) {
                        let f = self.make_finding(
                            "high-entropy",
                            "High-entropy token (possible unknown secret)",
                            Severity::Medium,
                            line,
                            &token,
                        );
                        if !self.is_allowed(&f, line)
                            && seen.insert(format!("{}:{}:high-entropy", f.path, f.line_no))
                        {
                            findings.push(f);
                        }
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
        Finding {
            fingerprint: fingerprint(rule_id, matched),
            rule_id: rule_id.to_string(),
            description: description.to_string(),
            severity,
            path: line.path.clone(),
            line_no: line.line_no,
            snippet: matched.to_string(),
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

fn match_custom_rule(
    line: &AddedLine,
    regex: &regex::Regex,
    secret_group: Option<usize>,
    keywords: &[String],
    path_matcher: Option<&globset::GlobMatcher>,
    entropy: Option<f64>,
) -> Option<String> {
    if !keywords.is_empty() {
        let lower = line.text.to_ascii_lowercase();
        let hit = keywords.iter().any(|k| {
            if k.chars().any(|c| c.is_ascii_uppercase()) {
                line.text.contains(k)
            } else {
                lower.contains(&k.to_ascii_lowercase())
            }
        });
        if !hit {
            return None;
        }
    }
    if let Some(matcher) = path_matcher {
        let path = config::normalize_scan_path(&line.path);
        if !matcher.is_match(path.as_str()) {
            return None;
        }
    }
    let caps = regex.captures(&line.text)?;
    let matched = if let Some(g) = secret_group {
        caps.get(g)?.as_str().to_string()
    } else {
        caps.get(0)?.as_str().to_string()
    };
    if let Some(min_ent) = entropy {
        if shannon_entropy(&matched) < min_ent {
            return None;
        }
    }
    Some(matched)
}

pub fn read_files_as_added(paths: &[PathBuf]) -> Result<Vec<AddedLine>, String> {
    let mut out = Vec::new();
    for path in paths {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let display = path.display().to_string();
        for (i, line) in text.lines().enumerate() {
            out.push(AddedLine {
                path: display.clone(),
                line_no: i + 1,
                text: line.to_string(),
                is_new_file: false,
            });
        }
    }
    Ok(out)
}

fn is_env_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.eq_ignore_ascii_case(".env.example")
        || name.eq_ignore_ascii_case(".env.sample")
        || name.eq_ignore_ascii_case(".env.template")
        || name.eq_ignore_ascii_case(".env.test")
    {
        return false;
    }
    name == ".env" || name.starts_with(".env.")
}

fn is_allow_comment(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("verify:allow")
        || lower.contains("verify-ignore")
        || lower.contains("verify:ignore")
}

fn looks_like_placeholder(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "your_",
        "changeme",
        "placeholder",
        "example",
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

pub fn fingerprint(rule_id: &str, secret: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in rule_id
        .bytes()
        .chain(std::iter::once(0))
        .chain(secret.trim().bytes())
    {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("vf_{h:016x}")
}

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut ent = 0.0;
    for c in counts {
        if c > 0 {
            let p = c as f64 / len;
            ent -= p * p.log2();
        }
    }
    ent
}

fn high_entropy_token(line: &str, min_len: usize, threshold: f64) -> Option<String> {
    let mut best: Option<(f64, String)> = None;
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
        let e = shannon_entropy(token);
        if e >= threshold {
            match &best {
                Some((prev, _)) if *prev >= e => {}
                _ => best = Some((e, token.to_string())),
            }
        }
    }
    best.map(|(_, t)| t)
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
    use crate::config::Config;

    fn scan_line(text: &str) -> Vec<Finding> {
        let engine = Engine::new(&Config::default()).unwrap();
        engine.scan_added_lines(&[AddedLine {
            path: "src/main.rs".into(),
            line_no: 1,
            text: text.into(),
            is_new_file: false,
        }])
    }

    #[test]
    fn catches_aws_key() {
        let f = scan_line(r#"const K: &str = "AKIAIOSFODNN7EXAMPLE";"#);
        assert!(f.iter().any(|x| x.rule_id == "aws-access-key"), "{f:?}");
    }

    #[test]
    fn catches_postgres() {
        let f = scan_line("url = postgres://admin:hunter2secret@prod-db.internal:5432/app");
        assert!(f.iter().any(|x| x.rule_id == "postgres-conn"), "{f:?}");
    }

    #[test]
    fn allow_comment_skips() {
        let f = scan_line(r#"password = "supersecret12" // verify:allow"#);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn entropy_of_random_is_high() {
        let e = shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        assert!(e > 4.0, "entropy={e}");
    }
}