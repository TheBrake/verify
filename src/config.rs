use std::path::Path;

#[derive(Debug, Clone)]
pub struct Config {
    pub fail_on: FailOn,
    pub redact: bool,
    pub max_file_bytes: usize,
    pub entropy_enabled: bool,
    pub entropy_min_length: usize,
    pub entropy_threshold: f64,
    pub exclude: Vec<String>,
    pub block_env_files: bool,
    pub custom_rules: Vec<CustomRule>,
    pub allow: Vec<Allow>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            fail_on: FailOn::Any,
            redact: true,
            max_file_bytes: 1_048_576,
            entropy_enabled: true,
            entropy_min_length: 24,
            entropy_threshold: 4.5,
            exclude: default_excludes(),
            block_env_files: true,
            custom_rules: Vec::new(),
            allow: Vec::new(),
        }
    }
}

fn default_excludes() -> Vec<String> {
    vec![
        "**/.git/**".into(),
        "**/node_modules/**".into(),
        "**/target/**".into(),
        "**/vendor/**".into(),
        "**/dist/**".into(),
        "**/*.lock".into(),
        "**/*.min.js".into(),
        "**/*.map".into(),
        "**/package-lock.json".into(),
        "**/pnpm-lock.yaml".into(),
        "**/Cargo.lock".into(),
        "**/*.md".into(),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOn {
    Any,
    High,
}

#[derive(Debug, Clone)]
pub struct CustomRule {
    pub id: String,
    pub description: String,
    pub pattern: String,
    pub severity: String,
}

#[derive(Debug, Clone, Default)]
pub struct Allow {
    pub rule: Option<String>,
    pub path: Option<String>,
    pub fingerprint: Option<String>,
    pub contains: Option<String>,
}

pub fn load(explicit: Option<&Path>, repo: &Path) -> Result<Config, String> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => repo.join("verify.toml"),
    };
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    parse_toml(&text)
}

/// Tiny TOML subset reader for verify.toml. Not a general parser.
pub fn parse_toml(text: &str) -> Result<Config, String> {
    let mut cfg = Config::default();
    let mut section = String::new();
    let mut current_rule: Option<CustomRule> = None;
    let mut current_allow: Option<Allow> = None;

    let flush_rule = |cfg: &mut Config, rule: &mut Option<CustomRule>| {
        if let Some(r) = rule.take() {
            if !r.id.is_empty() && !r.pattern.is_empty() {
                cfg.custom_rules.push(r);
            }
        }
    };
    let flush_allow = |cfg: &mut Config, allow: &mut Option<Allow>| {
        if let Some(a) = allow.take() {
            if a.rule.is_some() || a.path.is_some() || a.fingerprint.is_some() || a.contains.is_some()
            {
                cfg.allow.push(a);
            }
        }
    };

    for raw in text.lines() {
        let stripped = strip_comment(raw);
        let line = stripped.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            flush_rule(&mut cfg, &mut current_rule);
            flush_allow(&mut cfg, &mut current_allow);
            section = line[1..line.len() - 1].trim().to_string();
            if section == "rules" || section == "[rules]" || line.starts_with("[[rules]]") {
                current_rule = Some(CustomRule {
                    id: String::new(),
                    description: String::new(),
                    pattern: String::new(),
                    severity: "critical".into(),
                });
                section = "rules".into();
            } else if section == "allow" || line.starts_with("[[allow]]") {
                current_allow = Some(Allow::default());
                section = "allow".into();
            }
            continue;
        }
        if line == "[[rules]]" {
            flush_rule(&mut cfg, &mut current_rule);
            current_rule = Some(CustomRule {
                id: String::new(),
                description: String::new(),
                pattern: String::new(),
                severity: "critical".into(),
            });
            section = "rules".into();
            continue;
        }
        if line == "[[allow]]" {
            flush_allow(&mut cfg, &mut current_allow);
            current_allow = Some(Allow::default());
            section = "allow".into();
            continue;
        }

        let (key, val) = match split_kv(line) {
            Some(kv) => kv,
            None => continue,
        };

        match (section.as_str(), key.as_str()) {
            ("verify", "fail_on") => {
                cfg.fail_on = if val == "high" {
                    FailOn::High
                } else {
                    FailOn::Any
                };
            }
            ("verify", "redact") => cfg.redact = parse_bool(&val),
            ("verify", "max_file_bytes") => {
                if let Ok(n) = val.parse() {
                    cfg.max_file_bytes = n;
                }
            }
            ("verify", "entropy_enabled") => cfg.entropy_enabled = parse_bool(&val),
            ("verify", "entropy_min_length") => {
                if let Ok(n) = val.parse() {
                    cfg.entropy_min_length = n;
                }
            }
            ("verify", "entropy_threshold") => {
                if let Ok(n) = val.parse() {
                    cfg.entropy_threshold = n;
                }
            }
            ("verify", "block_env_files") => cfg.block_env_files = parse_bool(&val),
            ("paths", "exclude") => {
                // multiline arrays handled loosely: collect quoted strings on this line
                cfg.exclude.extend(parse_string_list(&val));
            }
            ("rules", "id") => {
                if let Some(r) = current_rule.as_mut() {
                    r.id = val;
                }
            }
            ("rules", "description") => {
                if let Some(r) = current_rule.as_mut() {
                    r.description = val;
                }
            }
            ("rules", "pattern") => {
                if let Some(r) = current_rule.as_mut() {
                    r.pattern = val;
                }
            }
            ("rules", "severity") => {
                if let Some(r) = current_rule.as_mut() {
                    r.severity = val;
                }
            }
            ("allow", "rule") => {
                if let Some(a) = current_allow.as_mut() {
                    a.rule = Some(val);
                }
            }
            ("allow", "path") => {
                if let Some(a) = current_allow.as_mut() {
                    a.path = Some(val);
                }
            }
            ("allow", "fingerprint") => {
                if let Some(a) = current_allow.as_mut() {
                    a.fingerprint = Some(val);
                }
            }
            ("allow", "contains") => {
                if let Some(a) = current_allow.as_mut() {
                    a.contains = Some(val);
                }
            }
            _ => {}
        }
    }
    flush_rule(&mut cfg, &mut current_rule);
    flush_allow(&mut cfg, &mut current_allow);
    Ok(cfg)
}

fn strip_comment(line: &str) -> String {
    let mut out = String::new();
    let mut in_str = false;
    let mut prev = '\0';
    for c in line.chars() {
        if c == '"' && prev != '\\' {
            in_str = !in_str;
        }
        if c == '#' && !in_str {
            break;
        }
        out.push(c);
        prev = c;
    }
    out
}

fn split_kv(line: &str) -> Option<(String, String)> {
    let eq = line.find('=')?;
    let key = line[..eq].trim().to_string();
    let mut val = line[eq + 1..].trim().to_string();
    if val.starts_with('[') {
        return Some((key, val));
    }
    if let Some(s) = unquote(&val) {
        val = s;
    }
    Some((key, val))
}

fn unquote(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        return Some(unescape(&s[1..s.len() - 1]));
    }
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        return Some(s[1..s.len() - 1].to_string());
    }
    None
}

fn unescape(s: &str) -> String {
    s.replace("\\\\", "\\").replace("\\\"", "\"")
}

fn parse_bool(s: &str) -> bool {
    matches!(s, "true" | "True" | "1" | "yes")
}

fn parse_string_list(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    let mut quote = '\0';
    for c in s.chars() {
        if !in_str && (c == '"' || c == '\'') {
            in_str = true;
            quote = c;
            cur.clear();
            continue;
        }
        if in_str && c == quote {
            in_str = false;
            out.push(cur.clone());
            cur.clear();
            continue;
        }
        if in_str {
            cur.push(c);
        }
    }
    out
}

/// Very small globber: supports `*`, `**`, and exact suffix/prefix.
pub fn glob_match(pat: &str, path: &str) -> bool {
    let path = path.replace('\\', "/");
    glob_rec(pat, &path)
}

fn glob_rec(pat: &str, path: &str) -> bool {
    if pat == "**" {
        return true;
    }
    if let Some(rest) = pat.strip_prefix("**/") {
        if glob_rec(rest, path) {
            return true;
        }
        if let Some(slash) = path.find('/') {
            return glob_rec(pat, &path[slash + 1..]);
        }
        return glob_rec(rest, path);
    }
    if let Some(rest) = pat.strip_suffix("/**") {
        return path == rest || path.starts_with(&format!("{rest}/"));
    }
    // split on first *
    if let Some(star) = pat.find('*') {
        if pat[star..].starts_with("**") {
            let prefix = &pat[..star];
            let suffix = &pat[star + 2..];
            let suffix = suffix.strip_prefix('/').unwrap_or(suffix);
            if !path.starts_with(prefix) {
                return false;
            }
            let rest = &path[prefix.len()..];
            if suffix.is_empty() {
                return true;
            }
            if glob_rec(suffix, rest) {
                return true;
            }
            if let Some(slash) = rest.find('/') {
                return glob_match(&format!("**/{suffix}"), &rest[slash + 1..]);
            }
            return glob_rec(suffix, rest);
        }
        let prefix = &pat[..star];
        let suffix = &pat[star + 1..];
        if !path.starts_with(prefix) {
            return false;
        }
        let rest = &path[prefix.len()..];
        // `*` does not cross `/`
        if suffix.is_empty() {
            return !rest.contains('/');
        }
        if let Some(suf_star) = suffix.find('*') {
            let mid = &suffix[..suf_star];
            if let Some(idx) = rest.find(mid) {
                if rest[..idx].contains('/') {
                    return false;
                }
                return glob_rec(&suffix[suf_star..], &rest[idx + mid.len()..]);
            }
            return false;
        }
        if let Some(idx) = rest.rfind(suffix) {
            return !rest[..idx].contains('/') && rest[idx..] == *suffix;
        }
        return false;
    }
    pat == path
}

pub const STARTER_TOML: &str = r#"# Verify — local pre-push secret auditor

[verify]
# "any" blocks every finding. "high" only blocks critical/high severity.
fail_on = "any"
redact = true
max_file_bytes = 1048576
entropy_enabled = true
entropy_min_length = 24
entropy_threshold = 4.5
block_env_files = true

[paths]
exclude = ["**/tests/fixtures/**", "**/*.md"]

# [[rules]]
# id = "prod-postgres"
# description = "No production PostgreSQL connection strings"
# pattern = '(?i)postgres(?:ql)?://[^\s]+:[^\s]+@[^\s]*(?:prod|production)'
# severity = "critical"

# [[allow]]
# rule = "generic-api-key"
# path = "testdata/sample.env"
# contains = "EXAMPLE_NOT_A_REAL_KEY"
"#;
