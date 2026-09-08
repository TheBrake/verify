use crate::config::CustomRule;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            _ => Self::Low,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

pub struct CompiledRule {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub kind: Kind,
}

pub enum Kind {
    Builtin(fn(&str) -> Option<String>),
    Wildcard { ignore_case: bool, pat: String },
}

pub fn compile_all(custom: &[CustomRule]) -> Result<Vec<CompiledRule>, String> {
    let mut out = builtin();
    for rule in custom {
        let (ignore_case, pat) = if let Some(rest) = rule.pattern.strip_prefix("(?i)") {
            (true, rest.to_string())
        } else {
            (false, rule.pattern.clone())
        };
        out.push(CompiledRule {
            id: rule.id.clone(),
            description: rule.description.clone(),
            severity: Severity::parse(&rule.severity),
            kind: Kind::Wildcard { ignore_case, pat },
        });
    }
    Ok(out)
}

fn builtin() -> Vec<CompiledRule> {
    vec![
        b("private-key", "PEM private key material", Severity::Critical, find_private_key),
        b("aws-access-key", "AWS access key ID", Severity::Critical, find_aws_access_key),
        b("github-token", "GitHub token", Severity::Critical, find_github_token),
        b("gitlab-token", "GitLab token", Severity::Critical, find_gitlab_token),
        b("slack-token", "Slack token", Severity::Critical, find_slack_token),
        b("stripe-key", "Stripe live secret key", Severity::Critical, find_stripe_key),
        b("openai-key", "OpenAI API key", Severity::High, find_openai_key),
        b("google-api-key", "Google API key", Severity::High, find_google_api_key),
        b("jwt", "JSON Web Token", Severity::High, find_jwt),
        b("postgres-conn", "PostgreSQL connection string with credentials", Severity::Critical, find_postgres),
        b("mysql-conn", "MySQL connection string with credentials", Severity::Critical, find_mysql),
        b("mongodb-conn", "MongoDB connection string with credentials", Severity::Critical, find_mongo),
        b("redis-conn", "Redis connection string with credentials", Severity::High, find_redis),
        b("generic-db-url", "DATABASE_URL / connection string assignment", Severity::High, find_db_url_assign),
        b("generic-api-key", "Generic API key / secret / token assignment", Severity::High, find_api_assign),
        b("password-assign", "Hard-coded password assignment", Severity::High, find_password_assign),
    ]
}

fn b(
    id: &'static str,
    description: &'static str,
    severity: Severity,
    f: fn(&str) -> Option<String>,
) -> CompiledRule {
    CompiledRule {
        id: id.into(),
        description: description.into(),
        severity,
        kind: Kind::Builtin(f),
    }
}

pub fn print_catalog() {
    println!("Built-in rules");
    println!();
    for rule in builtin() {
        println!(
            "  {:<18} {:>8}  {}",
            rule.id,
            rule.severity.as_str(),
            rule.description
        );
    }
}

fn find_private_key(line: &str) -> Option<String> {
    const MARKERS: &[&str] = &[
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
    ];
    MARKERS
        .iter()
        .find(|m| line.contains(*m))
        .map(|m| (*m).to_string())
}

fn find_aws_access_key(line: &str) -> Option<String> {
    find_prefixed_alnum(line, "AKIA", 16, 16, true)
}

fn find_github_token(line: &str) -> Option<String> {
    for p in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"] {
        if let Some(s) = find_prefixed_alnum(line, p, 20, 255, false) {
            return Some(s);
        }
    }
    None
}

fn find_gitlab_token(line: &str) -> Option<String> {
    for p in ["glpat-", "glptt-", "gldt-"] {
        if let Some(s) = find_prefixed_alnum(line, p, 20, 255, false) {
            return Some(s);
        }
    }
    None
}

fn find_slack_token(line: &str) -> Option<String> {
    for p in ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"] {
        if let Some(s) = find_prefixed_charset(line, p, 10, 80, is_slack) {
            return Some(s);
        }
    }
    None
}

fn find_stripe_key(line: &str) -> Option<String> {
    find_prefixed_alnum(line, "sk_live_", 20, 255, false)
}

fn find_openai_key(line: &str) -> Option<String> {
    let mut start = 0;
    while let Some(rel) = line[start..].find("sk-") {
        let i = start + rel;
        if let Some(s) = take_alnum_from(line, i, 3, 20, 255, false) {
            if !s.starts_with("sk-live") {
                return Some(s);
            }
        }
        start = i + 3;
    }
    None
}

fn find_google_api_key(line: &str) -> Option<String> {
    find_prefixed_charset(line, "AIza", 35, 35, is_urlsafe)
}

fn find_jwt(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b'e' && bytes[i + 1] == b'y' && bytes[i + 2] == b'J' {
            if let Some(tok) = take_jwt(line, i) {
                return Some(tok);
            }
        }
        i += 1;
    }
    None
}

fn take_jwt(line: &str, start: usize) -> Option<String> {
    let rest = &line[start..];
    let mut parts = rest.split('.');
    let h = parts.next()?;
    let p = parts.next()?;
    let s = parts.next()?;
    if h.len() >= 10 && p.len() >= 10 && s.len() >= 10 && is_jwt_part(h) && is_jwt_part(p) {
        let sig_end = s.find(|c: char| !is_jwt_char(c)).unwrap_or(s.len());
        if sig_end >= 10 {
            return Some(format!("{}.{}.{}", h, p, &s[..sig_end]));
        }
    }
    None
}

fn find_postgres(line: &str) -> Option<String> {
    find_url_with_userpass(line, &["postgres://", "postgresql://"])
}

fn find_mysql(line: &str) -> Option<String> {
    find_url_with_userpass(line, &["mysql://"])
}

fn find_mongo(line: &str) -> Option<String> {
    find_url_with_userpass(line, &["mongodb://", "mongodb+srv://"])
}

fn find_redis(line: &str) -> Option<String> {
    find_url_with_userpass(line, &["redis://"])
}

fn find_url_with_userpass(line: &str, schemes: &[&str]) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    for scheme in schemes {
        if let Some(idx) = lower.find(scheme) {
            let slice = &line[idx..];
            if let Some(at) = slice.find('@') {
                let creds = &slice[scheme.len()..at];
                if creds.contains(':') && creds.len() >= 3 {
                    let end = slice[at + 1..]
                        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                        .map(|n| at + 1 + n)
                        .unwrap_or(slice.len());
                    return Some(slice[..end].to_string());
                }
            }
        }
    }
    None
}

fn find_db_url_assign(line: &str) -> Option<String> {
    assign_after(line, &["database_url", "db_url", "connection_string", "conn_str"])
}

fn find_api_assign(line: &str) -> Option<String> {
    assign_after(
        line,
        &[
            "api_key",
            "api-key",
            "apikey",
            "api_secret",
            "access_token",
            "auth_token",
            "secret_key",
            "private_key",
            "client_secret",
        ],
    )
}

fn find_password_assign(line: &str) -> Option<String> {
    assign_after(line, &["password", "passwd", "pwd", "db_password", "db_pass"])
}

fn assign_after(line: &str, keys: &[&str]) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    for key in keys {
        let mut search_from = 0;
        while let Some(rel) = lower[search_from..].find(key) {
            let i = search_from + rel;
            let after_key = i + key.len();
            let rest = line[after_key..].trim_start();
            if let Some(eq) = rest.find('=').or_else(|| rest.find(':')) {
                if eq <= 8 {
                    let val = rest[eq + 1..].trim_start();
                    let val = val.trim_start_matches(|c: char| c == '"' || c == '\'');
                    let take: String = val
                        .chars()
                        .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
                        .collect();
                    if take.len() >= 8 {
                        return Some(format!("{key}={take}"));
                    }
                }
            }
            search_from = after_key;
        }
    }
    None
}

fn find_prefixed_alnum(
    line: &str,
    prefix: &str,
    min: usize,
    max: usize,
    upper_body: bool,
) -> Option<String> {
    find_prefixed_charset(line, prefix, min, max, |c| {
        if upper_body {
            c.is_ascii_uppercase() || c.is_ascii_digit()
        } else {
            c.is_ascii_alphanumeric() || c == '_' || c == '-'
        }
    })
}

fn find_prefixed_charset(
    line: &str,
    prefix: &str,
    min: usize,
    max: usize,
    ok: impl Fn(char) -> bool,
) -> Option<String> {
    let mut start = 0;
    while let Some(rel) = line[start..].find(prefix) {
        let i = start + rel;
        if let Some(s) = take_from(line, i, prefix.len(), min, max, &ok) {
            return Some(s);
        }
        start = i + prefix.len();
    }
    None
}

fn take_alnum_from(
    line: &str,
    start: usize,
    prefix_len: usize,
    min: usize,
    max: usize,
    upper_body: bool,
) -> Option<String> {
    take_from(line, start, prefix_len, min, max, |c| {
        if upper_body {
            c.is_ascii_uppercase() || c.is_ascii_digit()
        } else {
            c.is_ascii_alphanumeric() || c == '_' || c == '-'
        }
    })
}

fn take_from(
    line: &str,
    start: usize,
    prefix_len: usize,
    min: usize,
    max: usize,
    ok: impl Fn(char) -> bool,
) -> Option<String> {
    let body = &line[start + prefix_len..];
    let n = body.chars().take_while(|c| ok(*c)).count();
    if n >= min && n <= max {
        let body_bytes = body.chars().take(n).collect::<String>();
        Some(format!("{}{}", &line[start..start + prefix_len], body_bytes))
    } else {
        None
    }
}

fn is_slack(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

fn is_urlsafe(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

fn is_jwt_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

fn is_jwt_part(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_jwt_char)
}

pub fn wildcard_find(hay: &str, pat: &str, ignore_case: bool) -> Option<String> {
    if ignore_case {
        let h = hay.to_ascii_lowercase();
        let p = pat.to_ascii_lowercase();
        if wildcard_is_match(&h, &p) {
            return Some(hay.trim().to_string());
        }
        None
    } else if wildcard_is_match(hay, pat) {
        Some(hay.trim().to_string())
    } else {
        None
    }
}

fn wildcard_is_match(hay: &str, pat: &str) -> bool {
    wildcard_rec(hay.as_bytes(), pat.as_bytes())
}

fn wildcard_rec(hay: &[u8], pat: &[u8]) -> bool {
    if pat.is_empty() {
        return hay.is_empty();
    }
    if pat[0] == b'*' {
        let mut i = 0;
        while i < pat.len() && pat[i] == b'*' {
            i += 1;
        }
        if i == pat.len() {
            return true;
        }
        for skip in 0..=hay.len() {
            if wildcard_rec(&hay[skip..], &pat[i..]) {
                return true;
            }
        }
        false
    } else if !hay.is_empty() && (pat[0] == b'?' || pat[0] == hay[0]) {
        wildcard_rec(&hay[1..], &pat[1..])
    } else {
        false
    }
}
