use crate::config::{CustomRule, MAX_REGEX_SIZE};
use regex::RegexBuilder;
use std::collections::HashSet;

pub use crate::config::Severity;

/// Static description of a built-in detector. `builtin_specs()` is the single
/// source consumed by `compile_all` and `print_catalog`.
#[derive(Debug, Clone, Copy)]
pub struct RuleSpec {
    pub id: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub pattern: &'static str,
    pub keywords: &'static [&'static str],
    pub secret_group: Option<usize>,
    /// Every built-in can be replaced from verify.toml by reusing `id`.
    pub overridable: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub kind: Kind,
    pub overridable: bool,
}

#[derive(Debug, Clone)]
pub enum Kind {
    Regex {
        regex: regex::Regex,
        secret_group: Option<usize>,
        keywords: Vec<String>,
        path_matcher: Option<globset::GlobMatcher>,
        entropy: Option<f64>,
    },
}

pub fn builtin_specs() -> &'static [RuleSpec] {
    BUILTIN_SPECS
}

pub fn compile_all(custom: &[CustomRule]) -> Result<Vec<CompiledRule>, String> {
    let mut out: Vec<CompiledRule> = BUILTIN_SPECS
        .iter()
        .map(compile_spec)
        .collect::<Result<Vec<_>, _>>()?;

    let mut seen_custom = HashSet::new();
    for rule in custom {
        if !seen_custom.insert(rule.id.as_str()) {
            return Err(format!("duplicate custom rule id '{}'", rule.id));
        }
        let compiled = compiled_from_custom(rule);
        if let Some(idx) = out.iter().position(|r| r.id == rule.id) {
            out[idx] = compiled;
        } else {
            out.push(compiled);
        }
    }
    Ok(out)
}

fn compile_spec(spec: &RuleSpec) -> Result<CompiledRule, String> {
    Ok(CompiledRule {
        id: spec.id.to_string(),
        description: spec.description.to_string(),
        severity: spec.severity,
        overridable: spec.overridable,
        kind: Kind::Regex {
            regex: compile_regex(spec.pattern, spec.id)?,
            secret_group: spec.secret_group,
            keywords: spec.keywords.iter().map(|s| (*s).to_string()).collect(),
            path_matcher: None,
            entropy: None,
        },
    })
}

fn compiled_from_custom(rule: &CustomRule) -> CompiledRule {
    CompiledRule {
        id: rule.id.clone(),
        description: rule.description.clone(),
        severity: rule.severity,
        overridable: true,
        kind: Kind::Regex {
            regex: rule.regex.clone(),
            secret_group: rule.secret_group,
            keywords: rule.keywords.clone(),
            path_matcher: rule.path_matcher.clone(),
            entropy: rule.entropy,
        },
    }
}

fn compile_regex(pat: &str, id: &str) -> Result<regex::Regex, String> {
    RegexBuilder::new(pat)
        .size_limit(MAX_REGEX_SIZE)
        .dfa_size_limit(MAX_REGEX_SIZE)
        .build()
        .map_err(|e| format!("built-in rule '{id}' has invalid regex: {e}"))
}

/// Every match of `rule` on `line`. Path-scoped rules need `path`.
pub fn match_line(rule: &CompiledRule, line: &str, path: &str) -> Vec<String> {
    let Kind::Regex {
        regex,
        secret_group,
        keywords,
        path_matcher,
        entropy,
    } = &rule.kind;

    if !keywords.is_empty() && !keywords_hit(line, keywords) {
        return Vec::new();
    }
    if let Some(matcher) = path_matcher {
        let norm = crate::config::normalize_scan_path(path);
        if !matcher.is_match(norm.as_str()) {
            return Vec::new();
        }
    }

    let mut out = Vec::new();
    for caps in regex.captures_iter(line) {
        let token = if let Some(g) = *secret_group {
            caps.get(g).map(|m| m.as_str().to_string())
        } else {
            caps.get(0).map(|m| m.as_str().to_string())
        };
        let Some(token) = token else { continue };
        if let Some(min_ent) = *entropy {
            if shannon_entropy(&token) < min_ent {
                continue;
            }
        }
        if !out.iter().any(|t| t == &token) {
            out.push(token);
        }
    }
    out
}

fn keywords_hit(line: &str, keywords: &[String]) -> bool {
    let lower = line.to_ascii_lowercase();
    keywords.iter().any(|k| {
        if k.chars().any(|c| c.is_ascii_uppercase()) {
            line.contains(k)
        } else {
            lower.contains(&k.to_ascii_lowercase())
        }
    })
}

fn shannon_entropy(s: &str) -> f64 {
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

pub fn print_catalog() {
    println!("Built-in rules  (id in verify.toml [[rules]] replaces the built-in)");
    println!();
    for spec in builtin_specs() {
        let flag = if spec.overridable { "overridable" } else { "locked" };
        println!(
            "  {:<22} {:>8}  [{}]  {}",
            spec.id,
            spec.severity.as_str(),
            flag,
            spec.description
        );
    }
}

// ---------------------------------------------------------------------------
// Detector table. Add coverage here, not as new functions.
// secret_group extracts the credential, never "key=value" or the full URL.
// ---------------------------------------------------------------------------

const BUILTIN_SPECS: &[RuleSpec] = &[
    RuleSpec {
        id: "private-key",
        description: "PEM / OpenSSH private key header",
        severity: Severity::Critical,
        pattern: r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----",
        keywords: &["PRIVATE KEY"],
        secret_group: None,
        overridable: true,
    },
    RuleSpec {
        id: "aws-access-key",
        description: "AWS access key ID (AKIA / ASIA)",
        severity: Severity::Critical,
        pattern: r"(?i)\b((?:AKIA|ASIA)[A-Z0-9]{16})\b",
        keywords: &["AKIA", "ASIA"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "aws-secret-access-key",
        description: "AWS secret access key assignment",
        severity: Severity::Critical,
        pattern: r#"(?i)(?:^|[^A-Za-z0-9])aws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})"#,
        keywords: &["aws_secret_access_key"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "github-token",
        description: "GitHub PAT / App / fine-grained token",
        severity: Severity::Critical,
        pattern: r"\b((?:ghp|gho|ghu|ghs|ghr|ghn)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b",
        keywords: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "ghn_", "github_pat_"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "gitlab-token",
        description: "GitLab personal / deploy / runner / agent token",
        severity: Severity::Critical,
        pattern: r"\b((?:glpat|glptt|gldt|glrt|glagent)-[A-Za-z0-9_\-]{20,})\b",
        keywords: &["glpat-", "glptt-", "gldt-", "glrt-", "glagent-"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "slack-token",
        description: "Slack bot / user / app / export token",
        severity: Severity::Critical,
        pattern: r"\b(xox[bparsec]-[A-Za-z0-9\-]{10,80})\b",
        keywords: &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxe-", "xoxc-"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "stripe-key",
        description: "Stripe live secret / restricted key or webhook secret",
        severity: Severity::Critical,
        pattern: r"\b((?:sk_live_|rk_live_)[A-Za-z0-9]{20,}|(?:whsec_)[A-Za-z0-9]{16,})\b",
        keywords: &["sk_live_", "rk_live_", "whsec_"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "openai-key",
        description: "OpenAI API key (sk-proj / sk-svcacct / sk-)",
        severity: Severity::High,
        pattern: r"\b(sk-proj-[A-Za-z0-9_-]{20,}|sk-svcacct-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,})\b",
        keywords: &["sk-"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "google-api-key",
        description: "Google API key",
        severity: Severity::High,
        pattern: r"\b(AIza[A-Za-z0-9_-]{35})\b",
        keywords: &["AIza"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "jwt",
        description: "JSON Web Token",
        severity: Severity::High,
        pattern: r"\b(eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b",
        keywords: &["eyJ"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "postgres-conn",
        description: "PostgreSQL connection string with credentials",
        severity: Severity::Critical,
        pattern: r"(?i)postgres(?:ql)?://([^:\s]+:[^@\s]+)@",
        keywords: &["postgres"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "mysql-conn",
        description: "MySQL connection string with credentials",
        severity: Severity::Critical,
        pattern: r"(?i)mysql://([^:\s]+:[^@\s]+)@",
        keywords: &["mysql://"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "mongodb-conn",
        description: "MongoDB connection string with credentials",
        severity: Severity::Critical,
        pattern: r"(?i)mongodb(?:\+srv)?://([^:\s]+:[^@\s]+)@",
        keywords: &["mongodb"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "redis-conn",
        description: "Redis / TLS Redis connection string with credentials",
        severity: Severity::High,
        pattern: r"(?i)rediss?://([^:\s]+:[^@\s]+)@",
        keywords: &["redis://", "rediss://"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "generic-db-url",
        description: "DATABASE_URL / connection string assignment",
        severity: Severity::High,
        pattern: r#"(?i)(?:^|[^A-Za-z0-9])(?:database_url|db_url|connection_string|conn_str)\s*[=:]\s*['"]?([^'"\s]{8,})"#,
        keywords: &["database_url", "db_url", "connection_string", "conn_str"],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "generic-api-key",
        description: "Generic API key / secret / token assignment",
        severity: Severity::High,
        pattern: r#"(?i)(?:^|[^A-Za-z0-9])(?:api[_-]?key|api_secret|access_token|auth_token|secret_key|client_secret)\s*[=:]\s*['"]?([A-Za-z0-9/_\-+=.]{12,})"#,
        keywords: &[
            "api_key",
            "api-key",
            "apikey",
            "api_secret",
            "access_token",
            "auth_token",
            "secret_key",
            "client_secret",
        ],
        secret_group: Some(1),
        overridable: true,
    },
    RuleSpec {
        id: "password-assign",
        description: "Hard-coded password assignment",
        severity: Severity::High,
        pattern: r#"(?i)(?:^|[^A-Za-z0-9])(?:password|passwd|pwd|db_password|db_pass)\s*[=:]\s*['"]?([^\s'"]{8,})"#,
        keywords: &["password", "passwd", "pwd", "db_password", "db_pass"],
        secret_group: Some(1),
        overridable: true,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    fn compiled() -> Vec<CompiledRule> {
        compile_all(&[]).expect("builtins must compile")
    }

    fn rule<'a>(rules: &'a [CompiledRule], id: &str) -> &'a CompiledRule {
        rules
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("missing rule {id}"))
    }

    fn hits(id: &str, line: &str) -> Vec<String> {
        let rules = compiled();
        match_line(rule(&rules, id), line, "src/main.rs")
    }

    fn custom(id: &str, pattern: &str) -> CustomRule {
        CustomRule {
            id: id.into(),
            description: "override".into(),
            pattern: pattern.into(),
            regex: Regex::new(pattern).unwrap(),
            severity: Severity::Low,
            keywords: Vec::new(),
            path: None,
            path_matcher: None,
            entropy: None,
            secret_group: None,
        }
    }

    #[test]
    fn builtins_compile() {
        let rules = compiled();
        assert_eq!(rules.len(), BUILTIN_SPECS.len());
        assert!(rules.iter().all(|r| matches!(r.kind, Kind::Regex { .. })));
    }

    #[test]
    fn custom_replaces_builtin_with_same_id() {
        let rules = compile_all(&[custom("jwt", "OVERRIDE_JWT_TOKEN")]).unwrap();
        let jwt = rule(&rules, "jwt");
        assert_eq!(jwt.severity, Severity::Low);
        assert_eq!(
            rules.iter().filter(|r| r.id == "jwt").count(),
            1,
            "override must not leave two jwt rules"
        );
        assert!(match_line(jwt, "OVERRIDE_JWT_TOKEN", "").len() == 1);
        assert!(match_line(jwt, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbb", "").is_empty());
    }

    #[test]
    fn custom_new_id_is_appended() {
        let rules = compile_all(&[custom("acme-token", "acme_[A-Z]{8}")]).unwrap();
        assert!(rules.iter().any(|r| r.id == "acme-token"));
        assert!(rules.iter().any(|r| r.id == "jwt"));
    }

    #[test]
    fn duplicate_custom_ids_error() {
        let err = compile_all(&[custom("x", "a"), custom("x", "b")]).unwrap_err();
        assert!(err.contains("duplicate"), "{err}");
    }

    #[test]
    fn aws_akia_and_asia() {
        assert_eq!(
            hits("aws-access-key", r#"const K: &str = "AKIAIOSFODNN7EXAMPLE";"#),
            vec!["AKIAIOSFODNN7EXAMPLE"]
        );
        assert_eq!(
            hits("aws-access-key", "ASIAIOSFODNN7EXAMPLE"),
            vec!["ASIAIOSFODNN7EXAMPLE"]
        );
        assert!(hits("aws-access-key", "FOOAKIAIOSFODNN7EXAMPLE").is_empty());
    }

    #[test]
    fn aws_secret_extracts_value_only() {
        let h = hits(
            "aws-secret-access-key",
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        assert_eq!(h, vec!["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]);
        assert!(!h[0].contains("aws_secret"));
    }

    #[test]
    fn github_classic_and_fine_grained() {
        let classic = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(hits("github-token", classic), vec![classic]);
        let fine = format!("github_pat_{}", "a".repeat(40));
        assert_eq!(hits("github-token", &fine), vec![fine]);
        assert!(hits("github-token", "ghp_short").is_empty());
    }

    #[test]
    fn gitlab_runner_prefix() {
        let tok = format!("glrt-{}", "b".repeat(20));
        assert_eq!(hits("gitlab-token", &tok), vec![tok]);
    }

    #[test]
    fn slack_export_prefix() {
        let tok = "xoxe-1234567890-abcdef";
        assert_eq!(hits("slack-token", tok), vec![tok]);
    }

    #[test]
    fn stripe_live_and_restricted() {
        let sk = format!("sk_live_{}", "c".repeat(24));
        let rk = format!("rk_live_{}", "d".repeat(24));
        assert_eq!(hits("stripe-key", &sk), vec![sk.clone()]);
        assert_eq!(hits("stripe-key", &rk), vec![rk]);
        assert!(hits("openai-key", &sk).is_empty(), "stripe must not trip openai");
    }

    #[test]
    fn openai_project_and_not_stripe() {
        let proj = format!("sk-proj-{}", "e".repeat(24));
        assert_eq!(hits("openai-key", &proj), vec![proj]);
        assert!(hits("openai-key", "sk-short").is_empty());
        assert!(hits("openai-key", "sk-live_notopenai_zzzzzzzzzzzzzzzzzzzz").is_empty());
    }

    #[test]
    fn jwt_rejects_short_segments() {
        assert!(hits("jwt", "eyJhbGciOi.aaa.bbb").is_empty());
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbb";
        assert_eq!(hits("jwt", jwt), vec![jwt]);
    }

    #[test]
    fn pem_covers_ed25519_and_encrypted() {
        assert!(!hits("private-key", "-----BEGIN ED25519 PRIVATE KEY-----").is_empty());
        assert!(!hits("private-key", "-----BEGIN ENCRYPTED PRIVATE KEY-----").is_empty());
        assert!(!hits("private-key", "-----BEGIN RSA PRIVATE KEY-----").is_empty());
        assert!(hits("private-key", "-----BEGIN CERTIFICATE-----").is_empty());
    }

    #[test]
    fn postgres_extracts_userpass_not_url() {
        let h = hits(
            "postgres-conn",
            "url = postgres://admin:hunter2secret@prod-db.internal:5432/app",
        );
        assert_eq!(h, vec!["admin:hunter2secret"]);
        assert!(hits("postgres-conn", "postgres://admin@host/db").is_empty());
    }

    #[test]
    fn redis_tls_scheme() {
        let h = hits("redis-conn", "rediss://u:supersecret@cache:6380");
        assert_eq!(h, vec!["u:supersecret"]);
    }

    #[test]
    fn password_not_substring_and_extracts_value() {
        assert!(hits("password-assign", "password_hash_rounds = 12abcdef").is_empty());
        assert!(hits("password-assign", "passwordless = truevalue").is_empty());
        let h = hits("password-assign", r#"password = "supersecret12""#);
        assert_eq!(h, vec!["supersecret12"]);
    }

    #[test]
    fn generic_api_key_drops_private_key_and_extracts_value() {
        assert!(hits("generic-api-key", r#"private_key = "cert/path/key.pem""#).is_empty());
        let h = hits("generic-api-key", r#"api_key = "sk_test_abcdefghijk""#);
        assert_eq!(h, vec!["sk_test_abcdefghijk"]);
    }

    #[test]
    fn two_tokens_on_one_line() {
        let line = r#"AKIAIOSFODNN7EXAMPLE ghp_abcdefghijklmnopqrstuvwxyz0123456789"#;
        let rules = compiled();
        let aws = match_line(rule(&rules, "aws-access-key"), line, "");
        let gh = match_line(rule(&rules, "github-token"), line, "");
        assert_eq!(aws, vec!["AKIAIOSFODNN7EXAMPLE"]);
        assert_eq!(gh, vec!["ghp_abcdefghijklmnopqrstuvwxyz0123456789"]);
        let doubled = format!(
            "AKIAIOSFODNN7EXAMPLE AKIA{}{}",
            "J", "OSFODNN7EXAMPLE"
        );
        let two = match_line(rule(&rules, "aws-access-key"), &doubled, "");
        assert_eq!(two.len(), 2, "{two:?}");
    }

    #[test]
    fn catalog_marks_overridable() {
        assert!(BUILTIN_SPECS.iter().all(|s| s.overridable));
        assert!(BUILTIN_SPECS.iter().any(|s| s.id == "jwt"));
    }
}