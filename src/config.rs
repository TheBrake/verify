use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use regex::RegexBuilder;
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// Hard cap so a pathological verify.toml cannot stall the hook at load time.
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
/// Cap compiled regex programs (bytes) so a single pattern cannot explode memory.
pub const MAX_REGEX_SIZE: usize = 1024 * 1024;

const ENTROPY_MIN: f64 = 0.0;
const ENTROPY_MAX: f64 = 8.0;

#[derive(Debug, Clone)]
pub struct Config {
    pub fail_on: FailOn,
    pub redact: bool,
    pub max_file_bytes: usize,
    pub entropy_enabled: bool,
    pub entropy_min_length: usize,
    pub entropy_threshold: f64,
    /// Effective exclude patterns after default merge / replace.
    pub exclude: Vec<String>,
    /// Compiled once. The engine must use this, not a recursive globber.
    pub exclude_set: GlobSet,
    pub replace_excludes: bool,
    pub block_env_files: bool,
    pub custom_rules: Vec<CustomRule>,
    pub allow: Vec<Allow>,
    pub source: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        compile_raw(RawFile::default(), Path::new("<default>"), None)
            .expect("built-in default config must compile")
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailOn {
    Any,
    High,
}

impl Default for FailOn {
    fn default() -> Self {
        Self::Any
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Severity {
    fn default() -> Self {
        Self::Critical
    }
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllowCondition {
    And,
    Or,
}

impl Default for AllowCondition {
    fn default() -> Self {
        // Preserve previous allow semantics: every set field must match.
        Self::And
    }
}

#[derive(Debug, Clone)]
pub struct CustomRule {
    pub id: String,
    pub description: String,
    pub pattern: String,
    pub regex: regex::Regex,
    pub severity: Severity,
    pub keywords: Vec<String>,
    pub path: Option<String>,
    pub path_matcher: Option<globset::GlobMatcher>,
    pub entropy: Option<f64>,
    pub secret_group: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct Allow {
    pub rule: Option<String>,
    pub paths: Vec<String>,
    pub path_set: GlobSet,
    pub contains: Vec<String>,
    pub regexes: Vec<regex::Regex>,
    pub fingerprint: Option<String>,
    pub condition: AllowCondition,
}

impl Allow {
    pub fn is_empty(&self) -> bool {
        self.rule.is_none()
            && self.paths.is_empty()
            && self.contains.is_empty()
            && self.regexes.is_empty()
            && self.fingerprint.is_none()
    }

    /// Evaluate this allow entry against a finding.
    ///
    /// `And` (default): every constraint that was declared must match.
    /// `Or`: any declared constraint is enough.
    pub fn matches(
        &self,
        rule_id: &str,
        path: &str,
        snippet: &str,
        line: &str,
        fingerprint: &str,
    ) -> bool {
        if self.is_empty() {
            return false;
        }
        let path = normalize_scan_path(path);
        let mut checks: Vec<bool> = Vec::new();
        if let Some(rule) = &self.rule {
            checks.push(rule == rule_id);
        }
        if !self.paths.is_empty() {
            checks.push(self.path_set.is_match(path.as_str()) || self.paths.iter().any(|p| p == &path));
        }
        if let Some(fp) = &self.fingerprint {
            checks.push(fp == fingerprint);
        }
        if !self.contains.is_empty() {
            checks.push(
                self.contains
                    .iter()
                    .any(|c| line.contains(c) || snippet.contains(c)),
            );
        }
        if !self.regexes.is_empty() {
            checks.push(
                self.regexes
                    .iter()
                    .any(|re| re.is_match(line) || re.is_match(snippet)),
            );
        }
        match self.condition {
            AllowCondition::And => checks.iter().all(|ok| *ok),
            AllowCondition::Or => checks.iter().any(|ok| *ok),
        }
    }
}

impl Config {
    pub fn is_excluded(&self, path: &str) -> bool {
        self.exclude_set.is_match(normalize_scan_path(path).as_str())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        message: String,
        line: Option<usize>,
        column: Option<usize>,
        field: Option<String>,
    },
    Validation {
        path: PathBuf,
        field: String,
        message: String,
    },
    Limit {
        path: PathBuf,
        message: String,
    },
    OutsideRepo {
        path: PathBuf,
        repo: PathBuf,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read {}: {source}", path.display())
            }
            Self::Parse {
                path,
                message,
                line,
                column,
                field,
            } => {
                write!(f, "failed to parse {}", path.display())?;
                if let Some(l) = line {
                    write!(f, ":{l}")?;
                    if let Some(c) = column {
                        write!(f, ":{c}")?;
                    }
                }
                if let Some(field) = field {
                    write!(f, " ({field})")?;
                }
                write!(f, ": {message}")
            }
            Self::Validation { path, field, message } => {
                write!(f, "{}: invalid {field}: {message}", path.display())
            }
            Self::Limit { path, message } => {
                write!(f, "{}: {message}", path.display())
            }
            Self::OutsideRepo { path, repo } => write!(
                f,
                "refusing to load {} (outside repo {}) — pass --config to use a file outside the repository",
                path.display(),
                repo.display()
            ),
        }
    }
}

impl From<ConfigError> for String {
    fn from(err: ConfigError) -> Self {
        err.to_string()
    }
}

// ---------------------------------------------------------------------------
// Raw TOML shape (serde). Unknown keys are rejected.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    verify: RawVerify,
    #[serde(default)]
    paths: RawPaths,
    #[serde(default)]
    rules: Vec<RawRule>,
    #[serde(default)]
    allow: Vec<RawAllow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVerify {
    #[serde(default)]
    fail_on: FailOn,
    #[serde(default = "default_true")]
    redact: bool,
    #[serde(default = "default_max_file_bytes")]
    max_file_bytes: usize,
    #[serde(default = "default_true")]
    entropy_enabled: bool,
    #[serde(default = "default_entropy_min_length")]
    entropy_min_length: usize,
    #[serde(default = "default_entropy_threshold")]
    entropy_threshold: f64,
    #[serde(default = "default_true")]
    block_env_files: bool,
}

impl Default for RawVerify {
    fn default() -> Self {
        Self {
            fail_on: FailOn::Any,
            redact: true,
            max_file_bytes: default_max_file_bytes(),
            entropy_enabled: true,
            entropy_min_length: default_entropy_min_length(),
            entropy_threshold: default_entropy_threshold(),
            block_env_files: true,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPaths {
    #[serde(default)]
    exclude: Vec<String>,
    /// When true, `exclude` replaces `default_excludes()` instead of extending it.
    #[serde(default)]
    replace_excludes: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    #[serde(default)]
    description: String,
    pattern: String,
    #[serde(default)]
    severity: Severity,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    entropy: Option<f64>,
    #[serde(default)]
    secret_group: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAllow {
    #[serde(default)]
    rule: Option<String>,
    /// Single-path form kept so existing starter snippets still parse.
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    contains: StringOrList,
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    condition: AllowCondition,
}

#[derive(Debug, Default)]
struct StringOrList(Vec<String>);

impl<'de> Deserialize<'de> for StringOrList {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Helper {
            One(String),
            Many(Vec<String>),
        }
        match Helper::deserialize(deserializer)? {
            Helper::One(s) => Ok(Self(vec![s])),
            Helper::Many(v) => Ok(Self(v)),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_max_file_bytes() -> usize {
    1_048_576
}
fn default_entropy_min_length() -> usize {
    24
}
fn default_entropy_threshold() -> f64 {
    4.5
}

// ---------------------------------------------------------------------------
// Load / parse
// ---------------------------------------------------------------------------

pub fn load(explicit: Option<&Path>, repo: &Path) -> Result<Config, ConfigError> {
    let chosen = match explicit {
        Some(p) => {
            if !p.exists() {
                return Err(ConfigError::Io {
                    path: p.to_path_buf(),
                    source: io::Error::new(io::ErrorKind::NotFound, "config file does not exist"),
                });
            }
            Some(p.to_path_buf())
        }
        None => discover_repo_config(repo)?,
    };

    let Some(path) = chosen else {
        return Ok(Config::default());
    };

    let meta = std::fs::metadata(&path).map_err(|source| ConfigError::Io {
        path: path.clone(),
        source,
    })?;
    if meta.len() > MAX_CONFIG_BYTES as u64 {
        return Err(ConfigError::Limit {
            path,
            message: format!(
                "config file is {} bytes; limit is {MAX_CONFIG_BYTES} bytes",
                meta.len()
            ),
        });
    }

    let text = std::fs::read_to_string(&path).map_err(|source| ConfigError::Io {
        path: path.clone(),
        source,
    })?;
    compile_raw(parse_raw(&text, &path)?, &path, Some(path.clone()))
}

fn discover_repo_config(repo: &Path) -> Result<Option<PathBuf>, ConfigError> {
    let candidates = [repo.join("verify.toml"), repo.join(".verify.toml")];
    for path in candidates {
        if !path.exists() {
            continue;
        }
        ensure_inside_repo(&path, repo)?;
        return Ok(Some(path));
    }
    Ok(None)
}

fn ensure_inside_repo(path: &Path, repo: &Path) -> Result<(), ConfigError> {
    let repo_canon = std::fs::canonicalize(repo).unwrap_or_else(|_| repo.to_path_buf());
    let path_canon = std::fs::canonicalize(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !path_canon.starts_with(&repo_canon) {
        return Err(ConfigError::OutsideRepo {
            path: path_canon,
            repo: repo_canon,
        });
    }
    Ok(())
}

/// Public wrapper kept for tests and `verify init` consumers.
/// The real reader is `toml::from_str` — this is not a hand-rolled parser.
pub fn parse_toml(text: &str) -> Result<Config, ConfigError> {
    let path = Path::new("<memory>");
    compile_raw(parse_raw(text, path)?, path, None)
}

fn parse_raw(text: &str, path: &Path) -> Result<RawFile, ConfigError> {
    toml::from_str::<RawFile>(text).map_err(|err| map_toml_error(path, text, err))
}

fn map_toml_error(path: &Path, input: &str, err: toml::de::Error) -> ConfigError {
    let message = err.message().to_string();
    let field = extract_field_hint(&message);
    let (line, column) = match err.span() {
        Some(span) => offset_to_line_col(input, span.start)
            .map(|(l, c)| (Some(l), Some(c)))
            .unwrap_or((None, None)),
        None => (None, None),
    };
    ConfigError::Parse {
        path: path.to_path_buf(),
        message,
        line,
        column,
        field,
    }
}

fn extract_field_hint(message: &str) -> Option<String> {
    for prefix in ["unknown field `", "missing field `"] {
        if let Some(rest) = message.strip_prefix(prefix) {
            if let Some(end) = rest.find('`') {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

fn offset_to_line_col(input: &str, offset: usize) -> Option<(usize, usize)> {
    let offset = offset.min(input.len());
    let mut line = 1usize;
    let mut col = 1usize;
    for (i, ch) in input.char_indices() {
        if i >= offset {
            return Some((line, col));
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    Some((line, col))
}

fn compile_raw(raw: RawFile, path: &Path, source: Option<PathBuf>) -> Result<Config, ConfigError> {
    let v = &raw.verify;

    if v.max_file_bytes == 0 {
        return Err(ConfigError::Validation {
            path: path.to_path_buf(),
            field: "verify.max_file_bytes".into(),
            message: "must be > 0".into(),
        });
    }
    if !(ENTROPY_MIN..=ENTROPY_MAX).contains(&v.entropy_threshold) {
        return Err(ConfigError::Validation {
            path: path.to_path_buf(),
            field: "verify.entropy_threshold".into(),
            message: format!("must be between {ENTROPY_MIN} and {ENTROPY_MAX}"),
        });
    }

    let replace_excludes = raw.paths.replace_excludes;
    let exclude = if replace_excludes {
        raw.paths.exclude.clone()
    } else {
        let mut all = default_excludes();
        all.extend(raw.paths.exclude.iter().cloned());
        all
    };
    let exclude_set = compile_globs(&exclude, path, "paths.exclude")?;

    let mut seen_ids = HashSet::new();
    let mut custom_rules = Vec::with_capacity(raw.rules.len());
    for (i, rule) in raw.rules.into_iter().enumerate() {
        let field = format!("rules[{i}]");
        if rule.id.trim().is_empty() {
            return Err(ConfigError::Validation {
                path: path.to_path_buf(),
                field: format!("{field}.id"),
                message: "must be non-empty".into(),
            });
        }
        if !seen_ids.insert(rule.id.clone()) {
            return Err(ConfigError::Validation {
                path: path.to_path_buf(),
                field: format!("{field}.id"),
                message: format!("duplicate id '{}'", rule.id),
            });
        }
        if let Some(ent) = rule.entropy {
            if !(ENTROPY_MIN..=ENTROPY_MAX).contains(&ent) {
                return Err(ConfigError::Validation {
                    path: path.to_path_buf(),
                    field: format!("{field}.entropy"),
                    message: format!("must be between {ENTROPY_MIN} and {ENTROPY_MAX}"),
                });
            }
        }
        let regex = compile_regex(&rule.pattern, path, &format!("{field}.pattern"))?;
        if let Some(g) = rule.secret_group {
            if regex.captures_len() <= g {
                return Err(ConfigError::Validation {
                    path: path.to_path_buf(),
                    field: format!("{field}.secret_group"),
                    message: format!(
                        "group {g} does not exist (pattern has {} group(s))",
                        regex.captures_len().saturating_sub(1)
                    ),
                });
            }
        }
        let path_matcher = match &rule.path {
            Some(p) => Some(compile_one_glob(p, path, &format!("{field}.path"))?.compile_matcher()),
            None => None,
        };
        custom_rules.push(CustomRule {
            id: rule.id,
            description: rule.description,
            pattern: rule.pattern,
            regex,
            severity: rule.severity,
            keywords: rule.keywords,
            path: rule.path,
            path_matcher,
            entropy: rule.entropy,
            secret_group: rule.secret_group,
        });
    }

    let mut allow = Vec::with_capacity(raw.allow.len());
    for (i, a) in raw.allow.into_iter().enumerate() {
        let field = format!("allow[{i}]");
        let mut paths = a.paths;
        if let Some(single) = a.path {
            if !single.is_empty() && !paths.iter().any(|p| p == &single) {
                paths.push(single);
            }
        }
        let path_set = compile_globs(&paths, path, &format!("{field}.paths"))?;
        let mut regexes = Vec::with_capacity(a.regexes.len());
        for (j, pat) in a.regexes.iter().enumerate() {
            regexes.push(compile_regex(pat, path, &format!("{field}.regexes[{j}]"))?);
        }
        let compiled = Allow {
            rule: a.rule,
            paths,
            path_set,
            contains: a.contains.0,
            regexes,
            fingerprint: a.fingerprint,
            condition: a.condition,
        };
        if compiled.is_empty() {
            return Err(ConfigError::Validation {
                path: path.to_path_buf(),
                field,
                message: "allow entry needs at least one of rule, path(s), contains, regexes, fingerprint"
                    .into(),
            });
        }
        allow.push(compiled);
    }

    Ok(Config {
        fail_on: v.fail_on,
        redact: v.redact,
        max_file_bytes: v.max_file_bytes,
        entropy_enabled: v.entropy_enabled,
        entropy_min_length: v.entropy_min_length,
        entropy_threshold: v.entropy_threshold,
        exclude,
        exclude_set,
        replace_excludes,
        block_env_files: v.block_env_files,
        custom_rules,
        allow,
        source,
    })
}

fn compile_regex(pat: &str, path: &Path, field: &str) -> Result<regex::Regex, ConfigError> {
    RegexBuilder::new(pat)
        .size_limit(MAX_REGEX_SIZE)
        .dfa_size_limit(MAX_REGEX_SIZE)
        .build()
        .map_err(|e| ConfigError::Validation {
            path: path.to_path_buf(),
            field: field.to_string(),
            message: format!("invalid regex: {e}"),
        })
}

fn compile_one_glob(pat: &str, path: &Path, field: &str) -> Result<Glob, ConfigError> {
    GlobBuilder::new(pat)
        .literal_separator(true)
        .build()
        .map_err(|e| ConfigError::Validation {
            path: path.to_path_buf(),
            field: field.to_string(),
            message: format!("invalid glob '{pat}': {e}"),
        })
}

fn compile_globs(pats: &[String], path: &Path, field: &str) -> Result<GlobSet, ConfigError> {
    let mut builder = GlobSetBuilder::new();
    for (i, pat) in pats.iter().enumerate() {
        builder.add(compile_one_glob(pat, path, &format!("{field}[{i}]"))?);
    }
    builder.build().map_err(|e| ConfigError::Validation {
        path: path.to_path_buf(),
        field: field.to_string(),
        message: format!("failed to compile glob set: {e}"),
    })
}

pub fn normalize_scan_path(path: &str) -> String {
    let mut p = path.replace('\\', "/");
    while p.starts_with("./") {
        p = p[2..].to_string();
    }
    p
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
# false (default): patterns below are appended to built-in excludes.
# true: built-in excludes are discarded and only this list is used.
replace_excludes = false
exclude = ["**/tests/fixtures/**", "**/*.md"]

# [[rules]]
# id = "prod-postgres"
# description = "No production PostgreSQL connection strings"
# pattern = '(?i)postgres(?:ql)?://[^\s]+:[^\s]+@[^\s]*(?:prod|production)'
# severity = "critical"
# keywords = ["postgres"]
# # path = "**/*.env"
# # entropy = 3.5
# # secret_group = 0

# [[allow]]
# rule = "generic-api-key"
# paths = ["testdata/sample.env"]
# contains = "EXAMPLE_NOT_A_REAL_KEY"
# # regexes = ["EXAMPLE_"]
# # fingerprint = "vf_deadbeef"
# # condition = "and"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Config {
        parse_toml(text).unwrap_or_else(|e| panic!("parse failed: {e}"))
    }

    fn parse_err(text: &str) -> String {
        parse_toml(text).unwrap_err().to_string()
    }

    #[test]
    fn starter_toml_roundtrips() {
        let cfg = parse(STARTER_TOML);
        assert_eq!(cfg.fail_on, FailOn::Any);
        assert!(cfg.redact);
        assert_eq!(cfg.max_file_bytes, 1_048_576);
        assert!(cfg.entropy_enabled);
        assert_eq!(cfg.entropy_min_length, 24);
        assert!((cfg.entropy_threshold - 4.5).abs() < f64::EPSILON);
        assert!(cfg.block_env_files);
        assert!(!cfg.replace_excludes);
        assert!(cfg.custom_rules.is_empty());
        assert!(cfg.allow.is_empty());
        assert!(cfg.exclude.iter().any(|p| p == "**/*.md"));
        assert!(cfg.exclude.iter().any(|p| p == "**/tests/fixtures/**"));
        assert!(cfg.exclude.iter().any(|p| p == "**/target/**"));
    }

    #[test]
    fn multiline_exclude_array_is_collected() {
        let cfg = parse(
            r#"
[paths]
exclude = [
    "**/foo/**",
    "**/bar/*.tmp",
]
"#,
        );
        assert!(cfg.exclude.iter().any(|p| p == "**/foo/**"));
        assert!(cfg.exclude.iter().any(|p| p == "**/bar/*.tmp"));
    }

    #[test]
    fn unknown_key_is_an_error() {
        let err = parse_err(
            r#"
[verify]
redakt = true
"#,
        );
        assert!(err.contains("redakt") || err.contains("unknown"), "{err}");
    }

    #[test]
    fn incomplete_rule_is_an_error() {
        let err = parse_err(
            r#"
[[rules]]
description = "missing id and pattern"
"#,
        );
        assert!(
            err.contains("missing field") || err.contains("id") || err.contains("pattern"),
            "{err}"
        );
    }

    #[test]
    fn invalid_fail_on_is_an_error() {
        let err = parse_err(
            r#"
[verify]
fail_on = "hight"
"#,
        );
        assert!(
            err.contains("hight") || err.contains("fail_on") || err.contains("any"),
            "{err}"
        );
    }

    #[test]
    fn invalid_severity_is_an_error() {
        let err = parse_err(
            r#"
[[rules]]
id = "x"
pattern = "secret"
severity = "ultra"
"#,
        );
        assert!(err.contains("ultra") || err.contains("severity"), "{err}");
    }

    #[test]
    fn invalid_regex_is_an_error() {
        let err = parse_err(
            r#"
[[rules]]
id = "bad"
pattern = "(unclosed"
"#,
        );
        assert!(err.contains("rules[0].pattern"), "{err}");
        assert!(err.contains("invalid regex"), "{err}");
    }

    #[test]
    fn duplicate_rule_id_is_an_error() {
        let err = parse_err(
            r#"
[[rules]]
id = "dup"
pattern = "a"

[[rules]]
id = "dup"
pattern = "b"
"#,
        );
        assert!(err.contains("duplicate"), "{err}");
    }

    #[test]
    fn entropy_out_of_range_is_an_error() {
        let err = parse_err(
            r#"
[verify]
entropy_threshold = 9.1
"#,
        );
        assert!(err.contains("entropy_threshold"), "{err}");
    }

    #[test]
    fn max_file_bytes_zero_is_an_error() {
        let err = parse_err(
            r#"
[verify]
max_file_bytes = 0
"#,
        );
        assert!(err.contains("max_file_bytes"), "{err}");
    }

    #[test]
    fn merge_vs_replace_excludes() {
        let merged = parse(
            r#"
[paths]
replace_excludes = false
exclude = ["**/only-extra/**"]
"#,
        );
        assert!(!merged.replace_excludes);
        assert!(merged.exclude.iter().any(|p| p == "**/*.md"));
        assert!(merged.exclude.iter().any(|p| p == "**/only-extra/**"));

        let replaced = parse(
            r#"
[paths]
replace_excludes = true
exclude = ["**/keep-only/**"]
"#,
        );
        assert!(replaced.replace_excludes);
        assert_eq!(replaced.exclude, vec!["**/keep-only/**".to_string()]);
        assert!(!replaced.is_excluded("README.md"));
        assert!(replaced.is_excluded("vendor/keep-only/x"));
    }

    #[test]
    fn glob_markdown_and_normalization() {
        let cfg = Config::default();
        assert!(cfg.is_excluded("README.md"), "default should skip markdown");
        assert!(cfg.is_excluded("./docs/guide.md"));
        assert!(cfg.is_excluded("src/target/debug/foo"));
        assert!(!cfg.is_excluded("src/main.rs"));
    }

    #[test]
    fn custom_rule_compiles_and_captures() {
        let cfg = parse(
            r#"
[[rules]]
id = "prod-postgres"
description = "prod db"
pattern = '(?i)postgres(?:ql)?://([^\s]+)'
severity = "high"
keywords = ["postgres"]
secret_group = 1
"#,
        );
        let rule = &cfg.custom_rules[0];
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.keywords, vec!["postgres"]);
        let caps = rule.regex.captures("POSTGRES://user:pass@host").unwrap();
        assert_eq!(caps.get(1).unwrap().as_str(), "user:pass@host");
    }

    #[test]
    fn allow_paths_and_condition() {
        let cfg = parse(
            r#"
[[allow]]
rule = "generic-api-key"
paths = ["testdata/**", "fixtures/sample.env"]
contains = ["EXAMPLE_NOT_A_REAL_KEY", "FIXTURE"]
condition = "and"
"#,
        );
        let a = &cfg.allow[0];
        assert_eq!(a.rule.as_deref(), Some("generic-api-key"));
        assert_eq!(a.condition, AllowCondition::And);
        assert!(a.matches(
            "generic-api-key",
            "testdata/sample.env",
            "EXAMPLE_NOT_A_REAL_KEY",
            "KEY=EXAMPLE_NOT_A_REAL_KEY",
            "vf_x"
        ));
        assert!(!a.matches(
            "other-rule",
            "testdata/sample.env",
            "EXAMPLE_NOT_A_REAL_KEY",
            "KEY=EXAMPLE_NOT_A_REAL_KEY",
            "vf_x"
        ));
    }

    #[test]
    fn simple_table_rules_is_rejected() {
        let err = parse_err(
            r#"
[rules]
id = "x"
pattern = "y"
"#,
        );
        assert!(!err.is_empty(), "{err}");
    }

    #[test]
    fn load_explicit_missing_file_errors() {
        let repo = std::env::temp_dir();
        let missing = repo.join("verify-does-not-exist-xyz.toml");
        let err = load(Some(&missing), &repo).unwrap_err().to_string();
        assert!(
            err.contains("does not exist") || err.contains("failed to read"),
            "{err}"
        );
    }

    #[test]
    fn load_discovers_dotfile() {
        let tmp = std::env::temp_dir().join(format!("verify-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join(".verify.toml"),
            r#"
[verify]
fail_on = "high"
"#,
        )
        .unwrap();
        let cfg = load(None, &tmp).unwrap();
        assert_eq!(cfg.fail_on, FailOn::High);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}