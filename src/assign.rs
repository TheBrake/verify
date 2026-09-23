//! Assignment syntax shared by secret-assignment detectors.
//!
//! Isolated from individual rule catalogs so JSON / JS / TS quoting can
//! evolve without rewriting every detector, and so those detectors stay
//! independent of each other.

/// Non-identifier boundary so `password` does not fire inside `passwordless`.
/// Duplicated as a literal inside `assign_pat!` (`concat!` only accepts literals).
#[allow(dead_code)]
pub const KEY_BOUNDARY: &str = r"(?:^|[^A-Za-z0-9])";

/// Optional quotes closing a key, then `=` or `:`, then optional quotes
/// opening a value.
///
/// Covers the forms that show up in env files, Python, JSON, JS and TS:
/// - `password = "…"` / `password='…'`
/// - `password: "…"`
/// - `"password": "…"` / `'api_key': '…'`
/// - `"password":"…"` (compact JSON)
/// Duplicated as a literal inside `assign_pat!` (`concat!` only accepts literals).
#[allow(dead_code)]
pub const KEY_ASSIGN: &str = r#"['"]?\s*[=:]\s*['"]?"#;

/// Case-insensitive assignment pattern: boundary + keys + assign + value group.
///
/// `$keys` is a regex atom (usually a non-capturing group of identifiers).
/// `$value` is the capturing group that extracts the secret.
#[macro_export]
macro_rules! assign_pat {
    ($keys:expr, $value:expr) => {
        concat!(
            r"(?i)",
            r"(?:^|[^A-Za-z0-9])",
            $keys,
            r#"['"]?\s*[=:]\s*['"]?"#,
            $value
        )
    };
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    fn re(keys: &str, value: &str) -> Regex {
        Regex::new(&format!(
            "(?i){}(?:{}){}({})",
            super::KEY_BOUNDARY,
            keys,
            super::KEY_ASSIGN,
            value
        ))
        .unwrap()
    }

    fn cap<'a>(rx: &Regex, line: &'a str) -> Option<&'a str> {
        rx.captures(line).and_then(|c| c.get(1)).map(|m| m.as_str())
    }

    #[test]
    fn unquoted_equals_and_colon() {
        let rx = re("password", r#"[^\s'"]{8,}"#);
        assert_eq!(
            cap(&rx, r#"password = "supersecret12""#),
            Some("supersecret12")
        );
        assert_eq!(
            cap(&rx, r#"password: supersecret12"#),
            Some("supersecret12")
        );
    }

    #[test]
    fn json_and_js_quoted_keys() {
        let pw = re("password", r#"[^\s'"]{8,}"#);
        let key = re("api[_-]?key", r"[A-Za-z0-9/_\-+=.]{12,}");
        assert_eq!(
            cap(&pw, r#"{ "password": "supersecret12" }"#),
            Some("supersecret12")
        );
        assert_eq!(
            cap(&pw, r#"{'password': 'supersecret12'}"#),
            Some("supersecret12")
        );
        assert_eq!(
            cap(&pw, r#"{"password":"supersecret12"}"#),
            Some("supersecret12")
        );
        assert_eq!(
            cap(&key, r#"const cfg = { "api_key": "sk_test_abcdefghijk" };"#),
            Some("sk_test_abcdefghijk")
        );
        assert_eq!(
            cap(
                &key,
                r#"export const cfg = { 'api-key': 'sk_test_abcdefghijk' };"#
            ),
            Some("sk_test_abcdefghijk")
        );
    }

    #[test]
    fn spaced_json_colon() {
        let rx = re("password", r#"[^\s'"]{8,}"#);
        assert_eq!(
            cap(&rx, r#""password" : "supersecret12""#),
            Some("supersecret12")
        );
    }

    #[test]
    fn macro_matches_json_quoted_key() {
        let rx = Regex::new(assign_pat!(r"(?:password|passwd)", r#"([^\s'"]{8,})"#)).unwrap();
        assert_eq!(
            cap(&rx, r#"{ "password": "supersecret12" }"#),
            Some("supersecret12")
        );
    }
}
