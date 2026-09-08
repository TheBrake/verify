use crate::engine::Finding;
use crate::rules::Severity;

pub fn print_verdict(
    findings: &[Finding],
    show_secrets: bool,
    remote: Option<&str>,
    url: Option<&str>,
) {
    if findings.is_empty() {
        eprintln!("\x1b[32;1mverify\x1b[0m  no secrets in outgoing diff — push allowed");
        return;
    }

    eprintln!();
    eprintln!("\x1b[31m╔══════════════════════════════════════════════════════╗\x1b[0m");
    eprintln!("\x1b[31;1m║   VERIFY  ·  secret leak detected — push blocked     ║\x1b[0m");
    eprintln!("\x1b[31m╚══════════════════════════════════════════════════════╝\x1b[0m");
    if let (Some(r), Some(u)) = (remote, url) {
        eprintln!("  remote  {r}  ({u})");
    }
    eprintln!();

    for (i, f) in findings.iter().enumerate() {
        eprintln!(
            "  {}. {}  \x1b[36;1m{}\x1b[0m  {}",
            i + 1,
            color_severity(f.severity),
            f.rule_id,
            f.description
        );
        eprintln!("     \x1b[33m{}:{}\x1b[0m", f.path, f.line_no);
        let shown = if show_secrets {
            f.snippet.clone()
        } else {
            redact(&f.snippet)
        };
        eprintln!("     \x1b[31m{shown}\x1b[0m");
        eprintln!("     fingerprint {}", f.fingerprint);
        eprintln!();
    }

    eprintln!(
        "  \x1b[31;1m→\x1b[0m  {} finding(s). Fix the leak, or add `// verify:allow` on that line.",
        findings.len()
    );
    eprintln!("  →  emergency bypass: git push --no-verify   (auditable, use rarely)");
    eprintln!();
}

fn color_severity(s: Severity) -> String {
    match s {
        Severity::Critical => "\x1b[31;1mCRITICAL\x1b[0m".into(),
        Severity::High => "\x1b[38;5;208;1mHIGH    \x1b[0m".into(),
        Severity::Medium => "\x1b[33mMEDIUM  \x1b[0m".into(),
        Severity::Low => "LOW     ".into(),
    }
}

pub fn redact(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let n = chars.len();
    if n <= 6 {
        return "*".repeat(n.max(4));
    }
    if n <= 12 {
        let keep = 2;
        format!(
            "{}{}{}",
            chars[..keep].iter().collect::<String>(),
            "*".repeat(n - keep * 2),
            chars[n - keep..].iter().collect::<String>()
        )
    } else {
        let keep = 4;
        format!(
            "{}{}{}",
            chars[..keep].iter().collect::<String>(),
            "*".repeat((n - keep * 2).min(16)),
            chars[n - keep..].iter().collect::<String>()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_keeps_edges() {
        let r = redact("AKIAIOSFODNN7EXAMPLE");
        assert!(r.starts_with("AKIA"));
        assert!(r.ends_with("MPLE"));
        assert!(r.contains('*'));
        assert!(!r.contains("IOSFODNN7EXA"));
    }
}
