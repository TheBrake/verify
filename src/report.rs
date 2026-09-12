use crate::config::Config;
use crate::engine::Finding;
use crate::rules::Severity;
use std::io::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Hook,
    Commit,
    Scan,
}

pub fn print_verdict(
    findings: &[Finding],
    show_secrets: bool,
    remote: Option<&str>,
    url: Option<&str>,
    cfg: &Config,
    mode: Mode,
) {
    let color = std::io::stderr().is_terminal();
    let text = format_verdict(findings, show_secrets, remote, url, cfg, mode, color);
    eprint!("{text}");
}

pub fn format_verdict(
    findings: &[Finding],
    show_secrets: bool,
    remote: Option<&str>,
    url: Option<&str>,
    cfg: &Config,
    mode: Mode,
    color: bool,
) -> String {
    let mut out = String::new();
    if findings.is_empty() {
        match mode {
            Mode::Hook => line(
                &mut out,
                color,
                32,
                true,
                "verify",
                " no secrets in outgoing diff — push allowed",
            ),
            Mode::Commit => line(
                &mut out,
                color,
                32,
                true,
                "verify",
                " no secrets in the index — commit allowed",
            ),
            Mode::Scan => line(&mut out, color, 32, true, "verify", " no secrets found"),
        }
        return out;
    }

    let mut items: Vec<&Finding> = findings.iter().collect();
    items.sort_by_key(|f| severity_rank(f.severity));

    let blocking: Vec<&Finding> = items.iter().copied().filter(|f| f.blocks(cfg)).collect();
    let reported: Vec<&Finding> = items.iter().copied().filter(|f| !f.blocks(cfg)).collect();
    let blocked = !blocking.is_empty();

    out.push('\n');
    banner(&mut out, color, mode, blocked);
    if let (Some(r), Some(u)) = (remote, url) {
        out.push_str(&format!("  remote  {r}  ({u})\n"));
    }
    if show_secrets {
        out.push_str("  redact off — snippets are shown in full\n");
    }
    out.push('\n');

    if !blocking.is_empty() {
        out.push_str("  blocked\n");
        write_items(&mut out, &blocking, show_secrets, color, true);
    }
    if !reported.is_empty() {
        out.push_str("  reported (does not fail this run)\n");
        write_items(&mut out, &reported, show_secrets, color, false);
    }

    if blocked {
        out.push_str(&format!(
            "  {} {} blocking finding(s). Fix the leak, add `// verify:allow` (or `verify:ignore`) on that line,\n",
            paint(color, 31, true, "→"),
            blocking.len()
        ));
        if let Some(fp) = blocking.first().map(|f| f.fingerprint.as_str()) {
            out.push_str("     or allow the fingerprint in verify.toml:\n");
            out.push_str("       [[allow]]\n");
            out.push_str(&format!("       fingerprint = \"{fp}\"\n"));
        }
        match mode {
            Mode::Hook => {
                out.push_str("  →  last resort: git push --no-verify   (auditable, use rarely)\n");
            }
            Mode::Commit => {
                out.push_str(
                    "  →  last resort: git commit --no-verify   (auditable, use rarely)\n",
                );
            }
            Mode::Scan => {}
        }
    } else {
        out.push_str(&format!(
            "  {} {} reported finding(s) below fail_on — hook would still pass.\n",
            paint(color, 33, true, "→"),
            reported.len()
        ));
    }
    out.push('\n');
    out
}

fn write_items(
    out: &mut String,
    items: &[&Finding],
    show_secrets: bool,
    color: bool,
    blocked: bool,
) {
    for (i, f) in items.iter().enumerate() {
        let tag = if blocked { "[blocked]" } else { "[reported]" };
        out.push_str(&format!(
            "  {}. {}  {}  {}  {}\n",
            i + 1,
            color_severity(f.severity, color),
            paint(color, 36, true, &f.rule_id),
            f.description,
            tag
        ));
        out.push_str(&format!(
            "     {}\n",
            paint(color, 33, false, &format!("{}:{}", f.path, f.line_no))
        ));
        let shown = if show_secrets {
            f.snippet.clone()
        } else {
            redact(&f.snippet)
        };
        out.push_str(&format!("     {}\n", paint(color, 31, false, &shown)));
        out.push_str(&format!("     fingerprint {}\n\n", f.fingerprint));
    }
}

fn banner(out: &mut String, color: bool, mode: Mode, blocked: bool) {
    let (code, title) = match (mode, blocked) {
        (Mode::Hook, true) => (31u8, "VERIFY  ·  secret leak detected — push blocked"),
        (Mode::Hook, false) => (33, "VERIFY  ·  findings reported — push allowed"),
        (Mode::Commit, true) => (31u8, "VERIFY  ·  secret leak detected — commit blocked"),
        (Mode::Commit, false) => (33, "VERIFY  ·  findings reported — commit allowed"),
        (Mode::Scan, true) => (31, "VERIFY  ·  secret leak detected"),
        (Mode::Scan, false) => (33, "VERIFY  ·  findings reported"),
    };
    let bar = "═".repeat(54);
    out.push_str(&paint(color, code, false, &format!("╔{bar}╗")));
    out.push('\n');
    out.push_str(&paint(color, code, true, &format!("║   {title:<48} ║")));
    out.push('\n');
    out.push_str(&paint(color, code, false, &format!("╚{bar}╝")));
    out.push('\n');
}

fn line(out: &mut String, color: bool, code: u8, bold: bool, head: &str, rest: &str) {
    out.push_str(&paint(color, code, bold, head));
    out.push_str(rest);
    out.push('\n');
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    }
}

fn color_severity(s: Severity, color: bool) -> String {
    match s {
        Severity::Critical => paint(color, 31, true, "CRITICAL"),
        Severity::High => paint(color, 208, true, "HIGH    "),
        Severity::Medium => paint(color, 33, false, "MEDIUM  "),
        Severity::Low => "LOW     ".into(),
    }
}

fn paint(color: bool, code: u8, bold: bool, text: &str) -> String {
    if !color {
        return text.to_string();
    }
    if code == 208 {
        return format!("\x1b[38;5;208;1m{text}\x1b[0m");
    }
    if bold {
        format!("\x1b[{code};1m{text}\x1b[0m")
    } else {
        format!("\x1b[{code}m{text}\x1b[0m")
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
    use crate::config::{Config, FailOn};
    use crate::engine::Finding;
    use crate::rules::Severity;

    fn finding(id: &str, sev: Severity, fp: &str) -> Finding {
        Finding {
            rule_id: id.into(),
            description: "desc".into(),
            severity: sev,
            path: "src/a.rs".into(),
            line_no: 3,
            snippet: "AKIAAAAAAAAAAAAAAAAA".into(),
            fingerprint: fp.into(),
        }
    }

    fn cfg_high() -> Config {
        let mut c = Config::default();
        c.fail_on = FailOn::High;
        c
    }

    #[test]
    fn redact_keeps_edges() {
        let r = redact("AKIAIOSFODNN7EXAMPLE");
        assert!(r.starts_with("AKIA"));
        assert!(r.ends_with("MPLE"));
        assert!(r.contains('*'));
        assert!(!r.contains("IOSFODNN7EXA"));
    }

    #[test]
    fn redact_short_and_capped() {
        assert_eq!(redact("abcd"), "****");
        let r8 = redact("abcdefgh");
        assert!(r8.starts_with("ab"));
        assert!(r8.ends_with("gh"));
        let long = "x".repeat(40);
        let r = redact(&long);
        assert!(r.starts_with("xxxx"));
        assert!(r.ends_with("xxxx"));
        assert_eq!(r.chars().filter(|c| *c == '*').count(), 16);
    }

    #[test]
    fn empty_scan_does_not_talk_about_push() {
        let t = format_verdict(
            &[],
            false,
            None,
            None,
            &Config::default(),
            Mode::Scan,
            false,
        );
        assert!(t.contains("no secrets found"));
        assert!(!t.contains("push"));
        assert!(!t.contains("blocked"));
    }

    #[test]
    fn medium_with_fail_on_high_is_not_blocked() {
        let f = finding("high-entropy", Severity::Medium, "vf_aaa");
        let t = format_verdict(&[f], false, None, None, &cfg_high(), Mode::Hook, false);
        assert!(!t.to_ascii_lowercase().contains("blocked"));
        assert!(t.contains("push allowed"));
        assert!(t.contains("[reported]"));
        assert!(t.contains("does not fail this run"));
    }

    #[test]
    fn critical_in_hook_says_push_blocked_and_prints_allow_toml() {
        let f = finding("aws-access-key", Severity::Critical, "vf_deadbeef");
        let t = format_verdict(&[f], false, None, None, &cfg_high(), Mode::Hook, false);
        assert!(t.contains("push blocked"));
        assert!(t.contains("[blocked]"));
        assert!(t.contains("[[allow]]"));
        assert!(t.contains("fingerprint = \"vf_deadbeef\""));
        assert!(t.contains("--no-verify"));
        assert!(!t.contains("\x1b["));
    }

    #[test]
    fn critical_in_commit_says_commit_blocked() {
        let f = finding("env-file", Severity::Critical, "vf_env");
        let t = format_verdict(
            &[f],
            false,
            None,
            None,
            &Config::default(),
            Mode::Commit,
            false,
        );
        assert!(t.contains("commit blocked"));
        assert!(t.contains("git commit --no-verify"));
        assert!(!t.contains("git push --no-verify"));
    }

    #[test]
    fn critical_in_scan_does_not_say_push_blocked() {
        let f = finding("aws-access-key", Severity::Critical, "vf_x");
        let t = format_verdict(&[f], false, None, None, &cfg_high(), Mode::Scan, false);
        assert!(t.contains("secret leak detected"));
        assert!(!t.contains("push blocked"));
        assert!(!t.contains("--no-verify"));
    }

    #[test]
    fn severity_orders_critical_first() {
        let med = finding("high-entropy", Severity::Medium, "vf_m");
        let crit = finding("aws-access-key", Severity::Critical, "vf_c");
        let t = format_verdict(
            &[med, crit],
            false,
            None,
            None,
            &cfg_high(),
            Mode::Hook,
            false,
        );
        let c = t.find("aws-access-key").unwrap();
        let m = t.find("high-entropy").unwrap();
        assert!(c < m, "{t}");
    }
}
