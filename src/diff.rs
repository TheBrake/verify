/// A single added line extracted from a unified diff.
#[derive(Debug, Clone)]
pub struct AddedLine {
    pub path: String,
    pub line_no: usize,
    pub text: String,
    pub is_new_file: bool,
}

/// Parse `git diff --unified=0` output and keep only added (`+`) lines.
/// Context lines and deletions are ignored — they are not leaving the machine.
pub fn parse_unified_diff(raw: &str) -> Vec<AddedLine> {
    let mut out = Vec::new();
    let mut path = String::new();
    let mut new_line: usize = 0;
    let mut is_new_file = false;
    let mut skip_file = false;

    for raw_line in raw.split_inclusive('\n') {
        let line = raw_line.trim_end_matches(['\n', '\r']);

        if let Some(rest) = line.strip_prefix("diff --git ") {
            skip_file = false;
            is_new_file = false;
            path = parse_b_path(rest).unwrap_or_default();
            continue;
        }
        if line.starts_with("new file mode") {
            is_new_file = true;
            continue;
        }
        if line.starts_with("deleted file mode") {
            skip_file = true;
            continue;
        }
        if line.starts_with("Binary files") || line.starts_with("GIT binary patch") {
            skip_file = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("+++ ") {
            if rest != "/dev/null" {
                path = strip_ab_prefix(rest);
            }
            continue;
        }
        if line.starts_with("--- ") {
            continue;
        }
        if skip_file {
            continue;
        }
        if let Some(rest) = line.strip_prefix("@@ ") {
            new_line = parse_hunk_new_start(rest).unwrap_or(0);
            continue;
        }
        if line.starts_with('+') && !line.starts_with("+++") {
            out.push(AddedLine {
                path: path.clone(),
                line_no: new_line,
                text: line[1..].to_string(),
                is_new_file,
            });
            new_line = new_line.saturating_add(1);
        } else if line.starts_with(' ') {
            new_line = new_line.saturating_add(1);
        } else if line.starts_with('\\') {
            // "\ No newline at end of file"
        }
        // deletions (`-`) do not advance the new-file line counter
    }
    out
}

fn parse_b_path(rest: &str) -> Option<String> {
    // `a/foo b/foo` or `a/foo b/foo with spaces`
    if let Some(idx) = rest.rfind(" b/") {
        return Some(rest[idx + 3..].to_string());
    }
    rest.split_whitespace().nth(1).map(|s| {
        s.strip_prefix("b/")
            .unwrap_or(s)
            .to_string()
    })
}

fn strip_ab_prefix(s: &str) -> String {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("b/") {
        return rest.to_string();
    }
    if let Some(rest) = s.strip_prefix("a/") {
        return rest.to_string();
    }
    s.to_string()
}

fn parse_hunk_new_start(rest: &str) -> Option<usize> {
    // "@@ -12,0 +18,4 @@ context"
    let plus = rest.split_whitespace().find(|p| p.starts_with('+'))?;
    let num = plus.trim_start_matches('+').split(',').next()?;
    num.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_only_added_lines_with_correct_numbers() {
        let diff = "\
diff --git a/src/app.rs b/src/app.rs
index 111..222 100644
--- a/src/app.rs
+++ b/src/app.rs
@@ -10,0 +11,2 @@ fn main() {
+let key = \"AKIAIOSFODNN7EXAMPLE\";
+println!(\"{key}\");
";
        let lines = parse_unified_diff(diff);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].path, "src/app.rs");
        assert_eq!(lines[0].line_no, 11);
        assert!(lines[0].text.contains("AKIA"));
        assert_eq!(lines[1].line_no, 12);
    }

    #[test]
    fn detects_new_env_file() {
        let diff = "\
diff --git a/.env b/.env
new file mode 100644
index 000..111
--- /dev/null
+++ b/.env
@@ -0,0 +1,1 @@
+DATABASE_URL=postgres://u:p@host/db
";
        let lines = parse_unified_diff(diff);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].is_new_file);
        assert_eq!(lines[0].path, ".env");
    }
}
