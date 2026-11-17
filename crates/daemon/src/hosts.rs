//! Managing a marked section of `/etc/hosts`.

use std::collections::BTreeSet;

pub const BEGIN: &str = "# >>> deepwork >>> (managed automatically, do not edit)";
pub const END: &str = "# <<< deepwork <<<";

/// Common subdomains added for every blocked domain. `/etc/hosts` has no
/// wildcards, so this covers the usual entry points.
const PREFIXES: &[&str] = &[
    "", "www.", "m.", "mobile.", "old.", "new.", "web.", "app.", "en.", "de.", "touch.",
];

/// Above this many domains (e.g. an imported list) only `www.` is added, to
/// keep the hosts file a reasonable size.
const FULL_EXPANSION_LIMIT: usize = 2000;

pub fn expand(domains: &BTreeSet<String>) -> BTreeSet<String> {
    let prefixes = if domains.len() > FULL_EXPANSION_LIMIT {
        &PREFIXES[..2]
    } else {
        PREFIXES
    };
    domains
        .iter()
        .flat_map(|d| prefixes.iter().map(move |p| format!("{p}{d}")))
        .collect()
}

/// Remove our section from an existing hosts file.
pub fn strip(content: &str) -> String {
    let mut out = Vec::new();
    let mut inside = false;
    for line in content.lines() {
        if line.trim_end() == BEGIN {
            inside = true;
        } else if inside && line.trim_end() == END {
            inside = false;
        } else if !inside {
            out.push(line);
        }
    }
    while out.last().is_some_and(|l| l.trim().is_empty()) {
        out.pop();
    }
    let mut s = out.join("\n");
    s.push('\n');
    s
}

/// The full hosts file with our section reflecting `domains` (expanded with
/// common subdomains) and `exact` (added as-is).
pub fn render(content: &str, domains: &BTreeSet<String>, exact: &BTreeSet<String>) -> String {
    let mut s = strip(content);
    if domains.is_empty() && exact.is_empty() {
        return s;
    }
    s.push('\n');
    s.push_str(BEGIN);
    s.push('\n');
    let mut all = expand(domains);
    all.extend(exact.iter().cloned());
    for host in all {
        s.push_str(&format!("0.0.0.0 {host}\n:: {host}\n"));
    }
    s.push_str(END);
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "127.0.0.1 localhost\n::1 localhost\n";

    #[test]
    fn roundtrip() {
        let d: BTreeSet<String> = ["reddit.com".to_string()].into();
        let none = BTreeSet::new();
        let r = render(BASE, &d, &none);
        assert!(r.starts_with(BASE));
        assert!(r.contains("0.0.0.0 reddit.com\n"));
        assert!(r.contains(":: www.reddit.com\n"));
        assert_eq!(render(&r, &d, &none), r, "idempotent");
        assert_eq!(render(&r, &BTreeSet::new(), &none), BASE);
        assert_eq!(strip(&r), BASE);
    }

    #[test]
    fn keeps_user_lines_after_section() {
        let d: BTreeSet<String> = ["a.com".to_string()].into();
        let none = BTreeSet::new();
        let r = render(BASE, &d, &none) + "10.0.0.1 nas\n";
        let again = render(&r, &d, &none);
        assert!(again.contains("10.0.0.1 nas"));
        assert_eq!(again.matches(BEGIN).count(), 1);
    }
}
