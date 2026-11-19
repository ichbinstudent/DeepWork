//! Managing a marked section of `/etc/hosts`.

use std::collections::BTreeSet;

pub const BEGIN: &str = "# >>> deepwork >>> (managed automatically, do not edit)";
pub const END: &str = "# <<< deepwork <<<";

/// Common subdomains added for every blocked domain. `/etc/hosts` has no
/// wildcards, so this covers the usual entry points.
const PREFIXES: &[&str] = &[
    "", "www.", "m.", "mobile.", "old.", "new.", "web.", "app.", "en.", "de.", "touch.",
];

/// Only this many domains (e.g. of an imported list) get every prefix; the
/// rest only `www.`, to keep the hosts file a reasonable size.
const FULL_EXPANSION_LIMIT: usize = 2000;

/// The host names for `domains`, which come most important first (see
/// [`crate::state::Plan::priority`]): the first [`FULL_EXPANSION_LIMIT`] get
/// every common subdomain. Domains added later go to the back, so they can't
/// take subdomains away from domains that were blocked already.
pub fn expand(domains: &[String]) -> BTreeSet<String> {
    domains
        .iter()
        .enumerate()
        .flat_map(|(i, d)| {
            let prefixes = if i < FULL_EXPANSION_LIMIT {
                PREFIXES
            } else {
                &PREFIXES[..2]
            };
            prefixes.iter().map(move |p| format!("{p}{d}"))
        })
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

/// The full hosts file with our section reflecting `domains` (most
/// important first, expanded with common subdomains) and `exact` (added
/// as-is).
pub fn render(content: &str, domains: &[String], exact: &BTreeSet<String>) -> String {
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
        let d = ["reddit.com".to_string()];
        let none = BTreeSet::new();
        let r = render(BASE, &d, &none);
        assert!(r.starts_with(BASE));
        assert!(r.contains("0.0.0.0 reddit.com\n"));
        assert!(r.contains(":: www.reddit.com\n"));
        assert_eq!(render(&r, &d, &none), r, "idempotent");
        assert_eq!(render(&r, &[], &none), BASE);
        assert_eq!(strip(&r), BASE);
    }

    /// Adding many domains never takes subdomains away from the domains
    /// that come first.
    #[test]
    fn additions_dont_push_out_earlier_domains() {
        let mut d = vec!["reddit.com".to_string()];
        assert!(expand(&d).contains("old.reddit.com"));
        d.extend((0..5000).map(|i| format!("a{i}.example")));
        let all = expand(&d);
        assert!(all.contains("old.reddit.com"));
        assert!(all.contains("old.a0.example"));
        assert!(!all.contains("old.a4999.example"));
        assert!(all.contains("www.a4999.example") && all.contains("a4999.example"));
    }

    #[test]
    fn keeps_user_lines_after_section() {
        let d = ["a.com".to_string()];
        let none = BTreeSet::new();
        let r = render(BASE, &d, &none) + "10.0.0.1 nas\n";
        let again = render(&r, &d, &none);
        assert!(again.contains("10.0.0.1 nas"));
        assert_eq!(again.matches(BEGIN).count(), 1);
    }
}
