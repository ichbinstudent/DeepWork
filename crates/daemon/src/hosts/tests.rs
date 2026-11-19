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
