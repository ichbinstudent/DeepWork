use super::*;
use crate::model::normalize_app;

#[test]
fn builtin_lists_are_valid() {
    let mut ids = BTreeSet::new();
    for l in LISTS {
        assert!(ids.insert(l.id), "duplicate list id {}", l.id);
        assert!(
            !l.websites.is_empty() || !l.apps.is_empty(),
            "{} is empty",
            l.id
        );
        let mut seen = BTreeSet::new();
        for w in l.websites {
            assert_eq!(normalize_domain(w).as_deref(), Ok(*w), "{}: {w}", l.id);
            assert!(seen.insert(*w), "{}: duplicate {w}", l.id);
        }
        let mut seen = BTreeSet::new();
        for a in l.apps {
            assert_eq!(normalize_app(a).as_deref(), Ok(*a), "{}: {a}", l.id);
            assert!(seen.insert(a.to_lowercase()), "{}: duplicate {a}", l.id);
        }
    }
}

#[test]
fn parses_common_formats() {
    let text = "\
# a hosts file
127.0.0.1 localhost
0.0.0.0 ads.example.com tracker.example.com
::1 ip6-localhost
||adblock.example^
||withopts.example^$third-party
@@||allowed.example^
! adblock comment
https://www.Some-Site.org/path
*.wild.example
plain.example.net   # trailing comment
not a domain
";
    let (domains, skipped) = parse_domain_list(text);
    assert_eq!(
        domains,
        vec![
            "ads.example.com",
            "tracker.example.com",
            "adblock.example",
            "withopts.example",
            "some-site.org",
            "wild.example",
            "plain.example.net"
        ]
    );
    // localhost line, ip6-localhost line, allow rule, "not a domain"
    assert_eq!(skipped, 4);
}
