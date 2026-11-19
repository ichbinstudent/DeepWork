use super::*;
use crate::model::normalize_domain;

#[test]
fn entries_are_valid() {
    for h in DOH_HOSTS {
        assert_eq!(normalize_domain(h).as_deref(), Ok(*h), "{h}");
    }
    for a in DOH_IPV4 {
        let ip = a.split('/').next().unwrap();
        assert!(ip.parse::<std::net::Ipv4Addr>().is_ok(), "{a}");
    }
    for a in DOH_IPV6 {
        let ip = a.split('/').next().unwrap();
        assert!(ip.parse::<std::net::Ipv6Addr>().is_ok(), "{a}");
    }
}
