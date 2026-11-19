use super::*;

fn cfg() -> Config {
    Config {
        uid_min: 1000,
        filter: Some(FilterPorts {
            v4: (41443, 41080),
            v6: Some((41444, 41081)),
        }),
    }
}

#[test]
fn ruleset_shapes() {
    let both = ruleset(
        &cfg(),
        NetWant {
            doh: true,
            filter: true,
            ..Default::default()
        },
    );
    assert!(both.contains("set doh4"));
    assert!(both.contains("meta nfproto ipv4 tcp dport 443 redirect to :41443"));
    assert!(both.contains("meta nfproto ipv6 tcp dport 80 redirect to :41081"));
    assert!(!both.contains("reject with tcp reset"));
    assert!(both.contains("meta skuid < 1000 return"));
    assert!(both.contains("udp dport 443 reject"));
    assert!(!both.contains("oiftype"));
    let tunnels = ruleset(
        &cfg(),
        NetWant {
            tunnels: true,
            ..Default::default()
        },
    );
    assert!(tunnels.contains("meta oiftype { 0xfffe"));
    assert!(tunnels.contains("meta skuid < 1000 return"));
    assert!(!tunnels.contains("redirect"));
    let doh = ruleset(
        &cfg(),
        NetWant {
            doh: true,
            ..Default::default()
        },
    );
    assert!(!doh.contains("redirect"));
    assert!(!doh.contains("udp dport 443 reject"));
    let filter = ruleset(
        &Config {
            uid_min: 0,
            ..cfg()
        },
        NetWant {
            filter: true,
            ..Default::default()
        },
    );
    assert!(!filter.contains("doh4"));
    assert!(!filter.contains("skuid"));

    // Without IPv6 the filter can't take IPv6 traffic: it's refused.
    let filter = NetWant {
        filter: true,
        ..Default::default()
    };
    let v4_only = ruleset(
        &Config {
            filter: Some(FilterPorts {
                v4: (41443, 41080),
                v6: None,
            }),
            ..cfg()
        },
        filter,
    );
    assert!(v4_only.contains("ip6 daddr != ::1 tcp dport { 80, 443 } reject"));
    assert!(!v4_only.contains("ip daddr != 127.0.0.0/8"));
    assert!(!v4_only.contains("nfproto ipv6"));
    // Without the filter, web traffic is refused rather than let through.
    let down = ruleset(
        &Config {
            filter: None,
            ..cfg()
        },
        filter,
    );
    assert!(down.contains("ip daddr != 127.0.0.0/8 tcp dport { 80, 443 } reject"));
    assert!(!down.contains("redirect"));
}
