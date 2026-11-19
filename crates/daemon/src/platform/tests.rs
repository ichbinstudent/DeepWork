use super::*;

#[test]
fn capabilities_follow_the_pieces() {
    let opts = Options {
        root: "/nonexistent".into(),
        state_dir: "/nonexistent/state".into(),
        sandbox: true,
        force_net: false,
        filter_uid_min: 1000,
        filter_ports: (41443, 41080),
    };
    let caps = unsupported(&opts).capabilities();
    assert!(caps.websites);
    assert!(!caps.apps && !caps.freeze && !caps.hardcore && !caps.https_filter);
    let native = native(&opts).capabilities();
    assert!(native.websites);
}
