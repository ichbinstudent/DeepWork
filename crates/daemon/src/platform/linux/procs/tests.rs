use super::*;

#[test]
fn reads_own_process() {
    let me = read_proc(std::process::id(), 1000).unwrap();
    assert!(!me.comm.is_empty() && me.start_time > 0);
    assert!(
        ProcFs { uid_min: 1000 }
            .list()
            .iter()
            .any(|p| p.pid == me.pid)
    );
}

#[test]
fn only_peoples_accounts_are_closable() {
    assert!(is_user_account(1000, 1000));
    assert!(is_user_account(60_001, 1000)); // systemd-homed
    assert!(is_user_account(1_234_567, 1000)); // directory services
    for service in [0, 33, 999, 61_184, 65_534, 65_535] {
        assert!(!is_user_account(service, 1000), "{service}");
    }
    // Tests that filter every user still never touch root.
    assert!(is_user_account(5, 0) && !is_user_account(0, 0));
}
