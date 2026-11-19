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

/// A program can make itself non-dumpable, which turns the files in its
/// `/proc` folder root's; the folder itself must still say whose it is.
#[test]
fn non_dumpable_programs_stay_their_users() {
    struct Child(libc::pid_t);
    impl Drop for Child {
        fn drop(&mut self) {
            // SAFETY: our own child.
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
                libc::waitpid(self.0, std::ptr::null_mut(), 0);
            }
        }
    }
    let me = unsafe { libc::getuid() };
    // SAFETY: the child only makes system calls until it is killed.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            loop {
                libc::pause();
            }
        }
    }
    let child = Child(pid);
    let base = format!("/proc/{}", child.0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while me != 0 && fs::metadata(format!("{base}/status")).unwrap().uid() != 0 {
        assert!(std::time::Instant::now() < deadline, "still dumpable");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(fs::metadata(&base).unwrap().uid(), me);
}
