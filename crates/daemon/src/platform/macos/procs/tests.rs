use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::*;

#[test]
fn people_and_services() {
    assert!(is_user_account(501, 500));
    assert!(is_user_account(1_234_567_890, 500));
    for service in [0, 1, 88, 499, u32::MAX - 1, u32::MAX] {
        assert!(!is_user_account(service, 500), "{service}");
    }
    assert!(!is_user_account(0, 0));
}

#[test]
fn reads_arguments() {
    let mut data = 2i32.to_ne_bytes().to_vec();
    data.extend(b"/bin/x\0\0\0\0x\0two words\0HOME=/\0");
    let (exec, args) = parse_arguments(&data).unwrap();
    assert_eq!(exec, "/bin/x");
    assert_eq!(args, ["x", "two words"]);
    assert_eq!(parse_arguments(b"\x01"), None);
    assert_eq!(parse_arguments(&[0xff; 64]), None);
}

#[test]
fn apps_and_their_helpers() {
    let of = |exe| bundle_of(exe).map(|b| b.to_string_lossy().into_owned());
    assert_eq!(
        of("/Applications/A.app/Contents/Frameworks/A Helper.app/Contents/MacOS/A Helper"),
        Some("/Applications/A.app".into())
    );
    assert_eq!(of("/usr/bin/true"), None);
    let finder = Path::new("/System/Library/CoreServices/Finder.app");
    assert_eq!(read_bundle_id(finder).as_deref(), Some("com.apple.finder"));
}

#[test]
fn odd_app_folders_are_left_alone() {
    let dir = std::env::temp_dir().join(format!("deepwork-{}.app", std::process::id()));
    let plist = dir.join("Contents/Info.plist");
    fs::create_dir_all(plist.parent().unwrap()).unwrap();
    assert_eq!(read_bundle_id(&dir), None);
    fs::write(&plist, b"not a plist").unwrap();
    assert_eq!(read_bundle_id(&dir), None);
    fs::remove_file(&plist).unwrap();
    // A pipe nobody writes to must not hang the service.
    assert!(
        Command::new("mkfifo")
            .arg(&plist)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(read_bundle_id(&dir), None);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn protected_programs_must_be_the_systems() {
    assert!(is_system("/bin/zsh"));
    let copy = std::env::temp_dir().join(format!("deepwork-zsh-{}", std::process::id()));
    fs::copy("/bin/zsh", &copy).unwrap();
    assert!(!is_system(&copy.to_string_lossy()));
    fs::remove_file(copy).unwrap();
}

#[test]
fn describes_and_closes_processes() {
    let mut child = Command::new("/bin/sleep")
        .arg("60")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    // Everyone but root counts as a person here, whatever the test runs as.
    let table = Processes::new(1);
    let find = || table.list().into_iter().find(|p| p.pid == child.id());
    let deadline = Instant::now() + Duration::from_secs(5);
    let p = loop {
        match find().filter(|p| p.comm == "sleep") {
            Some(p) => break p,
            None if Instant::now() > deadline => panic!("{:?}", find()),
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    assert_eq!(p.exe, "/bin/sleep");
    assert_eq!(p.cmdline, "/bin/sleep 60");
    assert!(!p.privileged);
    assert!(table.list().iter().any(|p| p.pid == 1 && p.privileged));
    // Not if it's another process by now.
    let other = Proc {
        start_time: 1,
        ..p.clone()
    };
    table.terminate(&[other], true);
    assert!(child.try_wait().unwrap().is_none());
    table.terminate(&[p], false);
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "still running");
        std::thread::sleep(Duration::from_millis(20));
    }
}
