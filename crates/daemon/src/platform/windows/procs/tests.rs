use std::process::Command;
use std::time::{Duration, Instant};

use super::*;

#[test]
fn people_and_services() {
    assert!(is_person("S-1-5-21-1-2-3-1001"));
    assert!(is_person("S-1-12-1-1-2-3-4"));
    for service in [
        "S-1-5-18",
        "S-1-5-19",
        "S-1-5-80-1",
        "S-1-5-90-0-1",
        "S-1-5-96-0-1",
    ] {
        assert!(!is_person(service), "{service}");
    }
}

#[test]
fn first_arguments() {
    assert_eq!(first_argument(r#""C:\a b\x.exe" -v"#), r"C:\a b\x.exe");
    assert_eq!(first_argument(r"C:\x.exe  -v"), r"C:\x.exe");
    assert_eq!(first_argument(""), "");
}

#[test]
fn describes_processes() {
    let me = std::process::id();
    let handle = open(me, PROCESS_QUERY_LIMITED_INFORMATION).unwrap();
    let exe = exe(&handle).unwrap();
    assert!(
        exe.eq_ignore_ascii_case(&std::env::current_exe().unwrap().to_string_lossy()),
        "{exe}"
    );
    assert!(cmdline(&handle).unwrap().contains("deepwork"));
    assert!(user(&handle).unwrap().starts_with("S-1-"));
    assert_eq!(package_family(&handle), None);
    let age = now() - started(&handle).unwrap();
    assert!(age < 3600 * 10_000_000, "{age}");

    let table = Processes::default();
    for _ in 0..2 {
        let list = table.list();
        assert!(list.iter().any(|p| p.pid == me));
        // Services aren't people's: the session manager, say.
        let smss = list
            .iter()
            .find(|p| p.comm.eq_ignore_ascii_case("smss.exe"));
        assert!(smss.is_none_or(|p| p.privileged));
    }
}

#[test]
fn knows_whose_programs_are() {
    let system = std::env::var("SystemRoot").unwrap() + r"\explorer.exe";
    assert!(belongs_to_system(&system));
    let mine = std::env::temp_dir().join(format!("deepwork-mine-{}.exe", std::process::id()));
    std::fs::write(&mine, b"x").unwrap();
    // Elevated administrators' files may belong to the administrators.
    let _ = belongs_to_system(&mine.to_string_lossy());
    std::fs::remove_file(mine).unwrap();
    assert!(!belongs_to_system(r"C:\no\such\file.exe"));
}

#[test]
fn closes_processes() {
    let mut child = Command::new("ping")
        .args(["-n", "60", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let table = Processes::default();
    let p = table
        .list()
        .into_iter()
        .find(|p| p.pid == child.id())
        .unwrap();
    assert!(p.comm.eq_ignore_ascii_case("ping.exe"), "{p:?}");
    // Not if it's another process by now.
    let other = Proc {
        start_time: 1,
        ..p.clone()
    };
    table.terminate(&[other], true);
    assert!(child.try_wait().unwrap().is_none());
    // It just started, so it is closed without asking.
    table.terminate(&[p], false);
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "still running");
        std::thread::sleep(Duration::from_millis(20));
    }
}
