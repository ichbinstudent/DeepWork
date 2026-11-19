use std::time::Duration;

use deepwork_core::client::Client;
use deepwork_core::protocol::Capabilities;

use super::*;
use crate::state::Persisted;

#[test]
fn answers_over_the_pipe() {
    let name = format!(r"\\.\pipe\deepwork-test-{}", std::process::id());
    let daemon = Arc::new(Mutex::new(Daemon::new(
        Persisted::default(),
        String::new(),
        Capabilities::all("Windows"),
    )));
    {
        let name = name.clone();
        std::thread::spawn(move || serve(Path::new(&name), daemon, None));
    }
    let client = Client::new(name.clone());
    let mut status = None;
    for _ in 0..100 {
        match client.status() {
            Ok(s) => {
                status = Some(s);
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let status = status.expect("the pipe server never answered");
    assert_eq!(status.capabilities.os, "Windows");
    // Later connections get new pipe instances.
    for _ in 0..3 {
        client.status().unwrap();
    }
    // A second server can't take over the name.
    let err = serve(
        Path::new(&name),
        Arc::new(Mutex::new(Daemon::new(
            Persisted::default(),
            String::new(),
            Capabilities::all("Windows"),
        ))),
        None,
    )
    .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(5), "{err}"); // ERROR_ACCESS_DENIED
}
