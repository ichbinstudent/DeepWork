use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use super::*;

const ERROR_ACCESS_DENIED: u32 = 5;

/// Open a connection on loopback, close it from outside, and check that
/// both ends notice.
fn cuts(listen: &str) {
    let Ok(listener) = TcpListener::bind(listen) else {
        eprintln!("skipped: cannot listen on {listen}");
        return;
    };
    let server = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(server).unwrap();
    let (mut accepted, _) = listener.accept().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    accepted
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let (closed, error) = cut_where(|remote| remote == server);
    // CI runs as administrator; elsewhere this may not be possible.
    if error == Some(ERROR_ACCESS_DENIED) && std::env::var_os("CI").is_none() {
        eprintln!("skipped: closing connections needs administrator rights");
        return;
    }
    assert_eq!((closed, error), (1, None), "{listen}");

    let mut buf = [0u8; 1];
    for (end, stream) in [("client", &mut client), ("server", &mut accepted)] {
        match stream.read(&mut buf) {
            Ok(0) => {}
            Err(e)
                if e.kind() != std::io::ErrorKind::TimedOut
                    && e.kind() != std::io::ErrorKind::WouldBlock => {}
            other => panic!("{listen}: the {end} end is still open: {other:?}"),
        }
    }
}

#[test]
fn cuts_ipv4_connections() {
    cuts("127.0.0.1:0");
}

#[test]
fn cuts_ipv6_connections() {
    cuts("[::1]:0");
}

#[test]
fn ports_are_big_endian() {
    // Port 443 as a MIB row holds it: bytes 0x01 0xBB first.
    let field = u32::from_ne_bytes([0x01, 0xBB, 0xAA, 0xAA]);
    assert_eq!(port(field), 443);
    let s = sockaddr_in6([0; 16], field, 0);
    assert_eq!(&s[2..4], &[0x01, 0xBB]);
}
