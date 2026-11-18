//! Closing open TCP connections, so a page that is already open (a chat's
//! WebSocket, say) loses its connection and runs into the block when it
//! reconnects. Needs administrator rights.
//!
//! IPv4 connections are closed with `SetTcpEntry`. Windows has no documented
//! way to close an IPv6 connection, so those go through `NsiSetAllParameters`
//! in nsi.dll, which is what `SetTcpEntry` does underneath (the call is the
//! same as in other tools that close connections, such as SocketCloser).

use std::collections::HashSet;
use std::mem::{align_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetTcp6Table, GetTcpTable, MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_DELETE_TCB,
    MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_TIME_WAIT, MIB_TCP6ROW, MIB_TCP6TABLE, MIB_TCPROW_LH,
    MIB_TCPTABLE, SetTcpEntry,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};

/// Close every TCP connection to one of `ips`.
pub fn cut(ips: &[IpAddr]) {
    let targets: HashSet<IpAddr> = ips.iter().map(|ip| ip.to_canonical()).collect();
    if targets.is_empty() {
        return;
    }
    let (closed, error) = cut_where(|remote| targets.contains(&remote.ip()));
    if let Some(e) = error {
        eprintln!("deepwork: cannot close some connections (error {e})");
    }
    if closed > 0 {
        eprintln!("deepwork: closed {closed} open connection(s) to blocked sites");
    }
}

/// Close the connections whose remote end matches. Returns how many were
/// closed and the last error, if any failed.
fn cut_where(matches: impl Fn(SocketAddr) -> bool) -> (usize, Option<u32>) {
    let mut closed = 0;
    let mut error = None;
    let mut done = |ret: u32, error: &mut Option<u32>| match ret {
        NO_ERROR => closed += 1,
        e => *error = Some(e),
    };

    // SAFETY: GetTcpTable fills the buffer with a MIB_TCPTABLE.
    let rows4 = read_table::<MIB_TCPROW_LH>(|buf, size| unsafe {
        GetTcpTable(buf.cast::<MIB_TCPTABLE>(), size, 0)
    });
    for mut row in rows4 {
        // SAFETY: both union fields are the same 32-bit state.
        if !open(unsafe { row.Anonymous.State }) {
            continue;
        }
        // Addresses and ports are in network byte order.
        let ip = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
        if matches(SocketAddr::new(IpAddr::V4(ip), port(row.dwRemotePort))) {
            row.Anonymous.State = MIB_TCP_STATE_DELETE_TCB;
            // SAFETY: a row as GetTcpTable returned it, with the new state.
            done(unsafe { SetTcpEntry(&row) }, &mut error);
        }
    }

    // SAFETY: GetTcp6Table fills the buffer with a MIB_TCP6TABLE.
    let rows6 = read_table::<MIB_TCP6ROW>(|buf, size| unsafe {
        GetTcp6Table(buf.cast::<MIB_TCP6TABLE>(), size, 0)
    });
    let mut set = None;
    for row in rows6 {
        if !open(row.State) {
            continue;
        }
        // SAFETY: every bit pattern is a valid byte array.
        let ip = Ipv6Addr::from(unsafe { row.RemoteAddr.u.Byte });
        if !matches(SocketAddr::new(
            IpAddr::V6(ip).to_canonical(),
            port(row.dwRemotePort),
        )) {
            continue;
        }
        let Some(set) = *set.get_or_insert_with(nsi_set_all_parameters) else {
            error = Some(ERROR_PROC_NOT_FOUND);
            break;
        };
        // The connection's key: its local and remote SOCKADDR_IN6.
        let mut key = [0u8; 56];
        // SAFETY: as above.
        let local = unsafe { row.LocalAddr.u.Byte };
        key[..28].copy_from_slice(&sockaddr_in6(local, row.dwLocalPort, row.dwLocalScopeId));
        key[28..].copy_from_slice(&sockaddr_in6(
            ip.octets(),
            row.dwRemotePort,
            row.dwRemoteScopeId,
        ));
        // The arguments SetTcpEntry uses: the TCP module's connection table
        // (object 16), set.
        // SAFETY: the module id and key are valid for the sizes given.
        let ret = unsafe {
            set(
                1,
                2,
                NPI_MS_TCP_MODULEID.as_ptr(),
                16,
                key.as_ptr(),
                key.len() as u32,
                null(),
                0,
            )
        };
        // The connection may have closed on its own in the meantime.
        if ret != ERROR_GONE_NSI {
            done(ret, &mut error);
        }
    }
    (closed, error)
}

const ERROR_PROC_NOT_FOUND: u32 = 127;
/// What nsi.dll returns when the connection is already gone.
const ERROR_GONE_NSI: u32 = 317;

/// Whether a connection in this state is worth closing (not a listening
/// socket, and not one that is already closing).
fn open(state: i32) -> bool {
    ![
        MIB_TCP_STATE_LISTEN,
        MIB_TCP_STATE_CLOSED,
        MIB_TCP_STATE_TIME_WAIT,
        MIB_TCP_STATE_DELETE_TCB,
    ]
    .contains(&state)
}

/// NPI_MODULEID of the TCP module: size 24, type 1 (GUID), then
/// {EB004A03-9B1A-11D4-9123-0050047759BC}.
const NPI_MS_TCP_MODULEID: [u8; 24] = [
    0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x4A, 0x00, 0xEB, 0x1A, 0x9B, 0xD4, 0x11,
    0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC,
];

type NsiSetAllParameters =
    unsafe extern "system" fn(u32, u32, *const u8, u32, *const u8, u32, *const u8, u32) -> u32;

fn nsi_set_all_parameters() -> Option<NsiSetAllParameters> {
    let dll: Vec<u16> = "nsi.dll\0".encode_utf16().collect();
    // SAFETY: nul-terminated names; nsi.dll stays loaded (iphlpapi uses it).
    unsafe {
        let module = LoadLibraryExW(dll.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
        if module.is_null() {
            return None;
        }
        let f = GetProcAddress(module, c"NsiSetAllParameters".as_ptr().cast())?;
        Some(std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            NsiSetAllParameters,
        >(f))
    }
}

/// A SOCKADDR_IN6. `port` is a MIB row's port field (network byte order in
/// its low 16 bits).
fn sockaddr_in6(addr: [u8; 16], port: u32, scope_id: u32) -> [u8; 28] {
    const AF_INET6: u16 = 23;
    let mut s = [0u8; 28];
    s[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
    s[2..4].copy_from_slice(&(port as u16).to_ne_bytes());
    s[8..24].copy_from_slice(&addr);
    s[24..28].copy_from_slice(&scope_id.to_ne_bytes());
    s
}

/// A port from a MIB row (network byte order in the low 16 bits).
fn port(field: u32) -> u16 {
    u16::from_be_bytes((field as u16).to_ne_bytes())
}

/// Read a `{ count: u32, rows: [Row] }` table with a `GetTcpTable`-style
/// function, growing the buffer until it fits.
fn read_table<Row: Copy>(get: impl Fn(*mut u8, *mut u32) -> u32) -> Vec<Row> {
    const { assert!(align_of::<Row>() <= 4) };
    let mut buf: Vec<u32> = Vec::new();
    let mut size = 0u32;
    for _ in 0..5 {
        match get(buf.as_mut_ptr().cast(), &mut size) {
            NO_ERROR if !buf.is_empty() => {
                let bytes = (buf.len() * 4).min(size as usize);
                let max = bytes.saturating_sub(4) / size_of::<Row>();
                let n = (buf[0] as usize).min(max);
                // SAFETY: n rows fit in the buffer after the count; rows
                // are at most 4-aligned, like the buffer.
                return (0..n)
                    .map(|i| unsafe {
                        buf.as_ptr()
                            .cast::<u8>()
                            .add(4 + i * size_of::<Row>())
                            .cast::<Row>()
                            .read()
                    })
                    .collect();
            }
            NO_ERROR => return vec![],
            ERROR_INSUFFICIENT_BUFFER => {
                // Room for connections opened in the meantime.
                let words = (size as usize).div_ceil(4) + 64;
                buf = vec![0; words];
                size = (words * 4) as u32;
            }
            _ => return vec![],
        }
    }
    vec![]
}

#[cfg(test)]
mod tests {
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
        if error == Some(ERROR_ACCESS_DENIED) {
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
}
