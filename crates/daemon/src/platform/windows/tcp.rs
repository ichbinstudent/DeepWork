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
    GetExtendedTcpTable, MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_LISTEN,
    MIB_TCP_STATE_TIME_WAIT, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_LH, MIB_TCPROW_LH_0,
    MIB_TCPROW_OWNER_PID, SetTcpEntry, TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;

/// Close every TCP connection to a website (port 443 or 80) at one of
/// `ips` that a program in someone's session made. Services' and SYSTEM's
/// connections (session 0), and connections coming in (Remote Desktop, file
/// sharing), stay up whatever address a website is given.
pub fn cut(ips: &[IpAddr]) {
    let targets: HashSet<IpAddr> = ips.iter().map(|ip| ip.to_canonical()).collect();
    if targets.is_empty() {
        return;
    }
    let (closed, error) = cut_where(|remote, pid| {
        matches!(remote.port(), 443 | 80) && targets.contains(&remote.ip()) && in_session(pid)
    });
    if let Some(e) = error {
        eprintln!("deepwork: cannot close some connections (error {e})");
    }
    if closed > 0 {
        eprintln!("deepwork: closed {closed} open connection(s) to blocked sites");
    }
}

/// Whether process `pid` runs in someone's session, not in session 0 with
/// the services. Unknown counts as not.
fn in_session(pid: u32) -> bool {
    let mut session = 0;
    // SAFETY: valid out pointer.
    unsafe { ProcessIdToSessionId(pid, &mut session) != 0 && session != 0 }
}

/// Close the connections whose remote end and owning process match.
/// Returns how many were closed and the last error, if any failed.
fn cut_where(matches: impl Fn(SocketAddr, u32) -> bool) -> (usize, Option<u32>) {
    let mut closed = 0;
    let mut error = None;
    let mut done = |ret: u32, error: &mut Option<u32>| match ret {
        NO_ERROR => closed += 1,
        e => *error = Some(e),
    };

    // SAFETY: GetExtendedTcpTable fills the buffer with a
    // MIB_TCPTABLE_OWNER_PID.
    let rows4 = read_table::<MIB_TCPROW_OWNER_PID>(|buf, size| unsafe {
        GetExtendedTcpTable(
            buf.cast(),
            size,
            0,
            AF_INET.into(),
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        )
    });
    for row in rows4 {
        if !open(row.dwState as i32) {
            continue;
        }
        // Addresses and ports are in network byte order.
        let ip = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
        let remote = SocketAddr::new(IpAddr::V4(ip), port(row.dwRemotePort));
        if matches(remote, row.dwOwningPid) {
            // The same connection as a MIB_TCPROW, to be deleted.
            let delete = MIB_TCPROW_LH {
                Anonymous: MIB_TCPROW_LH_0 {
                    State: MIB_TCP_STATE_DELETE_TCB,
                },
                dwLocalAddr: row.dwLocalAddr,
                dwLocalPort: row.dwLocalPort,
                dwRemoteAddr: row.dwRemoteAddr,
                dwRemotePort: row.dwRemotePort,
            };
            // SAFETY: a valid row.
            done(unsafe { SetTcpEntry(&delete) }, &mut error);
        }
    }

    // SAFETY: GetExtendedTcpTable fills the buffer with a
    // MIB_TCP6TABLE_OWNER_PID.
    let rows6 = read_table::<MIB_TCP6ROW_OWNER_PID>(|buf, size| unsafe {
        GetExtendedTcpTable(
            buf.cast(),
            size,
            0,
            AF_INET6.into(),
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        )
    });
    let mut set = None;
    for row in rows6 {
        if !open(row.dwState as i32) {
            continue;
        }
        let ip = Ipv6Addr::from(row.ucRemoteAddr);
        let remote = SocketAddr::new(IpAddr::V6(ip).to_canonical(), port(row.dwRemotePort));
        if !matches(remote, row.dwOwningPid) {
            continue;
        }
        let Some(set) = *set.get_or_insert_with(nsi_set_all_parameters) else {
            error = Some(ERROR_PROC_NOT_FOUND);
            break;
        };
        // The connection's key: its local and remote SOCKADDR_IN6.
        let mut key = [0u8; 56];
        key[..28].copy_from_slice(&sockaddr_in6(
            row.ucLocalAddr,
            row.dwLocalPort,
            row.dwLocalScopeId,
        ));
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
/// function (`get(buffer, size)`), growing the buffer until it fits.
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
mod tests;
