//! Reading the site name of a web connection without decrypting it: the
//! server name (SNI) of a TLS ClientHello, or the `Host` header of plain
//! HTTP. Shared by every platform's web filter.

// Only Linux has a web filter so far.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashSet;
use std::io::{self, Read};

const MAX_HELLO: usize = 64 * 1024;
const MAX_HTTP_HEAD: usize = 16 * 1024;

/// `example.com` blocks `example.com` and every subdomain.
pub fn is_blocked(host: &str, blocked: &HashSet<String>) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let mut s = host.as_str();
    loop {
        if blocked.contains(s) {
            return true;
        }
        match s.find('.') {
            Some(i) => s = &s[i + 1..],
            None => return false,
        }
    }
}

// ----------------------------------------------------------------------------- TLS

/// Read the complete ClientHello (possibly spread over several records).
/// Returns everything read plus the SNI host name, if any.
pub fn read_client_hello(r: &mut impl Read) -> io::Result<(Vec<u8>, Option<String>)> {
    let mut raw = Vec::new();
    let mut hs = Vec::new();
    loop {
        let mut header = [0u8; 5];
        r.read_exact(&mut header)?;
        raw.extend_from_slice(&header);
        if header[0] != 0x16 {
            return Ok((raw, None)); // not a TLS handshake record
        }
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let start = raw.len();
        raw.resize(start + len, 0);
        r.read_exact(&mut raw[start..])?;
        hs.extend_from_slice(&raw[start..]);
        if hs.len() >= 4 {
            if hs[0] != 1 {
                return Ok((raw, None)); // not a ClientHello
            }
            let need = 4 + (u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize);
            if hs.len() >= need {
                return Ok((raw, parse_sni(&hs[..need])));
            }
        }
        if raw.len() > MAX_HELLO {
            return Ok((raw, None));
        }
    }
}

fn u16_at(b: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]) as usize)
}

/// Extract the server_name extension from a ClientHello handshake message.
pub fn parse_sni(hs: &[u8]) -> Option<String> {
    let mut p = 4 + 2 + 32; // handshake header, version, random
    p += 1 + *hs.get(p)? as usize; // session id
    p += 2 + u16_at(hs, p)?; // cipher suites
    p += 1 + *hs.get(p)? as usize; // compression methods
    let ext_len = u16_at(hs, p)?;
    p += 2;
    let end = (p + ext_len).min(hs.len());
    while p + 4 <= end {
        let typ = u16_at(hs, p)?;
        let len = u16_at(hs, p + 2)?;
        if typ == 0 {
            // server_name: list length (2), then entries of type (1) + length (2) + name
            let list_end = (p + 4 + len).min(end);
            let mut q = p + 6;
            while q + 3 <= list_end {
                let name_type = hs[q];
                let nl = u16_at(hs, q + 1)?;
                let name = hs.get(q + 3..q + 3 + nl)?;
                if name_type == 0 {
                    return std::str::from_utf8(name)
                        .ok()
                        .map(|s| s.to_ascii_lowercase());
                }
                q += 3 + nl;
            }
            return None;
        }
        p += 4 + len;
    }
    None
}

// ----------------------------------------------------------------------------- HTTP

pub fn read_http_head(r: &mut impl Read) -> io::Result<(Vec<u8>, Option<String>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < MAX_HTTP_HEAD {
        let n = r.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let host = String::from_utf8_lossy(&buf)
        .lines()
        .skip(1)
        .take_while(|l| !l.is_empty())
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("host").then(|| {
                let v = v.trim();
                // strip the port, keeping IPv6 literals intact
                if v.starts_with('[') {
                    v.to_string()
                } else {
                    v.split(':').next().unwrap_or(v).to_ascii_lowercase()
                }
            })
        });
    Ok((buf, host))
}

pub fn block_page(host: &str) -> String {
    let host: String = host
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .collect();
    let body = format!(
        "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content=\"width=device-width\">\
         <title>Blocked</title><style>body{{font:16px system-ui,sans-serif;display:grid;place-items:center;\
         min-height:90vh;margin:0;background:#f6f5f4;color:#2e3436}}main{{text-align:center;max-width:32em;padding:2em}}\
         h1{{font-size:2em;margin:.2em 0}}p{{opacity:.75}}@media(prefers-color-scheme:dark){{body{{background:#222226;color:#eee}}}}\
         </style></head><body><main><div style=\"font-size:3em\">&#x1F6E1;</div><h1>Blocked by DeepWork</h1>\
         <p><b>{host}</b> is blocked right now. Back to work &mdash; it'll still be there later.</p></main></body></html>"
    );
    format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n\
         Connection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal but well-formed ClientHello with an SNI extension.
    pub fn client_hello(sni: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        // some unrelated extension first (supported_groups)
        ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);
        let name = sni.as_bytes();
        let mut sn = Vec::new();
        sn.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sn.push(0);
        sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sn.extend_from_slice(name);
        ext.extend_from_slice(&[0x00, 0x00]);
        ext.extend_from_slice(&(sn.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sn);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(32);
        body.extend_from_slice(&[9u8; 32]);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn reads_sni() {
        let hello = client_hello("Www.Reddit.com");
        let (raw, sni) = read_client_hello(&mut hello.as_slice()).unwrap();
        assert_eq!(raw, hello);
        assert_eq!(sni.as_deref(), Some("www.reddit.com"));
    }

    #[test]
    fn reads_fragmented_hello() {
        // split the handshake across two TLS records
        let hello = client_hello("example.org");
        let hs = &hello[5..];
        let (a, b) = hs.split_at(20);
        let mut two = vec![0x16, 0x03, 0x01];
        two.extend_from_slice(&(a.len() as u16).to_be_bytes());
        two.extend_from_slice(a);
        two.extend_from_slice(&[0x16, 0x03, 0x01]);
        two.extend_from_slice(&(b.len() as u16).to_be_bytes());
        two.extend_from_slice(b);
        let (raw, sni) = read_client_hello(&mut two.as_slice()).unwrap();
        assert_eq!(raw, two);
        assert_eq!(sni.as_deref(), Some("example.org"));
    }

    #[test]
    fn garbage_is_not_a_hello() {
        let (_, sni) = read_client_hello(&mut &b"GET / HTTP/1.1\r\n\r\n"[..]).unwrap();
        assert_eq!(sni, None);
        assert_eq!(parse_sni(&[1, 0, 0, 3, 3, 3]), None);
    }

    #[test]
    fn reads_http_host() {
        let req = b"GET /r/rust HTTP/1.1\r\nUser-Agent: x\r\nHOST: Reddit.com:8080\r\n\r\nbody";
        let (raw, host) = read_http_head(&mut &req[..]).unwrap();
        assert_eq!(raw, req);
        assert_eq!(host.as_deref(), Some("reddit.com"));
    }

    #[test]
    fn suffix_matching() {
        let set: HashSet<String> = ["reddit.com".to_string()].into();
        assert!(is_blocked("reddit.com", &set));
        assert!(is_blocked("old.reddit.com.", &set));
        assert!(!is_blocked("notreddit.com", &set));
        assert!(!is_blocked("com", &set));
    }
}
