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

/// Longest chunk-size line or trailer section accepted in a request body.
const MAX_HTTP_LINE: usize = 4 * 1024;

/// Why a plain-HTTP connection must stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// A request for this blocked site.
    Blocked(String),
    /// Not plain HTTP/1.x with a site name, or framed in a way that a server
    /// might read differently from the filter (which could hide a request).
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Gate {
    /// Reading a request head.
    #[default]
    Head,
    /// This many more body bytes.
    Body(u64),
    /// Reading a chunk-size line.
    ChunkSize,
    /// This many more bytes of chunk data.
    ChunkData(u64),
    /// The line break after chunk data.
    ChunkEnd,
    /// Trailer lines after the last chunk.
    Trailers,
    /// The request asked to switch to WebSocket; the server's answer decides
    /// what the rest of the connection is.
    AwaitUpgrade,
    /// Switched to WebSocket: the rest belongs to the same site.
    Open,
}

/// Checks every request on a plain-HTTP connection, not just the first: a
/// client could otherwise ask for an allowed site and then for a blocked
/// one over the same connection. Requests are delimited the way servers
/// delimit them, and anything ambiguous closes the connection, so no
/// request reaches the server without being checked.
#[derive(Debug, Default)]
pub struct HttpGate {
    state: Gate,
    /// Bytes from the client not processed yet.
    pending: Vec<u8>,
    /// Whether a request went through already.
    started: bool,
    /// The current request asks to switch to WebSocket.
    upgrade: bool,
    /// Size of the current request's trailer section so far.
    trailers: usize,
}

/// A parsed request head.
struct Head {
    /// The head to forward (without upgrades other than WebSocket).
    bytes: Vec<u8>,
    /// Every name the request gives for its site.
    hosts: Vec<String>,
    body: Body,
    websocket: bool,
}

enum Body {
    Length(u64),
    Chunked,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A host name without its port, keeping IPv6 literals intact.
fn host_of(authority: &str) -> String {
    let a = authority.trim();
    let a = a.rsplit_once('@').map_or(a, |(_, h)| h);
    if a.starts_with('[') {
        return a.split(']').next().unwrap_or(a).to_string() + "]";
    }
    a.split(':').next().unwrap_or(a).to_ascii_lowercase()
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Parse and check a request head (ending in an empty line). Strict: every
/// line ends in CRLF, no folded or nameless headers, one Host, and a body
/// length nobody can read two ways.
fn parse_head(head: &[u8]) -> Result<Head, Stop> {
    let text = std::str::from_utf8(head).map_err(|_| Stop::Invalid)?;
    let body = text.strip_suffix("\r\n\r\n").ok_or(Stop::Invalid)?;
    if body.bytes().any(|b| b == 0) {
        return Err(Stop::Invalid);
    }
    let mut lines = body.split("\r\n");
    let request_line = lines.next().ok_or(Stop::Invalid)?;
    let lines: Vec<&str> = lines.collect();
    // Bare CR or LF would split lines differently for some servers.
    if request_line.contains(['\r', '\n']) || lines.iter().any(|l| l.contains(['\r', '\n'])) {
        return Err(Stop::Invalid);
    }
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Stop::Invalid);
    };
    // CONNECT would turn the connection into a tunnel the filter can't see into.
    if !is_token(method) || method.eq_ignore_ascii_case("CONNECT") || target.is_empty() {
        return Err(Stop::Invalid);
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(Stop::Invalid);
    }
    let mut hosts = vec![];
    // Absolute form ("GET http://site/ HTTP/1.1"): servers go by this, not Host.
    let lower = target.to_ascii_lowercase();
    if let Some(rest) = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
    {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        hosts.push(host_of(authority));
    }

    let (mut host_headers, mut lengths, mut encodings) = (0, vec![], vec![]);
    let mut websocket = false;
    let mut out = format!("{request_line}\r\n");
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(Stop::Invalid)?;
        if !is_token(name) {
            return Err(Stop::Invalid); // also folded lines and "Name :"
        }
        let value = value.trim_matches([' ', '\t']);
        match name.to_ascii_lowercase().as_str() {
            "host" => {
                host_headers += 1;
                hosts.push(host_of(value));
            }
            "content-length" => lengths.push(value),
            "transfer-encoding" => encodings.push(value),
            "upgrade" => {
                // Only WebSocket stays with the same site. Other upgrades
                // (h2c could carry requests for any site) are left out, so
                // the server answers in HTTP/1.1.
                if value.eq_ignore_ascii_case("websocket") {
                    websocket = true;
                } else {
                    continue;
                }
            }
            "http2-settings" => continue,
            _ => {}
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    if host_headers > 1 || hosts.is_empty() || hosts.iter().any(|h| h.is_empty()) {
        return Err(Stop::Invalid);
    }
    let body = match (encodings.as_slice(), lengths.as_slice()) {
        ([], []) => Body::Length(0),
        ([], [first, rest @ ..]) => {
            if !first.bytes().all(|b| b.is_ascii_digit()) || rest.iter().any(|l| l != first) {
                return Err(Stop::Invalid);
            }
            Body::Length(first.parse().map_err(|_| Stop::Invalid)?)
        }
        ([te], []) if te.eq_ignore_ascii_case("chunked") && version == "HTTP/1.1" => Body::Chunked,
        _ => return Err(Stop::Invalid),
    };
    Ok(Head {
        bytes: out.into_bytes(),
        hosts,
        body,
        websocket,
    })
}

impl HttpGate {
    /// Whether a request has gone through already.
    pub fn started(&self) -> bool {
        self.started
    }

    /// Waiting for the server's answer to a WebSocket upgrade.
    pub fn awaiting_upgrade(&self) -> bool {
        self.state == Gate::AwaitUpgrade
    }

    /// Take bytes from the client and append what may go on to the server
    /// to `out`. On an error, `out` still holds what came before it.
    pub fn feed(
        &mut self,
        input: &[u8],
        blocked: &HashSet<String>,
        out: &mut Vec<u8>,
    ) -> Result<(), Stop> {
        self.pending.extend_from_slice(input);
        self.run(blocked, out)
    }

    /// The server answered the upgrade request: with `101 Switching
    /// Protocols` (`switched`) or anything else, in which case requests go
    /// on as before.
    pub fn upgrade_answered(
        &mut self,
        switched: bool,
        blocked: &HashSet<String>,
        out: &mut Vec<u8>,
    ) -> Result<(), Stop> {
        if self.state == Gate::AwaitUpgrade {
            self.state = if switched { Gate::Open } else { Gate::Head };
        }
        self.run(blocked, out)
    }

    fn request_done(&mut self) {
        self.state = if self.upgrade {
            Gate::AwaitUpgrade
        } else {
            Gate::Head
        };
    }

    fn run(&mut self, blocked: &HashSet<String>, out: &mut Vec<u8>) -> Result<(), Stop> {
        let data = std::mem::take(&mut self.pending);
        let mut pos = 0;
        let result = loop {
            let rest = &data[pos..];
            if rest.is_empty() {
                break Ok(());
            }
            match self.state {
                Gate::Open => {
                    out.extend_from_slice(rest);
                    pos = data.len();
                }
                Gate::AwaitUpgrade => break Ok(()),
                Gate::Head => {
                    let Some(end) = find(rest, b"\r\n\r\n") else {
                        if rest.len() > MAX_HTTP_HEAD {
                            break Err(Stop::Invalid);
                        }
                        break Ok(());
                    };
                    let head = match parse_head(&rest[..end + 4]) {
                        Ok(h) => h,
                        Err(e) => break Err(e),
                    };
                    if let Some(host) = head.hosts.iter().find(|h| is_blocked(h, blocked)) {
                        break Err(Stop::Blocked(host.clone()));
                    }
                    // A switch of protocols is only followed on a fresh connection.
                    if head.websocket && self.started {
                        break Err(Stop::Invalid);
                    }
                    out.extend_from_slice(&head.bytes);
                    pos += end + 4;
                    self.started = true;
                    self.upgrade = head.websocket;
                    match head.body {
                        Body::Length(0) => self.request_done(),
                        Body::Length(n) => self.state = Gate::Body(n),
                        Body::Chunked => self.state = Gate::ChunkSize,
                    }
                }
                Gate::Body(n) | Gate::ChunkData(n) => {
                    let take = rest.len().min(usize::try_from(n).unwrap_or(usize::MAX));
                    out.extend_from_slice(&rest[..take]);
                    pos += take;
                    let left = n - take as u64;
                    match (self.state, left) {
                        (Gate::Body(_), 0) => self.request_done(),
                        (Gate::Body(_), _) => self.state = Gate::Body(left),
                        (_, 0) => self.state = Gate::ChunkEnd,
                        _ => self.state = Gate::ChunkData(left),
                    }
                }
                Gate::ChunkEnd => {
                    if rest.len() < 2 {
                        break Ok(());
                    }
                    if &rest[..2] != b"\r\n" {
                        break Err(Stop::Invalid);
                    }
                    out.extend_from_slice(b"\r\n");
                    pos += 2;
                    self.state = Gate::ChunkSize;
                }
                Gate::ChunkSize | Gate::Trailers => {
                    let Some(end) = find(rest, b"\r\n") else {
                        if rest.len() > MAX_HTTP_LINE {
                            break Err(Stop::Invalid);
                        }
                        break Ok(());
                    };
                    let line = &rest[..end];
                    if line.len() > MAX_HTTP_LINE
                        || line.iter().any(|b| matches!(b, b'\r' | b'\n' | 0))
                    {
                        break Err(Stop::Invalid);
                    }
                    if self.state == Gate::ChunkSize {
                        let size = line.split(|b| *b == b';').next().unwrap_or_default();
                        let size = std::str::from_utf8(size)
                            .ok()
                            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()))
                            .and_then(|s| u64::from_str_radix(s, 16).ok());
                        let Some(size) = size else {
                            break Err(Stop::Invalid);
                        };
                        self.state = if size == 0 {
                            self.trailers = 0;
                            Gate::Trailers
                        } else {
                            Gate::ChunkData(size)
                        };
                    } else if line.is_empty() {
                        self.request_done();
                    } else {
                        self.trailers += line.len();
                        if self.trailers > MAX_HTTP_HEAD
                            || !line
                                .split(|b| *b == b':')
                                .next()
                                .and_then(|n| std::str::from_utf8(n).ok())
                                .is_some_and(is_token)
                            || !line.contains(&b':')
                        {
                            break Err(Stop::Invalid);
                        }
                    }
                    out.extend_from_slice(&rest[..end + 2]);
                    pos += end + 2;
                }
            }
        };
        self.pending = data[pos..].to_vec();
        result
    }
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
mod tests;
