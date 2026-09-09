//! Tiny HTTP/1.1 helpers: enough to issue `GET /key`, to perform the ts2021 and
//! DERP `Upgrade:` requests and to parse the response head.

use std::io::{self, Read, Write};

#[derive(Debug, Default)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Bytes read past the end of the head (belong to the upgraded stream/body).
    pub leftover: Vec<u8>,
}

impl ResponseHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Reads an HTTP/1.x response head, byte-wise buffered, from `r`.
pub fn read_response_head(r: &mut dyn Read) -> io::Result<ResponseHead> {
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 256];
    let end;
    loop {
        let n = r.read(&mut tmp)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof in http response head",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_head_end(&buf) {
            end = pos;
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http response head too large",
            ));
        }
    }
    let head = std::str::from_utf8(&buf[..end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 head"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad status line: {status_line:?}"),
            )
        })?;
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(ResponseHead {
        status,
        headers,
        leftover: buf[end + 4..].to_vec(),
    })
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Reads a body given a parsed head: honours `Content-Length`, chunked
/// encoding, or reads to EOF.
pub fn read_body(r: &mut dyn Read, head: &ResponseHead, max: usize) -> io::Result<Vec<u8>> {
    let mut body = head.leftover.clone();
    if let Some(len) = head
        .header("content-length")
        .and_then(|v| v.parse::<usize>().ok())
    {
        if len > max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
        }
        while body.len() < len {
            let mut tmp = [0u8; 1024];
            let n = r.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(len);
        return Ok(body);
    }
    if head
        .header("transfer-encoding")
        .map(|v| v.eq_ignore_ascii_case("chunked"))
        .unwrap_or(false)
    {
        // Read everything then de-chunk (bodies here are tiny).
        let mut raw = body;
        let mut tmp = [0u8; 1024];
        loop {
            let n = r.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&tmp[..n]);
            if raw.len() > max {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
            }
            if raw.ends_with(b"0\r\n\r\n") {
                break;
            }
        }
        return dechunk(&raw);
    }
    let mut tmp = [0u8; 1024];
    loop {
        let n = r.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
        }
    }
    Ok(body)
}

fn dechunk(raw: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let line_end = raw[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunk"))?;
        let size_str = std::str::from_utf8(&raw[pos..pos + line_end]).unwrap_or("");
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
        pos += line_end + 2;
        if size == 0 {
            break;
        }
        if pos + size > raw.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated chunk",
            ));
        }
        out.extend_from_slice(&raw[pos..pos + size]);
        pos += size + 2;
    }
    Ok(out)
}

/// Writes a simple request with no body.
pub fn write_request(
    w: &mut dyn Write,
    method: &str,
    path: &str,
    host: &str,
    extra_headers: &[(&str, &str)],
) -> io::Result<()> {
    let mut s = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: tsnode/0.1\r\n");
    for (k, v) in extra_headers {
        s.push_str(k);
        s.push_str(": ");
        s.push_str(v);
        s.push_str("\r\n");
    }
    s.push_str("\r\n");
    w.write_all(s.as_bytes())?;
    w.flush()
}

/// Performs `GET path` on an already-connected stream and returns the body.
pub fn get(
    conn: &mut dyn Read,
    w: &mut dyn Write,
    host: &str,
    path: &str,
) -> io::Result<(u16, Vec<u8>)> {
    write_request(
        w,
        "GET",
        path,
        host,
        &[("Connection", "close"), ("Accept", "*/*")],
    )?;
    let head = read_response_head(conn)?;
    let body = read_body(conn, &head, 256 * 1024)?;
    Ok((head.status, body))
}
