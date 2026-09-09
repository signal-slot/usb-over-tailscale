//! A deliberately small HTTP/2 client: one connection, a handful of sequential
//! streams, no server push, no priorities. It is what the Tailscale control
//! server speaks inside the ts2021 Noise channel.

use crate::net::{is_timeout, Conn};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0;
const FRAME_HEADERS: u8 = 1;
const FRAME_PRIORITY: u8 = 2;
const FRAME_RST_STREAM: u8 = 3;
const FRAME_SETTINGS: u8 = 4;
const FRAME_PUSH_PROMISE: u8 = 5;
const FRAME_PING: u8 = 6;
const FRAME_GOAWAY: u8 = 7;
const FRAME_WINDOW_UPDATE: u8 = 8;
const FRAME_CONTINUATION: u8 = 9;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

const SETTINGS_HEADER_TABLE_SIZE: u16 = 1;
const SETTINGS_ENABLE_PUSH: u16 = 2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 5;
/// (type, flags, stream id, payload)
type Frame = (u8, u8, u32, Vec<u8>);
/// What we advertise in SETTINGS_MAX_FRAME_SIZE; peers must not exceed it.
const MAX_FRAME_SIZE: usize = 16_384;
/// Cap on a stream's accumulated header block (HEADERS + CONTINUATION).
const MAX_HEADER_BLOCK: usize = 64 * 1024;

const DEFAULT_WINDOW: u32 = 65_535;
/// Window we advertise per stream and add to the connection.
const OUR_WINDOW: u32 = 256 * 1024;
const WINDOW_UPDATE_THRESHOLD: u32 = OUR_WINDOW / 2;

#[derive(Default)]
struct Stream {
    status: Option<u16>,
    headers: Vec<(String, String)>,
    header_block: Vec<u8>,
    headers_done: bool,
    body: Vec<u8>,
    end_stream: bool,
    reset: Option<u32>,
    send_window: i64,
    recv_consumed: u32,
}

pub struct H2Conn {
    conn: Box<dyn Conn>,
    inbuf: Vec<u8>,
    encoder: hpack::Encoder<'static>,
    decoder: hpack::Decoder<'static>,
    next_stream_id: u32,
    streams: HashMap<u32, Stream>,
    conn_send_window: i64,
    conn_recv_consumed: u32,
    peer_max_frame: usize,
    peer_initial_window: u32,
    goaway: Option<String>,
    authority: String,
}

impl H2Conn {
    /// Sends the client preface and initial settings. Does not wait for the
    /// server's settings; they are processed as frames arrive.
    pub fn new(conn: Box<dyn Conn>, authority: &str) -> io::Result<Self> {
        Self::with_prefix(conn, authority, Vec::new())
    }

    /// Like `new`, but `prefix` holds bytes already read from `conn` that
    /// belong to the HTTP/2 stream.
    pub fn with_prefix(
        mut conn: Box<dyn Conn>,
        authority: &str,
        prefix: Vec<u8>,
    ) -> io::Result<Self> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(PREFACE);
        let mut settings = Vec::new();
        for (id, val) in [
            (SETTINGS_ENABLE_PUSH, 0u32),
            (SETTINGS_MAX_CONCURRENT_STREAMS, 8),
            (SETTINGS_INITIAL_WINDOW_SIZE, OUR_WINDOW),
            (SETTINGS_MAX_FRAME_SIZE, MAX_FRAME_SIZE as u32),
            (SETTINGS_HEADER_TABLE_SIZE, 4096),
        ] {
            settings.extend_from_slice(&id.to_be_bytes());
            settings.extend_from_slice(&val.to_be_bytes());
        }
        push_frame(&mut out, FRAME_SETTINGS, 0, 0, &settings);
        // Grow the connection-level receive window.
        push_frame(
            &mut out,
            FRAME_WINDOW_UPDATE,
            0,
            0,
            &(OUR_WINDOW - DEFAULT_WINDOW).to_be_bytes(),
        );
        conn.write_all(&out)?;
        conn.flush()?;
        Ok(H2Conn {
            conn,
            inbuf: prefix,
            encoder: hpack::Encoder::new(),
            decoder: hpack::Decoder::new(),
            next_stream_id: 1,
            streams: HashMap::new(),
            conn_send_window: DEFAULT_WINDOW as i64,
            conn_recv_consumed: 0,
            peer_max_frame: 16_384,
            peer_initial_window: DEFAULT_WINDOW,
            goaway: None,
            authority: authority.to_string(),
        })
    }

    /// Sends a complete request and returns the stream id.
    pub fn request(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> io::Result<u32> {
        if let Some(g) = &self.goaway {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("h2 connection closed: {g}"),
            ));
        }
        let id = self.next_stream_id;
        self.next_stream_id += 2;
        self.streams.insert(
            id,
            Stream {
                send_window: self.peer_initial_window as i64,
                ..Default::default()
            },
        );

        let mut hdrs: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b":method".to_vec(), method.as_bytes().to_vec()),
            (b":scheme".to_vec(), b"https".to_vec()),
            (b":authority".to_vec(), self.authority.as_bytes().to_vec()),
            (b":path".to_vec(), path.as_bytes().to_vec()),
            (b"user-agent".to_vec(), b"tsnode/0.1".to_vec()),
        ];
        for (k, v) in headers {
            hdrs.push((k.to_ascii_lowercase().into_bytes(), v.as_bytes().to_vec()));
        }
        if !body.is_empty() {
            hdrs.push((
                b"content-length".to_vec(),
                body.len().to_string().into_bytes(),
            ));
        }
        let block = self
            .encoder
            .encode(hdrs.iter().map(|(k, v)| (k.as_slice(), v.as_slice())));
        let mut out = Vec::with_capacity(block.len() + body.len() + 32);
        let mut flags = FLAG_END_HEADERS;
        if body.is_empty() {
            flags |= FLAG_END_STREAM;
        }
        push_frame(&mut out, FRAME_HEADERS, flags, id, &block);
        self.conn.write_all(&out)?;
        self.conn.flush()?;
        if !body.is_empty() {
            self.send_body(id, body)?;
        }
        Ok(id)
    }

    fn send_body(&mut self, id: u32, body: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < body.len() {
            let stream_window = self.streams.get(&id).map(|s| s.send_window).unwrap_or(0);
            let allowed = stream_window.min(self.conn_send_window).max(0) as usize;
            if allowed == 0 {
                // Wait for WINDOW_UPDATE.
                self.process_one(Duration::from_secs(30))?;
                if let Some(r) = self.streams.get(&id).and_then(|s| s.reset) {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("stream reset {r}"),
                    ));
                }
                continue;
            }
            let n = (body.len() - offset).min(allowed).min(self.peer_max_frame);
            let last = offset + n == body.len();
            let mut out = Vec::with_capacity(n + 9);
            push_frame(
                &mut out,
                FRAME_DATA,
                if last { FLAG_END_STREAM } else { 0 },
                id,
                &body[offset..offset + n],
            );
            self.conn.write_all(&out)?;
            self.conn.flush()?;
            offset += n;
            self.conn_send_window -= n as i64;
            if let Some(s) = self.streams.get_mut(&id) {
                s.send_window -= n as i64;
            }
        }
        Ok(())
    }

    /// Waits for the response headers of `id` and returns the status code.
    pub fn response_status(&mut self, id: u32, timeout: Duration) -> io::Result<u16> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(s) = self.streams.get(&id) {
                if let Some(r) = s.reset {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("stream reset {r}"),
                    ));
                }
                if let Some(st) = s.status {
                    return Ok(st);
                }
                if s.end_stream {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stream ended without headers",
                    ));
                }
            } else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "unknown stream"));
            }
            self.check_goaway()?;
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timeout waiting for response headers",
                ));
            }
            self.process_one(deadline - now)?;
        }
    }

    pub fn response_header(&self, id: u32, name: &str) -> Option<&str> {
        self.streams
            .get(&id)?
            .headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Returns the next available body bytes, `Ok(None)` at end of stream.
    /// Blocks up to `timeout` for new data.
    pub fn read_body(&mut self, id: u32, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let s = self
                    .streams
                    .get_mut(&id)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown stream"))?;
                if !s.body.is_empty() {
                    return Ok(Some(std::mem::take(&mut s.body)));
                }
                if let Some(r) = s.reset {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("stream reset {r}"),
                    ));
                }
                if s.end_stream {
                    return Ok(None);
                }
            }
            self.check_goaway()?;
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timeout waiting for body",
                ));
            }
            self.process_one(deadline - now)?;
        }
    }

    /// Reads the whole body.
    pub fn read_full_body(
        &mut self,
        id: u32,
        timeout: Duration,
        max: usize,
    ) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(chunk) = self.read_body(id, timeout)? {
            out.extend_from_slice(&chunk);
            if out.len() > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response body too large",
                ));
            }
        }
        self.streams.remove(&id);
        Ok(out)
    }

    pub fn forget_stream(&mut self, id: u32) {
        self.streams.remove(&id);
    }

    fn check_goaway(&self) -> io::Result<()> {
        match &self.goaway {
            Some(g) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("h2 goaway: {g}"),
            )),
            None => Ok(()),
        }
    }

    /// Reads and processes one frame, blocking at most `timeout`.
    fn process_one(&mut self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some((typ, flags, sid, payload)) = self.take_frame()? {
                return self.handle_frame(typ, flags, sid, payload);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "h2 read timeout"));
            }
            self.conn
                .set_read_timeout(Some((deadline - now).max(Duration::from_millis(10))))?;
            let mut tmp = [0u8; 2048];
            match self.conn.read(&mut tmp) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "h2 connection closed",
                    ))
                }
                Ok(n) => self.inbuf.extend_from_slice(&tmp[..n]),
                Err(e) if is_timeout(&e) => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "h2 read timeout"))
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn take_frame(&mut self) -> io::Result<Option<Frame>> {
        if self.inbuf.len() < 9 {
            return Ok(None);
        }
        let len = ((self.inbuf[0] as usize) << 16)
            | ((self.inbuf[1] as usize) << 8)
            | self.inbuf[2] as usize;
        if len > MAX_FRAME_SIZE {
            // Larger than what we advertised in SETTINGS: a protocol error,
            // and on a small device an allocation we must not attempt.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("h2 frame of {len} bytes exceeds the advertised maximum"),
            ));
        }
        if self.inbuf.len() < 9 + len {
            return Ok(None);
        }
        let typ = self.inbuf[3];
        let flags = self.inbuf[4];
        let sid = u32::from_be_bytes([self.inbuf[5], self.inbuf[6], self.inbuf[7], self.inbuf[8]])
            & 0x7fff_ffff;
        let payload = self.inbuf[9..9 + len].to_vec();
        self.inbuf.drain(..9 + len);
        Ok(Some((typ, flags, sid, payload)))
    }

    fn handle_frame(&mut self, typ: u8, flags: u8, sid: u32, payload: Vec<u8>) -> io::Result<()> {
        match typ {
            FRAME_DATA => {
                let data = strip_padding(&payload, flags & FLAG_PADDED != 0)?;
                let len = payload.len() as u32;
                if let Some(s) = self.streams.get_mut(&sid) {
                    s.body.extend_from_slice(data);
                    if flags & FLAG_END_STREAM != 0 {
                        s.end_stream = true;
                    }
                    s.recv_consumed += len;
                }
                self.conn_recv_consumed += len;
                self.maybe_window_update(sid)?;
            }
            FRAME_HEADERS => {
                let mut block = strip_padding(&payload, flags & FLAG_PADDED != 0)?;
                if flags & FLAG_PRIORITY != 0 {
                    if block.len() < 5 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "short priority headers",
                        ));
                    }
                    block = &block[5..];
                }
                let end_stream = flags & FLAG_END_STREAM != 0;
                let end_headers = flags & FLAG_END_HEADERS != 0;
                let s = self.streams.entry(sid).or_default();
                s.header_block.extend_from_slice(block);
                if end_stream {
                    s.end_stream = true;
                }
                if end_headers {
                    self.finish_headers(sid)?;
                }
            }
            FRAME_CONTINUATION => {
                let s = self.streams.entry(sid).or_default();
                s.header_block.extend_from_slice(&payload);
                if flags & FLAG_END_HEADERS != 0 {
                    self.finish_headers(sid)?;
                }
            }
            FRAME_PRIORITY => {}
            FRAME_RST_STREAM => {
                let code = if payload.len() >= 4 {
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                } else {
                    0
                };
                if let Some(s) = self.streams.get_mut(&sid) {
                    s.reset = Some(code);
                }
            }
            FRAME_SETTINGS => {
                if flags & FLAG_ACK == 0 {
                    for chunk in payload.as_chunks::<6>().0 {
                        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                        let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                        match id {
                            SETTINGS_MAX_FRAME_SIZE => {
                                self.peer_max_frame = (val as usize).clamp(16_384, 1 << 24)
                            }
                            SETTINGS_INITIAL_WINDOW_SIZE => {
                                let delta = val as i64 - self.peer_initial_window as i64;
                                self.peer_initial_window = val;
                                for s in self.streams.values_mut() {
                                    s.send_window += delta;
                                }
                            }
                            SETTINGS_HEADER_TABLE_SIZE => {
                                // Our encoder never grows its table beyond the default 4096;
                                // if the peer allows less, shrink accordingly.
                                let _ = val;
                            }
                            _ => {}
                        }
                    }
                    let mut out = Vec::new();
                    push_frame(&mut out, FRAME_SETTINGS, FLAG_ACK, 0, &[]);
                    self.conn.write_all(&out)?;
                    self.conn.flush()?;
                }
            }
            FRAME_PUSH_PROMISE => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected push promise",
                ));
            }
            FRAME_PING => {
                if flags & FLAG_ACK == 0 {
                    let mut out = Vec::new();
                    push_frame(&mut out, FRAME_PING, FLAG_ACK, 0, &payload);
                    self.conn.write_all(&out)?;
                    self.conn.flush()?;
                }
            }
            FRAME_GOAWAY => {
                let code = if payload.len() >= 8 {
                    u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]])
                } else {
                    0
                };
                let debug = if payload.len() > 8 {
                    String::from_utf8_lossy(&payload[8..]).to_string()
                } else {
                    String::new()
                };
                self.goaway = Some(format!("code {code} {debug}"));
            }
            FRAME_WINDOW_UPDATE if payload.len() >= 4 => {
                let inc = (u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                    & 0x7fff_ffff) as i64;
                if sid == 0 {
                    self.conn_send_window += inc;
                } else if let Some(s) = self.streams.get_mut(&sid) {
                    s.send_window += inc;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn finish_headers(&mut self, sid: u32) -> io::Result<()> {
        let block = match self.streams.get_mut(&sid) {
            Some(s) => std::mem::take(&mut s.header_block),
            None => return Ok(()),
        };
        if block.len() > MAX_HEADER_BLOCK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "h2 header block too large",
            ));
        }
        // The hpack crate panics on some malformed inputs (dynamic table
        // size updates); on unwinding targets turn that into an error.
        let decoder = &mut self.decoder;
        let decoded =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decoder.decode(&block)))
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "hpack decoder panicked"))?
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("hpack decode error: {e:?}"),
                    )
                })?;
        let s = self.streams.get_mut(&sid).unwrap();
        for (k, v) in decoded {
            let k = String::from_utf8_lossy(&k).to_string();
            let v = String::from_utf8_lossy(&v).to_string();
            if k == ":status" {
                if let Ok(code) = v.parse::<u16>() {
                    // Ignore 1xx informational responses.
                    if code >= 200 || s.status.is_none() {
                        s.status = Some(code);
                    }
                }
            } else {
                s.headers.push((k, v));
            }
        }
        s.headers_done = true;
        Ok(())
    }

    fn maybe_window_update(&mut self, sid: u32) -> io::Result<()> {
        let mut out = Vec::new();
        if self.conn_recv_consumed >= WINDOW_UPDATE_THRESHOLD {
            push_frame(
                &mut out,
                FRAME_WINDOW_UPDATE,
                0,
                0,
                &self.conn_recv_consumed.to_be_bytes(),
            );
            self.conn_recv_consumed = 0;
        }
        if let Some(s) = self.streams.get_mut(&sid) {
            if s.recv_consumed >= WINDOW_UPDATE_THRESHOLD && !s.end_stream {
                push_frame(
                    &mut out,
                    FRAME_WINDOW_UPDATE,
                    0,
                    sid,
                    &s.recv_consumed.to_be_bytes(),
                );
                s.recv_consumed = 0;
            }
        }
        if !out.is_empty() {
            self.conn.write_all(&out)?;
            self.conn.flush()?;
        }
        Ok(())
    }
}

fn strip_padding(payload: &[u8], padded: bool) -> io::Result<&[u8]> {
    if !padded {
        return Ok(payload);
    }
    if payload.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty padded frame",
        ));
    }
    let pad = payload[0] as usize;
    if pad + 1 > payload.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad padding"));
    }
    Ok(&payload[1..payload.len() - pad])
}

fn push_frame(out: &mut Vec<u8>, typ: u8, flags: u8, sid: u32, payload: &[u8]) {
    let len = payload.len();
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.push(typ);
    out.push(flags);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(payload);
}
