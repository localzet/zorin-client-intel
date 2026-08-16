use client_intel_core::{
    fingerprint_http1_wire, fingerprint_http2, Http1WireObservation, Http2FrameObservation,
    Http2Observation, Http2Setting,
};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_CAPTURE: usize = 128 * 1024;
const MAX_H2_FRAMES: usize = 32;

#[derive(Debug, Clone, Default)]
pub struct WireSnapshot {
    pub http1: Option<Http1WireObservation>,
    pub http2: Option<Http2Observation>,
}

#[derive(Clone, Default)]
pub struct WireState {
    inner: Arc<Mutex<WireParser>>,
}

impl WireState {
    pub fn feed(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Ok(mut parser) = self.inner.lock() {
            parser.feed(bytes);
        }
    }

    pub fn snapshot(&self) -> WireSnapshot {
        self.inner
            .lock()
            .map(|parser| parser.snapshot())
            .unwrap_or_default()
    }
}

#[derive(Default)]
struct WireParser {
    buffer: Vec<u8>,
    h1: Option<Http1WireObservation>,
    h2: Option<Http2Observation>,
    h2_offset: usize,
    protocol_decided: bool,
}

impl WireParser {
    fn feed(&mut self, bytes: &[u8]) {
        if self.h1.is_some() {
            return;
        }

        let remaining = MAX_CAPTURE.saturating_sub(self.buffer.len());
        if remaining == 0 {
            return;
        }
        self.buffer.extend_from_slice(&bytes[..bytes.len().min(remaining)]);

        if !self.protocol_decided {
            if self.buffer.len() <= H2_PREFACE.len()
                && H2_PREFACE.starts_with(self.buffer.as_slice())
            {
                if self.buffer.len() < H2_PREFACE.len() {
                    return;
                }
            }

            if self.buffer.starts_with(H2_PREFACE) {
                self.protocol_decided = true;
                self.h2_offset = H2_PREFACE.len();
                self.h2 = Some(Http2Observation {
                    client_preface_seen: true,
                    bytes_observed: self.buffer.len(),
                    ..Http2Observation::default()
                });
            } else if let Some(end) = find_header_end(&self.buffer) {
                self.protocol_decided = true;
                self.parse_h1(end);
                return;
            }
        }

        if self.h2.is_some() {
            self.parse_h2_frames();
        }
    }

    fn parse_h1(&mut self, end: usize) {
        let header_bytes = &self.buffer[..end];
        let text = String::from_utf8_lossy(header_bytes);
        let mut lines = text.split("\r\n");
        let request_line = lines.next().map(str::to_string);
        let mut header_names = Vec::new();
        let mut normalized_header_names = Vec::new();

        for line in lines {
            if line.is_empty() {
                break;
            }
            let Some((name, _)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim().to_string();
            normalized_header_names.push(name.to_ascii_lowercase());
            header_names.push(name);
        }

        let mut observation = Http1WireObservation {
            request_line,
            header_count: header_names.len(),
            header_names,
            normalized_header_names,
            header_bytes: end,
            fingerprint: None,
        };
        observation.fingerprint = Some(fingerprint_http1_wire(&observation));
        self.h1 = Some(observation);
    }

    fn parse_h2_frames(&mut self) {
        loop {
            if self.buffer.len().saturating_sub(self.h2_offset) < 9 {
                break;
            }

            let header = &self.buffer[self.h2_offset..self.h2_offset + 9];
            let length = ((header[0] as usize) << 16)
                | ((header[1] as usize) << 8)
                | header[2] as usize;
            let frame_type = header[3];
            let flags = header[4];
            let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]])
                & 0x7fff_ffff;
            let frame_end = self.h2_offset + 9 + length;
            if self.buffer.len() < frame_end {
                break;
            }

            let payload = &self.buffer[self.h2_offset + 9..frame_end];
            if let Some(http2) = self.h2.as_mut() {
                http2.bytes_observed = self.buffer.len();
                if http2.first_frames.len() < MAX_H2_FRAMES {
                    http2.first_frames.push(Http2FrameObservation {
                        frame_type,
                        flags,
                        stream_id,
                        length: length as u32,
                    });
                }

                match frame_type {
                    0x04 if stream_id == 0 => {
                        if flags & 0x01 != 0 {
                            http2.settings_ack_seen = true;
                        } else if length % 6 == 0 && http2.settings.is_empty() {
                            for setting in payload.chunks_exact(6) {
                                http2.settings.push(Http2Setting {
                                    id: u16::from_be_bytes([setting[0], setting[1]]),
                                    value: u32::from_be_bytes([
                                        setting[2], setting[3], setting[4], setting[5],
                                    ]),
                                });
                            }
                        }
                    }
                    0x08 if stream_id == 0 && payload.len() == 4 => {
                        let increment = u32::from_be_bytes([
                            payload[0], payload[1], payload[2], payload[3],
                        ]) & 0x7fff_ffff;
                        http2.connection_window_update.get_or_insert(increment);
                    }
                    _ => {}
                }
                http2.fingerprint = Some(fingerprint_http2(http2));
            }

            self.h2_offset = frame_end;
            if self.h2_offset >= MAX_CAPTURE {
                break;
            }
        }
    }

    fn snapshot(&self) -> WireSnapshot {
        WireSnapshot {
            http1: self.h1.clone(),
            http2: self.h2.clone(),
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
}

pub struct TapIo<T> {
    inner: T,
    state: WireState,
}

impl<T> TapIo<T> {
    pub fn new(inner: T, state: WireState) -> Self {
        Self { inner, state }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TapIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let after = buf.filled().len();
            if after > before {
                self.state.feed(&buf.filled()[before..after]);
            }
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TapIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_http1_header_order_and_case() {
        let state = WireState::default();
        state.feed(
            b"GET /inspect HTTP/1.1\r\nHost: example.test\r\nUser-Agent: zci\r\nX-Custom: 1\r\n\r\n",
        );
        let snapshot = state.snapshot();
        let h1 = snapshot.http1.expect("HTTP/1 wire observation");
        assert_eq!(h1.header_names, vec!["Host", "User-Agent", "X-Custom"]);
        assert!(h1.fingerprint.unwrap_or_default().starts_with("zh1w1_"));
    }

    #[test]
    fn captures_http2_settings_order() {
        let state = WireState::default();
        let mut bytes = H2_PREFACE.to_vec();
        bytes.extend_from_slice(&[0, 0, 12, 4, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0, 1, 0, 0, 16, 0, 0, 4, 0, 0, 255, 255]);
        state.feed(&bytes);

        let snapshot = state.snapshot();
        let h2 = snapshot.http2.expect("HTTP/2 wire observation");
        assert!(h2.client_preface_seen);
        assert_eq!(h2.settings.len(), 2);
        assert_eq!(h2.settings[0].id, 1);
        assert_eq!(h2.settings[1].id, 4);
        assert!(h2.fingerprint.unwrap_or_default().starts_with("zh2_"));
    }
}
