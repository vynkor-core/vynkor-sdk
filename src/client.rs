//! Async client for the Vynkor kernel IPC socket.
//!
//! [`VynkorClient`] speaks the full Vynkor wire protocol as specified in
//! `docs/FRAMING.md` over two transports:
//!
//! - **UDS** (default) — Unix domain socket via [`VynkorClient::connect`] /
//!   [`VynkorClient::connect_with_secret`].
//! - **WebSocket** — the kernel's WS gateway (`ws://host:port/ws`) via
//!   [`VynkorClient::connect_ws`], for remote devices (see the Remote Devices
//!   roadmap, D-05). Paired devices use [`VynkorClient::connect_ws_device`]
//!   with their own `device_secret` (E-01). Registration, frame-MAC enable and reconnect mirror the
//!   UDS client exactly; the only differences are dictated by the gateway
//!   (R5-03): outbound frames are never zstd-compressed and never fragmented,
//!   while `FLAG_RAW_BINARY` passes unchanged.
//!
//! Protocol surface (transport-independent):
//!
//! - **Framing** — 44-byte header (magic, flags, length, target, crc32) via the
//!   kernel framing layer (re-exported in [`crate::framing`]).
//! - **Compression** (`FLAG_COMPRESSED`) — outbound payloads ≥ 64 KiB are
//!   transparently zstd-compressed by `write_frame_raw` on the UDS path only;
//!   inbound frames are decompressed and normalized by `read_frame`.
//! - **MAC** (`FLAG_MAC_PRESENT`) — on secured kernels every frame carries an
//!   HMAC-SHA256 tag over the *plaintext* header + payload, keyed by an
//!   HKDF-derived per-connection session key.
//! - **Fragmentation** (`FLAG_FRAGMENTED`) — large messages can be split into
//!   fragments with [`VynkorClient::send_fragmented`] on the UDS path; inbound
//!   fragments are reassembled transparently by [`VynkorClient::recv_frame`]
//!   with the same bounds the kernel enforces (64 streams, 1 MiB, 30 s).
//! - **Raw binary** (`FLAG_RAW_BINARY`) — audio frames bypass Protobuf; see
//!   [`VynkorClient::send_raw_audio`] and [`VynkorClient::recv_frame`].

use crate::framing::{read_frame, Frame, FLAG_FRAGMENTED, FLAG_MAC_PRESENT, FLAG_RAW_BINARY};
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::net::UnixStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use vynkor_wire::framing::{
    parse_frag_header, serialize_header, write_frame_raw, FRAG_HEADER_SIZE, MAX_PAYLOAD_SIZE,
};
use vynkor_wire::mac::{compute_tag, derive_session_key, verify_tag};
use vynkor_wire::proto::vynkor::{
    envelope, ActionRequest, ActionRequestChunk, ActionResponse, ActionResponseChunk,
    AudioStreamChunk, Envelope, EventAck, EventPublish, EventPublishAck, KernelCommand,
    KernelCommandAck, Ping, PluginManifest, PluginRegister, PluginRegisterAck, SessionClose,
    Subscribe, Unsubscribe,
};
use vynkor_wire::WireError as VynkorError;

/// Mirror of the kernel's inbound reassembly bounds (see `src/ipc/connection.rs`).
const MAX_REASSEMBLY_STREAMS: usize = 64;
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Default request timeout when a caller passes `timeout_ms == 0`.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

static ACTION_SEQ: AtomicU64 = AtomicU64::new(0);

struct ReassemblyBuf {
    fragments: HashMap<u16, Vec<u8>>,
    total: u16,
    target: [u8; 32],
    flags: u16,
    first_seen: Instant,
    buffered_bytes: usize,
}

impl ReassemblyBuf {
    fn is_complete(&self) -> bool {
        self.fragments.len() == self.total as usize
    }

    fn reassemble(mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.buffered_bytes);
        for seq in 0..self.total {
            if let Some(chunk) = self.fragments.remove(&seq) {
                out.extend_from_slice(&chunk);
            }
        }
        out
    }
}

/// Wire transport backing a [`VynkorClient`].
///
/// UDS delegates to the shared framing layer (`write_frame_raw`/`read_frame`),
/// which handles zstd compression of large payloads. WS mirrors those
/// semantics with the R5-03 gateway limits: one frame per WebSocket binary
/// message, never compressed (the gateway rejects `FLAG_COMPRESSED` and
/// `FLAG_FRAGMENTED` inbound and does not normalize before MAC
/// verification), while `FLAG_RAW_BINARY` passes unchanged.
enum Transport {
    Uds {
        read: OwnedReadHalf,
        write: OwnedWriteHalf,
    },
    Ws(Box<WebSocketStream<MaybeTlsStream<TcpStream>>>),
}

impl Transport {
    async fn write_frame(&mut self, frame: &Frame) -> Result<(), VynkorError> {
        match self {
            Transport::Uds { write, .. } => write_frame_raw(write, frame).await,
            Transport::Ws(ws) => {
                // No compression over WS: the gateway rejects FLAG_COMPRESSED
                // inbound, so never auto-compress (write_frame_raw would) and
                // never send fragments. A frame is one WS binary message.
                if frame.payload.len() > MAX_PAYLOAD_SIZE {
                    return Err(VynkorError::PayloadTooLarge(frame.payload.len()));
                }
                let mut out = Vec::with_capacity(44 + frame.payload.len() + 32);
                out.extend_from_slice(&serialize_header(frame));
                out.extend_from_slice(&frame.payload);
                if let Some(tag) = &frame.mac {
                    out.extend_from_slice(tag);
                }
                ws.send(WsMessage::Binary(out)).await.map_err(ws_io_error)
            }
        }
    }

    async fn read_frame(&mut self) -> Result<Frame, VynkorError> {
        match self {
            Transport::Uds { read, .. } => read_frame(read).await,
            Transport::Ws(ws) => loop {
                match ws.next().await {
                    Some(Ok(WsMessage::Binary(data))) => {
                        let mut cursor: &[u8] = &data;
                        return read_frame(&mut cursor).await;
                    }
                    Some(Ok(WsMessage::Close(_))) | None => {
                        return Err(ws_io_error(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "websocket connection closed",
                        )));
                    }
                    // WS control frames (ping/pong/text) are ignored; the
                    // kernel gateway never sends them as traffic.
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(ws_io_error(e)),
                }
            },
        }
    }
}

/// Map a tungstenite error onto [`VynkorError::Io`] so WS transport failures
/// read like stream failures (matching how UDS EOF/errors surface).
fn ws_io_error<E: Into<Box<dyn std::error::Error + Send + Sync>>>(e: E) -> VynkorError {
    VynkorError::Io(io::Error::other(e))
}

/// Async connection to the Vynkor kernel over a Unix domain socket or a
/// WebSocket.
///
/// Create with [`VynkorClient::connect`] / [`VynkorClient::connect_with_secret`]
/// (UDS, no auth / secured) or [`VynkorClient::connect_ws`] (the kernel's WS
/// gateway, e.g. for remote devices), then call [`VynkorClient::register`] /
/// [`VynkorClient::register_with_token`] before any other traffic.
pub struct VynkorClient {
    transport: Transport,
    /// MAC key material: the host's shared JWT secret for local plugins, or
    /// the paired device's own secret (E-01). None => no MAC.
    secret: Option<Vec<u8>>,
    /// Sent in `PluginRegister.device_id`. Set => kernel keys the MAC off the
    /// device's credential row, not the master secret (E-01).
    device_id: Option<String>,
    /// Per-connection MAC key, set after a secured registration.
    session_key: Option<[u8; 32]>,
    /// Inbound fragment reassembly buffers, keyed by stream_id.
    reassembly: HashMap<u32, ReassemblyBuf>,
    /// Monotonic stream id source for [`VynkorClient::send_fragmented`].
    next_stream_id: u32,
}

impl VynkorClient {
    /// Connect to an unsecured kernel (started with `allow_no_auth: true`).
    pub async fn connect(socket_path: &str) -> Result<Self, VynkorError> {
        Self::connect_inner(socket_path, None).await
    }

    /// Connect with the shared JWT secret so the client can derive the frame-MAC
    /// key after registration (required to talk to a kernel started with auth).
    pub async fn connect_with_secret(
        socket_path: &str,
        secret: &[u8],
    ) -> Result<Self, VynkorError> {
        Self::connect_inner(socket_path, Some(secret.to_vec())).await
    }

    /// Connect using the standard environment:
    /// `VYN_SOCKET_PATH` (falls back to the per-user default path) and
    /// `VYN_JWT_SECRET` (optional; enables frame MACs when set).
    pub async fn connect_from_env() -> Result<Self, VynkorError> {
        let socket_path = std::env::var("VYN_SOCKET_PATH")
            .unwrap_or_else(|_| vynkor_wire::socket::default_socket_path());
        match std::env::var("VYN_JWT_SECRET") {
            Ok(secret) if !secret.is_empty() => {
                Self::connect_with_secret(&socket_path, secret.as_bytes()).await
            }
            _ => Self::connect(&socket_path).await,
        }
    }

    /// Wrap an already-connected [`UnixStream`]. Useful for tests
    /// (`UnixStream::pair`) and custom transports.
    pub fn from_stream(stream: UnixStream, secret: Option<Vec<u8>>) -> Self {
        let (read, write) = stream.into_split();
        Self {
            transport: Transport::Uds { read, write },
            secret,
            device_id: None,
            session_key: None,
            reassembly: HashMap::new(),
            next_stream_id: 1,
        }
    }

    /// Connect to the kernel's WebSocket gateway (D-05). `url` is a
    /// `ws://` or `wss://` endpoint, normally `ws://<host>:<port>/ws`.
    ///
    /// The client always offers the `vynkor` subprotocol (the gateway's
    /// handshake marker). `jwt_token`, when non-empty, is appended to it in
    /// the `Sec-WebSocket-Protocol: vynkor, <jwt>` header — the gateway's
    /// only channel for the token; never put tokens in the URL, they leak
    /// into access logs. Pass the same token to
    /// [`VynkorClient::register_full`]; a non-empty token is required on
    /// secured kernels. `secret` enables frame MACs after registration,
    /// exactly like [`VynkorClient::connect_with_secret`] on UDS.
    ///
    /// On a dropped connection the client is left in its last state; reconnect
    /// by calling `connect_ws` again and re-registering — the session key is
    /// re-derived from the fresh nonce in the new ack (mirrors the UDS client).
    pub async fn connect_ws(
        url: &str,
        jwt_token: &str,
        secret: Option<&[u8]>,
    ) -> Result<Self, VynkorError> {
        let mut req = url
            .into_client_request()
            .map_err(|e| VynkorError::Internal(format!("invalid ws url: {e}")))?;
        let protocol = if jwt_token.is_empty() {
            "vynkor".to_string()
        } else {
            format!("vynkor, {jwt_token}")
        };
        let value = HeaderValue::from_str(&protocol)
            .map_err(|e| VynkorError::Internal(format!("invalid jwt for ws header: {e}")))?;
        req.headers_mut().insert("sec-websocket-protocol", value);
        let (ws, _resp) = connect_async(req).await.map_err(ws_io_error)?;
        Ok(Self {
            transport: Transport::Ws(Box::new(ws)),
            secret: secret.map(|s| s.to_vec()),
            device_id: None,
            session_key: None,
            reassembly: HashMap::new(),
            next_stream_id: 1,
        })
    }

    /// Connect a paired remote device (E-01) to the kernel's WS gateway.
    ///
    /// `jwt_token` and `device_secret` are the pair issued by
    /// `vyn device connect`; the master `jwt_secret` never leaves the host.
    /// Registration carries `device_id`, so the kernel checks the token's
    /// `sub` against it and derives the frame-MAC key from `device_secret`.
    pub async fn connect_ws_device(
        url: &str,
        jwt_token: &str,
        device_id: &str,
        device_secret: &[u8],
    ) -> Result<Self, VynkorError> {
        Ok(Self::connect_ws(url, jwt_token, Some(device_secret))
            .await?
            .with_device_id(device_id))
    }

    /// Mark this connection as belonging to a paired device: registration
    /// sends `device_id`, and the secret given at connect time must be that
    /// device's `device_secret`, not the host `jwt_secret`.
    pub fn with_device_id(mut self, device_id: impl Into<String>) -> Self {
        self.device_id = Some(device_id.into());
        self
    }

    async fn connect_inner(
        socket_path: &str,
        secret: Option<Vec<u8>>,
    ) -> Result<Self, VynkorError> {
        let stream = UnixStream::connect(socket_path)
            .await
            .map_err(VynkorError::Io)?;
        Ok(Self::from_stream(stream, secret))
    }

    /// True once a secured registration has derived the per-connection MAC key.
    pub fn is_secured(&self) -> bool {
        self.session_key.is_some()
    }

    // ── Registration ────────────────────────────────────────────────

    /// Register without a JWT (unsecured kernel only).
    pub async fn register(
        &mut self,
        plugin_id: &str,
        manifest: PluginManifest,
    ) -> Result<PluginRegisterAck, VynkorError> {
        self.register_with_token(plugin_id, manifest, "").await
    }

    /// Register presenting a JWT. On a secured kernel the ack carries a
    /// `session_nonce`; combined with the shared secret and plugin id it yields
    /// the frame-MAC key used for all subsequent frames.
    pub async fn register_with_token(
        &mut self,
        plugin_id: &str,
        manifest: PluginManifest,
        jwt_token: &str,
    ) -> Result<PluginRegisterAck, VynkorError> {
        self.register_full(plugin_id, "1.0.0", manifest, jwt_token)
            .await
    }

    /// Register with an explicit plugin version string.
    pub async fn register_full(
        &mut self,
        plugin_id: &str,
        version: &str,
        manifest: PluginManifest,
        jwt_token: &str,
    ) -> Result<PluginRegisterAck, VynkorError> {
        let env = Envelope {
            payload: Some(envelope::Payload::PluginRegister(PluginRegister {
                plugin_id: plugin_id.to_string(),
                version: version.to_string(),
                manifest: Some(manifest),
                jwt_token: jwt_token.to_string(),
                device_id: self.device_id.clone().unwrap_or_default(),
                ..Default::default()
            })),
            ..Default::default()
        };
        self.send("kernel", env).await?;
        let response = self.recv().await?;
        match response.payload {
            Some(envelope::Payload::PluginRegisterAck(ack)) => {
                if let Some(secret) = &self.secret {
                    if !ack.session_nonce.is_empty() {
                        self.session_key =
                            Some(derive_session_key(secret, &ack.session_nonce, plugin_id));
                    }
                }
                Ok(ack)
            }
            Some(envelope::Payload::Error(err)) => Err(VynkorError::Internal(format!(
                "registration rejected: {} ({})",
                err.message, err.details
            ))),
            _ => Err(VynkorError::Internal("expected PluginRegisterAck".into())),
        }
    }

    // ── Sending ─────────────────────────────────────────────────────

    /// Encode and send a Protobuf [`Envelope`] to `target` ("kernel" or a
    /// peer plugin id).
    pub async fn send(&mut self, target: &str, envelope: Envelope) -> Result<(), VynkorError> {
        let mut payload = Vec::new();
        envelope
            .encode(&mut payload)
            .map_err(|_| VynkorError::Internal("encode failed".into()))?;
        self.send_raw(target, payload).await
    }

    /// Send a pre-encoded payload. Applies MAC when secured; on the UDS path
    /// payloads ≥ 64 KiB are transparently zstd-compressed by the framing
    /// layer (the WS path never compresses — see [`Transport`]).
    pub async fn send_raw(&mut self, target: &str, payload: Vec<u8>) -> Result<(), VynkorError> {
        self.send_raw_with_flags(target, 0, payload).await
    }

    /// Send a raw payload with explicit extra flags ORed into the frame header
    /// (e.g. [`FLAG_RAW_BINARY`]). MAC is added automatically when secured.
    pub async fn send_raw_with_flags(
        &mut self,
        target: &str,
        extra_flags: u16,
        payload: Vec<u8>,
    ) -> Result<(), VynkorError> {
        let base_flags = if self.session_key.is_some() {
            FLAG_MAC_PRESENT
        } else {
            0
        };
        let mut frame = build_frame(target, base_flags | extra_flags, payload);
        if let Some(key) = &self.session_key {
            let header = serialize_header(&frame);
            frame.mac = Some(compute_tag(key, &header, &frame.payload));
        }
        self.transport.write_frame(&frame).await
    }

    /// Split `payload` into `FLAG_FRAGMENTED` frames of at most `chunk_size`
    /// data bytes each and send them on a fresh stream id. The kernel
    /// reassembles them into a single logical frame for `target`.
    ///
    /// Bounds mirror the kernel: total payload ≤ 1 MiB, ≤ 65 535 fragments.
    /// UDS only — the WS gateway rejects fragmented inbound frames (R5-03),
    /// so this errors on a WebSocket transport.
    pub async fn send_fragmented(
        &mut self,
        target: &str,
        payload: &[u8],
        chunk_size: usize,
    ) -> Result<(), VynkorError> {
        if matches!(self.transport, Transport::Ws(_)) {
            return Err(VynkorError::Internal(
                "fragmented frames are not supported over WebSocket (R5-03)".into(),
            ));
        }
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(VynkorError::PayloadTooLarge(payload.len()));
        }
        if chunk_size == 0 || chunk_size + FRAG_HEADER_SIZE > MAX_PAYLOAD_SIZE {
            return Err(VynkorError::Internal(format!(
                "invalid fragment chunk_size: {chunk_size}"
            )));
        }
        let total = payload.len().div_ceil(chunk_size).max(1);
        if total > u16::MAX as usize {
            return Err(VynkorError::Internal(format!(
                "payload needs {total} fragments; max is {}",
                u16::MAX
            )));
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1).max(1);
        let fragment_id = (stream_id & 0xFFFF) as u16;

        for (seq, chunk) in payload.chunks(chunk_size).enumerate() {
            let mut frag_payload = Vec::with_capacity(FRAG_HEADER_SIZE + chunk.len());
            frag_payload.extend_from_slice(&fragment_id.to_be_bytes());
            frag_payload.extend_from_slice(&(seq as u16).to_be_bytes());
            frag_payload.extend_from_slice(&(total as u16).to_be_bytes());
            frag_payload.extend_from_slice(&stream_id.to_be_bytes());
            frag_payload.extend_from_slice(chunk);
            self.send_raw_with_flags(target, FLAG_FRAGMENTED, frag_payload)
                .await?;
        }
        Ok(())
    }

    // ── Receiving ───────────────────────────────────────────────────

    /// Receive the next complete frame. Verifies the MAC on secured
    /// connections, reassembles fragmented messages, and returns raw-binary
    /// frames as-is (check `frame.flags & FLAG_RAW_BINARY`). Compressed frames
    /// arrive already decompressed and normalized by the framing layer.
    pub async fn recv_frame(&mut self) -> Result<Frame, VynkorError> {
        loop {
            let frame = self.transport.read_frame().await?;
            self.verify_frame_mac(&frame)?;
            if frame.flags & FLAG_FRAGMENTED != 0 {
                if let Some(complete) = self.absorb_fragment(frame)? {
                    return Ok(complete);
                }
                continue;
            }
            return Ok(frame);
        }
    }

    /// Receive and decode the next Protobuf [`Envelope`]. Errors on raw-binary
    /// frames; use [`VynkorClient::recv_frame`] when expecting audio.
    pub async fn recv(&mut self) -> Result<Envelope, VynkorError> {
        let frame = self.recv_frame().await?;
        if frame.flags & FLAG_RAW_BINARY != 0 {
            return Err(VynkorError::Internal(
                "received raw-binary frame; use recv_frame() for audio".into(),
            ));
        }
        Envelope::decode(frame.payload.as_ref()).map_err(VynkorError::Proto)
    }

    /// [`VynkorClient::recv`] bounded by `timeout`. Returns
    /// [`VynkorError::Timeout`] if nothing arrives in time.
    pub async fn recv_timeout(&mut self, timeout: Duration) -> Result<Envelope, VynkorError> {
        match tokio::time::timeout(timeout, self.recv()).await {
            Ok(result) => result,
            Err(_) => Err(VynkorError::Timeout),
        }
    }

    fn verify_frame_mac(&self, frame: &Frame) -> Result<(), VynkorError> {
        if let Some(key) = &self.session_key {
            let valid = frame.flags & FLAG_MAC_PRESENT != 0
                && match &frame.mac {
                    Some(tag) => {
                        let header = serialize_header(frame);
                        verify_tag(key, &header, &frame.payload, tag)
                    }
                    None => false,
                };
            if !valid {
                return Err(VynkorError::Internal(
                    "frame MAC verification failed".into(),
                ));
            }
        }
        Ok(())
    }

    /// Buffer one fragment; returns the reassembled frame when the set is
    /// complete. Enforces the kernel's bounds and errors (instead of silently
    /// growing) on violations.
    fn absorb_fragment(&mut self, frame: Frame) -> Result<Option<Frame>, VynkorError> {
        // Prune stale sets first so an abandoned stream cannot pin memory.
        self.reassembly
            .retain(|_, buf| buf.first_seen.elapsed() < REASSEMBLY_TIMEOUT);

        let hdr = parse_frag_header(&frame.payload)
            .ok_or_else(|| VynkorError::Internal("fragment header too short".into()))?;
        if hdr.total == 0 || hdr.sequence >= hdr.total {
            return Err(VynkorError::Internal(format!(
                "invalid fragment header: seq {} / total {}",
                hdr.sequence, hdr.total
            )));
        }
        if let Some(existing) = self.reassembly.get(&hdr.stream_id) {
            if existing.total != hdr.total {
                self.reassembly.remove(&hdr.stream_id);
                return Err(VynkorError::Internal(
                    "fragment total mismatch within stream".into(),
                ));
            }
        } else if self.reassembly.len() >= MAX_REASSEMBLY_STREAMS {
            return Err(VynkorError::Internal(
                "too many concurrent fragment streams".into(),
            ));
        }

        let chunk = frame.payload[FRAG_HEADER_SIZE..].to_vec();
        let entry = self
            .reassembly
            .entry(hdr.stream_id)
            .or_insert_with(|| ReassemblyBuf {
                fragments: HashMap::new(),
                total: hdr.total,
                target: frame.target,
                flags: frame.flags & !(FLAG_FRAGMENTED | FLAG_MAC_PRESENT),
                first_seen: Instant::now(),
                buffered_bytes: 0,
            });
        // A re-sent sequence replaces its old bytes; subtracting first keeps the
        // arithmetic underflow-free (buffered_bytes >= replaced_len always holds),
        // matching the kernel's reassembly accounting in src/ipc/connection.rs.
        let replaced_len = entry.fragments.get(&hdr.sequence).map_or(0, Vec::len);
        let new_total = entry.buffered_bytes - replaced_len + chunk.len();
        if new_total > MAX_PAYLOAD_SIZE {
            self.reassembly.remove(&hdr.stream_id);
            return Err(VynkorError::PayloadTooLarge(MAX_PAYLOAD_SIZE + 1));
        }
        entry.buffered_bytes = new_total;
        entry.fragments.insert(hdr.sequence, chunk);

        if entry.is_complete() {
            let buf = self.reassembly.remove(&hdr.stream_id).unwrap();
            let target = buf.target;
            let flags = buf.flags;
            let payload = buf.reassemble();
            let crc32 = crc32fast::hash(&payload);
            return Ok(Some(Frame {
                magic: 0x5652,
                flags,
                length: payload.len() as u32,
                target,
                crc32,
                payload: payload.into(),
                mac: None,
            }));
        }
        Ok(None)
    }

    // ── Kernel requests ─────────────────────────────────────────────

    /// Subscribe to event types ("*" for all).
    pub async fn subscribe(&mut self, event_types: Vec<String>) -> Result<(), VynkorError> {
        let env = Envelope {
            payload: Some(envelope::Payload::Subscribe(Subscribe { event_types })),
            ..Default::default()
        };
        self.send("kernel", env).await
    }

    /// Unsubscribe from event types.
    pub async fn unsubscribe(&mut self, event_types: Vec<String>) -> Result<(), VynkorError> {
        let env = Envelope {
            payload: Some(envelope::Payload::Unsubscribe(Unsubscribe { event_types })),
            ..Default::default()
        };
        self.send("kernel", env).await
    }

    /// Acknowledge a delivered event so the kernel stops retrying it.
    pub async fn ack_event(&mut self, event_id: &str) -> Result<(), VynkorError> {
        let env = Envelope {
            payload: Some(envelope::Payload::EventAck(EventAck {
                event_id: event_id.to_string(),
            })),
            ..Default::default()
        };
        self.send("kernel", env).await
    }

    /// Publish an event to the kernel event bus. The kernel namespaces
    /// `event_type` as `"plugin.<this-client's-registered-id>.<event_type>"`
    /// before delivering it to subscribers.
    /// Requires `PERMISSION_EVENT_PUBLISH`. `timeout_ms == 0` uses the
    /// kernel default of 30s.
    pub async fn publish_event(
        &mut self,
        event_type: &str,
        payload_json: &[u8],
        timeout_ms: u32,
    ) -> Result<EventPublishAck, VynkorError> {
        let env = Envelope {
            payload: Some(envelope::Payload::EventPublish(EventPublish {
                event_type: event_type.to_string(),
                payload_json: payload_json.to_vec(),
            })),
            ..Default::default()
        };
        self.send("kernel", env).await?;

        let timeout = if timeout_ms == 0 {
            DEFAULT_REQUEST_TIMEOUT
        } else {
            Duration::from_millis(timeout_ms as u64)
        };
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(VynkorError::Timeout);
            }
            let response = self.recv_timeout(remaining).await?;
            match response.payload {
                Some(envelope::Payload::EventPublishAck(ack)) => return Ok(ack),
                Some(envelope::Payload::Error(err)) => {
                    return Err(VynkorError::Internal(format!(
                        "kernel error: {} ({})",
                        err.message, err.details
                    )));
                }
                _ => continue, // unrelated traffic while waiting
            }
        }
    }

    /// Ask the kernel to perform an action (e.g. `"get_weather"`,
    /// `"play_audio"`) and await its [`ActionResponse`]. `timeout_ms == 0`
    /// uses the kernel default of 30 s. Frames that arrive while waiting but
    /// are not the matching response are discarded — drive request/response
    /// traffic from a single task.
    pub async fn send_action(
        &mut self,
        action: &str,
        params_json: &[u8],
        timeout_ms: u32,
    ) -> Result<ActionResponse, VynkorError> {
        let action_id = next_request_id("act");
        let env = Envelope {
            payload: Some(envelope::Payload::ActionRequest(ActionRequest {
                action_id: action_id.clone(),
                action: action.to_string(),
                params_json: params_json.to_vec(),
                timeout_ms,
                streaming: false,
                ..Default::default()
            })),
            ..Default::default()
        };
        self.send("kernel", env).await?;

        let timeout = if timeout_ms == 0 {
            DEFAULT_REQUEST_TIMEOUT
        } else {
            Duration::from_millis(timeout_ms as u64)
        };
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(VynkorError::Timeout);
            }
            let response = self.recv_timeout(remaining).await?;
            match response.payload {
                Some(envelope::Payload::ActionResponse(resp)) if resp.action_id == action_id => {
                    return Ok(resp);
                }
                Some(envelope::Payload::ActionStreamAbort(abort))
                    if abort.action_id == action_id =>
                {
                    return Err(VynkorError::Internal(format!(
                        "stream aborted: {}",
                        abort.reason
                    )));
                }
                Some(envelope::Payload::Error(err)) => {
                    return Err(VynkorError::Internal(format!(
                        "kernel error: {} ({})",
                        err.message, err.details
                    )));
                }
                _ => continue, // unrelated traffic while waiting
            }
        }
    }

    /// Like [`VynkorClient::send_action`] but for an action whose body will
    /// be delivered incrementally via [`VynkorClient::send_request_chunk`]
    /// rather than all at once in `params_json`. Returns the generated
    /// `action_id` immediately — this does NOT wait for an `ActionResponse`;
    /// drive that separately via [`VynkorClient::recv`]/`recv_timeout`,
    /// matching on the same `action_id` (mirrors `send_action`'s own
    /// single-task-drives-request/response convention).
    pub async fn send_action_streaming(
        &mut self,
        action: &str,
        timeout_ms: u32,
    ) -> Result<String, VynkorError> {
        let action_id = next_request_id("act");
        let env = Envelope {
            payload: Some(envelope::Payload::ActionRequest(ActionRequest {
                action_id: action_id.clone(),
                action: action.to_string(),
                params_json: vec![],
                timeout_ms,
                streaming: true,
                ..Default::default()
            })),
            ..Default::default()
        };
        self.send("kernel", env).await?;
        Ok(action_id)
    }

    /// Send one chunk of a streaming action's request body. `action_id` is
    /// the id returned by [`VynkorClient::send_action_streaming`]. Set
    /// `is_final` on the last chunk.
    pub async fn send_request_chunk(
        &mut self,
        action_id: &str,
        seq: u32,
        chunk: Vec<u8>,
        is_final: bool,
    ) -> Result<(), VynkorError> {
        let env = Envelope {
            payload: Some(envelope::Payload::ActionRequestChunk(ActionRequestChunk {
                action_id: action_id.to_string(),
                seq,
                chunk,
                r#final: is_final,
            })),
            ..Default::default()
        };
        self.send("kernel", env).await
    }

    /// Provider-side: send one chunk of a streaming action's response body.
    /// `action_id` here is the id from the `ActionRequest` the provider
    /// received (already kernel-internal, matching how a provider's terminal
    /// `ActionResponse` is addressed today). Terminate the stream with a
    /// normal `ActionResponse` — there is no separate "final" response chunk.
    pub async fn send_response_chunk(
        &mut self,
        action_id: &str,
        seq: u32,
        chunk: Vec<u8>,
    ) -> Result<(), VynkorError> {
        let env = Envelope {
            payload: Some(envelope::Payload::ActionResponseChunk(
                ActionResponseChunk {
                    action_id: action_id.to_string(),
                    seq,
                    chunk,
                },
            )),
            ..Default::default()
        };
        self.send("kernel", env).await
    }

    /// R6-04: gracefully close a long-lived streaming session. `action_id`
    /// is whichever id this side already uses to address the session — the
    /// original `action_id` on the requester side (same as
    /// [`VynkorClient::send_request_chunk`]), or the kernel-internal id on
    /// the provider side (same as [`VynkorClient::send_response_chunk`]).
    /// The kernel forwards this to the other peer and evicts the session;
    /// only valid after the session has been accepted (the provider's first
    /// `ActionResponse{status: ACTION_OK}`) — closing before that is
    /// rejected as a protocol error.
    pub async fn close_session(
        &mut self,
        action_id: &str,
        reason: &str,
    ) -> Result<(), VynkorError> {
        let env = Envelope {
            payload: Some(envelope::Payload::SessionClose(SessionClose {
                action_id: action_id.to_string(),
                reason: reason.to_string(),
            })),
            ..Default::default()
        };
        self.send("kernel", env).await
    }

    /// Send a [`KernelCommand`] and await its ack.
    pub async fn send_command(
        &mut self,
        command_id: &str,
        command: &str,
        params_json: &[u8],
    ) -> Result<KernelCommandAck, VynkorError> {
        let env = Envelope {
            payload: Some(envelope::Payload::KernelCommand(KernelCommand {
                command_id: command_id.to_string(),
                command: command.to_string(),
                params_json: params_json.to_vec(),
            })),
            ..Default::default()
        };
        self.send("kernel", env).await?;
        let response = self.recv().await?;
        match response.payload {
            Some(envelope::Payload::KernelCommandAck(ack)) => Ok(ack),
            _ => Err(VynkorError::Internal("expected KernelCommandAck".into())),
        }
    }

    /// Round-trip a Ping to the kernel; returns measured latency.
    pub async fn ping(&mut self) -> Result<Duration, VynkorError> {
        let start = Instant::now();
        let env = Envelope {
            payload: Some(envelope::Payload::Ping(Ping {
                timestamp: unix_millis(),
            })),
            ..Default::default()
        };
        self.send("kernel", env).await?;
        let response = self.recv().await?;
        match response.payload {
            Some(envelope::Payload::Pong(_)) => Ok(start.elapsed()),
            _ => Err(VynkorError::Internal("expected Pong".into())),
        }
    }

    // ── Audio ───────────────────────────────────────────────────────

    /// Send an [`AudioStreamChunk`] (stream negotiation / Opus-over-envelope)
    /// to a peer plugin. Requires `PERMISSION_AUDIO_STREAM`.
    pub async fn send_audio_chunk(
        &mut self,
        target: &str,
        chunk: AudioStreamChunk,
    ) -> Result<(), VynkorError> {
        let env = Envelope {
            payload: Some(envelope::Payload::AudioStreamChunk(chunk)),
            ..Default::default()
        };
        self.send(target, env).await
    }

    /// Send raw audio bytes (PCM_S16LE or Opus) with `FLAG_RAW_BINARY`; the
    /// router skips Protobuf decode. Stream metadata must be negotiated first
    /// via [`VynkorClient::send_audio_chunk`]. Requires
    /// `PERMISSION_AUDIO_STREAM`. Raw-binary payloads are never compressed.
    pub async fn send_raw_audio(&mut self, target: &str, data: Vec<u8>) -> Result<(), VynkorError> {
        self.send_raw_with_flags(target, FLAG_RAW_BINARY, data)
            .await
    }
}

fn build_frame(target: &str, flags: u16, payload: Vec<u8>) -> Frame {
    let mut t = [0u8; 32];
    let b = target.as_bytes();
    let n = b.len().min(32);
    t[..n].copy_from_slice(&b[..n]);
    Frame {
        magic: 0x5652,
        flags,
        length: payload.len() as u32,
        target: t,
        crc32: crc32fast::hash(&payload),
        payload: payload.into(),
        mac: None,
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn next_request_id(prefix: &str) -> String {
    let seq = ACTION_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{}-{seq}", unix_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_frame_truncates_long_target() {
        let long = "x".repeat(64);
        let frame = build_frame(&long, 0, vec![1, 2, 3]);
        assert_eq!(frame.target, [b'x'; 32]);
        assert_eq!(frame.length, 3);
        assert_eq!(frame.crc32, crc32fast::hash(&[1, 2, 3]));
    }

    #[test]
    fn request_ids_are_unique() {
        let a = next_request_id("act");
        let b = next_request_id("act");
        assert_ne!(a, b);
    }
}
