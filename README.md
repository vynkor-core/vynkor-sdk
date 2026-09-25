# vynkor-sdk

[![crates.io](https://img.shields.io/crates/v/vynkor-sdk.svg)](https://crates.io/crates/vynkor-sdk)
[![docs.rs](https://docs.rs/vynkor-sdk/badge.svg)](https://docs.rs/vynkor-sdk)

Rust SDK for writing Vynkor plugins.

A Vynkor plugin is a separate OS process supervised by the Vynkor kernel. It
talks to the kernel using the Vynkor wire protocol — 44-byte framed messages
carrying Protobuf envelopes, with optional zstd compression, HMAC-SHA256 frame
authentication, and fragmentation — over a Unix domain socket (local plugins)
or the kernel's WebSocket gateway (remote devices, D-05).

## Install

```bash
cargo add vynkor-sdk
```

## Quick start

```rust
use vynkor_sdk::{Plugin, VynkorClient, VynkorError};
use vynkor_sdk::proto::{envelope, ActionResponse, ActionStatus, Envelope, PluginManifest};

struct EchoPlugin;

impl Plugin for EchoPlugin {
    fn id(&self) -> &str {
        "echo"
    }

    fn manifest(&self) -> PluginManifest {
        PluginManifest::default()
    }

    async fn on_message(&mut self, envelope: Envelope) -> Result<Option<Envelope>, VynkorError> {
        match envelope.payload {
            Some(envelope::Payload::ActionRequest(req)) => Ok(Some(Envelope {
                payload: Some(envelope::Payload::ActionResponse(ActionResponse {
                    action_id: req.action_id,
                    status: ActionStatus::ActionOk as i32,
                    data_json: req.params_json,
                    error: String::new(),
                })),
                ..Default::default()
            })),
            _ => Ok(None),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), VynkorError> {
    EchoPlugin.run().await
}
```

`Plugin::run` connects, registers, and serves until the kernel asks the plugin
to shut down. The SDK answers `Ping` automatically, acknowledges delivered
events after `on_event` succeeds, and exits the loop on `PluginShutdown`.

### Confirmation gate (high-risk actions)

For high-risk operations (a kernel gate would violate the dumb-core rule, so
the gate lives in the plugin), [`ConfirmationGate`] splits one operation into
`request_<op>` — any caller may invoke, the action spec is marked
`requires_confirmation`, nothing executes — and `confirm_<op>`, which only
callers on the gate's allowlist may invoke and which executes the params
stored at request time. Enforcement keys on the kernel-stamped
`caller_plugin_id`, which the kernel overwrites from the real registered
sender and cannot be spoofed:

```rust
use vynkor_sdk::confirmation_gate::{ConfirmationGate, send_confirmation_request, send_confirmation};
use vynkor_sdk::proto::ActionRisk;

let gate = ConfirmationGate::new(
    "transfer",
    "Move money between accounts",
    r#"{"type":"object"}"#,
    ActionRisk::Critical,
    &["device.phone"],      // only the user's device may confirm
)?;
let (actions, action_specs) = gate.manifest_entries();
// merge into PluginManifest { actions, action_specs, .. }

// provider side, per inbound request:
gate.route(req, |params| execute(params)).await

// caller side:
let pending_id = send_confirmation_request(&mut client, "transfer", params).await?;
let resp = send_confirmation(&mut client, "transfer", &pending_id).await?;
```

Pending requests expire (default 5 minutes, configurable via
`with_pending_ttl`), and the allowlist supports `prefix.*` globs so
`"device.*"` covers every device bridge mirror. See `src/confirmation_gate.rs`
for the full API.

### WebSocket transport (remote devices)

`Plugin::run_ws(url)` is the WS mirror of `Plugin::run` for plugins that live
on a different machine than the kernel (see the Remote Devices roadmap). The
URL is the gateway endpoint, e.g. `ws://host:8080/ws`:

```rust
#[tokio::main]
async fn main() -> Result<(), VynkorError> {
    EchoPlugin.run_ws("ws://192.168.1.10:8080/ws").await
}
```

A **paired device** (E-01) sets `VYN_DEVICE_ID` + `VYN_DEVICE_SECRET`, both
issued by `vyn device connect` on the host: registration carries `device_id`
and the frame MAC keys off the device's own secret, so the host master
`jwt_secret` never leaves the host. `run_ws` refuses a half-set pair, and
refuses `VYN_JWT_SECRET` set next to a device pair. Without a device pair
the legacy `VYN_JWT_SECRET` path applies. The token is presented both in the `Sec-WebSocket-Protocol: vynkor, <jwt>` handshake header
and in the registration envelope. Registration, frame-MAC enable and reconnect
behave exactly like the UDS client. Two differences are dictated by the
gateway (R5-03): outbound frames are never zstd-compressed and never
fragmented over WS (`send_fragmented` errors), while `FLAG_RAW_BINARY` audio
passes unchanged.

## Environment

| Variable             | Meaning                                                        |
|----------------------|----------------------------------------------------------------|
| `VYN_SOCKET_PATH` | Kernel UDS path. Default: `XDG_RUNTIME_DIR` → `/run/user/<uid>` → `~/.local/state/vyn/run` (never shared `/tmp`). |
| `VYN_JWT_TOKEN`   | JWT presented at registration (required on secured kernels).   |
| `VYN_JWT_SECRET`  | Shared secret; enables per-frame HMAC-SHA256 tags after registration. |
| `VYN_DEVICE_ID`   | Paired device id (`run_ws` only, E-01). Requires `VYN_DEVICE_SECRET`. |
| `VYN_DEVICE_SECRET` | Paired device's own MAC secret (`run_ws` only, E-01); replaces `VYN_JWT_SECRET`. |

## Protocol coverage

The SDK re-exports the kernel framing layer (`vynkor_sdk::framing`), so the
wire format cannot drift between the two sides. All flag bits from
`docs/FRAMING.md` are handled:

| Flag               | Send                                             | Receive                                    |
|--------------------|--------------------------------------------------|--------------------------------------------|
| `FLAG_MAC_PRESENT` | automatic after secured registration             | verified; untagged frames rejected         |
| `FLAG_COMPRESSED`  | automatic for payloads ≥ 64 KiB (UDS only — the WS gateway rejects compressed inbound frames, so the WS transport never compresses) | decompressed + normalized by `read_frame`  |
| `FLAG_FRAGMENTED`  | `VynkorClient::send_fragmented` (UDS only — errors over WS) | reassembled by `recv`/`recv_frame` (64 streams, 1 MiB, 30 s bounds) |
| `FLAG_RAW_BINARY`  | `VynkorClient::send_raw_audio` (UDS and WS)      | returned raw by `recv_frame`               |

## Versioning & unpublished crates

The SDK tracks the `vynkor-wire` protocol (protocol v1.6). Before a crates.io
release the `vynkor-wire` dependency may point at a version that isn't
published yet — resolve it from git with a `[patch.crates-io]` override in
your own `Cargo.toml` (or in `.cargo/config.toml`, gitignored):

```toml
[patch.crates-io]
vynkor-wire = { git = "https://github.com/vynkor-core/vynkor-wire" }
```

To release the SDK itself (`cargo publish`), crates.io requires registry
dependencies — switch the `vynkor-wire` requirement back to a plain version
spec first, then publish `vynkor-wire` before `vynkor-sdk`.

## Client API

For lower-level control, use `VynkorClient` directly:

```rust,ignore
let mut client = VynkorClient::connect_with_secret(&socket, secret).await?;
let ack = client.register_with_token("weather", manifest, &jwt).await?;

client.subscribe(vec!["alarm.fired".into()]).await?;
let resp = client.send_action("get_weather", br#"{"city":"Berlin"}"#, 5_000).await?;
let ack = client.publish_event("weather.updated", br#"{"city":"Berlin"}"#, 5_000).await?;
let latency = client.ping().await?;

let action_id = client.send_action_streaming("transcribe", 30_000).await?;
client.send_request_chunk(&action_id, 0, b"hi", true).await?;
client.send_response_chunk(&action_id, 0, b"ok").await?;
client.close_session(&action_id, "done").await?;
```

Over WebSocket, connect with the gateway URL instead — same API afterwards:

```rust,ignore
// paired device (E-01): token + device_secret from `vyn device connect`
let mut client =
    VynkorClient::connect_ws_device("ws://host:8080/ws", &jwt, "phone-1", device_secret).await?;
let ack = client.register_with_token("phone-1", manifest, &jwt).await?;
```

`publish_event` requires `PERMISSION_EVENT_PUBLISH`; `timeout_ms == 0` uses
the kernel's 30s default. It returns the kernel's `EventPublishAck` as-is —
inspect `ack.status` yourself (`EVENT_PUBLISH_OK`/`ERROR`/`PERMISSION_DENY`)
— and only errors on a kernel `Error` envelope or on timeout.

`send_action` follows the same `timeout_ms == 0` → 30s-default convention
and returns the kernel's `ActionResponse` as-is (inspect `.status` yourself).
It errors on a kernel `Error` envelope, on an `ActionStreamAbort` for this
`action_id`, or on timeout. `send_action_streaming` fires an
`ActionRequest{streaming: true}` and returns its generated `action_id`
immediately, without waiting for any response — drive `recv`/chunks yourself
afterward. `send_request_chunk`, `send_response_chunk`, and `close_session`
are fire-and-forget sends (no response awaited); `close_session` has no
`final` flag — the response side of a stream is terminated by an ordinary
`ActionResponse`.

Requests and responses are matched on a single connection; drive
request/response traffic from one task, or use the `Plugin` trait's serve
loop.

## License

MIT
