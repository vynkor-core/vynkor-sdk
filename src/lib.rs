//! # Vynkor Rust SDK
//!
//! Write Vynkor plugins in Rust. A plugin is a separate OS process that talks
//! to the Vynkor kernel using the Vynkor wire protocol (length-prefixed frames
//! carrying Protobuf envelopes; see `docs/FRAMING.md` in the Vynkor
//! repository) over a Unix domain socket or — for remote devices — the
//! kernel's WebSocket gateway.
//!
//! ## Quick start
//!
//! ```no_run
//! use vynkor_sdk::{Plugin, VynkorClient};
//! use vynkor_sdk::proto::{envelope, ActionResponse, ActionStatus, Envelope, PluginManifest};
//! use vynkor_sdk::VynkorError;
//!
//! struct EchoPlugin;
//!
//! impl Plugin for EchoPlugin {
//!     fn id(&self) -> &str {
//!         "echo"
//!     }
//!
//!     fn manifest(&self) -> PluginManifest {
//!         PluginManifest::default()
//!     }
//!
//!     async fn on_message(&mut self, envelope: Envelope) -> Result<Option<Envelope>, VynkorError> {
//!         match envelope.payload {
//!             Some(envelope::Payload::ActionRequest(req)) => Ok(Some(Envelope {
//!                 payload: Some(envelope::Payload::ActionResponse(ActionResponse {
//!                     action_id: req.action_id,
//!                     status: ActionStatus::ActionOk as i32,
//!                     data_json: req.params_json,
//!                     error: String::new(),
//!                 })),
//!                 ..Default::default()
//!             })),
//!             _ => Ok(None),
//!         }
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), VynkorError> {
//!     EchoPlugin.run().await
//! }
//! ```
//!
//! ## Environment
//!
//! | Variable             | Meaning                                                    |
//! |----------------------|------------------------------------------------------------|
//! | `VYN_SOCKET_PATH` | Kernel UDS path (default: per-user runtime dir)            |
//! | `VYN_JWT_TOKEN`   | JWT presented at registration (secured kernels)            |
//! | `VYN_JWT_SECRET`  | Shared secret; enables per-frame HMAC-SHA256 tags          |
//! | `VYN_DEVICE_ID`   | Paired device id (WS only, E-01)                           |
//! | `VYN_DEVICE_SECRET` | Paired device's own MAC secret (WS only, E-01)           |
//!
//! [`Plugin::run_ws`](crate::Plugin::run_ws) connects over WebSocket. A
//! paired remote device sets `VYN_DEVICE_ID` + `VYN_DEVICE_SECRET` (from
//! `vyn device connect`) instead of `VYN_JWT_SECRET` — the host master
//! secret never has to leave the host.
//!
//! ## Protocol coverage
//!
//! Compression (`FLAG_COMPRESSED`), frame MACs (`FLAG_MAC_PRESENT`),
//! fragmentation (`FLAG_FRAGMENTED`) and raw audio (`FLAG_RAW_BINARY`) are all
//! handled — see [`VynkorClient`] for the transport API and [`framing`] for
//! the shared wire-format primitives. Over WebSocket, compression and
//! fragmentation are outbound-disabled to match the gateway's limits (R5-03).

pub mod client;
pub mod concurrent;
pub mod confirmation_gate;
pub mod framing;
pub mod plugin;

pub use client::VynkorClient;
pub use concurrent::{response_envelope, run_concurrent_loop, serve_concurrent, ConcurrentHandler};
pub use confirmation_gate::{
    send_confirmation, send_confirmation_request, ConfirmationGate, PendingAction,
};
pub use plugin::Plugin;
pub use vynkor_wire::WireError as VynkorError;

/// Frame-MAC primitives (HKDF session-key derivation, HMAC-SHA256 tags),
/// shared with the kernel.
pub use vynkor_wire::mac as frame_mac;

/// Generated Protobuf types for the Vynkor protocol
/// (`wire/proto/vynkor_protocol.proto`).
pub mod proto {
    pub use vynkor_wire::proto::vynkor::*;
}
