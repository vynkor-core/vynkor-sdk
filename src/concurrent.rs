//! Concurrent message loop for hot-path plugins.
//!
//! The default [`Plugin::serve`](crate::Plugin::serve) loop is fully
//! sequential: `recv().await` → `on_message().await` → reply → next
//! `recv()`. That is correct for low-volume, network-bound plugins
//! (`ai`, `tts`, `stt`) but wrong for storage-class plugins that get
//! called far more often — a slow request would block every other caller.
//!
//! This module provides the ROADMAP's "hot-path plugins" pattern as a
//! first-class SDK facility instead of a per-plugin copy-paste:
//!
//! - one task owns the [`VynkorClient`] exclusively and
//!   [`tokio::select!`]s between inbound frames and an mpsc channel of
//!   completed response envelopes;
//! - each inbound [`ActionRequest`] is dispatched to a [`tokio::spawn`]ed
//!   handler task, so requests run concurrently and replies may come back
//!   out of order (the kernel matches on `action_id`);
//! - the client is never wrapped in a `Mutex`, so a handler replying can
//!   never deadlock against the loop parked inside `recv()` (a handler
//!   only needs the channel's internal queue lock);
//! - a panicking handler is caught by a double-spawn and becomes an
//!   `ACTION_ERROR` response instead of a silently dropped reply.
//!
//! # Usage
//!
//! Implement [`ConcurrentHandler`] (not [`Plugin`](crate::Plugin)) and
//! drive it from `main` via [`serve_concurrent`], or use
//! [`run_concurrent_loop`] directly in tests against a pre-registered
//! client. See `plugins/database` and `plugins/network` in the
//! `vynkor-plugins` repository for migrated examples.

use std::future::Future;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::client::VynkorClient;
use crate::proto::{
    envelope, ActionRequest, ActionResponse, ActionResponseChunk, ActionStatus, Envelope, Event,
    PluginManifest, Pong, SessionClose,
};
use crate::VynkorError;

/// Size of the mpsc channel funneling completed response envelopes from
/// spawned handler tasks back to the single task that owns the client.
const RESPONSE_CHANNEL_CAPACITY: usize = 256;

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build the response envelope for a completed (or failed) action.
pub fn response_envelope(action_id: String, result: Result<Vec<u8>, String>) -> Envelope {
    let response = match result {
        Ok(data_json) => ActionResponse {
            action_id,
            status: ActionStatus::ActionOk as i32,
            data_json,
            error: String::new(),
        },
        Err(error) => ActionResponse {
            action_id,
            status: ActionStatus::ActionError as i32,
            data_json: Vec::new(),
            error,
        },
    };
    Envelope {
        payload: Some(envelope::Payload::ActionResponse(response)),
        ..Default::default()
    }
}

/// Provider-side outlet for a streaming reply (CD-03).
///
/// Envelopes pushed here reach the kernel through the same channel as final
/// replies, in push order, while the handler is still running — so a
/// handler can emit a response incrementally instead of returning it all at
/// the end.
///
/// Kernel session contract for an `ActionRequest{streaming: true}`:
/// 1. [`ResponseSink::accept`] — `ActionResponse{ACTION_OK}` opens the
///    session (the kernel keeps the pending action alive instead of
///    evicting it, and forwards the response to the requester);
/// 2. any number of [`ResponseSink::chunk`]s, `seq` increasing from 0;
/// 3. [`ResponseSink::close`] — `SessionClose` ends the stream normally.
///    A second `ActionResponse{ACTION_OK}` does *not* end it.
///
/// To fail after accepting, send an error `ActionResponse` (e.g.
/// [`response_envelope`] with `Err`); the kernel evicts the session and
/// forwards the error. The requester cancels with its own `SessionClose`,
/// which arrives at [`ConcurrentHandler::on_message`] addressed by the same
/// `action_id` the handler saw.
#[derive(Clone)]
pub struct ResponseSink {
    tx: mpsc::Sender<Envelope>,
}

impl ResponseSink {
    /// Queue one envelope for the kernel. Waits while the loop's channel is
    /// full, so a fast producer is paced by the connection. `Err` means the
    /// loop has exited — stop producing.
    pub async fn send(&self, envelope: Envelope) -> Result<(), VynkorError> {
        self.tx
            .send(envelope)
            .await
            .map_err(|_| VynkorError::Internal("concurrent loop closed".into()))
    }

    /// Open the streaming session (`ActionResponse{ACTION_OK}`); `data_json`
    /// is optional metadata the requester sees with the acceptance.
    pub async fn accept(&self, action_id: &str, data_json: Vec<u8>) -> Result<(), VynkorError> {
        self.send(response_envelope(action_id.to_string(), Ok(data_json)))
            .await
    }

    /// One `ActionResponseChunk` of an accepted session.
    pub async fn chunk(
        &self,
        action_id: &str,
        seq: u32,
        chunk: Vec<u8>,
    ) -> Result<(), VynkorError> {
        self.send(Envelope {
            payload: Some(envelope::Payload::ActionResponseChunk(
                ActionResponseChunk {
                    action_id: action_id.to_string(),
                    seq,
                    chunk,
                },
            )),
            ..Default::default()
        })
        .await
    }

    /// End an accepted session (`SessionClose`), e.g. with reason `"done"`.
    pub async fn close(&self, action_id: &str, reason: &str) -> Result<(), VynkorError> {
        self.send(Envelope {
            payload: Some(envelope::Payload::SessionClose(SessionClose {
                action_id: action_id.to_string(),
                reason: reason.to_string(),
            })),
            ..Default::default()
        })
        .await
    }
}

/// Handler for a plugin driven by the concurrent message loop.
///
/// Unlike [`Plugin`](crate::Plugin), handlers are invoked through `&self`
/// from multiple concurrently running tasks, so implementations must be
/// `Send + Sync` and share interior state (pools, caches) behind `Arc`.
///
/// Registration metadata (`id`/`version`/`manifest`) lives on the trait so
/// [`serve_concurrent`] can perform registration itself — plugin `main`
/// functions don't need their own `PLUGIN_ID`/`PLUGIN_VERSION` constants.
pub trait ConcurrentHandler: Send + Sync + 'static {
    /// Unique plugin id, e.g. `"database"`.
    fn id(&self) -> &str;

    /// Semver version reported at registration.
    fn version(&self) -> &str {
        "1.0.0"
    }

    /// Declared capabilities: permissions, actions, event subscriptions.
    fn manifest(&self) -> PluginManifest;

    /// Called once after successful registration, before the receive loop.
    /// Use the client to subscribe, negotiate streams, etc.
    fn on_init(
        &self,
        _client: &mut VynkorClient,
    ) -> impl Future<Output = Result<(), VynkorError>> + Send {
        async { Ok(()) }
    }

    /// Pre-spawn gate, run in the loop task before a handler task is
    /// spawned for `req`. Return `Err(message)` to reject the request
    /// immediately with an `ACTION_ERROR` (no task spawned, nothing
    /// dispatched). Keep this cheap — it runs on the loop's critical
    /// path. The default accepts everything.
    ///
    /// A plugin that limits per-caller concurrency (e.g. `network`'s
    /// in-flight cap) checks its counters here. Because the check and the
    /// actual slot acquisition happen in different tasks, the authoritative
    /// acquisition (with its own over-cap rejection) belongs in
    /// [`ConcurrentHandler::on_action`] — this gate exists to avoid
    /// spawning a task at all when the answer is already known.
    fn accept(&self, _req: &ActionRequest) -> Result<(), String> {
        Ok(())
    }

    /// Handle one inbound [`ActionRequest`] in a spawned task.
    ///
    /// Return the reply envelope(s) to send back to the kernel — usually
    /// exactly one [`ActionResponse`] (use [`response_envelope`]), but a
    /// handler may return additional best-effort envelopes (e.g. an event
    /// publish sent only after the response). A panic inside this method
    /// is caught and converted into an `ACTION_ERROR` reply for the
    /// request's `action_id`, so no reply is ever dropped on the floor.
    ///
    /// Defaults to an `ACTION_ERROR` so a handler that only implements
    /// [`ConcurrentHandler::on_action_stream`] need not stub this out.
    fn on_action(&self, req: ActionRequest) -> impl Future<Output = Vec<Envelope>> + Send {
        async move {
            vec![response_envelope(
                req.action_id,
                Err("on_action not implemented".into()),
            )]
        }
    }

    /// What the loop actually calls for each inbound request. Override it
    /// to reply incrementally through `sink` (see [`ResponseSink`] for the
    /// session contract); the returned envelopes are sent after everything
    /// already pushed to `sink`. The default ignores `sink` and delegates
    /// to [`ConcurrentHandler::on_action`]. Panics are handled the same
    /// way: the request still gets an `ACTION_ERROR`.
    fn on_action_stream(
        &self,
        req: ActionRequest,
        sink: ResponseSink,
    ) -> impl Future<Output = Vec<Envelope>> + Send {
        let _ = sink;
        self.on_action(req)
    }

    /// Called for each inbound [`Event`] the kernel delivers. Returning
    /// `Ok(..)` makes the loop send an `EventAck` so the kernel stops
    /// retrying; return a reply envelope to send additional traffic.
    fn on_event(
        &self,
        _event: Event,
    ) -> impl Future<Output = Result<Option<Envelope>, VynkorError>> + Send {
        async { Ok(None) }
    }

    /// Called for any inbound envelope the loop does not handle itself
    /// (Ping, `PluginShutdown`, `ActionRequest` and `Event` are consumed
    /// by the loop). Return a reply envelope to send, or `None`.
    fn on_message(
        &self,
        _env: Envelope,
    ) -> impl Future<Output = Result<Option<Envelope>, VynkorError>> + Send {
        async { Ok(None) }
    }

    /// Called once when the loop ends (kernel shutdown request, disconnect,
    /// or handler error).
    fn on_shutdown(&self) -> impl Future<Output = Result<(), VynkorError>> + Send {
        async { Ok(()) }
    }
}

/// Register `handler` with the kernel, run [`ConcurrentHandler::on_init`],
/// then drive the concurrent message loop until shutdown.
///
/// Wraps [`run_concurrent_loop`] with registration; `jwt_token` is
/// presented at registration (empty string on unsecured kernels). A
/// rejected registration is an [`VynkorError::PermissionDenied`].
pub async fn serve_concurrent<H: ConcurrentHandler>(
    mut client: VynkorClient,
    jwt_token: &str,
    handler: Arc<H>,
) -> Result<(), VynkorError> {
    let ack = client
        .register_full(
            handler.id(),
            handler.version(),
            handler.manifest(),
            jwt_token,
        )
        .await?;
    if !ack.accepted {
        return Err(VynkorError::PermissionDenied(format!(
            "registration rejected: {}",
            ack.reject_reason
        )));
    }
    if let Err(e) = handler.on_init(&mut client).await {
        let _ = handler.on_shutdown().await;
        return Err(e);
    }
    let result = run_concurrent_loop(client, handler.clone()).await;
    let _ = handler.on_shutdown().await;
    result
}

/// Drive the concurrent message loop to completion (disconnect, EOF, or an
/// explicit `PluginShutdown`).
///
/// `client` is owned exclusively by this function — never shared behind a
/// lock. Each loop iteration is a single [`tokio::select!`] between two
/// futures:
///
/// - `client.recv()`: the next inbound frame from the kernel. This is the
///   only place the client is touched for reading, and nothing else needs
///   it while this future is pending.
/// - `rx.recv()`: the next completed response envelope pushed by a spawned
///   handler task. Handler tasks never touch the client — they only need a
///   clone of the mpsc sender, which has no relationship to the client's
///   state (there is no lock around it).
///
/// Because the client is never wrapped in a `Mutex`, a handler finishing
/// while this function is parked inside `client.recv().await` only calls
/// `tx.send(...)`, which needs the channel's internal queue lock — a
/// short-lived, always-available lock unrelated to the client. No task
/// ever waits on a resource held by a task that is itself waiting on it,
/// which is exactly the deadlock the old `Arc<Mutex<VynkorClient>>`
/// design produced.
///
/// Use this directly in tests against a pre-registered client (e.g. built
/// with [`VynkorClient::from_stream`] over `UnixStream::pair`).
pub async fn run_concurrent_loop<H: ConcurrentHandler>(
    mut client: VynkorClient,
    handler: Arc<H>,
) -> Result<(), VynkorError> {
    let (tx, mut rx) = mpsc::channel::<Envelope>(RESPONSE_CHANNEL_CAPACITY);

    loop {
        tokio::select! {
            envelope = client.recv() => {
                let envelope = match envelope {
                    Ok(env) => env,
                    Err(_) => break, // disconnect / EOF
                };

                match envelope.payload {
                    Some(envelope::Payload::Ping(ping)) => {
                        let pong = Envelope {
                            payload: Some(envelope::Payload::Pong(Pong {
                                original_timestamp: ping.timestamp,
                                server_timestamp: unix_millis(),
                            })),
                            ..Default::default()
                        };
                        let _ = client.send("kernel", pong).await;
                    }
                    Some(envelope::Payload::PluginShutdown(_)) => break,
                    Some(envelope::Payload::ActionRequest(req)) => {
                        match handler.accept(&req) {
                            Ok(()) => spawn_handler(handler.clone(), tx.clone(), req),
                            Err(error) => {
                                let envelope =
                                    response_envelope(req.action_id.clone(), Err(error));
                                let _ = client.send("kernel", envelope).await;
                            }
                        }
                    }
                    Some(envelope::Payload::Event(event)) => {
                        let event_id = event.event_id.clone();
                        // On handler error no ack is sent — the kernel will retry.
                        if let Ok(reply) = handler.on_event(event).await {
                            let _ = client.ack_event(&event_id).await;
                            if let Some(resp) = reply {
                                let _ = client.send("kernel", resp).await;
                            }
                        }
                    }
                    Some(other) => {
                        if let Ok(Some(reply)) = handler.on_message(Envelope {
                            payload: Some(other),
                            ..Default::default()
                        }).await {
                            let _ = client.send("kernel", reply).await;
                        }
                    }
                    None => {}
                }
            }
            Some(response_envelope) = rx.recv() => {
                let _ = client.send("kernel", response_envelope).await;
            }
        }
    }

    Ok(())
}

/// Spawn a handler task for `req` that always produces at least one
/// response envelope on `tx`, even if [`ConcurrentHandler::on_action`]
/// panics.
///
/// This double-spawns: the inner [`tokio::spawn`] runs the actual handler
/// and its `JoinHandle` is awaited by the outer task. A panic inside the
/// inner task is caught by Tokio and surfaced as `Err(JoinError)` to the
/// outer task rather than unwinding it, so the outer task can always reach
/// `tx.send(...)` at the end — a panicking handler becomes an
/// `ACTION_ERROR` response instead of a silently dropped reply.
fn spawn_handler<H: ConcurrentHandler>(
    handler: Arc<H>,
    tx: mpsc::Sender<Envelope>,
    req: ActionRequest,
) {
    tokio::spawn(async move {
        let inner = handler.clone();
        let action_id = req.action_id.clone();
        let sink = ResponseSink { tx: tx.clone() };
        let join = tokio::spawn(async move { inner.on_action_stream(req, sink).await });
        let envelopes = match join.await {
            Ok(envelopes) => envelopes,
            Err(join_err) => {
                vec![response_envelope(
                    action_id,
                    Err(format!("handler panicked: {join_err}")),
                )]
            }
        };
        // Receiver side only goes away when the main loop exits, at which
        // point dropping the replies is the correct behavior anyway.
        for envelope in envelopes {
            let _ = tx.send(envelope).await;
        }
    });
}
