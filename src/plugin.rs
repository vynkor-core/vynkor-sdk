//! The [`Plugin`] trait: implement it, call [`Plugin::run`], and the SDK
//! handles connection, registration, auth, the receive loop, Ping/Pong,
//! event acknowledgement, and graceful shutdown.

#![allow(async_fn_in_trait)]

use crate::client::VynkorClient;
use std::env;
use vynkor_wire::proto::vynkor::{envelope, Envelope, Event, PluginManifest, Pong};
use vynkor_wire::WireError as VynkorError;

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A Vynkor plugin. Only [`Plugin::id`], [`Plugin::manifest`] and
/// [`Plugin::on_message`] are mandatory; everything else has a sensible
/// default.
///
/// Lifecycle driven by [`Plugin::run`]:
///
/// 1. Connect to the kernel socket (`VYN_SOCKET_PATH` or the per-user
///    default; never the shared world-writable `/tmp`).
/// 2. Register, presenting `VYN_JWT_TOKEN` if set. When
///    `VYN_JWT_SECRET` is also set, all subsequent frames carry an
///    HMAC-SHA256 tag (see `docs/FRAMING.md`).
/// 3. Call [`Plugin::on_init`].
/// 4. Receive loop: Ping is answered automatically; `PluginShutdown` exits
///    the loop; [`Event`]s are passed to [`Plugin::on_event`] and
///    acknowledged when it returns `Ok`; everything else goes to
///    [`Plugin::on_message`].
/// 5. Call [`Plugin::on_shutdown`].
pub trait Plugin {
    /// Unique plugin id, e.g. `"weather"`.
    fn id(&self) -> &str;

    /// Semver version reported at registration.
    fn version(&self) -> &str {
        "1.0.0"
    }

    /// Declared capabilities: permissions, actions, event subscriptions,
    /// IPC targets.
    fn manifest(&self) -> PluginManifest;

    /// Called once after successful registration, before the receive loop.
    /// Use the client to subscribe, negotiate audio streams, etc.
    async fn on_init(&mut self, client: &mut VynkorClient) -> Result<(), VynkorError> {
        let _ = client;
        Ok(())
    }

    /// Called for every inbound envelope not handled by the SDK
    /// (Ping/Pong, PluginShutdown and Event have dedicated handling).
    /// Return `Ok(Some(reply))` to send a response back to the kernel.
    async fn on_message(&mut self, envelope: Envelope) -> Result<Option<Envelope>, VynkorError>;

    /// Called for each delivered [`Event`]. Returning `Ok(..)` makes the SDK
    /// send an `EventAck` so the kernel stops retrying. Return a reply
    /// envelope to send additional traffic.
    async fn on_event(&mut self, event: Event) -> Result<Option<Envelope>, VynkorError> {
        let _ = event;
        Ok(None)
    }

    /// Called once when the receive loop ends (kernel shutdown request,
    /// disconnect, or handler error).
    async fn on_shutdown(&mut self) -> Result<(), VynkorError> {
        Ok(())
    }

    /// Connect, register and serve until shutdown. Socket path comes from
    /// `VYN_SOCKET_PATH`, falling back to the same per-user resolution as
    /// the kernel (XDG_RUNTIME_DIR → /run/user/{uid} → ~/.local/state/vyn/run). Never
    /// the world-writable shared /tmp (BUG-006).
    async fn run(&mut self) -> Result<(), VynkorError> {
        let socket_path = env::var("VYN_SOCKET_PATH")
            .unwrap_or_else(|_| vynkor_wire::socket::default_socket_path());
        self.run_with(&socket_path).await
    }

    /// [`Plugin::run`] against an explicit socket path. JWT credentials are
    /// still read from `VYN_JWT_TOKEN` / `VYN_JWT_SECRET` when present.
    async fn run_with(&mut self, socket_path: &str) -> Result<(), VynkorError> {
        let token = env::var("VYN_JWT_TOKEN").unwrap_or_default();
        let secret = env::var("VYN_JWT_SECRET").ok().filter(|s| !s.is_empty());
        let client = match secret {
            Some(s) => VynkorClient::connect_with_secret(socket_path, s.as_bytes()).await?,
            None => VynkorClient::connect(socket_path).await?,
        };
        self.serve(client, &token).await
    }

    /// Connect to a kernel WebSocket gateway (D-05), register and serve until
    /// shutdown — the WS mirror of [`Plugin::run_with`] for remote devices.
    ///
    /// A paired device (E-01) sets `VYN_DEVICE_ID` + `VYN_DEVICE_SECRET`
    /// (both issued by `vyn device connect`); registration then carries
    /// `device_id` and the frame MAC keys off the device's own secret.
    /// Without them the legacy `VYN_JWT_SECRET` path applies. The token
    /// (`VYN_JWT_TOKEN`) is presented both in the `Sec-WebSocket-Protocol`
    /// handshake header and in the registration envelope.
    async fn run_ws(&mut self, url: &str) -> Result<(), VynkorError> {
        let token = env::var("VYN_JWT_TOKEN").unwrap_or_default();
        let creds = resolve_ws_credentials(
            non_empty_env("VYN_DEVICE_ID"),
            non_empty_env("VYN_DEVICE_SECRET"),
            non_empty_env("VYN_JWT_SECRET"),
        )?;
        let client = match creds {
            WsCredentials::Device { device_id, secret } => {
                VynkorClient::connect_ws_device(url, &token, &device_id, secret.as_bytes()).await?
            }
            WsCredentials::Shared(secret) => {
                VynkorClient::connect_ws(url, &token, Some(secret.as_bytes())).await?
            }
            WsCredentials::None => VynkorClient::connect_ws(url, &token, None).await?,
        };
        self.serve(client, &token).await
    }

    /// Register on an existing client and run the receive loop. Building
    /// block for [`Plugin::run`]; also useful in tests.
    async fn serve(
        &mut self,
        mut client: VynkorClient,
        jwt_token: &str,
    ) -> Result<(), VynkorError> {
        let ack = client
            .register_full(self.id(), self.version(), self.manifest(), jwt_token)
            .await?;
        if !ack.accepted {
            return Err(VynkorError::PermissionDenied(format!(
                "registration rejected: {}",
                ack.reject_reason
            )));
        }
        if let Err(e) = self.on_init(&mut client).await {
            let _ = self.on_shutdown().await;
            return Err(e);
        }
        // A handler error ends the receive loop (see on_shutdown's doc
        // comment): it's the plugin signalling a fatal condition. Captured
        // here so it propagates out of `serve()` after `on_shutdown()` runs,
        // instead of being silently swallowed by the `break` (T-07: Rust SDK
        // was the only one of the three not surfacing this to the caller).
        let mut handler_err: Option<VynkorError> = None;
        loop {
            let env = match client.recv().await {
                Ok(env) => env,
                Err(_) => break, // disconnect / EOF
            };
            match env.payload {
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
                Some(envelope::Payload::Event(event)) => {
                    let event_id = event.event_id.clone();
                    // On handler error no ack is sent — the kernel will retry.
                    if let Ok(reply) = self.on_event(event).await {
                        let _ = client.ack_event(&event_id).await;
                        if let Some(resp) = reply {
                            let _ = client.send("kernel", resp).await;
                        }
                    }
                }
                _ => match self.on_message(env).await {
                    Ok(Some(resp)) => {
                        let _ = client.send("kernel", resp).await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        handler_err = Some(e);
                        break;
                    }
                },
            }
        }
        self.on_shutdown().await?;
        match handler_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

fn non_empty_env(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.is_empty())
}

/// MAC credentials for [`Plugin::run_ws`], picked from the environment.
#[derive(Debug, PartialEq, Eq)]
enum WsCredentials {
    /// Paired device (E-01): register with `device_id`, MAC off `secret`.
    Device { device_id: String, secret: String },
    /// Legacy: host master `jwt_secret` (local plugins, pre-E-01 devices).
    Shared(String),
    /// Unsecured kernel (`allow_no_auth`).
    None,
}

/// Decide which credential `run_ws` uses. Inputs are the non-empty
/// `VYN_DEVICE_ID` / `VYN_DEVICE_SECRET` / `VYN_JWT_SECRET` values.
///
/// Strict on purpose: a half-set device pair or a master secret next to a
/// device pair is a misconfiguration, reported here instead of as an opaque
/// "token plugin_id mismatch" from the kernel.
fn resolve_ws_credentials(
    device_id: Option<String>,
    device_secret: Option<String>,
    jwt_secret: Option<String>,
) -> Result<WsCredentials, VynkorError> {
    match (device_id, device_secret, jwt_secret) {
        // E-01: the master secret must never reach a paired device
        (Some(_), Some(_), Some(_)) => Err(VynkorError::Internal(
            "VYN_JWT_SECRET is set alongside VYN_DEVICE_ID/VYN_DEVICE_SECRET — \
             a paired device must not hold the host master secret; unset it"
                .into(),
        )),
        (Some(device_id), Some(secret), None) => Ok(WsCredentials::Device { device_id, secret }),
        (Some(_), None, _) => Err(VynkorError::Internal(
            "VYN_DEVICE_ID is set without VYN_DEVICE_SECRET".into(),
        )),
        (None, Some(_), _) => Err(VynkorError::Internal(
            "VYN_DEVICE_SECRET is set without VYN_DEVICE_ID".into(),
        )),
        (None, None, Some(secret)) => Ok(WsCredentials::Shared(secret)),
        (None, None, None) => Ok(WsCredentials::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn device_pair_selects_device_credentials() {
        assert_eq!(
            resolve_ws_credentials(s("phone-1"), s("dev-secret"), None).unwrap(),
            WsCredentials::Device {
                device_id: "phone-1".into(),
                secret: "dev-secret".into()
            }
        );
    }

    #[test]
    fn master_secret_alone_is_legacy_shared() {
        assert_eq!(
            resolve_ws_credentials(None, None, s("master")).unwrap(),
            WsCredentials::Shared("master".into())
        );
    }

    #[test]
    fn nothing_set_is_unsecured() {
        assert_eq!(
            resolve_ws_credentials(None, None, None).unwrap(),
            WsCredentials::None
        );
    }

    #[test]
    fn master_secret_next_to_device_pair_is_rejected() {
        let err = resolve_ws_credentials(s("phone-1"), s("dev-secret"), s("master"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("VYN_JWT_SECRET"), "{err}");
    }

    #[test]
    fn half_device_pair_is_rejected_even_with_master_fallback() {
        for (id, secret) in [(s("phone-1"), None), (None, s("dev-secret"))] {
            assert!(resolve_ws_credentials(id.clone(), secret.clone(), None).is_err());
            // no silent downgrade to the shared path
            assert!(resolve_ws_credentials(id, secret, s("master")).is_err());
        }
    }
}
