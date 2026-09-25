//! Confirmation gate (D-09): plugin-level permission separation for
//! high-risk actions.
//!
//! Splits one risky operation into two actions:
//!
//! - `request_<op>` — any registered caller may invoke; the params are
//!   stored as *pending* and the action spec is marked
//!   `requires_confirmation`. Nothing executes yet.
//! - `confirm_<op>` — only callers on the gate's confirm allowlist may
//!   invoke; it executes the params stored by the matching `request_<op>`
//!   call. Everyone else gets `PermissionDenied`.
//!
//! The kernel stays dumb on purpose (dumb-core rule — a kernel gate would
//! violate it): the gate lives entirely inside the plugin, keyed on the
//! kernel-stamped [`ActionRequest::caller_plugin_id`]. The kernel
//! overwrites that field from the real registered sender on every
//! forwarded request (see the kernel's `action_request_gets_caller_plugin_id_stamped_and_spoof_overwritten`
//! integration test), so the check cannot be spoofed by the caller.
//!
//! # Provider side — one-liner
//!
//! Build the gate once, merge [`ConfirmationGate::manifest_entries`] into
//! the plugin manifest, and route every inbound action request through
//! [`ConfirmationGate::route`]:
//!
//! ```
//! use vynkor_sdk::confirmation_gate::ConfirmationGate;
//! use vynkor_sdk::proto::ActionRisk;
//!
//! let gate = ConfirmationGate::new(
//!     "transfer",
//!     "Move money between accounts",
//!     r#"{"type":"object"}"#,
//!     ActionRisk::Critical,
//!     &["phone-1"], // only the user's paired device may confirm
//! )?;
//!
//! let (actions, action_specs) = gate.manifest_entries();
//! // merge into PluginManifest { actions, action_specs, .. }
//!
//! // in on_action: gate.route(req, |params| execute(params)).await
//! # Ok::<(), String>(())
//! ```
//!
//! Callers are kernel-stamped plugin ids. A paired device registers as its
//! `<device_id>` (single-WS, e.g. `phone-1`); legacy per-capability
//! registrations show up as `<device_id>.<cap>` (`phone-1.geo`, …). The
//! allowlist supports a trailing `.*` suffix: `"phone-1.*"` matches every
//! `phone-1.<cap>` but not the bare `phone-1` — list both to cover either
//! registration style.
//!
//! # Caller side
//!
//! The requesting side (e.g. the AI) calls
//! [`send_confirmation_request`] to obtain a `pending_id`, then the user's
//! device calls [`send_confirmation`] with it. Both are thin wrappers over
//! [`VynkorClient::send_action`] on `request_<op>` / `confirm_<op>`.
//!
//! # Pending store
//!
//! Pending requests expire after [`ConfirmationGate::with_pending_ttl`]
//! (default 5 minutes) — a request nobody confirms is forgotten, so a
//! hostile caller cannot accumulate unbounded pending entries.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::client::VynkorClient;
use crate::concurrent::response_envelope;
use crate::proto::{
    envelope, ActionRequest, ActionResponse, ActionRisk, ActionSpec, ActionStatus, Envelope,
};
use crate::VynkorError;

/// Default lifetime of an unconfirmed pending request.
const DEFAULT_PENDING_TTL: Duration = Duration::from_secs(300);

/// A stored `request_<op>` awaiting confirmation. Removed (and executed) by
/// `confirm_<op>`, or swept once [`ConfirmationGate::pending_ttl`] elapses.
#[derive(Debug, Clone)]
pub struct PendingAction {
    /// The `request_<op>` action name that created this entry.
    pub action: String,
    /// Params from the original request — this exact payload is handed to
    /// the executor at confirmation time, so the confirming caller cannot
    /// swap in different params between request and confirm.
    pub params: Vec<u8>,
    /// Kernel-stamped id of the plugin that requested; for audit.
    pub caller_plugin_id: String,
    /// When the request was stored; drives expiry.
    pub created_at: Instant,
}

/// Plugin-side confirmation gate for one high-risk operation. Cheap to
/// clone-free share behind `Arc` across concurrent handler tasks — the only
/// interior state is the pending map behind a `std::sync::Mutex`, never held
/// across an `.await`.
pub struct ConfirmationGate {
    op: String,
    description: String,
    params_schema: String,
    risk: ActionRisk,
    /// Callers allowed to confirm. Entries are exact plugin ids, or a
    /// `prefix.*` glob matching any caller whose id starts with `prefix`.
    confirm_callers: Vec<String>,
    pending_ttl: Duration,
    pending: Mutex<std::collections::HashMap<String, PendingAction>>,
}

fn next_seq() -> u64 {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn validate_op(op: &str) -> Result<(), String> {
    if op.is_empty() {
        return Err("operation name must not be empty".into());
    }
    if !op
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("operation name may only contain ASCII alphanumerics, '-' and '_'".into());
    }
    if op.starts_with("request_") || op.starts_with("confirm_") {
        return Err("operation name must not start with request_/confirm_ (would collide with the gate's own action names)".into());
    }
    Ok(())
}

impl ConfirmationGate {
    /// Create a gate for one operation, named `request_<op>` /
    /// `confirm_<op>`. `description` and `params_schema` (JSON Schema of the
    /// request params) are served to the AI as the `request_<op>` tool spec;
    /// `risk` is the risk both specs carry. Only ids in `confirm_callers`
    /// (exact plugin ids or `prefix.*` globs) may confirm.
    pub fn new(
        op: &str,
        description: &str,
        params_schema: &str,
        risk: ActionRisk,
        confirm_callers: &[&str],
    ) -> Result<Self, String> {
        validate_op(op)?;
        if description.is_empty() {
            return Err("description must not be empty".into());
        }
        if confirm_callers.is_empty() {
            return Err("confirm_callers must name at least one caller allowed to confirm".into());
        }
        Ok(Self {
            op: op.to_string(),
            description: description.to_string(),
            params_schema: params_schema.to_string(),
            risk,
            confirm_callers: confirm_callers.iter().map(|s| s.to_string()).collect(),
            pending_ttl: DEFAULT_PENDING_TTL,
            pending: Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Override how long an unconfirmed pending request survives. The gate
    /// forgets (and refuses to execute) requests older than this.
    pub fn with_pending_ttl(mut self, ttl: Duration) -> Self {
        self.pending_ttl = ttl;
        self
    }

    /// The operation name (`"transfer"` → actions `request_transfer` /
    /// `confirm_transfer`).
    pub fn op(&self) -> &str {
        &self.op
    }

    /// Manifest entries to merge into the plugin's [`crate::proto::PluginManifest`]:
    /// the two action names for `actions[]` (so the router resolves them) and
    /// the two [`ActionSpec`]s served to the AI (D-08) — `request_<op>`
    /// marked `requires_confirmation`, `confirm_<op>` carrying its
    /// `pending_id` param schema.
    pub fn manifest_entries(&self) -> (Vec<String>, Vec<ActionSpec>) {
        let request = format!("request_{}", self.op);
        let confirm = format!("confirm_{}", self.op);
        let actions = vec![request.clone(), confirm.clone()];
        let specs = vec![
            ActionSpec {
                name: request.clone(),
                description: format!(
                    "{} — requests execution; the operation only runs after an approved caller confirms (requires_confirmation).",
                    self.description
                ),
                params_schema: self.params_schema.clone(),
                risk: self.risk as i32,
                requires_confirmation: true,
            },
            ActionSpec {
                name: confirm.clone(),
                description: format!(
                    "{} — executes a previously requested operation; only approved callers may invoke.",
                    self.description
                ),
                params_schema: "{\"type\":\"object\",\"properties\":{\"pending_id\":{\"type\":\"string\"}},\"required\":[\"pending_id\"]}"
                    .to_string(),
                risk: self.risk as i32,
                requires_confirmation: false,
            },
        ];
        (actions, specs)
    }

    /// Route one inbound [`ActionRequest`] through the gate:
    ///
    /// - `request_<op>` from *any* caller → stores the params, replies
    ///   `{"pending_id": ..., "action": ..., "ttl_secs": ...}`.
    /// - `confirm_<op>` with `{"pending_id": ...}` from an allowlisted
    ///   caller → hands the stored params to `executor` and replies with its
    ///   result. From any other caller → `PermissionDenied` error (checked
    ///   before the pending id is looked up, so denied callers learn nothing
    ///   about which pending ids exist). Unknown or expired `pending_id` →
    ///   error.
    /// - anything else → `ActionNotFound`.
    ///
    /// Returns the response envelopes for the concurrent loop
    /// ([`crate::ConcurrentHandler`]) — a sequential
    /// [`crate::Plugin`](crate::Plugin::on_message) implementation takes the
    /// single element.
    pub async fn route<F, Fut>(&self, req: ActionRequest, executor: F) -> Vec<Envelope>
    where
        F: FnOnce(Vec<u8>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Vec<u8>, String>> + Send,
    {
        let action_id = req.action_id.clone();
        let op = &self.op;

        if let Some(requested) = req.action.strip_prefix("request_") {
            if requested != op {
                return Self::not_found(action_id);
            }
            let pending_id = self.store_request(&req);
            let ttl_secs = self.pending_ttl.as_secs();
            let data = serde_json::to_vec(&serde_json::json!({
                "pending_id": pending_id,
                "action": req.action,
                "ttl_secs": ttl_secs,
            }))
            .unwrap_or_default();
            return vec![response_envelope(action_id, Ok(data))];
        }

        if let Some(confirmed) = req.action.strip_prefix("confirm_") {
            if confirmed != op {
                return Self::not_found(action_id);
            }
            if !self.may_confirm(&req.caller_plugin_id) {
                return vec![response_envelope(
                    action_id,
                    Err(format!(
                        "permission denied: caller {} may not confirm {} (approved callers: {})",
                        req.caller_plugin_id,
                        self.op,
                        self.confirm_callers.join(", ")
                    )),
                )];
            }
            let pending_id = match Self::parse_pending_id(&req.params_json) {
                Ok(id) => id,
                Err(err) => return vec![response_envelope(action_id, Err(err))],
            };
            let pending = match self.take_pending(&pending_id) {
                Ok(pending) => pending,
                Err(err) => return vec![response_envelope(action_id, Err(err))],
            };
            // Execute with the *stored* params, never the confirm-time ones —
            // the confirming caller cannot swap in different arguments.
            let result = executor(pending.params).await;
            return vec![response_envelope(action_id, result)];
        }

        Self::not_found(action_id)
    }

    /// Whether `caller_plugin_id` is on the confirm allowlist (exact match or
    /// `prefix.*` glob — the glob keeps the dot, so `phone-1.*` matches
    /// `phone-1.geo` but neither `phone-10.geo` nor the bare `phone-1`).
    pub fn may_confirm(&self, caller_plugin_id: &str) -> bool {
        self.confirm_callers.iter().any(|allowed| {
            if let Some(prefix) = allowed.strip_suffix(".*") {
                caller_plugin_id.starts_with(prefix)
                    && caller_plugin_id.as_bytes().get(prefix.len()) == Some(&b'.')
            } else {
                caller_plugin_id == allowed
            }
        })
    }

    /// Snapshot of the pending map, for inspection/tests.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    fn store_request(&self, req: &ActionRequest) -> String {
        let mut pending = self.pending.lock().unwrap();
        self.sweep_expired(&mut pending);
        let id = format!("pending-{}-{}", unix_millis(), next_seq());
        pending.insert(
            id.clone(),
            PendingAction {
                action: req.action.clone(),
                params: req.params_json.clone(),
                caller_plugin_id: req.caller_plugin_id.clone(),
                created_at: Instant::now(),
            },
        );
        id
    }

    fn take_pending(&self, pending_id: &str) -> Result<PendingAction, String> {
        let mut pending = self.pending.lock().unwrap();
        self.sweep_expired(&mut pending);
        pending
            .remove(pending_id)
            .ok_or_else(|| format!("no pending {} request with id {}", self.op, pending_id))
    }

    fn sweep_expired(&self, pending: &mut std::collections::HashMap<String, PendingAction>) {
        pending.retain(|_, p| p.created_at.elapsed() < self.pending_ttl);
    }

    fn parse_pending_id(params_json: &[u8]) -> Result<String, String> {
        let value: serde_json::Value = serde_json::from_slice(params_json)
            .map_err(|e| format!("invalid confirm params: {e}"))?;
        value
            .get("pending_id")
            .and_then(|p| p.as_str())
            .map(str::to_string)
            .ok_or_else(|| "confirm params must include a string pending_id".to_string())
    }

    fn not_found(action_id: String) -> Vec<Envelope> {
        vec![Envelope {
            payload: Some(envelope::Payload::ActionResponse(ActionResponse {
                action_id,
                status: ActionStatus::ActionNotFound as i32,
                data_json: Vec::new(),
                error: "unknown action".into(),
            })),
            ..Default::default()
        }]
    }
}

/// Caller-side one-liner for the requesting side (e.g. the AI): invoke a
/// plugin's `request_<op>` with `params_json` and return the `pending_id`
/// the plugin assigned. Errors when the plugin replies anything but
/// `ActionOk`, or when the reply has no `pending_id`.
pub async fn send_confirmation_request(
    client: &mut VynkorClient,
    op: &str,
    params_json: &[u8],
) -> Result<String, VynkorError> {
    let resp = client
        .send_action(&format!("request_{op}"), params_json, 0)
        .await?;
    if resp.status != ActionStatus::ActionOk as i32 {
        return Err(VynkorError::Internal(format!(
            "request_{op} failed: {}",
            resp.error
        )));
    }
    let value: serde_json::Value = serde_json::from_slice(&resp.data_json)
        .map_err(|e| VynkorError::Internal(format!("invalid pending response: {e}")))?;
    value
        .get("pending_id")
        .and_then(|p| p.as_str())
        .map(str::to_string)
        .ok_or_else(|| VynkorError::Internal("pending response missing pending_id".into()))
}

/// Caller-side one-liner for the confirming side (e.g. the user's device):
/// invoke a plugin's `confirm_<op>` with a `pending_id` from
/// [`send_confirmation_request`]. Returns the provider's
/// [`ActionResponse`] as-is — a caller not on the plugin's confirm
/// allowlist gets an `ActionError` response with a permission-denied
/// message (inspect `.status` / `.error`).
pub async fn send_confirmation(
    client: &mut VynkorClient,
    op: &str,
    pending_id: &str,
) -> Result<ActionResponse, VynkorError> {
    let params = serde_json::to_vec(&serde_json::json!({ "pending_id": pending_id }))
        .map_err(|e| VynkorError::Internal(format!("failed to encode confirm params: {e}")))?;
    client
        .send_action(&format!("confirm_{op}"), &params, 0)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ActionStatus;

    fn gate(confirm_callers: &[&str]) -> ConfirmationGate {
        ConfirmationGate::new(
            "transfer",
            "Move money",
            r#"{"type":"object"}"#,
            ActionRisk::Critical,
            confirm_callers,
        )
        .unwrap()
    }

    fn request(action: &str, action_id: &str, caller: &str, params_json: &[u8]) -> ActionRequest {
        ActionRequest {
            action_id: action_id.to_string(),
            action: action.to_string(),
            params_json: params_json.to_vec(),
            timeout_ms: 0,
            streaming: false,
            caller_plugin_id: caller.to_string(),
        }
    }

    async fn run(gate: &ConfirmationGate, req: ActionRequest) -> ActionResponse {
        let envelopes = gate.route(req, |params| async move { Ok(params) }).await;
        assert_eq!(envelopes.len(), 1);
        match envelopes[0].payload.as_ref().unwrap() {
            envelope::Payload::ActionResponse(resp) => resp.clone(),
            other => panic!("expected ActionResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_stores_pending_and_returns_pending_id() {
        let g = gate(&["phone-1"]);
        let resp = run(
            &g,
            request(
                "request_transfer",
                "a1",
                "ai",
                br#"{"amount": 100, "to": "bob"}"#,
            ),
        )
        .await;
        assert_eq!(resp.status, ActionStatus::ActionOk as i32);
        let v: serde_json::Value = serde_json::from_slice(&resp.data_json).unwrap();
        let pending_id = v["pending_id"].as_str().unwrap();
        assert!(pending_id.starts_with("pending-"));
        assert_eq!(v["action"], "request_transfer");
        assert_eq!(g.pending_count(), 1);
    }

    #[tokio::test]
    async fn any_caller_can_request_even_one_not_allowed_to_confirm() {
        let g = gate(&["phone-1"]);
        let resp = run(
            &g,
            request(
                "request_transfer",
                "a1",
                "some_other_plugin",
                br#"{"amount": 1}"#,
            ),
        )
        .await;
        assert_eq!(resp.status, ActionStatus::ActionOk as i32);
    }

    #[tokio::test]
    async fn approved_caller_confirms_and_executes_stored_params() {
        let g = gate(&["phone-1"]);
        let pending_id = run(
            &g,
            request(
                "request_transfer",
                "a1",
                "ai",
                br#"{"amount": 42, "to": "bob"}"#,
            ),
        )
        .await;
        let pending_id: serde_json::Value = serde_json::from_slice(&pending_id.data_json).unwrap();
        let pending_id = pending_id["pending_id"].as_str().unwrap().to_string();

        // The executor must receive the *stored* params, not anything the
        // confirming caller supplies.
        let confirm_params = format!(r#"{{"pending_id": "{pending_id}"}}"#);
        let resp = run(
            &g,
            request(
                "confirm_transfer",
                "a2",
                "phone-1",
                confirm_params.as_bytes(),
            ),
        )
        .await;
        assert_eq!(resp.status, ActionStatus::ActionOk as i32);
        assert_eq!(
            resp.data_json, br#"{"amount": 42, "to": "bob"}"#,
            "executor ran with the request-time params"
        );
        assert_eq!(g.pending_count(), 0, "confirmed pending is consumed");
    }

    #[tokio::test]
    async fn unapproved_caller_is_denied_even_for_a_real_pending_id() {
        let g = gate(&["phone-1"]);
        let pending_resp = run(
            &g,
            request("request_transfer", "a1", "ai", br#"{"amount": 1}"#),
        )
        .await;
        let pending_id: serde_json::Value =
            serde_json::from_slice(&pending_resp.data_json).unwrap();
        let pending_id = pending_id["pending_id"].as_str().unwrap().to_string();

        // The AI calls confirm with the *real* pending id — still denied.
        let confirm_params = format!(r#"{{"pending_id": "{pending_id}"}}"#);
        let resp = run(
            &g,
            request("confirm_transfer", "a2", "ai", confirm_params.as_bytes()),
        )
        .await;
        assert_eq!(resp.status, ActionStatus::ActionError as i32);
        assert!(
            resp.error.contains("permission denied"),
            "error was: {}",
            resp.error
        );
        assert!(
            resp.error.contains("ai"),
            "error should name the denied caller: {}",
            resp.error
        );
        assert!(
            !resp.error.contains(&pending_id),
            "denied callers must not learn pending ids: {}",
            resp.error
        );
        // The pending is untouched — the real caller can still confirm it.
        assert_eq!(g.pending_count(), 1);
    }

    #[tokio::test]
    async fn prefix_glob_matches_all_sub_devices() {
        let g = gate(&["phone-1.*"]);
        let resp = run(
            &g,
            request("request_transfer", "a1", "phone-1.mic", br#"{"amount": 1}"#),
        )
        .await;
        let pending_id: serde_json::Value = serde_json::from_slice(&resp.data_json).unwrap();
        let pending_id = pending_id["pending_id"].as_str().unwrap().to_string();
        let confirm_params = format!(r#"{{"pending_id": "{pending_id}"}}"#);

        assert_eq!(
            run(
                &g,
                request(
                    "confirm_transfer",
                    "a2",
                    "phone-1.geo", // any phone-1.* mirror may confirm
                    confirm_params.as_bytes(),
                ),
            )
            .await
            .status,
            ActionStatus::ActionOk as i32
        );
        // A non-device caller still cannot.
        let confirm_params = format!(r#"{{"pending_id": "{pending_id}"}}"#);
        assert_eq!(
            run(
                &g,
                request("confirm_transfer", "a3", "ai", confirm_params.as_bytes()),
            )
            .await
            .status,
            ActionStatus::ActionError as i32
        );
    }

    #[tokio::test]
    async fn unknown_or_missing_pending_id_errors() {
        let g = gate(&["phone-1"]);
        let resp = run(
            &g,
            request(
                "confirm_transfer",
                "a1",
                "phone-1",
                br#"{"pending_id": "pending-does-not-exist"}"#,
            ),
        )
        .await;
        assert_eq!(resp.status, ActionStatus::ActionError as i32);
        assert!(resp.error.contains("no pending transfer request"));

        // Malformed params (missing pending_id).
        let resp = run(&g, request("confirm_transfer", "a2", "phone-1", br#"{}"#)).await;
        assert_eq!(resp.status, ActionStatus::ActionError as i32);
        assert!(resp.error.contains("pending_id"));
    }

    #[tokio::test]
    async fn expired_pending_is_swept_and_cannot_be_confirmed() {
        let g = gate(&["phone-1"]).with_pending_ttl(Duration::from_millis(10));
        let resp = run(
            &g,
            request("request_transfer", "a1", "ai", br#"{"amount": 1}"#),
        )
        .await;
        let pending_id: serde_json::Value = serde_json::from_slice(&resp.data_json).unwrap();
        let pending_id = pending_id["pending_id"].as_str().unwrap().to_string();
        assert_eq!(g.pending_count(), 1);

        tokio::time::sleep(Duration::from_millis(30)).await;
        // The next route call sweeps the expired entry before looking up.
        let confirm_params = format!(r#"{{"pending_id": "{pending_id}"}}"#);
        let resp = run(
            &g,
            request(
                "confirm_transfer",
                "a2",
                "phone-1",
                confirm_params.as_bytes(),
            ),
        )
        .await;
        assert_eq!(resp.status, ActionStatus::ActionError as i32);
        assert!(resp.error.contains("no pending transfer request"));
        assert_eq!(g.pending_count(), 0, "expired entry swept");
    }

    #[tokio::test]
    async fn unknown_actions_get_action_not_found() {
        let g = gate(&["phone-1"]);
        let resp = run(&g, request("do_something_else", "a1", "ai", b"{}")).await;
        assert_eq!(resp.status, ActionStatus::ActionNotFound as i32);
        // Cross-op requests are not routed by this gate either.
        let resp = run(&g, request("request_other_op", "a2", "ai", b"{}")).await;
        assert_eq!(resp.status, ActionStatus::ActionNotFound as i32);
    }

    #[test]
    fn manifest_entries_carry_confirmation_metadata() {
        let g = gate(&["phone-1"]);
        let (actions, specs) = g.manifest_entries();
        assert_eq!(actions, vec!["request_transfer", "confirm_transfer"]);

        let request_spec = specs.iter().find(|s| s.name == "request_transfer").unwrap();
        assert!(request_spec.requires_confirmation);
        assert_eq!(request_spec.risk, ActionRisk::Critical as i32);
        assert_eq!(request_spec.params_schema, r#"{"type":"object"}"#);

        let confirm_spec = specs.iter().find(|s| s.name == "confirm_transfer").unwrap();
        assert!(!confirm_spec.requires_confirmation);
        assert!(confirm_spec.params_schema.contains("pending_id"));
    }

    #[test]
    fn invalid_operations_are_rejected_at_construction() {
        assert!(ConfirmationGate::new("", "d", "{}", ActionRisk::Low, &["x"]).is_err());
        assert!(ConfirmationGate::new("bad op", "d", "{}", ActionRisk::Low, &["x"]).is_err());
        assert!(
            ConfirmationGate::new("request_x", "d", "{}", ActionRisk::Low, &["x"]).is_err(),
            "request_ prefix would collide with the gate's own naming"
        );
        assert!(
            ConfirmationGate::new("ok-op", "d", "{}", ActionRisk::Low, &[]).is_err(),
            "empty confirm allowlist is rejected"
        );
        assert!(ConfirmationGate::new("ok-op", "", "{}", ActionRisk::Low, &["x"]).is_err());
        assert!(ConfirmationGate::new("ok-op", "d", "{}", ActionRisk::Low, &["x"]).is_ok());
    }

    #[test]
    fn confirm_allowlist_matches_exact_and_glob() {
        let g = gate(&["phone-1", "host-ui"]);
        assert!(g.may_confirm("phone-1"));
        assert!(g.may_confirm("host-ui"));
        assert!(!g.may_confirm("phone-1.geo"));
        assert!(!g.may_confirm("ai"));

        let g = gate(&["phone-1.*"]);
        assert!(g.may_confirm("phone-1.mic"));
        assert!(g.may_confirm("phone-1.geo"));
        assert!(!g.may_confirm("phone-10.geo"), "prefix boundary is the dot");
        assert!(!g.may_confirm("phone-1"), "glob does not cover the bare id");
        assert!(!g.may_confirm("ai"));
    }
}
