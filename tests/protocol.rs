//! Protocol-conformance tests for the SDK transport: framing round-trips,
//! zstd compression normalization, HMAC frame MACs, fragmentation
//! reassembly, raw-binary frames, and the Plugin trait receive loop.
//!
//! All tests run over `UnixStream::pair()` — no kernel required. Full
//! kernel-in-the-loop coverage lives in the main repository's
//! `tests/integration/test_sdk_rust.rs`.

use prost::Message;
use std::time::Duration;
use tokio::net::UnixStream;
use vynkor_sdk::frame_mac::{compute_tag, derive_session_key, verify_tag};
use vynkor_sdk::framing::{
    parse_frag_header, read_frame, serialize_header, write_frame_raw, Frame, COMPRESS_THRESHOLD,
    FLAG_FRAGMENTED, FLAG_MAC_PRESENT, FLAG_RAW_BINARY, FRAG_HEADER_SIZE, MAX_PAYLOAD_SIZE,
};
use vynkor_sdk::proto::{
    envelope, ActionRequest, ActionStatus, ActionStreamAbort, Envelope, Event, Ping,
    PluginManifest, PluginRegisterAck, PluginShutdown, SessionClose,
};
use vynkor_sdk::{Plugin, VynkorClient, VynkorError};

fn envelope_with_event(event_id: &str) -> Envelope {
    Envelope {
        payload: Some(envelope::Payload::Event(Event {
            event_id: event_id.into(),
            event_type: "test.event".into(),
            payload_json: b"{}".to_vec(),
            retry_count: 0,
        })),
        ..Default::default()
    }
}

fn decode(frame: &Frame) -> Envelope {
    Envelope::decode(frame.payload.as_ref()).expect("decode envelope")
}

#[tokio::test]
async fn send_recv_roundtrip() {
    let (a, b) = UnixStream::pair().unwrap();
    let mut client = VynkorClient::from_stream(a, None);
    let mut peer = VynkorClient::from_stream(b, None);

    client
        .send("kernel", envelope_with_event("evt-1"))
        .await
        .unwrap();
    let env = peer.recv().await.unwrap();
    match env.payload {
        Some(envelope::Payload::Event(ev)) => assert_eq!(ev.event_id, "evt-1"),
        other => panic!("unexpected payload: {other:?}"),
    }
}

#[tokio::test]
async fn large_payload_is_compressed_on_wire_and_normalized_on_read() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let mut client = VynkorClient::from_stream(a, None);

    // Highly compressible payload above the threshold.
    let payload = vec![0x42u8; COMPRESS_THRESHOLD + 1024];
    let expected = payload.clone();
    let handle = tokio::spawn(async move {
        client.send_raw("peer", payload).await.unwrap();
        client
    });

    let frame = read_frame(&mut b).await.unwrap();
    handle.await.unwrap();

    // read_frame normalizes: plaintext payload, flags/length/crc32 describe it.
    assert_eq!(&*frame.payload, expected);
    assert_eq!(frame.length as usize, expected.len());
    assert_eq!(frame.crc32, crc32fast::hash(&expected));
    assert_eq!(frame.flags & vynkor_sdk::framing::FLAG_COMPRESSED, 0);
}

#[tokio::test]
async fn mac_secured_registration_and_tagged_frames() {
    let secret = b"test-shared-secret";
    let nonce = b"0123456789abcdef".to_vec(); // 16 bytes
    let plugin_id = "mac-plugin";

    let (a, mut kernel_side) = UnixStream::pair().unwrap();
    let mut client = VynkorClient::from_stream(a, Some(secret.to_vec()));

    // Fake kernel: read the register frame, reply with an ack carrying a nonce.
    let nonce_clone = nonce.clone();
    let kernel = tokio::spawn(async move {
        let reg = read_frame(&mut kernel_side).await.unwrap();
        let env = decode(&reg);
        assert!(matches!(
            env.payload,
            Some(envelope::Payload::PluginRegister(_))
        ));

        let ack = Envelope {
            payload: Some(envelope::Payload::PluginRegisterAck(PluginRegisterAck {
                accepted: true,
                session_nonce: nonce_clone,
                ..Default::default()
            })),
            ..Default::default()
        };
        let mut buf = Vec::new();
        ack.encode(&mut buf).unwrap();
        let mut target = [0u8; 32];
        target[..plugin_id.len()].copy_from_slice(plugin_id.as_bytes());
        let frame = Frame {
            magic: 0x5652,
            flags: 0,
            length: buf.len() as u32,
            target,
            crc32: crc32fast::hash(&buf),
            payload: buf.into(),
            mac: None,
        };
        write_frame_raw(&mut kernel_side, &frame).await.unwrap();

        // Next frame from the client must carry a valid MAC.
        let secured = read_frame(&mut kernel_side).await.unwrap();
        assert_ne!(secured.flags & FLAG_MAC_PRESENT, 0, "MAC flag missing");
        let key = derive_session_key(secret, b"0123456789abcdef", plugin_id);
        let header = serialize_header(&secured);
        let tag = secured.mac.expect("tag missing");
        assert!(
            verify_tag(&key, &header, &secured.payload, &tag),
            "MAC verification failed on kernel side"
        );
    });

    let ack = client
        .register(plugin_id, PluginManifest::default())
        .await
        .unwrap();
    assert!(ack.accepted);
    assert!(client.is_secured(), "session key not derived from nonce");

    client.subscribe(vec!["*".into()]).await.unwrap();
    kernel.await.unwrap();
}

#[tokio::test]
async fn device_registration_sends_device_id_and_macs_with_device_secret() {
    // E-01: a paired device keys its MAC off its own secret, never the
    // host master; the kernel only takes that path when device_id is sent
    let device_secret = b"per-device-secret-from-pairing";
    let plugin_id = "phone-1";

    let (a, mut kernel_side) = UnixStream::pair().unwrap();
    let mut client =
        VynkorClient::from_stream(a, Some(device_secret.to_vec())).with_device_id("phone-1");

    let kernel = tokio::spawn(async move {
        let reg = read_frame(&mut kernel_side).await.unwrap();
        match decode(&reg).payload {
            Some(envelope::Payload::PluginRegister(r)) => assert_eq!(r.device_id, "phone-1"),
            other => panic!("expected PluginRegister, got {other:?}"),
        }

        let ack = Envelope {
            payload: Some(envelope::Payload::PluginRegisterAck(PluginRegisterAck {
                accepted: true,
                session_nonce: b"0123456789abcdef".to_vec(),
                ..Default::default()
            })),
            ..Default::default()
        };
        let mut buf = Vec::new();
        ack.encode(&mut buf).unwrap();
        let mut target = [0u8; 32];
        target[..plugin_id.len()].copy_from_slice(plugin_id.as_bytes());
        let frame = Frame {
            magic: 0x5652,
            flags: 0,
            length: buf.len() as u32,
            target,
            crc32: crc32fast::hash(&buf),
            payload: buf.into(),
            mac: None,
        };
        write_frame_raw(&mut kernel_side, &frame).await.unwrap();

        let secured = read_frame(&mut kernel_side).await.unwrap();
        let key = derive_session_key(device_secret, b"0123456789abcdef", plugin_id);
        let tag = secured.mac.expect("tag missing");
        assert!(
            verify_tag(&key, &serialize_header(&secured), &secured.payload, &tag),
            "MAC not keyed by the device secret"
        );
    });

    client
        .register(plugin_id, PluginManifest::default())
        .await
        .unwrap();
    assert!(client.is_secured());
    client.subscribe(vec!["*".into()]).await.unwrap();
    kernel.await.unwrap();
}

#[tokio::test]
async fn local_registration_leaves_device_id_empty() {
    let (a, mut kernel_side) = UnixStream::pair().unwrap();
    let mut client = VynkorClient::from_stream(a, None);
    let kernel = tokio::spawn(async move {
        let reg = read_frame(&mut kernel_side).await.unwrap();
        match decode(&reg).payload {
            Some(envelope::Payload::PluginRegister(r)) => assert!(r.device_id.is_empty()),
            other => panic!("expected PluginRegister, got {other:?}"),
        }
    });
    // no ack comes back; only the outbound register frame matters here
    let _ = tokio::time::timeout(
        Duration::from_millis(200),
        client.register("local-plugin", PluginManifest::default()),
    )
    .await;
    kernel.await.unwrap();
}

#[tokio::test]
async fn recv_rejects_untagged_frame_when_secured() {
    let secret = b"s3cret";
    let (a, mut kernel_side) = UnixStream::pair().unwrap();
    let mut client = VynkorClient::from_stream(a, Some(secret.to_vec()));

    let kernel = tokio::spawn(async move {
        let _reg = read_frame(&mut kernel_side).await.unwrap();
        let ack = Envelope {
            payload: Some(envelope::Payload::PluginRegisterAck(PluginRegisterAck {
                accepted: true,
                session_nonce: b"ffffffffffffffff".to_vec(),
                ..Default::default()
            })),
            ..Default::default()
        };
        let mut buf = Vec::new();
        ack.encode(&mut buf).unwrap();
        let frame = Frame {
            magic: 0x5652,
            flags: 0,
            length: buf.len() as u32,
            target: [0u8; 32],
            crc32: crc32fast::hash(&buf),
            payload: buf.into(),
            mac: None,
        };
        write_frame_raw(&mut kernel_side, &frame).await.unwrap();

        // Send a follow-up frame WITHOUT a MAC — the client must reject it.
        let mut buf2 = Vec::new();
        envelope_with_event("evt-untagged")
            .encode(&mut buf2)
            .unwrap();
        let frame2 = Frame {
            magic: 0x5652,
            flags: 0,
            length: buf2.len() as u32,
            target: [0u8; 32],
            crc32: crc32fast::hash(&buf2),
            payload: buf2.into(),
            mac: None,
        };
        write_frame_raw(&mut kernel_side, &frame2).await.unwrap();
        kernel_side
    });

    client
        .register("p", PluginManifest::default())
        .await
        .unwrap();
    assert!(client.is_secured());
    let err = client.recv().await.expect_err("untagged frame accepted");
    assert!(err.to_string().contains("MAC"));
    kernel.await.unwrap();
}

#[tokio::test]
async fn fragmentation_roundtrip_via_client_recv() {
    let (a, b) = UnixStream::pair().unwrap();
    let mut sender = VynkorClient::from_stream(a, None);
    let mut receiver = VynkorClient::from_stream(b, None);

    // A payload that needs several fragments at a small chunk size.
    let mut inner = Vec::new();
    envelope_with_event("evt-frag").encode(&mut inner).unwrap();
    let payload = inner.clone();

    let send = tokio::spawn(async move {
        sender.send_fragmented("peer", &payload, 7).await.unwrap();
        sender
    });

    let env = receiver.recv().await.unwrap();
    send.await.unwrap();
    match env.payload {
        Some(envelope::Payload::Event(ev)) => assert_eq!(ev.event_id, "evt-frag"),
        other => panic!("unexpected payload: {other:?}"),
    }
}

#[tokio::test]
async fn fragment_wire_format_matches_framing_doc() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let mut sender = VynkorClient::from_stream(a, None);

    let payload = vec![9u8; 25]; // 3 fragments of 10 + header each
    let send = tokio::spawn(async move {
        sender.send_fragmented("peer", &payload, 10).await.unwrap();
    });

    for expected_seq in 0u16..3 {
        let frame = read_frame(&mut b).await.unwrap();
        assert_ne!(frame.flags & FLAG_FRAGMENTED, 0);
        let hdr = parse_frag_header(&frame.payload).expect("frag header");
        assert_eq!(hdr.sequence, expected_seq);
        assert_eq!(hdr.total, 3);
        let chunk_len = frame.payload.len() - FRAG_HEADER_SIZE;
        assert_eq!(chunk_len, if expected_seq < 2 { 10 } else { 5 });
    }
    send.await.unwrap();
}

#[tokio::test]
async fn send_fragmented_rejects_oversized_payload() {
    let (a, _b) = UnixStream::pair().unwrap();
    let mut sender = VynkorClient::from_stream(a, None);
    let payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
    let err = sender
        .send_fragmented("peer", &payload, 65536)
        .await
        .expect_err("oversized payload accepted");
    assert!(matches!(err, VynkorError::PayloadTooLarge(_)));
}

#[tokio::test]
async fn raw_binary_frame_bypasses_protobuf() {
    let (a, b) = UnixStream::pair().unwrap();
    let mut sender = VynkorClient::from_stream(a, None);
    let mut receiver = VynkorClient::from_stream(b, None);

    let pcm = vec![0x01u8, 0x02, 0x03, 0x04];
    sender.send_raw_audio("peer", pcm.clone()).await.unwrap();

    let frame = receiver.recv_frame().await.unwrap();
    assert_ne!(frame.flags & FLAG_RAW_BINARY, 0);
    assert_eq!(&*frame.payload, pcm);
}

#[tokio::test]
async fn recv_errors_on_raw_binary_frame() {
    let (a, b) = UnixStream::pair().unwrap();
    let mut sender = VynkorClient::from_stream(a, None);
    let mut receiver = VynkorClient::from_stream(b, None);

    sender.send_raw_audio("peer", vec![1, 2, 3]).await.unwrap();
    let err = receiver.recv().await.expect_err("raw frame decoded");
    assert!(err.to_string().contains("raw-binary"));
}

#[tokio::test]
async fn recv_timeout_returns_timeout_error() {
    let (a, _b) = UnixStream::pair().unwrap();
    let mut client = VynkorClient::from_stream(a, None);
    let err = client
        .recv_timeout(Duration::from_millis(50))
        .await
        .expect_err("recv returned without traffic");
    assert!(matches!(err, VynkorError::Timeout));
}

#[test]
fn mac_tag_roundtrip_over_serialized_header() {
    let key = derive_session_key(b"secret", b"0123456789abcdef", "p");
    let frame = Frame {
        magic: 0x5652,
        flags: FLAG_MAC_PRESENT,
        length: 5,
        target: [7u8; 32],
        crc32: 0xDEADBEEF,
        payload: b"hello".to_vec().into(),
        mac: None,
    };
    let header = serialize_header(&frame);
    let tag = compute_tag(&key, &header, &frame.payload);
    assert!(verify_tag(&key, &header, &frame.payload, &tag));
    assert!(!verify_tag(&key, &header, b"hellp", &tag));
}

// ── Plugin trait receive loop ───────────────────────────────────────

struct TestPlugin {
    events_seen: Vec<String>,
    init_called: bool,
    shutdown_called: bool,
}

impl Plugin for TestPlugin {
    fn id(&self) -> &str {
        "test-plugin"
    }

    fn version(&self) -> &str {
        "2.3.4"
    }

    fn manifest(&self) -> PluginManifest {
        PluginManifest::default()
    }

    async fn on_init(&mut self, _client: &mut VynkorClient) -> Result<(), VynkorError> {
        self.init_called = true;
        Ok(())
    }

    async fn on_event(&mut self, event: Event) -> Result<Option<Envelope>, VynkorError> {
        self.events_seen.push(event.event_id);
        Ok(None)
    }

    async fn on_message(&mut self, _env: Envelope) -> Result<Option<Envelope>, VynkorError> {
        Ok(None)
    }

    async fn on_shutdown(&mut self) -> Result<(), VynkorError> {
        self.shutdown_called = true;
        Ok(())
    }
}

#[tokio::test]
async fn plugin_serve_loop_handles_ping_event_and_shutdown() {
    let (a, mut kernel_side) = UnixStream::pair().unwrap();
    let client = VynkorClient::from_stream(a, None);

    let kernel = tokio::spawn(async move {
        // Registration → ack.
        let reg = read_frame(&mut kernel_side).await.unwrap();
        let env = decode(&reg);
        match env.payload {
            Some(envelope::Payload::PluginRegister(r)) => {
                assert_eq!(r.plugin_id, "test-plugin");
                assert_eq!(r.version, "2.3.4");
            }
            other => panic!("expected register, got {other:?}"),
        }
        let ack = Envelope {
            payload: Some(envelope::Payload::PluginRegisterAck(PluginRegisterAck {
                accepted: true,
                ..Default::default()
            })),
            ..Default::default()
        };
        let mut buf = Vec::new();
        ack.encode(&mut buf).unwrap();
        let frame = Frame {
            magic: 0x5652,
            flags: 0,
            length: buf.len() as u32,
            target: [0u8; 32],
            crc32: crc32fast::hash(&buf),
            payload: buf.into(),
            mac: None,
        };
        write_frame_raw(&mut kernel_side, &frame).await.unwrap();

        let send_env = |env: Envelope| {
            let mut buf = Vec::new();
            env.encode(&mut buf).unwrap();
            Frame {
                magic: 0x5652,
                flags: 0,
                length: buf.len() as u32,
                target: [0u8; 32],
                crc32: crc32fast::hash(&buf),
                payload: buf.into(),
                mac: None,
            }
        };

        // Ping → expect Pong.
        let ping = Envelope {
            payload: Some(envelope::Payload::Ping(Ping { timestamp: 12345 })),
            ..Default::default()
        };
        write_frame_raw(&mut kernel_side, &send_env(ping))
            .await
            .unwrap();
        let pong_frame = read_frame(&mut kernel_side).await.unwrap();
        match decode(&pong_frame).payload {
            Some(envelope::Payload::Pong(p)) => assert_eq!(p.original_timestamp, 12345),
            other => panic!("expected pong, got {other:?}"),
        }

        // Event → expect EventAck.
        write_frame_raw(&mut kernel_side, &send_env(envelope_with_event("evt-42")))
            .await
            .unwrap();
        let ack_frame = read_frame(&mut kernel_side).await.unwrap();
        match decode(&ack_frame).payload {
            Some(envelope::Payload::EventAck(a)) => assert_eq!(a.event_id, "evt-42"),
            other => panic!("expected event ack, got {other:?}"),
        }

        // Shutdown → loop must exit.
        let shutdown = Envelope {
            payload: Some(envelope::Payload::PluginShutdown(PluginShutdown {
                reason: "test over".into(),
                grace_seconds: 0,
            })),
            ..Default::default()
        };
        write_frame_raw(&mut kernel_side, &send_env(shutdown))
            .await
            .unwrap();
    });

    let mut plugin = TestPlugin {
        events_seen: Vec::new(),
        init_called: false,
        shutdown_called: false,
    };
    tokio::time::timeout(Duration::from_secs(5), plugin.serve(client, ""))
        .await
        .expect("serve loop did not exit on PluginShutdown")
        .unwrap();

    assert!(plugin.init_called);
    assert!(plugin.shutdown_called);
    assert_eq!(plugin.events_seen, vec!["evt-42".to_string()]);
    kernel.await.unwrap();
}

// ── T-07: on_message handler errors must propagate out of serve() ──────────

struct FailingPlugin {
    shutdown_called: bool,
}

impl Plugin for FailingPlugin {
    fn id(&self) -> &str {
        "failing-plugin"
    }

    fn manifest(&self) -> PluginManifest {
        PluginManifest::default()
    }

    async fn on_message(&mut self, _env: Envelope) -> Result<Option<Envelope>, VynkorError> {
        Err(VynkorError::Timeout)
    }

    async fn on_shutdown(&mut self) -> Result<(), VynkorError> {
        self.shutdown_called = true;
        Ok(())
    }
}

#[tokio::test]
async fn plugin_serve_propagates_on_message_handler_error() {
    let (a, mut kernel_side) = UnixStream::pair().unwrap();
    let client = VynkorClient::from_stream(a, None);

    let kernel = tokio::spawn(async move {
        let _reg = read_frame(&mut kernel_side).await.unwrap();
        let ack = Envelope {
            payload: Some(envelope::Payload::PluginRegisterAck(PluginRegisterAck {
                accepted: true,
                ..Default::default()
            })),
            ..Default::default()
        };
        let mut buf = Vec::new();
        ack.encode(&mut buf).unwrap();
        let frame = Frame {
            magic: 0x5652,
            flags: 0,
            length: buf.len() as u32,
            target: [0u8; 32],
            crc32: crc32fast::hash(&buf),
            payload: buf.into(),
            mac: None,
        };
        write_frame_raw(&mut kernel_side, &frame).await.unwrap();

        // Any envelope not handled specially (Ping/Event/PluginShutdown) routes
        // to on_message. A bare Pong lands there.
        let msg = Envelope {
            payload: Some(envelope::Payload::Pong(vynkor_sdk::proto::Pong {
                original_timestamp: 0,
                server_timestamp: 0,
            })),
            ..Default::default()
        };
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let frame = Frame {
            magic: 0x5652,
            flags: 0,
            length: buf.len() as u32,
            target: [0u8; 32],
            crc32: crc32fast::hash(&buf),
            payload: buf.into(),
            mac: None,
        };
        write_frame_raw(&mut kernel_side, &frame).await.unwrap();
        // Keep kernel_side alive until serve() has had time to observe the
        // error and exit; drop happens when this task ends.
        let _ = read_frame(&mut kernel_side).await;
    });

    let mut plugin = FailingPlugin {
        shutdown_called: false,
    };
    let result = tokio::time::timeout(Duration::from_secs(5), plugin.serve(client, ""))
        .await
        .expect("serve loop did not exit after handler error");

    assert!(
        matches!(result, Err(VynkorError::Timeout)),
        "handler error must propagate out of serve(), got {result:?}"
    );
    assert!(
        plugin.shutdown_called,
        "on_shutdown must still run before the error propagates"
    );
    let _ = kernel.await;
}

#[tokio::test]
async fn send_action_streaming_sets_streaming_flag_and_returns_action_id() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let mut client = VynkorClient::from_stream(a, None);

    let action_id = client.send_action_streaming("upload", 5000).await.unwrap();
    assert!(action_id.starts_with("act-"));

    let env = read_frame(&mut b)
        .await
        .map(|frame| decode(&frame))
        .unwrap();
    match env.payload {
        Some(envelope::Payload::ActionRequest(req)) => {
            assert_eq!(req.action_id, action_id);
            assert_eq!(req.action, "upload");
            assert!(req.streaming);
        }
        other => panic!("expected ActionRequest, got {other:?}"),
    }
}

#[tokio::test]
async fn send_request_chunk_and_send_response_chunk_roundtrip() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let mut client = VynkorClient::from_stream(a, None);

    client
        .send_request_chunk("act-1", 0, b"hello".to_vec(), false)
        .await
        .unwrap();
    let env = read_frame(&mut b)
        .await
        .map(|frame| decode(&frame))
        .unwrap();
    match env.payload {
        Some(envelope::Payload::ActionRequestChunk(c)) => {
            assert_eq!(c.action_id, "act-1");
            assert_eq!(c.seq, 0);
            assert_eq!(c.chunk, b"hello");
            assert!(!c.r#final);
        }
        other => panic!("expected ActionRequestChunk, got {other:?}"),
    }

    client
        .send_response_chunk("kact-1", 3, b"world".to_vec())
        .await
        .unwrap();
    let env = read_frame(&mut b)
        .await
        .map(|frame| decode(&frame))
        .unwrap();
    match env.payload {
        Some(envelope::Payload::ActionResponseChunk(c)) => {
            assert_eq!(c.action_id, "kact-1");
            assert_eq!(c.seq, 3);
            assert_eq!(c.chunk, b"world");
        }
        other => panic!("expected ActionResponseChunk, got {other:?}"),
    }
}

#[tokio::test]
async fn send_action_returns_error_when_stream_aborted_for_its_action_id() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let mut client = VynkorClient::from_stream(a, None);

    let send_fut = tokio::spawn(async move { client.send_action("upload", b"{}", 2000).await });

    // Read the ActionRequest the client just sent so we know its action_id.
    let env = read_frame(&mut b)
        .await
        .map(|frame| decode(&frame))
        .unwrap();
    let action_id = match env.payload {
        Some(envelope::Payload::ActionRequest(req)) => req.action_id,
        other => panic!("expected ActionRequest, got {other:?}"),
    };

    // Reply with an abort for that exact action_id instead of an ActionResponse.
    let abort_env = Envelope {
        payload: Some(envelope::Payload::ActionStreamAbort(ActionStreamAbort {
            action_id: action_id.clone(),
            reason: "receiver backpressure".to_string(),
        })),
        ..Default::default()
    };
    let mut buf = Vec::new();
    abort_env.encode(&mut buf).unwrap();
    let frame = Frame {
        magic: 0x5652,
        flags: 0,
        length: buf.len() as u32,
        target: [0u8; 32],
        crc32: crc32fast::hash(&buf),
        payload: buf.into(),
        mac: None,
    };
    write_frame_raw(&mut b, &frame).await.unwrap();

    let err = send_fut.await.unwrap().expect_err("expected an error");
    match err {
        VynkorError::Internal(msg) => {
            assert!(msg.contains("receiver backpressure"), "got: {msg}");
        }
        other => panic!("expected Internal error, got {other:?}"),
    }
}

#[tokio::test]
async fn close_session_sends_session_close_envelope() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let mut client = VynkorClient::from_stream(a, None);

    client.close_session("act-1", "done").await.unwrap();

    let env = read_frame(&mut b)
        .await
        .map(|frame| decode(&frame))
        .unwrap();
    match env.payload {
        Some(envelope::Payload::SessionClose(close)) => {
            assert_eq!(close.action_id, "act-1");
            assert_eq!(close.reason, "done");
        }
        other => panic!("expected SessionClose, got {other:?}"),
    }
}

#[tokio::test]
async fn recv_distinguishes_session_close_from_stream_abort() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let mut client = VynkorClient::from_stream(a, None);

    // Inbound SessionClose (peer closed cleanly).
    let close_env = Envelope {
        payload: Some(envelope::Payload::SessionClose(SessionClose {
            action_id: "act-1".to_string(),
            reason: "client closed".to_string(),
        })),
        ..Default::default()
    };
    let mut buf = Vec::new();
    close_env.encode(&mut buf).unwrap();
    let frame = Frame {
        magic: 0x5652,
        flags: 0,
        length: buf.len() as u32,
        target: [0u8; 32],
        crc32: crc32fast::hash(&buf),
        payload: buf.into(),
        mac: None,
    };
    write_frame_raw(&mut b, &frame).await.unwrap();

    let received = client.recv().await.unwrap();
    match received.payload {
        Some(envelope::Payload::SessionClose(close)) => {
            assert_eq!(close.action_id, "act-1");
            assert_eq!(close.reason, "client closed");
        }
        other => panic!("expected SessionClose, got {other:?}"),
    }

    // Inbound ActionStreamAbort (kernel forced it) must decode as a
    // distinct variant — callers can tell the two apart on the same
    // action_id.
    let abort_env = Envelope {
        payload: Some(envelope::Payload::ActionStreamAbort(ActionStreamAbort {
            action_id: "act-1".to_string(),
            reason: "idle timeout".to_string(),
        })),
        ..Default::default()
    };
    let mut buf = Vec::new();
    abort_env.encode(&mut buf).unwrap();
    let frame = Frame {
        magic: 0x5652,
        flags: 0,
        length: buf.len() as u32,
        target: [0u8; 32],
        crc32: crc32fast::hash(&buf),
        payload: buf.into(),
        mac: None,
    };
    write_frame_raw(&mut b, &frame).await.unwrap();

    let received = client.recv().await.unwrap();
    match received.payload {
        Some(envelope::Payload::ActionStreamAbort(abort)) => {
            assert_eq!(abort.action_id, "act-1");
            assert_eq!(abort.reason, "idle timeout");
        }
        other => panic!("expected ActionStreamAbort, got {other:?}"),
    }
}

// ── Concurrent serve loop (hot-path plugins) ─────────────────────────

use std::sync::Arc;
use vynkor_sdk::concurrent::{response_envelope, run_concurrent_loop};
use vynkor_sdk::ConcurrentHandler;

/// Handler that echoes params back, optionally panicking on a marker
/// action and optionally rejecting a marker caller via the accept gate.
struct TestConcurrentHandler;

impl ConcurrentHandler for TestConcurrentHandler {
    fn id(&self) -> &str {
        "test-concurrent"
    }

    fn version(&self) -> &str {
        "1.2.3"
    }

    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            actions: vec!["echo".into(), "panic".into()],
            ..Default::default()
        }
    }

    fn accept(&self, req: &vynkor_sdk::proto::ActionRequest) -> Result<(), String> {
        if req.caller_plugin_id == "rejected-caller" {
            return Err("caller rejected by gate".into());
        }
        Ok(())
    }

    async fn on_action(&self, req: vynkor_sdk::proto::ActionRequest) -> Vec<Envelope> {
        if req.action == "panic" {
            panic!("boom");
        }
        vec![response_envelope(req.action_id, Ok(req.params_json))]
    }
}

#[tokio::test]
async fn concurrent_loop_handles_burst_and_ping_and_shutdown() {
    let (plugin_side, kernel_side) = UnixStream::pair().unwrap();
    let client = VynkorClient::from_stream(plugin_side, None);
    let mut kernel = VynkorClient::from_stream(kernel_side, None);
    let handler = Arc::new(TestConcurrentHandler);

    let loop_task = tokio::spawn(run_concurrent_loop(client, handler));

    // Ping → Pong handled by the loop itself.
    let ping = Envelope {
        payload: Some(envelope::Payload::Ping(Ping { timestamp: 777 })),
        ..Default::default()
    };
    kernel.send("kernel", ping).await.unwrap();
    let pong = kernel.recv().await.unwrap();
    match pong.payload {
        Some(envelope::Payload::Pong(p)) => assert_eq!(p.original_timestamp, 777),
        other => panic!("expected Pong, got {other:?}"),
    }

    // Burst of ActionRequests back-to-back — all must be answered, in any
    // order (kernel matches on action_id). Under a sequential loop a slow
    // handler would stall this; here every request gets a spawned task.
    const N: usize = 20;
    for i in 0..N {
        let req = Envelope {
            payload: Some(envelope::Payload::ActionRequest(ActionRequest {
                action_id: format!("act-{i}"),
                action: "echo".into(),
                params_json: format!("v{i}").into_bytes(),
                timeout_ms: 0,
                streaming: false,
                caller_plugin_id: "caller_x".into(),
            })),
            ..Default::default()
        };
        kernel.send("kernel", req).await.unwrap();
    }

    let mut seen = std::collections::HashSet::new();
    for _ in 0..N {
        let env = tokio::time::timeout(Duration::from_secs(5), kernel.recv())
            .await
            .expect("timed out waiting for response — loop likely deadlocked")
            .unwrap();
        match env.payload {
            Some(envelope::Payload::ActionResponse(resp)) => {
                assert_eq!(resp.status, ActionStatus::ActionOk as i32);
                assert!(
                    seen.insert(resp.action_id.clone()),
                    "duplicate response {}",
                    resp.action_id
                );
                let id: usize = resp
                    .action_id
                    .strip_prefix("act-")
                    .unwrap()
                    .parse()
                    .unwrap();
                assert_eq!(resp.data_json, format!("v{id}").into_bytes());
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    // Gate: a caller rejected by accept() gets an immediate ACTION_ERROR
    // and no handler task is spawned.
    let req = Envelope {
        payload: Some(envelope::Payload::ActionRequest(ActionRequest {
            action_id: "act-rejected".into(),
            action: "echo".into(),
            params_json: Vec::new(),
            timeout_ms: 0,
            streaming: false,
            caller_plugin_id: "rejected-caller".into(),
        })),
        ..Default::default()
    };
    kernel.send("kernel", req).await.unwrap();
    let env = kernel.recv().await.unwrap();
    match env.payload {
        Some(envelope::Payload::ActionResponse(resp)) => {
            assert_eq!(resp.status, ActionStatus::ActionError as i32);
            assert!(resp.error.contains("gate"), "error was: {}", resp.error);
        }
        other => panic!("expected rejected ActionResponse, got {other:?}"),
    }

    // Shutdown → loop exits cleanly.
    let shutdown = Envelope {
        payload: Some(envelope::Payload::PluginShutdown(PluginShutdown {
            reason: "test done".into(),
            grace_seconds: 0,
        })),
        ..Default::default()
    };
    kernel.send("kernel", shutdown).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), loop_task)
        .await
        .expect("run_concurrent_loop did not exit after PluginShutdown")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn concurrent_loop_turns_handler_panic_into_action_error() {
    let (plugin_side, kernel_side) = UnixStream::pair().unwrap();
    let client = VynkorClient::from_stream(plugin_side, None);
    let mut kernel = VynkorClient::from_stream(kernel_side, None);
    let handler = Arc::new(TestConcurrentHandler);

    let loop_task = tokio::spawn(run_concurrent_loop(client, handler));

    let req = Envelope {
        payload: Some(envelope::Payload::ActionRequest(ActionRequest {
            action_id: "act-panic".into(),
            action: "panic".into(),
            params_json: Vec::new(),
            timeout_ms: 0,
            streaming: false,
            caller_plugin_id: "caller_x".into(),
        })),
        ..Default::default()
    };
    kernel.send("kernel", req).await.unwrap();

    let env = tokio::time::timeout(Duration::from_secs(5), kernel.recv())
        .await
        .expect("timed out waiting for panic-derived response")
        .unwrap();
    match env.payload {
        Some(envelope::Payload::ActionResponse(resp)) => {
            assert_eq!(resp.status, ActionStatus::ActionError as i32);
            assert!(
                resp.error.contains("panicked"),
                "expected panic-derived error, got: {}",
                resp.error
            );
        }
        other => panic!("expected ActionResponse, got {other:?}"),
    }

    let shutdown = Envelope {
        payload: Some(envelope::Payload::PluginShutdown(PluginShutdown {
            reason: "test done".into(),
            grace_seconds: 0,
        })),
        ..Default::default()
    };
    kernel.send("kernel", shutdown).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), loop_task)
        .await
        .expect("loop did not exit")
        .unwrap()
        .unwrap();
}
