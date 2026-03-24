#![cfg(feature = "ssr")]

use std::time::Duration;

use futures_util::StreamExt;
use reqwest::{Client, Response};
use scpy_crypto::{create_room, decrypt_clipboard, encrypt_clipboard, unlock_room_key, KdfParams};
use secopy::api::{
    api_router, AppState, ClipboardEvent, CreateRoomRequest, CreateRoomResponse, GetRoomResponse,
    UpdateClipboardRequest, UpdateClipboardResponse,
};

#[tokio::test]
async fn encrypted_room_flow_roundtrips_between_two_users_over_sse() {
    let state = AppState::memory(Duration::from_secs(60));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener must bind");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("address must resolve")
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, api_router::<AppState>().with_state(state))
            .await
            .expect("test server must run");
    });

    let client = Client::new();
    let password = "shared test password";

    let user_one = create_room(password, "alpha clipboard", KdfParams::testing())
        .expect("user one should encrypt the initial room");
    let create_response = client
        .post(format!("{base_url}/api/rooms"))
        .json(&CreateRoomRequest {
            meta: user_one.meta.clone(),
            envelope: user_one.envelope.clone(),
        })
        .send()
        .await
        .expect("create room request must succeed");
    assert_eq!(create_response.status(), reqwest::StatusCode::CREATED);
    let CreateRoomResponse { room_id } = create_response
        .json()
        .await
        .expect("create room response must deserialize");

    let room_snapshot = client
        .get(format!("{base_url}/api/rooms/{room_id}"))
        .send()
        .await
        .expect("room fetch must succeed");
    assert_eq!(room_snapshot.status(), reqwest::StatusCode::OK);
    let GetRoomResponse {
        meta,
        envelope,
        room_id: fetched_room_id,
    } = room_snapshot
        .json()
        .await
        .expect("room snapshot must deserialize");
    assert_eq!(fetched_room_id, room_id);

    let user_two_room_key =
        unlock_room_key(password, &meta).expect("user two should unlock the room locally");
    let user_two_plaintext = decrypt_clipboard(&user_two_room_key, &envelope)
        .expect("user two should decrypt the initial ciphertext");
    assert_eq!(user_two_plaintext, "alpha clipboard");

    let events_response = client
        .get(format!("{base_url}/api/rooms/{room_id}/events"))
        .send()
        .await
        .expect("sse subscription must connect");
    assert_eq!(events_response.status(), reqwest::StatusCode::OK);
    let mut sse = SseStream::new(events_response);

    let next_version = envelope.version + 1;
    let updated_envelope = encrypt_clipboard(&user_two_room_key, "beta clipboard", next_version)
        .expect("user two should re-encrypt the clipboard");
    let update_response = client
        .post(format!("{base_url}/api/rooms/{room_id}/clipboard"))
        .json(&UpdateClipboardRequest {
            envelope: updated_envelope,
        })
        .send()
        .await
        .expect("clipboard update must succeed");
    assert_eq!(update_response.status(), reqwest::StatusCode::OK);
    let UpdateClipboardResponse { version, .. } = update_response
        .json()
        .await
        .expect("update response must deserialize");
    assert_eq!(version, next_version);

    let ClipboardEvent {
        room_id: event_room_id,
        envelope: event_envelope,
    } = tokio::time::timeout(Duration::from_secs(5), sse.next_event())
        .await
        .expect("sse event should arrive in time")
        .expect("sse event should parse");
    assert_eq!(event_room_id, room_id);

    let user_one_plaintext = decrypt_clipboard(&user_one.room_key, &event_envelope)
        .expect("user one should decrypt the SSE-delivered ciphertext");
    assert_eq!(user_one_plaintext, "beta clipboard");

    server.abort();
}

struct SseStream {
    stream: futures_util::stream::BoxStream<'static, Result<bytes::Bytes, reqwest::Error>>,
    buffer: String,
}

impl SseStream {
    fn new(response: Response) -> Self {
        Self {
            stream: response.bytes_stream().boxed(),
            buffer: String::new(),
        }
    }

    async fn next_event(&mut self) -> Result<ClipboardEvent, String> {
        loop {
            if let Some(event) = extract_event(&mut self.buffer)? {
                return Ok(event);
            }

            let next_chunk = self
                .stream
                .next()
                .await
                .ok_or_else(|| "sse stream closed before an event arrived".to_string())?
                .map_err(|error| error.to_string())?;

            self.buffer
                .push_str(std::str::from_utf8(&next_chunk).map_err(|error| error.to_string())?);
        }
    }
}

fn extract_event(buffer: &mut String) -> Result<Option<ClipboardEvent>, String> {
    let normalized = buffer.replace("\r\n", "\n");
    if let Some(separator) = normalized.find("\n\n") {
        let event_block = normalized[..separator].to_string();
        *buffer = normalized[separator + 2..].to_string();

        let mut data_lines = Vec::new();
        for line in event_block.lines() {
            if let Some(data) = line.strip_prefix("data:") {
                data_lines.push(data.trim_start());
            }
        }

        if data_lines.is_empty() {
            return Ok(None);
        }

        let payload = data_lines.join("\n");
        let event =
            serde_json::from_str::<ClipboardEvent>(&payload).map_err(|error| error.to_string())?;
        Ok(Some(event))
    } else {
        Ok(None)
    }
}
