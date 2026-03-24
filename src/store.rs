use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use redis::aio::MultiplexedConnection;
use scpy_crypto::{CipherEnvelope, RoomMeta};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredRoom {
    pub meta: RoomMeta,
    pub envelope: CipherEnvelope,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("store payload serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[async_trait]
pub trait RoomStore: Send + Sync {
    async fn get(&self, room_id: &str) -> Result<Option<StoredRoom>, StoreError>;
    async fn set(&self, room_id: &str, room: StoredRoom, ttl: Duration) -> Result<(), StoreError>;
}

#[derive(Clone, Default)]
pub struct MemoryRoomStore {
    rooms: Arc<RwLock<HashMap<String, ExpiringRoom>>>,
}

#[derive(Clone)]
pub struct RedisRoomStore {
    connection: MultiplexedConnection,
    key_prefix: String,
}

#[derive(Clone, Debug)]
struct ExpiringRoom {
    room: StoredRoom,
    expires_at: Instant,
}

impl MemoryRoomStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RedisRoomStore {
    pub async fn connect(redis_url: &str) -> Result<Self, StoreError> {
        let client = redis::Client::open(redis_url)?;
        let connection = client.get_multiplexed_async_connection().await?;

        Ok(Self {
            connection,
            key_prefix: "scpy:room:".to_string(),
        })
    }

    fn key_for(&self, room_id: &str) -> String {
        format!("{}{}", self.key_prefix, room_id)
    }
}

#[async_trait]
impl RoomStore for MemoryRoomStore {
    async fn get(&self, room_id: &str) -> Result<Option<StoredRoom>, StoreError> {
        let now = Instant::now();

        {
            let rooms = self.rooms.read().await;
            match rooms.get(room_id) {
                Some(stored) if stored.expires_at > now => return Ok(Some(stored.room.clone())),
                Some(_) => {}
                None => return Ok(None),
            }
        }

        let mut rooms = self.rooms.write().await;
        match rooms.get(room_id) {
            Some(stored) if stored.expires_at > now => Ok(Some(stored.room.clone())),
            Some(_) => {
                rooms.remove(room_id);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn set(&self, room_id: &str, room: StoredRoom, ttl: Duration) -> Result<(), StoreError> {
        let expires_at = Instant::now().checked_add(ttl).unwrap_or_else(Instant::now);

        self.rooms
            .write()
            .await
            .insert(room_id.to_string(), ExpiringRoom { room, expires_at });

        Ok(())
    }
}

#[async_trait]
impl RoomStore for RedisRoomStore {
    async fn get(&self, room_id: &str) -> Result<Option<StoredRoom>, StoreError> {
        let mut connection = self.connection.clone();
        let payload = redis::cmd("GET")
            .arg(self.key_for(room_id))
            .query_async::<Option<String>>(&mut connection)
            .await?;

        payload
            .map(|json| serde_json::from_str(&json))
            .transpose()
            .map_err(StoreError::from)
    }

    async fn set(&self, room_id: &str, room: StoredRoom, ttl: Duration) -> Result<(), StoreError> {
        let mut connection = self.connection.clone();
        let ttl_millis = u64::try_from(ttl.as_millis().max(1)).unwrap_or(u64::MAX);
        let payload = serde_json::to_string(&room)?;

        redis::cmd("SET")
            .arg(self.key_for(room_id))
            .arg(payload)
            .arg("PX")
            .arg(ttl_millis)
            .query_async::<()>(&mut connection)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use scpy_crypto::{create_room, KdfParams};

    use super::{MemoryRoomStore, RoomStore, StoredRoom};

    #[tokio::test]
    async fn memory_store_evicts_expired_rooms_on_get() {
        let store = MemoryRoomStore::new();
        let created =
            create_room("password", "hello world", KdfParams::testing()).expect("room must build");

        store
            .set(
                "room123",
                StoredRoom {
                    meta: created.meta,
                    envelope: created.envelope,
                },
                Duration::from_millis(25),
            )
            .await
            .expect("room must store");

        assert!(
            store
                .get("room123")
                .await
                .expect("get must succeed")
                .is_some(),
            "fresh room should be readable before ttl elapses"
        );

        tokio::time::sleep(Duration::from_millis(40)).await;

        assert!(
            store
                .get("room123")
                .await
                .expect("get must succeed")
                .is_none(),
            "expired room should be lazily evicted"
        );
    }
}
