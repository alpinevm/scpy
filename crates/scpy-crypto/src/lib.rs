use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

const ROOM_KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub fn interactive() -> Self {
        Self {
            memory_cost_kib: 19_456,
            time_cost: 2,
            parallelism: 1,
        }
    }

    pub fn testing() -> Self {
        Self {
            memory_cost_kib: 64,
            time_cost: 1,
            parallelism: 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomMeta {
    pub schema_version: u8,
    pub kdf: KdfParams,
    pub kdf_salt_b64: String,
    pub wrapped_room_key_nonce_b64: String,
    pub wrapped_room_key_b64: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherEnvelope {
    pub version: u64,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RoomKey([u8; ROOM_KEY_LEN]);

impl core::fmt::Debug for RoomKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("RoomKey").field(&"<redacted>").finish()
    }
}

#[derive(Debug)]
pub struct CreatedRoom {
    pub meta: RoomMeta,
    pub envelope: CipherEnvelope,
    pub room_key: RoomKey,
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("password must not be empty")]
    EmptyPassword,
    #[error("invalid or unsupported KDF parameters")]
    InvalidKdfParams,
    #[error("randomness unavailable")]
    RandomnessUnavailable,
    #[error("ciphertext failed authentication")]
    AuthenticationFailed,
    #[error("encoded value is invalid")]
    InvalidEncoding,
    #[error("plaintext is not valid UTF-8")]
    InvalidUtf8,
}

pub fn cipher_suite_label() -> &'static str {
    "Argon2id + XChaCha20-Poly1305"
}

pub fn create_room(
    password: &str,
    plaintext: &str,
    kdf: KdfParams,
) -> Result<CreatedRoom, CryptoError> {
    ensure_password(password)?;

    let salt = random_array::<SALT_LEN>()?;
    let wrap_nonce = random_array::<NONCE_LEN>()?;
    let room_key_bytes = random_array::<ROOM_KEY_LEN>()?;

    let mut wrapping_key = derive_wrapping_key(password, &salt, kdf)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&wrapping_key));
    let wrapped_room_key = cipher
        .encrypt(XNonce::from_slice(&wrap_nonce), room_key_bytes.as_slice())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    wrapping_key.zeroize();

    let room_key = RoomKey(room_key_bytes);
    let envelope = encrypt_clipboard(&room_key, plaintext, 1)?;
    let meta = RoomMeta {
        schema_version: SCHEMA_VERSION,
        kdf,
        kdf_salt_b64: encode_bytes(&salt),
        wrapped_room_key_nonce_b64: encode_bytes(&wrap_nonce),
        wrapped_room_key_b64: encode_bytes(&wrapped_room_key),
    };

    Ok(CreatedRoom {
        meta,
        envelope,
        room_key,
    })
}

pub fn unlock_room_key(password: &str, meta: &RoomMeta) -> Result<RoomKey, CryptoError> {
    ensure_password(password)?;
    validate_schema(meta.schema_version)?;

    let salt = decode_fixed::<SALT_LEN>(&meta.kdf_salt_b64)?;
    let wrap_nonce = decode_fixed::<NONCE_LEN>(&meta.wrapped_room_key_nonce_b64)?;
    let wrapped_room_key = decode_bytes(&meta.wrapped_room_key_b64)?;

    let mut wrapping_key = derive_wrapping_key(password, &salt, meta.kdf)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&wrapping_key));
    let room_key = cipher
        .decrypt(XNonce::from_slice(&wrap_nonce), wrapped_room_key.as_slice())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    wrapping_key.zeroize();

    if room_key.len() != ROOM_KEY_LEN {
        return Err(CryptoError::AuthenticationFailed);
    }

    let mut bytes = [0u8; ROOM_KEY_LEN];
    bytes.copy_from_slice(&room_key);
    Ok(RoomKey(bytes))
}

pub fn encrypt_clipboard(
    room_key: &RoomKey,
    plaintext: &str,
    version: u64,
) -> Result<CipherEnvelope, CryptoError> {
    let nonce = random_array::<NONCE_LEN>()?;
    let aad = version.to_be_bytes();
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&room_key.0));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(CipherEnvelope {
        version,
        nonce_b64: encode_bytes(&nonce),
        ciphertext_b64: encode_bytes(&ciphertext),
    })
}

pub fn decrypt_clipboard(
    room_key: &RoomKey,
    envelope: &CipherEnvelope,
) -> Result<String, CryptoError> {
    let nonce = decode_fixed::<NONCE_LEN>(&envelope.nonce_b64)?;
    let ciphertext = decode_bytes(&envelope.ciphertext_b64)?;
    let aad = envelope.version.to_be_bytes();
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&room_key.0));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    String::from_utf8(plaintext).map_err(|_| CryptoError::InvalidUtf8)
}

fn ensure_password(password: &str) -> Result<(), CryptoError> {
    if password.trim().is_empty() {
        Err(CryptoError::EmptyPassword)
    } else {
        Ok(())
    }
}

fn validate_schema(schema_version: u8) -> Result<(), CryptoError> {
    if schema_version == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(CryptoError::InvalidEncoding)
    }
}

fn derive_wrapping_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
) -> Result<[u8; ROOM_KEY_LEN], CryptoError> {
    let params = Params::new(
        kdf.memory_cost_kib,
        kdf.time_cost,
        kdf.parallelism,
        Some(ROOM_KEY_LEN),
    )
    .map_err(|_| CryptoError::InvalidKdfParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; ROOM_KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|_| CryptoError::InvalidKdfParams)?;
    Ok(out)
}

fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
    Ok(bytes)
}

fn encode_bytes(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_bytes(value: &str) -> Result<Vec<u8>, CryptoError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CryptoError::InvalidEncoding)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], CryptoError> {
    let bytes = decode_bytes(value)?;
    if bytes.len() != N {
        return Err(CryptoError::InvalidEncoding);
    }

    let mut fixed = [0u8; N];
    fixed.copy_from_slice(&bytes);
    Ok(fixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_roundtrip_succeeds() {
        let created = create_room("shared secret", "hello world", KdfParams::testing())
            .expect("room should encrypt");
        let unlocked =
            unlock_room_key("shared secret", &created.meta).expect("room key should unwrap");
        let decrypted =
            decrypt_clipboard(&unlocked, &created.envelope).expect("ciphertext should decrypt");

        assert_eq!(decrypted, "hello world");
    }

    #[test]
    fn wrong_password_fails() {
        let created = create_room("shared secret", "hello world", KdfParams::testing())
            .expect("room should encrypt");

        let error =
            unlock_room_key("not the secret", &created.meta).expect_err("wrong password must fail");

        assert!(matches!(error, CryptoError::AuthenticationFailed));
    }
}
