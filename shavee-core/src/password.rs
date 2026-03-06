//! Password hashing and key derivation utilities using Argon2.

use crate::{Error, Result};
use argon2::{
    Params, Version,
    password_hash::{PasswordHasher, SaltString},
};

/// Argon2id parameters used for hashing.
const ARGON2_MEMORY: u32 = 524288; // 512 MB
const ARGON2_LANES: u32 = 4;
const ARGON2_ITERATIONS: u32 = 4;
const ARGON2_OUTPUT_LEN: usize = 64;

/// Hashes a password with a given salt using Argon2id.
///
/// This function uses Argon2id with a hardcoded static secret (from `crate::STATIC_SALT`)
/// for additional security and to maintain compatibility with existing datasets.
///
/// # Arguments
/// * `password` - The user-provided password bytes.
/// * `salt` - The salt bytes (usually from ZFS property or env).
///
/// # Returns
/// A `Result` containing the hashed bytes as a `Vec<u8>`.
pub fn hash_argon2(password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    crate::trace(&format!("Hashing password with salt: {:?}", salt));

    // Initialize Argon2 parameters (Memory, Iterations, Lanes, Output Length)
    let params = Params::new(
        ARGON2_MEMORY,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| Error::Crypto(e.to_string()))?;

    // Create Argon2 instance with the static secret
    let argon2 = argon2::Argon2::new_with_secret(
        crate::STATIC_SALT.as_bytes(),
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        params,
    )
    .map_err(|e| Error::Crypto(e.to_string()))?;

    // Encode salt as SaltString
    let salt_string = SaltString::encode_b64(salt).map_err(|e| Error::Crypto(e.to_string()))?;

    // Perform the hashing operation
    let hash = argon2
        .hash_password(password, &salt_string)
        .map_err(|e: argon2::password_hash::Error| Error::Crypto(e.to_string()))?;

    // Extract the hash bytes
    hash.hash
        .map(|h: argon2::password_hash::Output| h.as_bytes().to_vec())
        .ok_or_else(|| Error::Crypto("Argon2 produced an empty hash".to_string()))
}
