//! Orchestration logic for Shavee encryption workflows.
//!
//! This module combines the lower-level ZFS, Yubikey, and file-hashing components
//! to provide high-level operations for dataset management.

use crate::{
    Error, Result, password, yubikey,
    zfs::{Dataset, ZfsShaveeProperties},
};
use base64::{Engine, engine::general_purpose::NO_PAD};
use challenge_response::Device;
use rand::{RngCore, SeedableRng, rngs};
use std::sync::Mutex;

/// Base64 engine for standard alphabet without padding.
pub const BASE64_ENGINE: base64::engine::GeneralPurpose =
    base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, NO_PAD);

impl Dataset {
    /// Creates an encrypted dataset using Yubikey 2FA.
    ///
    /// # Arguments
    /// * `passphrase` - The user's primary password.
    /// * `yubi_slot` - The Yubikey slot to use (1 or 2).
    /// * `yubikey` - The Yubikey device protected by a Mutex.
    /// * `salt` - The salt for key derivation.
    ///
    /// # Returns
    /// `Result<()>` indicating success or failure of the creation process.
    pub fn yubi_create(
        &self,
        passphrase: &[u8],
        yubi_slot: Option<u8>,
        yubikey: &Mutex<Device>,
        salt: &[u8],
    ) -> Result<()> {
        crate::trace(&format!(
            "Creating ZFS dataset \"{}\" with Yubikey 2FA",
            self.name()
        ));

        // Calculate the derived passphrase using Yubikey HMAC-SHA1
        let derived_passphrase = yubi_key_calculation(passphrase, yubi_slot, salt, yubikey)?;

        // Instruct ZFS to create the dataset with the derived passphrase
        self.create(&derived_passphrase)?;

        crate::trace("Dataset created successfully");
        Ok(())
    }

    /// Creates an encrypted dataset using File 2FA.
    ///
    /// # Arguments
    /// * `passphrase` - The user's primary password.
    /// * `filehash` - The pre-calculated hash of the 2FA file.
    /// * `salt` - The salt for key derivation.
    ///
    /// # Returns
    /// `Result<()>` indicating success or failure of the creation process.
    pub fn file_create(&self, passphrase: &[u8], filehash: Vec<u8>, salt: &[u8]) -> Result<()> {
        crate::trace(&format!(
            "Creating ZFS dataset \"{}\" with File 2FA",
            self.name()
        ));

        // Calculate the derived passphrase using the file hash and user password
        let derived_passphrase = file_key_calculation(passphrase, filehash, salt)?;

        // Instruct ZFS to create the dataset with the derived passphrase
        self.create(&derived_passphrase)?;

        crate::trace("Dataset created successfully");
        Ok(())
    }
}

/// Derives a ZFS passphrase using Yubikey HMAC-SHA1.
///
/// This involves hashing the user password, sending it as a challenge to the Yubikey,
/// and then hashing the resulting HMAC response again to derive the final key.
pub fn yubi_key_calculation(
    pass: &[u8],
    yubi_slot: Option<u8>,
    salt: &[u8],
    yubikey: &Mutex<Device>,
) -> Result<String> {
    crate::trace("Calculating key using Yubikey");
    let key = yubikey::yubikey_get_hash(pass, yubi_slot, salt, yubikey)?;
    Ok(BASE64_ENGINE.encode(key))
}

/// Derives a ZFS passphrase using a file hash.
///
/// This method combines the file's hash with the Argon2 hash of the user's password,
/// then performs a final Argon2 hash on the concatenated result.
pub fn file_key_calculation(pass: &[u8], filehash: Vec<u8>, salt: &[u8]) -> Result<String> {
    crate::trace("Calculating key using File hash");

    // First, hash the user password
    let passhash = password::hash_argon2(pass, salt)?;

    // Concatenate file hash and password hash for the final KDF step
    let mut combined = filehash;
    combined.extend_from_slice(&passhash);

    // Hash the combined data to derive the final key
    let key = password::hash_argon2(&combined, salt)?;
    crate::trace("Key calculated successfully");
    Ok(BASE64_ENGINE.encode(key))
}

/// Derives a ZFS passphrase without a second factor.
///
/// Performs a single Argon2id pass on the user password with the provided salt.
pub fn password_mode_hash(password: &[u8], salt: &[u8]) -> Result<String> {
    crate::trace("Calculating key (password-only mode)");
    let key = password::hash_argon2(password, salt)?;
    Ok(BASE64_ENGINE.encode(key))
}

/// Retrieves the salt for a dataset according to the precedence rules:
/// 1. Dataset-specific salt property (`com.github.shavee:salt`).
/// 2. `SHAVEE_SALT` environment variable.
/// 3. Static fallback salt (for backward compatibility).
///
/// # Returns
/// `Result<Vec<u8>>` containing the salt bytes.
pub fn get_salt(dataset: Option<&Dataset>) -> Result<Vec<u8>> {
    crate::trace("Retrieving salt");

    // Precedence 1: Dataset property
    if let Some(ds) = dataset {
        if let Some(prop) = ds.get_property(&ZfsShaveeProperties::Salt.to_string())? {
            crate::trace("Using salt from ZFS dataset property");
            // Salt is stored base64-encoded in ZFS properties
            return BASE64_ENGINE
                .decode(prop.as_bytes())
                .map_err(|e| Error::Crypto(format!("Failed to decode salt from ZFS: {}", e)));
        }
    }

    // Precedence 2: Environment variable
    if let Ok(env_salt) = std::env::var(crate::ENV_SALT_VARIABLE) {
        crate::trace("Using salt from environment variable");
        return Ok(env_salt.into_bytes());
    }

    // Precedence 3: Static fallback
    crate::trace("Using static fallback salt");
    Ok(crate::STATIC_SALT.as_bytes().to_vec())
}

/// Generates a new random salt of length `RANDOM_SALT_LEN`.
///
/// Uses the operating system's secure random number generator.
pub fn generate_salt() -> Vec<u8> {
    crate::trace("Generating random salt");
    let mut salt = vec![0u8; crate::RANDOM_SALT_LEN];
    rngs::StdRng::from_os_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_eq!(salt1.len(), crate::RANDOM_SALT_LEN);
        assert_eq!(salt2.len(), crate::RANDOM_SALT_LEN);
        assert_ne!(salt1, salt2, "Generated salts should be random");
    }

    #[test]
    fn test_password_mode_hash_deterministic() {
        let password = b"my_password";
        let salt = b"somesalt123";
        let hash1 = password_mode_hash(password, salt).unwrap();
        let hash2 = password_mode_hash(password, salt).unwrap();
        assert_eq!(
            hash1, hash2,
            "Hashing same password and salt should produce the same output"
        );
    }

    #[test]
    fn test_file_key_calculation_deterministic() {
        let password = b"my_password";
        let filehash = vec![1, 2, 3, 4, 5];
        let salt = b"somesalt123";
        let hash1 = file_key_calculation(password, filehash.clone(), salt).unwrap();
        let hash2 = file_key_calculation(password, filehash.clone(), salt).unwrap();
        assert_eq!(hash1, hash2, "File key calculation should be deterministic");
    }

    #[test]
    fn test_file_key_calculation_different_filehash() {
        let password = b"my_password";
        let salt = b"somesalt123";
        let hash1 = file_key_calculation(password, vec![1, 2, 3], salt).unwrap();
        let hash2 = file_key_calculation(password, vec![1, 2, 4], salt).unwrap();
        assert_ne!(
            hash1, hash2,
            "Different file hashes should produce different keys"
        );
    }

    #[test]
    fn test_get_salt_fallback() {
        // Without environment variables and dataset, it should return STATIC_SALT
        let salt = get_salt(None).unwrap();
        assert_eq!(salt, crate::STATIC_SALT.as_bytes().to_vec());
    }
}
