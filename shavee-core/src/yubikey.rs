//! Yubikey HMAC-SHA1 challenge-response utilities.

use crate::{Error, Result};
use challenge_response::config::{Config, Mode, Slot};
use challenge_response::{ChallengeResponse, Device};
use std::sync::{Arc, Mutex};

/// Performs a HMAC-SHA1 challenge-response using a Yubikey.
///
/// # Arguments
/// * `password` - The user password to be hashed and used as a challenge.
/// * `slot` - The Yubikey slot to use (1 or 2). Defaults to 2 if not specified.
/// * `salt` - The salt for hashing the password before sending it as a challenge.
/// * `yubikey` - A Mutex-protected Yubikey device.
///
/// # Returns
/// A `Result` containing the final derived key as a `Vec<u8>`.
pub fn yubikey_get_hash(
    password: &[u8],
    slot: Option<u8>,
    salt: &[u8],
    yubikey: &Mutex<Device>,
) -> Result<Vec<u8>> {
    let mut yubi_service = ChallengeResponse::new()
        .map_err(|e| Error::Yubikey(format!("Failed to initialize Yubikey service: {}", e)))?;

    // Prepare the challenge by hashing the password
    let challenge = crate::password::hash_argon2(password, salt)?;

    let yslot = match slot {
        Some(1) => Slot::Slot1,
        _ => Slot::Slot2,
    };

    let hmac_result = {
        let key_handle = yubikey
            .lock()
            .map_err(|_| Error::Yubikey("Failed to lock Yubikey device".to_string()))?;

        let config = Config::new_from(key_handle.clone())
            .set_variable_size(false)
            .set_mode(Mode::Sha1)
            .set_slot(yslot);

        yubi_service
            .challenge_response_hmac(&challenge, config)
            .map_err(|e| Error::Yubikey(format!("HMAC challenge failed: {}", e)))?
    };

    // The HMAC result is used as input for a final Argon2 hash to derive the encryption key
    let final_hash = crate::password::hash_argon2(&hmac_result.0, salt)?;
    Ok(final_hash)
}

/// Retrieves a Yubikey device from a list based on its serial number.
///
/// # Arguments
/// * `yubikeys` - A list of Mutex-protected Yubikey devices.
/// * `serial` - The serial number to search for.
///
/// # Returns
/// A `Result` containing a reference to the matching Yubikey device.
pub fn yubikey_get_from_serial(yubikeys: &[Mutex<Device>], serial: u32) -> Result<&Mutex<Device>> {
    yubikeys
        .iter()
        .find(|key| {
            key.lock()
                .map(|k| k.serial == Some(serial))
                .unwrap_or(false)
        })
        .ok_or_else(|| Error::Yubikey(format!("Yubikey with serial {} not found", serial)))
}

/// Fetches all connected Yubikey devices.
///
/// # Returns
/// A `Result` containing an `Arc` slice of Mutex-protected Yubikey devices.
pub fn fetch_yubikeys() -> Result<Arc<[Mutex<Device>]>> {
    let mut yubi_service = ChallengeResponse::new()
        .map_err(|e| Error::Yubikey(format!("Failed to initialize Yubikey service: {}", e)))?;

    let fetched_keys = yubi_service
        .find_all_devices()
        .map_err(|e| Error::Yubikey(format!("Failed to find Yubikey devices: {}", e)))?;

    let keys: Vec<_> = fetched_keys.into_iter().map(Mutex::new).collect();

    Ok(Arc::from(keys))
}
