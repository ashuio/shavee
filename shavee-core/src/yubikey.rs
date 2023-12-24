use std::sync::{Arc, Mutex};

use yubico_manager::config::{Config, Mode, Slot};
use yubico_manager::{Yubico, Yubikey};

pub fn yubikey_get_hash(
    pass: &[u8],
    yubikey: Yubikey,
    slot: u8,
    salt: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut yubi = Yubico::new();
    // Search for Yubikey
    let challenge = crate::password::hash_argon2(&pass, salt).expect("Hash error"); // Prepare Challenge
    let yslot = if slot == 1 { Slot::Slot1 } else { Slot::Slot2 };

    let config = Config::new_from(yubikey) // Configure Yubikey
        .set_variable_size(false)
        .set_mode(Mode::Sha1)
        .set_slot(yslot);

    let hmac_result = yubi.challenge_response_hmac(&challenge, config);
    let hmac_result = match hmac_result {
        Ok(y) => y,
        Err(error) => return Err(error.into()),
    };
    let hash = hmac_result.0.to_vec(); // Prepare and return encryption key as hex string
    let finalhash = crate::password::hash_argon2(&hash[..], salt).expect("File Hash Error");
    Ok(finalhash) // Return the finalhash
}

pub fn yubikey_get_from_serial(yubikeys: Arc<Vec<Arc<Mutex<yubico_manager::Yubikey>>>>,serial: u32) -> Result<Arc<Mutex<Yubikey>>,()> {


    for key in yubikeys.iter() {
        if serial == key.lock().unwrap().serial.unwrap() {
            return Ok(key.clone())
        }
    }

    Err(())
}

// TODO: How to implement unit test for yubikey which requires human input?
