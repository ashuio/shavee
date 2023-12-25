use std::sync::{Arc, Mutex};
use yubico_manager::config::{Config, Mode, Slot};
use yubico_manager::{Yubico, Yubikey};

pub fn yubikey_get_hash(
    password: &[u8],
    slot: Option<u8>,
    salt: &[u8],
    yubikey: Arc<Mutex<Yubikey>>,
) -> Result<Vec<u8>,Box<dyn std::error::Error>> {

    let mut yubi = Yubico::new();
    // Search for Yubikey

    let challenge = crate::password::hash_argon2(&password, &salt)
        .expect("Hash error"); // Prepare Challenge
    
    let yslot = if slot == Some(1) {
        Slot::Slot1
    } else {
        Slot::Slot2
    };

    let key = yubikey.lock().unwrap();
    let config = Config::new_from(key.clone()) // Configure Yubikey
        .set_variable_size(false)
        .set_mode(Mode::Sha1)
        .set_slot(yslot);

    let hmac_result = yubi.challenge_response_hmac(&challenge, config)?;
    drop(key);
    let hash = hmac_result.0.to_vec(); // Prepare and return encryption key as hex string
    let finalhash =
        crate::password::hash_argon2(&hash[..], &salt).expect("File Hash Error");
    Ok(finalhash) // Return the finalhash
}

pub fn yubikey_get_from_serial(
    yubikeys: Arc<[Arc<Mutex<Yubikey>>]>,
    serial: u32,
) -> Result<Arc<Mutex<Yubikey>>, ()> {
    for key in yubikeys.iter() {
        if serial == key.lock().unwrap().serial.unwrap() {
            return Ok(key.clone());
        }
    }

    Err(())
}

pub fn fetch_yubikeys() -> Arc<[Arc<Mutex<Yubikey>>]> {
    let fetched_keys = match Yubico::new().find_all_yubikeys() {
        Ok(keys) => keys,
        Err(_) => Vec::new(),
    };

    let mut keys = Vec::new();

    for key in fetched_keys {
        let k = Arc::new(Mutex::new(key));
        keys.push(k);
    }

    Arc::from_iter(keys)
}

// TODO: How to implement unit test for yubikey which requires human input?
