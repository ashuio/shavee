use std::ops::Deref;
use yubico_manager::config::{Config, Mode, Slot};
use yubico_manager::Yubico;

pub fn yubikey_get_hash(
    pass: &[u8],
    slot: u8,
    salt: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut yubi = Yubico::new();
    // Search for Yubikey
    Ok(if let Ok(device) = yubi.find_yubikey() {
        let challenge = crate::password::hash_argon2(&pass, salt).expect("Hash error"); // Prepare Challenge
        let yslot = if slot == 1 { Slot::Slot1 } else { Slot::Slot2 };

        let config = Config::default() // Configure Yubikey
            .set_vendor_id(device.vendor_id)
            .set_product_id(device.product_id)
            .set_variable_size(false)
            .set_mode(Mode::Sha1)
            .set_slot(yslot);

        let hmac_result = yubi.challenge_response_hmac(&challenge, config);
        let hmac_result = match hmac_result {
            Ok(y) => y,
            Err(error) => return Err(error.into()),
        };
        let hash = hmac_result.deref().to_vec(); // Prepare and return encryption key as hex string
        let finalhash = crate::password::hash_argon2(&hash[..], salt).expect("File Hash Error");
        finalhash // Return the finalhash
    } else {
        return Err("Yubikey not found".to_string().into());
    })
}

// TODO: How to implement unit test for yubikey which requires human input?
