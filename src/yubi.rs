use sha2::{Digest, Sha512};
use std::{io, ops::Deref};
use yubico_manager::config::{Config, Mode, Slot};
use yubico_manager::Yubico;

pub fn get_hash(pass: &String) -> Result<String, io::Error> {
    let mut yubi = Yubico::new();
    // Search for Yubikey
    Ok(if let Ok(device) = yubi.find_yubikey() {
        let challenge = Sha512::digest(&pass.as_bytes()); // Prepare Challenge
        let config = Config::default() // Configure Yubikey
            .set_vendor_id(device.vendor_id)
            .set_product_id(device.product_id)
            .set_variable_size(false)
            .set_mode(Mode::Sha1)
            .set_slot(Slot::Slot2);

        // Challenge can not be greater than 64 bytes
        let hmac_result = yubi.challenge_response_hmac(&challenge, config).unwrap(); // Perform HMAC challenge

        format!("{:x}", &Sha512::digest(&hmac_result.deref())) // Prepare and return encryption key as hex string
    } else {
        let e = io::Error::new(io::ErrorKind::NotFound, "Yubikey not found");
        return Err(e);
    })
}
