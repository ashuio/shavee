use sha2::{Digest, Sha512};
use std::process::exit;
use std::{io, ops::Deref};
use yubico_manager::config::{Config, Mode, Slot};
use yubico_manager::Yubico;

pub fn get_hash(pass: &String, slot: u8) -> Result<String, io::Error> {
    let mut yubi = Yubico::new();
    // Search for Yubikey
    Ok(if let Ok(device) = yubi.find_yubikey() {
        eprintln!("Yubikey found ... Running HMAC challenge on SLOT {}",slot);
        let challenge = Sha512::digest(&pass.as_bytes()); // Prepare Challenge
        let yslot = if slot == 1 {
            Slot::Slot1
        } else if slot == 2 {
            Slot::Slot2
        } else {
            eprintln!("Invalid Slot");
            std::process::exit(1)
        };
        let config = Config::default() // Configure Yubikey
            .set_vendor_id(device.vendor_id)
            .set_product_id(device.product_id)
            .set_variable_size(false)
            .set_mode(Mode::Sha1)
            .set_slot(yslot);

        let hmac_result = yubi.challenge_response_hmac(&challenge, config);
        let hmac_result = match hmac_result {
            Ok(y) => {
                eprintln!("HMAC challenge on Yubikey on SLOT {} ... [OK]",slot);
                y
            },
            Err(error) => {
                eprintln!("Error: Failed to run HMAC challenge on Youbikey on Slot {}",slot);
                eprintln!("Error: {}",error);
                exit(1)
            }
        };
        format!("{:x}", &Sha512::digest(&hmac_result.deref())) // Prepare and return encryption key as hex string
    } else {
        let e = io::Error::new(io::ErrorKind::NotFound, "Error: Yubikey not found");
        return Err(e);
    })
}
