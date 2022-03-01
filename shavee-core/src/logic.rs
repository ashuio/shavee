use crate::{password::hash_argon2, yubikey::*, zfs::*};
use base64::encode_config;
use std::error::Error;

// All ZFS Dataset functions are methods for the Dataset Struct
impl Dataset {
    pub fn file_unlock(self, passphrase: String, filehash: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let passphrase = file_key_calculation(passphrase, filehash)?;
        self.loadkey(&passphrase)?.mount()?;
        Ok(())
    }

    pub fn yubi_unlock(self, passphrase: String, yubi_slot: u8) -> Result<(), Box<dyn Error>> {
        let passphrase = yubi_key_calculation(passphrase, yubi_slot)?;
        self.loadkey(&passphrase)?.mount()?;
        Ok(())
    }

    pub fn pass_unlock(self, passphrase: String) -> Result<(), Box<dyn Error>> {
        self.loadkey(&passphrase)?;
        let dataset_list = self.list()?;

        for each_set in dataset_list {
            each_set.mount()?;
        }
        Ok(())
    }

    pub fn yubi_create(self, passphrase: String, yubi_slot: u8) -> Result<(), Box<dyn Error>> {
        let passphrase = yubi_key_calculation(passphrase, yubi_slot)?;
        self.create(&passphrase)?;
        Ok(())
    }

    pub fn file_create(self, passphrase: String, filehash: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let passphrase = file_key_calculation(passphrase, filehash)?;
        self.create(&passphrase)?;
        Ok(())
    }
}

pub fn yubi_key_calculation(pass: String, yubi_slot: u8) -> Result<String, Box<dyn Error>> {
    let key = yubikey_get_hash(pass, yubi_slot)?;
    Ok(encode_config(key, base64::STANDARD_NO_PAD))
}

pub fn file_key_calculation(pass: String, filehash: Vec<u8>) -> Result<String, Box<dyn Error>> {
    let passhash = hash_argon2(pass.into_bytes())?;
    let key = hash_argon2([filehash, passhash].concat())?;
    Ok(encode_config(key, base64::STANDARD_NO_PAD))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_key_calculation_test() {
        let filehash = vec![
            105, 63, 149, 213, 131, 131, 166, 22, 45, 42, 171, 73, 235, 96,
        ];
        let output = file_key_calculation("test".to_string(), filehash).unwrap();
        assert_eq!(
            output,
            "SCf4JUjnkJUN3twj73Y4X+5hRWvUdAw+yGHUkQcu249S9SB/VITignRP6T58JkNa+/T5Ut4PUv3gT4h6bX3b7g");
    }
}

// TODO: Decide if unit tests are needed for the functions with simple logics?
