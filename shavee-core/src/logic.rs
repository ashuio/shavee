use crate::{password, yubikey::*, zfs::*};
use base64;
use rand::{self, RngCore};
use std::error::Error;

pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::general_purpose::NO_PAD,
);

// All ZFS Dataset functions are methods for the Dataset Struct
impl Dataset {
    /// Uses File 2FA to unlocks the dataset
    pub fn file_unlock(
        self,
        passphrase: &[u8],
        filehash: Vec<u8>,
        salt: &Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        crate::trace(&format!(
            "Unlocking ZFS \"{:?}\" dataset using File as 2FA.",
            self
        ));
        let passphrase = file_key_calculation(passphrase, filehash, salt)?;
        self.loadkey(&passphrase)?.mount()?;
        crate::trace("Unlocked and mounted successfully!");
        Ok(())
    }

    /// Uses Yubikey  2FA to unlocks the dataset
    pub fn yubi_unlock(
        self,
        passphrase: &[u8],
        yubi_slot: u8,
        salt: &Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        crate::trace(&format!(
            "Unlocking ZFS \"{:?}\" dataset using Yubikey as 2FA.",
            self
        ));
        let passphrase = yubi_key_calculation(passphrase, yubi_slot, salt)?;
        self.loadkey(&passphrase)?.mount()?;
        crate::trace("Unlocked and mounted successfully!");
        Ok(())
    }

    /// No 2FA used for unlocking the dataset
    pub fn pass_unlock(self, passphrase: String) -> Result<(), Box<dyn Error>> {
        crate::trace(&format!(
            "Unlocking ZFS \"{:?}\" dataset with no 2FA.",
            self
        ));
        self.loadkey(&passphrase)?;
        let dataset_list = self.list()?;

        for each_set in dataset_list {
            each_set.mount()?;
        }
        crate::trace("Unlocked and mounted successfully!");
        Ok(())
    }

    /// Uses Yubikey  2FA to create the dataset and stores salt in its ZFS property as base64 encode
    pub fn yubi_create(
        self,
        passphrase: &[u8],
        yubi_slot: u8,
        salt: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        crate::trace(&format!(
            "Creating ZFS \"{:?}\" dataset with Yubikey 2FA.",
            self
        ));
        let passphrase = yubi_key_calculation(passphrase, yubi_slot, salt)?;
        self.create(&passphrase)?;
        crate::trace("Dataset was created successfully!");
        // Store the in the ZFS dataset property as base64 encoded
        self.set_property(
            crate::ZFS_PROPERTY_SALT.to_owned(),
            &base64::Engine::encode(&BASE64_ENGINE, salt),
        )?;
        crate::trace(&format!("Salt \"{:?}\" stored successfully!", salt));
        Ok(())
    }

    /// Uses File 2FA to create the dataset and stores salt in its ZFS property as base64 encode
    pub fn file_create(
        self,
        passphrase: &[u8],
        filehash: Vec<u8>,
        salt: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        crate::trace(&format!(
            "Creating ZFS \"{:?}\" dataset with File as 2FA.",
            self
        ));
        let passphrase = file_key_calculation(passphrase, filehash, salt)?;
        self.create(&passphrase)?;
        crate::trace("Dataset was created successfully!");
        // Store the in the ZFS dataset property as base64 encoded
        self.set_property(
            crate::ZFS_PROPERTY_SALT.to_owned(),
            &base64::Engine::encode(&BASE64_ENGINE, salt),
        )?;
        crate::trace(&format!("Salt \"{:?}\" stored successfully!", salt));
        Ok(())
    }
}

/// Generates ZFS dataset passphrase based on yubikey 2FA
pub fn yubi_key_calculation(
    pass: &[u8],
    yubi_slot: u8,
    salt: &[u8],
) -> Result<String, Box<dyn Error>> {
    crate::trace("Calculating passphrase key using Yubikey.");
    let key = yubikey_get_hash(pass, yubi_slot, salt)?;
    crate::trace("Passphrase is calculated!");
    Ok(base64::Engine::encode(&BASE64_ENGINE, key))
}

/// Generates ZFS dataset passphrase based on File 2FA
pub fn file_key_calculation(
    pass: &[u8],
    filehash: Vec<u8>,
    salt: &[u8],
) -> Result<String, Box<dyn Error>> {
    crate::trace("Calculating passphrase key using Yubikey.");
    let passhash = password::hash_argon2(pass, salt)?;
    let key = password::hash_argon2(&[filehash, passhash].concat(), salt)?;
    crate::trace("Passphrase is calculated!");
    Ok(base64::Engine::encode(&BASE64_ENGINE, key))
}

/// Generates ZFS dataset passphrase without 2FA
pub fn password_mode_hash(password: &[u8], salt: &Vec<u8>) -> Result<String, Box<dyn Error>> {
    crate::trace("Calculating passphrase key without 2FA.");
    let key = password::hash_argon2(password, salt)?;
    let passphrase = base64::Engine::encode(&BASE64_ENGINE, key);
    crate::trace("Passphrase is calculated!");
    Ok(passphrase)
}

///  Based on the discussion on issue #23; to determine which salt to use:
///     1. Check if the ZFS dataset is specified
///     2. Check if the ZFS dataset has salt property value then use it after base64 decode
///     3. If salt is not extracted from above, then check for salt environment variable
///     4. If the salt environment variable exists, use it
///     5. If none of the above is valid, then use the default salt.
///
///  However to simplify the code:
///     i. Generate a variable to store the salt environment variable or static salt
///         if the environment variable is not set
///    ii. If the ZFS dataset has salt property value use it (base64 decode), otherwise use salt from (i)
pub fn get_salt(dataset: Option<&Dataset>) -> Result<Vec<u8>, Box<dyn Error>> {
    crate::trace("Extracting salt.");
    // Generate salt to be either env variable or default static.
    let store_env_salt = std::env::var(crate::ENV_SALT_VARIABLE);
    crate::trace(&format!(
        "Environment variable for salt is {:?}",
        store_env_salt
    ));
    let env_or_static_salt = store_env_salt
        .as_deref()
        .unwrap_or(crate::STATIC_SALT)
        .as_bytes()
        .to_vec();

    // If ZFS dataset has salt value use it after base64 decode
    // otherwise use the salt from above
    let salt = match dataset {
        Some(dataset) => {
            crate::trace(&format!(
                "Check if the ZFS \"{:?}\" dataset has a salt property",
                dataset
            ));
            match dataset.get_property(crate::ZFS_PROPERTY_SALT.to_owned())? {
                Some(property_value) => {
                    crate::trace(&format!(
                        "Dataset has salt! Base64 encoded: \"{}\".",
                        property_value
                    ));
                    base64::Engine::decode(&BASE64_ENGINE, property_value.as_bytes().to_vec())?
                }
                // ZFS salt property is empty use the next
                None => env_or_static_salt,
            }
        }
        // if no dataset is specified, then check for environment variable
        None => env_or_static_salt,
    };
    crate::trace(&format!("Salt value is: \"{:?}\"", salt));
    Ok(salt)
}

/// Generates random salt with `RANDOM_SALT_LEN` length
pub fn generate_salt() -> Vec<u8> {
    crate::trace("Generating a random salt:");
    // Generate a random salt using OS randomness
    let mut random_salt = vec![0u8; crate::RANDOM_SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut random_salt);
    crate::trace(&format!("{:?}", random_salt));
    // Return the generated salt
    random_salt
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_key_calculation_test() {
        crate::trace_init(false);
        let filehash = vec![
            105, 63, 149, 213, 131, 131, 166, 22, 45, 42, 171, 73, 235, 96,
        ];
        let output =
            file_key_calculation(b"test", filehash, &crate::STATIC_SALT.as_bytes()).unwrap();
        assert_eq!(
            output,
            "SCf4JUjnkJUN3twj73Y4X+5hRWvUdAw+yGHUkQcu249S9SB/VITignRP6T58JkNa+/T5Ut4PUv3gT4h6bX3b7g");
    }

    #[test]
    fn password_mode_hash_test() {
        crate::trace_init(false);
        let passphrase = password_mode_hash(b"test", &crate::STATIC_SALT.into())
            .expect("Couldn't generate the passphrase! Test terminating early!"); // use static salt for predictable result

        assert_eq!(
        passphrase,
        "LDa6mHK4xmv37cqoG8B+9M/ZIaEPLDhPQER6nuP7dw8mB1MoKoRkgZCbUNRwXvGwG2UkfWJUUEVOfWzUCCb8JA" // expected output for "test" password
    );
    }

    #[test]
    fn generate_salt_test() {
        crate::trace_init(false);
        let salt = generate_salt();
        // Check if the salt has the correct length
        assert_eq!(salt.len(), crate::RANDOM_SALT_LEN);
    }
}
// TODO: Decide if unit tests are needed for the functions with simple logics?
