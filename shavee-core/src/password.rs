use argon2::{Argon2, Params};

/// Generates hash of the password + salt
pub fn hash_argon2(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, argon2::Error> {
    crate::trace(&format!(
        "Hashing the password with \"{:?}\" as salt.",
        salt
    ));

    let params = Params::new(524288, 2, 1, Some(64))?;

    let config = Argon2::new_with_secret(
        crate::STATIC_SALT.as_bytes(),
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    )?;

    let mut hash = [0u8; 64];

    config.hash_password_into(password, salt, &mut hash)?;

    Ok(hash.to_vec())
}

mod tests {
    #[test]
    fn test_hash_argon2() {
        use super::*;

        crate::trace_init(false);
        // defining a struct that will hold input arguments
        // and their output hash results
        // need to use io::ErrorKind (instead of io:Error) which supports PartialEq
        #[derive(Debug, PartialEq)]
        struct PasswordHashPair<'a> {
            password: &'a [u8],
            hash_result: Vec<u8>,
        }

        // each entry of the array holds the input/output struct
        let password_hash_pairs = [
            PasswordHashPair {
                password: b"",
                hash_result: vec![
                    13, 58, 236, 241, 152, 183, 100, 212, 216, 84, 90, 94, 168, 228, 31, 30, 77,
                    49, 66, 19, 123, 152, 12, 239, 137, 235, 105, 65, 204, 16, 29, 214, 212, 15,
                    173, 80, 27, 108, 127, 193, 196, 252, 102, 37, 234, 173, 71, 28, 14, 157, 76,
                    244, 99, 170, 151, 224, 154, 190, 53, 226, 85, 233, 245, 225,
                ],
            },
            PasswordHashPair {
                password: b"This is a test!",
                hash_result: vec![
                    85, 96, 224, 183, 7, 56, 237, 97, 204, 74, 197, 74, 92, 189, 56, 227, 126, 87,
                    228, 28, 207, 173, 5, 111, 52, 228, 92, 208, 80, 152, 167, 236, 7, 214, 53,
                    103, 36, 168, 140, 9, 151, 221, 179, 68, 64, 180, 176, 81, 253, 221, 210, 100,
                    153, 141, 80, 152, 133, 23, 75, 217, 214, 153, 56, 173,
                ],
            },
        ];

        for index in 0..password_hash_pairs.len() {
            if let Ok(hash) = hash_argon2(
                password_hash_pairs[index].password.into(),
                &crate::STATIC_SALT.as_bytes(), // use static salt for predictable results
            ) {
                assert_eq!(hash, password_hash_pairs[index].hash_result)
            };
        }
    }
}
