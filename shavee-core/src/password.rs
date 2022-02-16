use argon2::{Config, ThreadMode, Variant, Version};

pub fn hash_argon2(password: Vec<u8>) -> Result<Vec<u8>, argon2::Error> {
    let salt = b"This Project is Dedicated to Aveesha.";
    let config = Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: 65536,
        time_cost: 1,
        lanes: 4,
        thread_mode: ThreadMode::Parallel,
        secret: &[],
        ad: &[],
        hash_length: 64,
    };
    // return the hash value but convert the error to Box<dyn>
    argon2::hash_raw(&password, salt, &config)
}

mod tests {
    #[test]
    fn test_hash_argon2() {
        use super::*;
        // defining a struct that will hold intput arguments
        // and their output hash results
        // need to use io::ErrorKind (instead of io:Error) which supports PartialEq
        #[derive(Debug, PartialEq)]
        struct PasswordHashPair<'a> {
            password: &'a str,
            hash_result: Vec<u8>,
        }

        // each entry of the array holds the input/output struct
        let password_hash_pairs = [
            PasswordHashPair {
                password: "",
                hash_result: vec![
                    13, 58, 236, 241, 152, 183, 100, 212, 216, 84, 90, 94, 168, 228, 31, 30, 77,
                    49, 66, 19, 123, 152, 12, 239, 137, 235, 105, 65, 204, 16, 29, 214, 212, 15,
                    173, 80, 27, 108, 127, 193, 196, 252, 102, 37, 234, 173, 71, 28, 14, 157, 76,
                    244, 99, 170, 151, 224, 154, 190, 53, 226, 85, 233, 245, 225,
                ],
            },
            PasswordHashPair {
                password: "This is a test!",
                hash_result: vec![
                    85, 96, 224, 183, 7, 56, 237, 97, 204, 74, 197, 74, 92, 189, 56, 227, 126, 87,
                    228, 28, 207, 173, 5, 111, 52, 228, 92, 208, 80, 152, 167, 236, 7, 214, 53,
                    103, 36, 168, 140, 9, 151, 221, 179, 68, 64, 180, 176, 81, 253, 221, 210, 100,
                    153, 141, 80, 152, 133, 23, 75, 217, 214, 153, 56, 173,
                ],
            },
        ];

        for index in 0..password_hash_pairs.len() {
            if let Ok(hash) = hash_argon2(password_hash_pairs[index].password.into()) {
                assert_eq!(hash, password_hash_pairs[index].hash_result)
            };
        }
    }
}
