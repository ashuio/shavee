use argon2::{Config, ThreadMode, Variant, Version};
use std::error::Error;

pub fn hash_argon2(password: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
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
    match argon2::hash_raw(&password, salt, &config) {
        Ok(i) => return Ok(i),
        Err(e) => return Err(e.into()),
    }
}