use pbkdf2::{Pbkdf2, password_hash::{PasswordHash, PasswordHasher, SaltString}, pbkdf2};

pub fn password_hash(pass: String) -> String {
    
    let mut res = 
    pbkdf2(pass.as_bytes() , b"Aveesha", 16384, res);
    String::from("a")
}