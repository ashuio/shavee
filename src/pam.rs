use crate::yubi;
use crate::zfs_mount;
use sha2::{Digest, Sha512};
use std::env;
use std::fs;
use std::{io::Read, process::exit};

pub fn pam_mode_yubi(pass: &String, base_dir: &String) {
    let user = env::var("PAM_USER").expect("Var not found"); // Get username from environment
    let key = yubi::get_hash(&pass).expect("Failed to calculate hash from Yubikey");
    let mut dir = base_dir.clone();
    if !dir.ends_with("/") {
        dir.push('/');
    }
    dir.push_str(&user);
    zfs_mount::zfs_mount(&key, dir.to_owned()); // Unlock and mount ZFS Dataset
    exit(0);
}

pub fn pam_mode_file(pass: &String, base_dir: &String, file: &String) {
    let user = env::var("PAM_USER").expect("User Var not found"); // Get username from environment
    let passhash = Sha512::digest(&pass.as_bytes());
    let mut f = fs::File::open(&file).expect("Failed to open file");
    let mut file_hash: Vec<u8> = Vec::new();
    f.read_to_end(&mut file_hash)
        .expect("Failed to read Keyfile");
    let file_hash = Sha512::digest(&file_hash);
    let key = [file_hash, passhash].concat();
    let key = Sha512::digest(&key);
    let mut dir = base_dir.clone();
    if !dir.ends_with("/") {
        dir.push('/');
    }
    dir.push_str(&user);
    zfs_mount::zfs_mount(&format!("{:x}", &key), dir.clone()); // Unlock and mount ZFS Dataset

    exit(0);
}
