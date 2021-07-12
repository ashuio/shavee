use crate::{
    filehash::get_filehash,
    yubi,
    zfs::{zfs_create, zfs_mount},
};

use sha2::{Digest, Sha512};
use std::process::exit;

pub fn print_mode_yubi(pass: &String,slot:u8) {
    let key = yubi::get_hash(&pass,slot).expect("Failed to calculate hash from Yubikey"); // Get encryption key
    println!("{}", &key);
    exit(0);
}

pub fn print_mode_file(pass: &String, file: &String, port: u16) {
    let passhash = Sha512::digest(&pass.as_bytes()).to_vec();

    let filehash = get_filehash(&file, port);
    let key = [filehash, passhash].concat();
    let key = Sha512::digest(&key);
    println!("{:x}", &key);
    exit(0);
}

pub fn unlock_zfs_yubi(pass: String, zfspath: String,slot:u8) {
    let key = yubi::get_hash(&pass,slot); // Get encryption key
    let mut zfspath = zfspath;
    match key {
        Ok(key) => {
            if zfspath.ends_with("/") {
                zfspath.pop();
                zfs_mount(&key, zfspath.to_string());
            } else {
                zfs_mount(&key, zfspath)
            }
        } // Print encryption key
        Err(error) => panic!("{}", error),
    }
}

pub fn unlock_zfs_file(pass: String, file: String, dataset: String, port: u16) {
    let mut dataset = dataset;
    if dataset.ends_with("/") {
        dataset.pop();
    }
    let passhash = Sha512::digest(&pass.as_bytes()).to_vec();
    let filehash = get_filehash(&file, port);
    let key = [filehash, passhash].concat();
    let key = Sha512::digest(&key);
    let key = format!("{:x}", key);
    zfs_mount(&key, dataset)
}

pub fn create_zfs_file(pass: String, file: String, dataset: String, port: u16) {
    let mut dataset = dataset;
    if dataset.ends_with("/") {
        dataset.pop();
    }
    let passhash = Sha512::digest(&pass.as_bytes()).to_vec();

    let filehash = get_filehash(&file, port);
    let key = [filehash, passhash].concat();
    let key = Sha512::digest(&key);
    let key = format!("{:x}", key);
    zfs_create(&key, dataset)
}

pub fn create_zfs_yubi(pass: String, zfspath: String,slot:u8) {
    let key = yubi::get_hash(&pass,slot); // Get encryption key
    let mut zfspath = zfspath;
    match key {
        Ok(key) => {
            if zfspath.ends_with("/") {
                zfspath.pop();
                zfs_create(&key, zfspath.to_string());
            } else {
                zfs_create(&key, zfspath)
            }
        } // Print encryption key
        Err(error) => panic!("{}", error),
    }
}

pub fn port_check(v: String) -> Result<(), String> {
    let v: u16 = v.parse::<u16>().expect("Invalid Port number");
    if v > 0 {
        return Ok(());
    }
    Err(String::from("Inavlid Port number"))
}
