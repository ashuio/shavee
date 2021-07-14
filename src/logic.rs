use crate::{
    filehash::get_filehash,
    yubikey,
    zfs::{zfs_create, zfs_mount},
};

use sha2::{Digest, Sha512};
use std::process::exit;

pub fn print_mode_yubi(pass: &String, slot: u8) {
    let key = yubikey::get_hash(&pass, slot); // Get encryption key
    let key = match key {
        Ok(key) => key,
        Err(error) => {
            eprintln!("Error: Failed to calculate hash from Yubikey\n{}", error);
            exit(1)
        }
    };
    println!("{}", &key);
    drop(key);
    exit(0);
}

pub fn print_mode_file(pass: &String, file: &String, port: u16) {
    let passhash = Sha512::digest(&pass.as_bytes()).to_vec();

    let filehash = get_filehash(&file, port);
    let key = [filehash, passhash].concat();
    let key = Sha512::digest(&key);
    println!("{:x}", &key);
    drop(key);
    exit(0);
}

pub fn unlock_zfs_yubi(pass: String, zfspath: String, slot: u8) {
    let key = yubikey::get_hash(&pass, slot); // Get encryption key
    match key {
        Ok(key) => {
            zfs_mount(&key, zfspath);
            drop(key);
        }

        Err(error) => {
            eprintln!("Error: Failed to calculate hash from Yubikey\n{}", error);
            exit(1)
        }
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
    zfs_mount(&key, dataset);
    drop(key);
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
    zfs_create(&key, dataset);
    drop(key);
}

pub fn create_zfs_yubi(pass: String, zfspath: String, slot: u8) {
    let key = yubikey::get_hash(&pass, slot); // Get encryption key
    let zfspath = zfspath;
    match key {
        Ok(key) => {
            zfs_create(&key, zfspath);
            drop(key);
        }
        Err(error) => {
            eprintln!("Error: Failed to calculate hash from Yubikey\n{}", error);
            exit(1)
        }
    }
}
