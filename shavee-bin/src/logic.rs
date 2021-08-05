use crate::{filehash::get_filehash, yubikey};
use shavee_zfs::*;

use sha2::{Digest, Sha512};
use std::process::exit;

pub fn print_mode_yubi(pass: String, slot: u8) {
    let key = yubikey::get_hash(&pass, slot); // Get encryption key
    let key = match key {
        Ok(key) => key,
        Err(error) => {
            eprintln!(
                "Error: Failed to run HMAC challenge on Yubikey on slot {}",
                slot
            );
            eprintln!("Error: {}", error);
            exit(1)
        }
    };
    println!("{}", &key);
    exit(0);
}

pub fn print_mode_file(pass: String, file: &String, port: u16) {
    let passhash = Sha512::digest(&pass.as_bytes()).to_vec();

    let filehash = get_filehash(&file, port);
    let key = [filehash, passhash].concat();
    let key = Sha512::digest(&key);
    println!("{:x}", &key);
    exit(0);
}

pub fn unlock_zfs_yubi(pass: String, zfspath: String, slot: u8) {
    let key = yubikey::get_hash(&pass, slot); // Get encryption key
    match key {
        Ok(key) => {
            match zfs_loadkey(key, zfspath.clone()) {
                Ok(()) => (),
                Err(error) => {
                    eprintln!("Error: {}", error);
                    exit(1)
                }
            };
            match zfs_mount(zfspath) {
                Ok(()) => (),
                Err(error) => {
                    eprintln!("Error: {}", error);
                    exit(1)
                }
            };
        }

        Err(error) => {
            eprintln!(
                "Error: Failed to run HMAC challenge on Yubikey on slot {}",
                slot
            );
            eprintln!("Error: {}", error);
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
    match zfs_loadkey(key, dataset.clone()) {
        Ok(()) => (),
        Err(error) => {
            eprintln!("Error: {}", error);
            exit(1)
        }
    };
    match zfs_mount(dataset) {
        Ok(()) => (),
        Err(error) => {
            eprintln!("Error: {}", error);
            exit(1)
        }
    };
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
    match zfs_create(key, dataset) {
        Ok(()) => (),
        Err(error) => {
            eprintln!("Error: {}", error);
            exit(1)
        }
    };
}

pub fn create_zfs_yubi(pass: String, zfspath: String, slot: u8) {
    let key = yubikey::get_hash(&pass, slot); // Get encryption key
    let zfspath = zfspath;
    match key {
        Ok(key) => {
            match zfs_create(key, zfspath) {
                Ok(()) => (),
                Err(error) => {
                    eprintln!("Error: {}", error);
                    exit(1)
                }
            };
        }
        Err(error) => {
            eprintln!(
                "Error: Failed to run HMAC challenge on Yubikey on slot {}",
                slot
            );
            eprintln!("Error: {}", error);
            exit(1)
        }
    }
}

pub fn unlock_zfs_pass(key: String, dataset: String) {
    let sets = match zfs_list(dataset.clone()) {
        Ok(i) => {
            match zfs_loadkey(key, dataset) {
                Ok(()) => (),
                Err(error) => {
                    eprintln!("ERROR: {}", error);
                    exit(1);
                }
            }
            i
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            exit(1)
        }
    };

    for i in sets {
        match zfs_mount(i) {
            Ok(()) => (),
            Err(error) => {
                eprintln!("ERROR: {}", error);
            }
        }
    }
}
