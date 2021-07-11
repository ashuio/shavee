use crate::{
    yubi,
    zfs::{zfs_create, zfs_mount},
};
use sha2::{Digest, Sha512};
use std::{io::Read, process::exit};

pub fn print_mode_yubi(pass: &String) {
    let key = yubi::get_hash(&pass).expect("Failed to calculate hash from Yubikey"); // Get encryption key
    println!("{}", &key);
    exit(0);
}

pub fn print_mode_file(pass: &String, file: &String) {
    let passhash = Sha512::digest(&pass.as_bytes());

    let mut f = std::fs::File::open(&file).expect("Failed opening file");
    let mut filehash: Vec<u8> = Vec::new();
    f.read_to_end(&mut filehash).expect("Failed reading file.");
    let filehash = Sha512::digest(&filehash);
    let key = [filehash, passhash].concat();
    let key = Sha512::digest(&key);
    println!("{:x}", &key);
    exit(0);
}

pub fn unlock_zfs_yubi(pass: String, zfspath: String) {
    let key = yubi::get_hash(&pass); // Get encryption key
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

pub fn unlock_zfs_file(pass: String, file: String, dataset: String) {
    let mut dataset = dataset;
    if dataset.ends_with("/") {
        dataset.pop();
    }
    let passhash = Sha512::digest(&pass.as_bytes());

    let mut f = std::fs::File::open(&file).expect("Failed opening file");
    let mut filehash: Vec<u8> = Vec::new();
    f.read_to_end(&mut filehash).expect("Failed reading file.");
    let filehash = Sha512::digest(&filehash);
    let key = [filehash, passhash].concat();
    let key = Sha512::digest(&key);
    let key = format!("{:x}", key);
    zfs_mount(&key, dataset)
}

pub fn create_zfs_file(pass: String, file: String, dataset: String) {
    let mut dataset = dataset;
    if dataset.ends_with("/") {
        dataset.pop();
    }
    let passhash = Sha512::digest(&pass.as_bytes());

    let mut f = std::fs::File::open(&file).expect("Failed opening file");
    let mut filehash: Vec<u8> = Vec::new();
    f.read_to_end(&mut filehash).expect("Failed reading file.");
    let filehash = Sha512::digest(&filehash);
    let key = [filehash, passhash].concat();
    let key = Sha512::digest(&key);
    let key = format!("{:x}", key);
    zfs_create(&key, dataset)
}

pub fn create_zfs_yubi(pass: String, zfspath: String) {
    let key = yubi::get_hash(&pass); // Get encryption key
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
