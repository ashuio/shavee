use crate::{password::hash_argon2, yubikey::*, zfs::*};
use base64::encode_config;
use std::error::Error;

fn unwrap_dataset(dataset: Option<String>) -> Result<String, Box<dyn Error>> {
    Ok(match dataset {
        None => {
            let error_message = "ZFS dataset unknown!";
            return Err(error_message.into());
        }
        Some(d) => d,
    })
}

fn yubi_key_calculation(pass: String, slot: u8) -> Result<String, Box<dyn Error>> {
    let key = yubikey_get_hash(pass, slot)?;
    Ok(encode_config(key, base64::STANDARD_NO_PAD))
}

fn file_key_calculation(pass: String, filehash: Vec<u8>) -> Result<String, Box<dyn Error>> {
    let passhash = hash_argon2(pass.into_bytes())?;
    let key = hash_argon2([filehash, passhash].concat())?;
    Ok(encode_config(key, base64::STANDARD_NO_PAD))
}

pub fn print_mode_yubi(pass: String, slot: u8) -> Result<(), Box<dyn Error>> {
    let key = yubi_key_calculation(pass, slot)?;
    println!("{}", key);
    Ok(())
}

pub fn unlock_zfs_yubi(
    pass: String,
    dataset: Option<String>,
    slot: u8,
) -> Result<(), Box<dyn Error>> {
    let dataset = unwrap_dataset(dataset)?;
    let key = yubi_key_calculation(pass, slot)?;
    zfs_loadkey(key, dataset.clone())?;
    zfs_mount(dataset)?;
    Ok(())
}

pub fn create_zfs_yubi(pass: String, zfspath: String, slot: u8) -> Result<(), Box<dyn Error>> {
    let key = yubi_key_calculation(pass, slot)?;
    zfs_create(key, zfspath)?;
    Ok(())
}

pub fn print_mode_file(pass: String, filehash: Vec<u8>) -> Result<(), Box<dyn Error>> {
    let key = file_key_calculation(pass, filehash)?;
    println!("{}", key);
    Ok(())
}

pub fn unlock_zfs_file(
    pass: String,
    filehash: Vec<u8>,
    dataset: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let dataset = unwrap_dataset(dataset)?;
    let key = file_key_calculation(pass, filehash)?;
    zfs_loadkey(key, dataset.clone())?;
    zfs_mount(dataset)?;
    Ok(())
}

pub fn create_zfs_file(
    pass: String,
    filehash: Vec<u8>,
    dataset: String,
) -> Result<(), Box<dyn Error>> {
    let key = file_key_calculation(pass, filehash)?;
    zfs_create(key, dataset)?;
    Ok(())
}

pub fn unlock_zfs_pass(key: String, dataset: Option<String>) -> Result<(), Box<dyn Error>> {
    let dataset = unwrap_dataset(dataset)?;
    let dataset_list = zfs_list(dataset.clone())?;
    zfs_loadkey(key, dataset)?;
    for set in dataset_list {
        zfs_mount(set)?;
    }
    Ok(())
}
