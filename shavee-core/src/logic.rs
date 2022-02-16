use crate::{password::hash_argon2, yubikey::*, zfs::*};
use base64::encode_config;
use std::error::Error;

// TODO: Decide if unit tests are needed for the functions with simple logics?

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

pub fn unlock_zfs_yubi(pass: String, dataset: Dataset, slot: u8) -> Result<(), Box<dyn Error>> {
    let passphrase = yubi_key_calculation(pass, slot)?;
    dataset.loadkey(&passphrase)?;
    dataset.mount()?;
    Ok(())
}

pub fn create_zfs_yubi(pass: String, dataset: Dataset, slot: u8) -> Result<(), Box<dyn Error>> {
    let passphrase = yubi_key_calculation(pass, slot)?;
    dataset.create(&passphrase)?;
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
    dataset: Dataset,
) -> Result<(), Box<dyn Error>> {
    let passphrase = file_key_calculation(pass, filehash)?;
    dataset.loadkey(&passphrase)?;
    dataset.mount()?;
    Ok(())
}

pub fn create_zfs_file(
    pass: String,
    filehash: Vec<u8>,
    dataset: Dataset,
) -> Result<(), Box<dyn Error>> {
    let passphrase = &file_key_calculation(pass, filehash)?;
    dataset.create(passphrase).map_err(Into::into)
}

pub fn unlock_zfs_pass(passphrase: String, dataset: Dataset) -> Result<(), Box<dyn Error>> {
    let dataset_list = dataset.list()?;
    dataset.loadkey(&passphrase)?;

    for each_set in dataset_list {
        each_set.mount()?;
    }
    Ok(())
}
