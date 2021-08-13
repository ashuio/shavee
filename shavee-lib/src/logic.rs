pub const UNREACHABLE_CODE : &str = "Panic! Something unexpected happened! Please help by reporting it as a bug.";

use crate::filehash::get_filehash;
use crate::password::hash_argon2;
use crate::yubikey::*;
use crate::zfs::*;
use base64::encode_config;
use std::error::Error;

fn yubi_key_calculation(pass: String, slot: u8) -> Result<String, Box<dyn Error>> {
    let key = yubikey_get_hash(pass, slot)?;
    Ok(encode_config(key, base64::STANDARD_NO_PAD))
}

pub fn print_mode_yubi(pass: String, slot: u8) -> Result<(), Box<dyn Error>> {
    let key = yubi_key_calculation(pass, slot)?;
    println!("{}", key);
    Ok(())
}

pub fn unlock_zfs_yubi(pass: String, dataset: Option<String>, slot: u8) -> Result<(), Box<dyn Error>> {
    let dataset = dataset
        .expect(UNREACHABLE_CODE);

    let key = yubi_key_calculation(pass, slot)?;
    zfs_loadkey(key, dataset.clone())?;
    zfs_mount(dataset)?;
    Ok(())
}

pub fn create_zfs_yubi(pass: String, zfspath: Option<String>, slot: u8) -> Result<(), Box<dyn Error>> {
    let key = yubi_key_calculation(pass, slot)?;
    zfs_create(key, zfspath)?;
    Ok(())
}

fn file_key_calculation(pass: String, file: Option<String>, port: Option<u16>) -> Result<String, Box<dyn Error>> {
    let file = file
        .expect(UNREACHABLE_CODE);
    let passhash = hash_argon2(pass.into_bytes())?;
    let filehash = get_filehash(file.clone(), port)?;
    let key = [filehash, passhash].concat();
    let key = hash_argon2(key)?;
    let key = encode_config(key, base64::STANDARD_NO_PAD);
    Ok(key)
}

pub fn print_mode_file(pass: String, file: Option<String>, port: Option<u16>) -> Result<(),Box<dyn Error>> {
    let key = file_key_calculation(pass, file, port)?;
    println!("{}", key);
    Ok(())
}

pub fn unlock_zfs_file(
    pass: String,
    file: Option<String>,
    dataset: Option<String>,
    port: Option<u16>
) -> Result<(),Box<dyn Error>> {
    let dataset = dataset
        .expect(UNREACHABLE_CODE);
    let key = file_key_calculation(pass, file, port)?;
    zfs_loadkey(key, dataset.clone())?;
    zfs_mount(dataset)?;
    Ok(())
}

pub fn create_zfs_file(
    pass: String,
    file: Option<String>,
    dataset: Option<String>,
    port: Option<u16>
) -> Result<(), Box<dyn Error>> {
    let key = file_key_calculation(pass, file, port)?;
    zfs_create(key, dataset)?;
    Ok(())
}


pub fn unlock_zfs_pass(key: String, dataset: Option<String>) -> Result<(), Box<dyn Error>> {
    let dataset = dataset
        .expect(UNREACHABLE_CODE);
    match zfs_list(dataset.clone()) {
        Ok(i) => {
            zfs_loadkey(key, dataset)?;
            for sets in i {
                match zfs_mount(sets) {
                    Ok(()) => (),
                    Err(error) => {
                        eprintln!("ERROR: {}", error);
                    }
                }
            }
        }

        Err(e) => return Err(e),
    }

    Ok(())
}
