use crate::filehash::get_filehash;
use crate::password::hash_argon2;
use crate::yubikey::*;
use crate::zfs::*;
use std::error::Error;
use base64::encode_config;
// use hex::encode;


pub fn print_mode_yubi(pass: String, slot: u8) -> Result<(),Box<dyn Error>> {
    let key = yubikey_get_hash(pass, slot)?; // Get encryption key
    let key = encode_config(key,base64::STANDARD_NO_PAD);
    println!("{}",key);
    Ok(())
}

pub fn print_mode_file(pass: String, file: &String, port: u16) -> Result<(),Box<dyn Error>> {
    let passhash = hash_argon2(pass.into_bytes());
    let filehash = get_filehash(file.clone(), port)?;
    let key = [filehash, passhash].concat();
    let key = hash_argon2(key);
    let key = encode_config(key,base64::STANDARD_NO_PAD);
    println!("{}",key);
    Ok(())
}

pub fn unlock_zfs_yubi(pass: String, dataset: String, slot: u8) -> Result<(),Box<dyn Error>> {
    let key = yubikey_get_hash(pass, slot)?; // Get encryption key
    let key = encode_config(key,base64::STANDARD_NO_PAD);
    zfs_loadkey(key, dataset.clone())?;
    zfs_mount(dataset)?;
    Ok(())
}

pub fn unlock_zfs_file(pass: String, file: String, dataset: String, port: u16) -> Result<(),Box<dyn Error>> {

    let passhash = hash_argon2(pass.into_bytes());
    let filehash = get_filehash(file.clone(), port)?;
    let key = [filehash, passhash].concat();
    let key = encode_config(hash_argon2(key),base64::STANDARD_NO_PAD);
    zfs_loadkey(key, dataset.clone())?;
    zfs_mount(dataset)?;
    Ok(())
}

pub fn create_zfs_file(pass: String, file: String, dataset: String, port: u16) -> Result<(),Box<dyn Error>> {
    
    let passhash = hash_argon2(pass.into_bytes());

    let filehash = get_filehash(file.clone(), port)?;
    let key = [filehash, passhash].concat();
    let key = encode_config(hash_argon2(key),base64::STANDARD_NO_PAD);
    zfs_create(key, dataset)?;
    Ok(())
}

pub fn create_zfs_yubi(pass: String, zfspath: String, slot: u8) -> Result<(),Box<dyn Error>> {
    let key = encode_config(yubikey_get_hash(pass, slot)?,base64::STANDARD_NO_PAD); // Get encryption key
    zfs_create(key, zfspath)?;
    Ok(())
}

pub fn unlock_zfs_pass(key: String, dataset: String) -> Result<(),Box<dyn Error>> {
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
                };
            
        }
    
        Err(e) => return Err(e),

    }


    Ok(())

}
