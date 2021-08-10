use crate::filehash::get_filehash;
use crate::yubikey::*;
use crate::zfs::*;
use std::error::Error;
use sha2::{Digest, Sha512};


pub fn print_mode_yubi(pass: String, slot: u8) -> Result<(),Box<dyn Error>> {
    let key = yubikey_get_hash(&pass, slot); // Get encryption key
    let key = match key {
        Ok(key) => key,
        Err(error) => return Err(error.to_string().into()),
    };
    println!("{}",&key);
    Ok(())
}

pub fn print_mode_file(pass: String, file: &String, port: u16) -> Result<(),Box<dyn Error>> {
    let passhash = Sha512::digest(&pass.as_bytes()).to_vec();

    let filehash = get_filehash(file.clone(), port)?;
    let key = [filehash, passhash].concat();
    let key = Sha512::digest(&key);
    println!("{:x}", &key);
    Ok(())
}

pub fn unlock_zfs_yubi(pass: String, dataset: String, slot: u8) -> Result<(),Box<dyn Error>> {
    let key = yubikey_get_hash(&pass, slot)?; // Get encryption key
    zfs_loadkey(key, dataset.clone())?;
    zfs_mount(dataset)?;
    Ok(())
}

pub fn unlock_zfs_file(pass: String, file: String, dataset: String, port: u16) -> Result<(),Box<dyn Error>> {

    let passhash = Sha512::digest(&pass.as_bytes()).to_vec();
    let filehash = get_filehash(file.clone(), port)?;
    let key = [filehash, passhash].concat();
    let key = Sha512::digest(&key);
    let key = format!("{:x}", key);
    zfs_loadkey(key, dataset.clone())?;
    zfs_mount(dataset)?;
    Ok(())
}

pub fn create_zfs_file(pass: String, file: String, dataset: String, port: u16) -> Result<(),Box<dyn Error>> {
    
    let passhash = Sha512::digest(&pass.as_bytes()).to_vec();

    let filehash = get_filehash(file.clone(), port)?;
    let key = [filehash, passhash].concat();
    let key = Sha512::digest(&key);
    let key = format!("{:x}", key);
    zfs_create(key, dataset)?;
    Ok(())
}

pub fn create_zfs_yubi(pass: String, zfspath: String, slot: u8) -> Result<(),Box<dyn Error>> {
    let key = yubikey_get_hash(&pass, slot)?; // Get encryption key
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
