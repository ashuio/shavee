mod args;

#[macro_use]
extern crate pamsm;

use base64::encode_config;
use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use shavee_lib::{
    filehash::get_filehash,
    logic::{unlock_zfs_file, unlock_zfs_pass, unlock_zfs_yubi},
    password::hash_argon2,
    zfs::*,
};
struct PamShavee;

impl PamServiceModule for PamShavee {
    fn authenticate(pam: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        let mut clap_args: Vec<String> = Vec::new();
        clap_args.push("libshavee_pam.so".to_string());
        clap_args.extend(args);
        let state = match args::Pargs::new_from(clap_args.into_iter()) {
            // Parse Args
            Ok(args) => args,
            Err(e) => {
                eprintln!("Error: {}", e);
                return PamError::BAD_ITEM;
            }
        };
        let user = match pam.get_user(Some("Username: ")) {
            Ok(None) => return PamError::USER_UNKNOWN,
            Ok(username) => match username.unwrap().to_str() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error {}!", e);
                    return PamError::USER_UNKNOWN;
                }
            },
            Err(e) => {
                eprintln!("Error {}!", e);
                return e;
            }
        };
        let mut dataset = state.dataset;
        dataset.push('/');
        dataset.push_str(user); // Push Username to dataset

        let pass = pam
            .get_authtok(Some("Dataset Password: "))
            .unwrap()
            .unwrap()
            .to_string_lossy()
            .to_string();

        match state.umode {
            shavee_lib::Umode::Yubikey { yslot } => {
                match unlock_zfs_yubi(pass, Some(dataset), yslot) {
                    Ok(_) => return PamError::SUCCESS,
                    Err(e) => {
                        eprintln!("Error: {}", e.to_string());
                        return PamError::AUTH_ERR;
                    }
                }
            }
            shavee_lib::Umode::File { file, port, size } => {
                let filehash = match get_filehash(file, port, size) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("Error: {}", e.to_string());
                        return PamError::AUTHINFO_UNAVAIL;
                    }
                };
                match unlock_zfs_file(pass, filehash, Some(dataset)) {
                    Ok(_) => return PamError::SUCCESS,
                    Err(e) => {
                        eprintln!("Error: {}", e.to_string());
                        return PamError::AUTH_ERR;
                    }
                }
            }
            shavee_lib::Umode::Password => {
                let key = hash_argon2(pass.into_bytes()).unwrap();
                let key = encode_config(key, base64::STANDARD_NO_PAD);
                match unlock_zfs_pass(key, Some(dataset)) {
                    Ok(_) => return PamError::SUCCESS,
                    Err(e) => {
                        eprintln!("Error: {}", e.to_string());
                        return PamError::AUTH_ERR;
                    }
                }
            }
        }
    }

    fn setcred(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
    fn open_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn close_session(pam: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        let mut dataset = String::from("zroot/data/home/");
        let p = Some("Username: ");

        let user = pam.get_user(p);
        let user = match user {
            Ok(i) => i,
            _ => return PamError::USER_UNKNOWN,
        };

        let user = match user {
            Some(i) => i.to_str().unwrap(),
            _ => return PamError::USER_UNKNOWN,
        };

        dataset.push_str(user);
        match zfs_umount(dataset) {
            Ok(_) => return PamError::SUCCESS,
            Err(_) => return PamError::SESSION_ERR,
        }
    }
}

pam_module!(PamShavee);
