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
    fn open_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn close_session(pam: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        let state = match pam_parse_args(args) {
            Ok(value) => value,
            Err(e) => return e,
        };

        let dataset =
            match pam_user_pass_expect(pam.get_user(Some("Username: ")), PamError::USER_UNKNOWN) {
                Ok(user) => {
                    let mut d = state.dataset;
                    d.push('/');
                    d.push_str(user);
                    d
                }
                Err(e) => return e,
            };

        match zfs_umount(dataset) {
            Ok(()) => return PamError::SUCCESS,
            Err(_) => return PamError::SESSION_ERR,
        }
    }
    fn authenticate(pam: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        let state = match pam_parse_args(args) {
            Ok(value) => value,
            Err(e) => return e,
        };

        let dataset =
            match pam_user_pass_expect(pam.get_user(Some("Username: ")), PamError::USER_UNKNOWN) {
                Ok(user) => {
                    let mut d = state.dataset;
                    d.push('/');
                    d.push_str(user);
                    d
                }
                Err(e) => return e,
            };

        let pass = match pam_user_pass_expect(pam.get_authtok(None), PamError::AUTHINFO_UNAVAIL) {
            Ok(value) => value.to_string(),
            Err(value) => return value,
        };

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
}

fn pam_parse_args(args: Vec<String>) -> Result<args::Pargs, PamError> {
    let mut clap_args: Vec<String> = Vec::new();
    clap_args.push("libshavee_pam.so".to_string());
    clap_args.extend(args);
    let state = match args::Pargs::new_from(clap_args.into_iter()) {
        // Parse Args
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(PamError::BAD_ITEM);
        }
    };
    Ok(state)
}

fn pam_user_pass_expect(
    pam_key: Result<Option<&std::ffi::CStr>, PamError>,
    pam_error: PamError,
) -> Result<&str, PamError> {
    let key = match pam_key {
        Ok(None) => return Err(pam_error),
        Ok(username) => match username.unwrap().to_str() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error {}!", e);
                return Err(pam_error);
            }
        },
        Err(e) => {
            eprintln!("Error {}!", e);
            return Err(e);
        }
    };
    Ok(key)
}

pam_module!(PamShavee);
