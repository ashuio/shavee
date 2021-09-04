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
        let (_umode, dataset, _pass) = match parse_pam_args(args, pam) {
            Ok(value) => value,
            Err(e) => return e,
        };

        match zfs_umount(dataset.clone()) {
            Ok(()) => return PamError::SUCCESS,
            Err(e) => {
                eprintln!(
                    "Error in unmounting user ZFS {} dataset: {}",
                    dataset,
                    e.to_string()
                );
                return PamError::SESSION_ERR;
            }
        }
    }

    fn authenticate(pam: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        let (umode, dataset, pass) = match parse_pam_args(args, pam) {
            Ok(value) => value,
            Err(e) => return e,
        };

        let result = match umode {
            args::Umode::Yubikey { yslot } => unlock_zfs_yubi(pass, Some(dataset), yslot),

            args::Umode::File { file, port, size } => {
                let filehash = match get_filehash(file, port, size) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("Error in generating filehash: {}", e.to_string());
                        return PamError::AUTHINFO_UNAVAIL;
                    }
                };
                unlock_zfs_file(pass, filehash, Some(dataset))
            }

            args::Umode::Password => {
                let key = hash_argon2(pass.into_bytes()).unwrap();
                let key = encode_config(key, base64::STANDARD_NO_PAD);
                unlock_zfs_pass(key, Some(dataset))
            }
        };

        match result {
            Ok(_) => return PamError::SUCCESS,
            Err(e) => {
                eprintln!("Error in mounting user ZFS dataset: {}", e.to_string());
                return PamError::AUTH_ERR;
            }
        }
    }

    fn setcred(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

fn parse_pam_args(args: Vec<String>, pam: Pam) -> Result<(args::Umode, String, String), PamError> {
    let state = match {
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
    } {
        Ok(value) => value,
        Err(e) => return Err(e),
    };
    let dataset =
        match unwrap_pam_user_pass(pam.get_user(Some("Username: ")), PamError::USER_UNKNOWN) {
            Ok(user) => {
                let mut d = state.dataset;
                d.push('/');
                d.push_str(user);
                d
            }
            Err(e) => return Err(e),
        };
    let pass = match unwrap_pam_user_pass(pam.get_authtok(None), PamError::AUTHINFO_UNAVAIL) {
        Ok(value) => value.to_string(),
        Err(value) => return Err(value),
    };
    Ok((state.umode, dataset, pass))
}

fn unwrap_pam_user_pass(
    pam_key: Result<Option<&std::ffi::CStr>, PamError>,
    pam_error: PamError,
) -> Result<&str, PamError> {
    let key = match pam_key {
        Ok(None) => return Err(pam_error),
        Ok(value) => match value.unwrap().to_str() {
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
