mod args;

#[macro_use]
extern crate pamsm;

use base64::{
    alphabet,
    engine::{general_purpose, GeneralPurpose},
    Engine,
};
use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
#[cfg(feature = "file")]
use shavee_core::filehash;
use shavee_core::password;
use shavee_core::zfs::Dataset;
struct PamShavee;

// TODO: Need unit tests implemented for the PAM module functions

const BASE64_ENGINE: GeneralPurpose =
    GeneralPurpose::new(&alphabet::STANDARD, general_purpose::NO_PAD);

impl PamServiceModule for PamShavee {
    fn open_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn close_session(pam: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        let (_umode, dataset, _pass) = match parse_pam_args(args, pam) {
            Ok(value) => value,
            Err(error) => return error,
        };

        match dataset.umount() {
            Ok(_) => match dataset.unloadkey() {
                Ok(_) => return PamError::SUCCESS,
                Err(error) => {
                    eprintln!(
                        "Error in unloading ZFS dataset {} key: {}",
                        dataset.to_string(),
                        error.to_string()
                    );
                    return PamError::SESSION_ERR;
                }
            },
            Err(error) => {
                eprintln!(
                    "Error in unmounting user {} ZFS dataset: {}",
                    dataset.to_string(),
                    error.to_string()
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
            #[cfg(feature = "yubikey")]
            args::TwoFactorMode::Yubikey { yslot } => dataset.yubi_unlock(pass, yslot),

            #[cfg(feature = "file")]
            args::TwoFactorMode::File { file, port, size } => {
                let filehash = match filehash::get_filehash(file, port, size) {
                    Ok(error) => error,
                    Err(error) => {
                        eprintln!("Error in generating filehash: {}", error.to_string());
                        return PamError::AUTHINFO_UNAVAIL;
                    }
                };
                dataset.file_unlock(pass, filehash)
            }

            args::TwoFactorMode::Password => {
                let key = password::hash_argon2(pass.into_bytes()).unwrap();
                let key = BASE64_ENGINE.encode(key);
                dataset.pass_unlock(key)
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

fn parse_pam_args(
    args: Vec<String>,
    pam: Pam,
) -> Result<(args::TwoFactorMode, Dataset, String), PamError> {
    let state = {
        let mut clap_args: Vec<String> = Vec::new();
        clap_args.push("libshavee_pam.so".to_string());
        clap_args.extend(args);
        match args::PamArgs::new_from(clap_args.into_iter()) {
            // Parse Args
            Ok(args) => args,
            Err(e) => {
                eprintln!("Error: {}", e);
                return Err(PamError::BAD_ITEM);
            }
        }
    };
    let dataset =
        match unwrap_pam_user_pass(pam.get_user(Some("Username: ")), PamError::USER_UNKNOWN) {
            Ok(user) => {
                let mut dataset = state.dataset;
                dataset.push('/');
                dataset.push_str(user);
                dataset
            }
            Err(error) => return Err(error),
        };

    let zfs_dataset = match Dataset::new(dataset) {
        Ok(dataset) => dataset,
        Err(error) => {
            eprintln!("{}", error.to_string());
            return Err(PamError::BAD_ITEM);
        }
    };

    let pass = match unwrap_pam_user_pass(pam.get_authtok(None), PamError::AUTHINFO_UNAVAIL) {
        Ok(slice) => slice.to_string(),
        Err(error) => return Err(error),
    };
    Ok((state.second_factor, zfs_dataset, pass))
}

fn unwrap_pam_user_pass(
    pam_key: Result<Option<&std::ffi::CStr>, PamError>,
    pam_error: PamError,
) -> Result<&str, PamError> {
    let key = match pam_key {
        Ok(None) => return Err(pam_error),
        Ok(value) => match value.unwrap().to_str() {
            Ok(s) => s,
            Err(error) => {
                eprintln!("Error {}!", error);
                return Err(pam_error);
            }
        },
        Err(error) => {
            eprintln!("Error {}!", error);
            return Err(error);
        }
    };
    Ok(key)
}

pam_module!(PamShavee);
