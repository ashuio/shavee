#[macro_use]
extern crate pamsm;

use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
#[cfg(feature = "file")]
use shavee_core::{filehash, logic, zfs::Dataset};
struct PamShavee;

// TODO: Need unit tests implemented for the PAM module functions

impl PamServiceModule for PamShavee {
    fn open_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn close_session(pam: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        eprintln!("{}", args[0]);

        let mut dataset_name = args[0].clone();
        if dataset_name.ends_with("/") {
            dataset_name.pop();
        };

        match unwrap_pam_user_pass(pam.get_user(Some("Username: ")), PamError::USER_UNKNOWN) {
            Ok(user) => {
                dataset_name.push('/');
                dataset_name.push_str(user);
            }
            Err(error) => return error,
        };

        let dataset = match Dataset::new(dataset_name) {
            Ok(d) => d,
            Err(_) => return PamError::INCOMPLETE,
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
        let mut dataset_name = args[0].clone();
        if dataset_name.ends_with("/") {
            dataset_name.pop();
        };

        match unwrap_pam_user_pass(pam.get_user(Some("Username: ")), PamError::USER_UNKNOWN) {
            Ok(user) => {
                dataset_name.push('/');
                dataset_name.push_str(user);
            }
            Err(error) => return error,
        };

        let dataset = match Dataset::new(dataset_name) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Invalid dataset name: {}", e);
                return PamError::INCOMPLETE;
            }
        };

        let pass = match unwrap_pam_user_pass(pam.get_authtok(None), PamError::AUTHINFO_UNAVAIL) {
            Ok(slice) => slice.to_string(),
            Err(error) => {
                eprintln!("Error Getting Password: {}", error);
                return error;
            }
        };

       let datasets = match dataset.list(){
            Ok(d) => d,
            Err(_) => {
                eprintln!("Unable to list ZFS Datasets");
                return PamError::BAD_ITEM
            }
        };

        for d in datasets {

        let umode = match d.get_property_2fa() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Error Getting Dataset Properties: {}", e);
                return PamError::BAD_ITEM;
            }
        };


        let salt = match logic::get_salt(Some(&d)) {
            Ok(salt) => salt,
            Err(error) => {
                eprintln!("Error in determining salt: {}", error.to_string());
                return PamError::INCOMPLETE;
            }
        };
        let password: &[u8] = &pass.clone().into_bytes();
        let result = match umode {
            #[cfg(feature = "yubikey")]
            shavee_core::structs::TwoFactorMode::Yubikey { yslot } => {
                d.yubi_unlock(password, yslot, &salt)
            }

            #[cfg(feature = "file")]
            shavee_core::structs::TwoFactorMode::File { file, port, size } => {
                let filehash = match filehash::get_filehash(&file, port, size) {
                    Ok(hash) => hash,
                    Err(error) => {
                        eprintln!("Error in generating filehash: {}", error.to_string());
                        return PamError::AUTHINFO_UNAVAIL;
                    }
                };
                d.file_unlock(password, filehash, &salt)
            }

            shavee_core::structs::TwoFactorMode::Password => {
                let key = match logic::password_mode_hash(password, &salt) {
                    Ok(key) => key,
                    Err(error) => {
                        eprintln!("Error in generating password hash: {}", error.to_string());
                        return PamError::AUTHINFO_UNAVAIL;
                    }
                };
                d.pass_unlock(key)
            }
        };
    

        match result {
            Ok(_) => {},
            Err(e) => {
                eprintln!("Error in mounting user ZFS dataset: {}", e.to_string());
            }
        }

    }
    PamError::SUCCESS
    }

    fn setcred(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
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
