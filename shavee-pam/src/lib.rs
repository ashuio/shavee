#[macro_use]
extern crate pamsm;

use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
#[cfg(feature = "file")]
use shavee_core::zfs::Dataset;
use std::{io::Write, process::Command};
struct PamShavee;

// TODO: Need unit tests implemented for the PAM module functions
impl PamServiceModule for PamShavee {
    fn open_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn close_session(pam: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
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

        let mut sets: Vec<Dataset> = dataset.list().unwrap();
        sets.reverse();

        for dataset in sets {
            match dataset.umount() {
                Ok(_) => match dataset.unloadkey() {
                    Ok(_) => {},
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

        PamError::SUCCESS
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

        let password = match unwrap_pam_user_pass(pam.get_authtok(None), PamError::AUTHINFO_UNAVAIL)
        {
            Ok(slice) => slice.to_string(),
            Err(error) => {
                eprintln!("Error Getting Password: {}", error);
                return error;
            }
        };

        let mut exec = match Command::new("shavee")
            .arg("-marz")
            .arg(dataset_name)
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                eprintln!("Error: {}", e);
                return PamError::AUTH_ERR;
            }
        };

        let pamstdin = match exec.stdin.as_mut() {
            Some(s) => s,
            None => {
                eprintln!("Failed to open child stdin");
                return PamError::AUTH_ERR;
            }
        };
        match pamstdin.write_all(password.as_str().as_bytes()) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                return PamError::AUTH_ERR;
            }
        };

        let res = match exec.wait() {
            Ok(ok) => ok,
            Err(e) => {
                eprintln!("Error: {}", e);
                return PamError::AUTH_ERR;
            }
        };

        if res.success() {
            return PamError::SUCCESS;
        }

        PamError::AUTH_ERR
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
