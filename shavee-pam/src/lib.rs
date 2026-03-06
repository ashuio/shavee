#[macro_use]
extern crate pamsm;

use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use shavee_core::zfs::Dataset;
use std::{error::Error, io::Write, process::Command};
struct PamShavee;

impl PamShavee {
    fn perform_authentication(pam: &Pam, args: &[String]) -> Result<(), Box<dyn Error>> {
        let dataset_name = get_user_dataset_name(pam, args).map_err(|e| e.to_string())?;
        let password = unwrap_pam_user_pass(pam.get_authtok(None), PamError::AUTHINFO_UNAVAIL)
            .map_err(|e| format!("PAM error getting password: {}", e))?;

        let mut child = Command::new("shavee")
            .arg("-marz")
            .arg(&dataset_name)
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(password.as_bytes())?;
        } else {
            return Err("Failed to open child stdin".into());
        }

        let output = child.wait_with_output()?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!(
                "shavee command failed with status {} and stderr: {}",
                output.status, stderr
            )
            .into())
        }
    }

    fn perform_close_session(pam: &Pam, args: &[String]) -> Result<(), Box<dyn Error>> {
        let dataset_name = get_user_dataset_name(pam, args).map_err(|e| e.to_string())?;
        let dataset = Dataset::new(dataset_name)?;
        dataset.unmount()?;
        dataset.unload_key(true)?;
        Ok(())
    }
}

// TODO: Need unit tests implemented for the PAM module functions
impl PamServiceModule for PamShavee {
    fn open_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn close_session(pam: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        match Self::perform_close_session(&pam, &args) {
            Ok(_) => PamError::SUCCESS,
            Err(e) => {
                eprintln!("shavee-pam: session close error: {}", e);
                PamError::SESSION_ERR
            }
        }
    }

    fn authenticate(pam: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        match Self::perform_authentication(&pam, &args) {
            Ok(_) => PamError::SUCCESS,
            Err(e) => {
                eprintln!("shavee-pam: authentication error: {}", e);
                PamError::AUTH_ERR
            }
        }
    }

    fn setcred(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

fn get_user_dataset_name(pam: &Pam, args: &[String]) -> Result<String, PamError> {
    if args.is_empty() {
        eprintln!("PAM module arguments are missing: no base dataset provided.");
        return Err(PamError::SERVICE_ERR);
    }

    let mut dataset_name = args[0].clone();
    dataset_name.truncate(dataset_name.trim_end_matches('/').len());

    let user = unwrap_pam_user_pass(pam.get_user(Some("Username: ")), PamError::USER_UNKNOWN)?;

    dataset_name.push('/');
    dataset_name.push_str(user);
    Ok(dataset_name)
}

fn unwrap_pam_user_pass<'a>(
    pam_key: Result<Option<&'a std::ffi::CStr>, PamError>,
    pam_error: PamError,
) -> Result<&'a str, PamError> {
    let c_str = pam_key
        .map_err(|e| {
            eprintln!("Error getting PAM item: {}", e);
            e
        })?
        .ok_or(pam_error)?;

    c_str.to_str().map_err(|e| {
        eprintln!("Error converting PAM string: {}", e);
        pam_error
    })
}

#[allow(unsafe_op_in_unsafe_fn)]
mod pam_entry {
    use super::*;
    pam_module!(PamShavee);
}
