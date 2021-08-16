#[macro_use]
extern crate pamsm;

use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use shavee_lib::zfs::*;
struct PamShavee;

impl PamServiceModule for PamShavee {
    fn authenticate(pam: Pam, _: PamFlags, _: Vec<String>) -> PamError {
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
        let pass = pam
            .get_authtok(Some("Dataset Password: "))
            .unwrap()
            .unwrap()
            .to_string_lossy()
            .to_string();

        match shavee_lib::logic::unlock_zfs_yubi(pass, Some(dataset), 2) {
            Ok(_) => return PamError::SUCCESS,
            Err(_) => return PamError::AUTH_ERR,
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
