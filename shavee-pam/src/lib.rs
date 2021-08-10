#[macro_use]
extern crate pamsm;

use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use shavee_lib::zfs::*;
use std::process::Command;

struct PamShavee;

impl PamServiceModule for PamShavee {
    fn open_session(pam: Pam, _: PamFlags, _: Vec<String>) -> PamError {
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

        let mut pass = pam.get_authtok(Some("Dataet Password: ")).unwrap().unwrap().to_string_lossy().to_string();
        pass.push_str("Aveesha");

        match shavee_lib::logic::unlock_zfs_yubi(pass, dataset, 2) {
            Ok(_) => return PamError::SUCCESS,
            Err(_) => return PamError::SESSION_ERR,
        }
        
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

        Command::new("pkill").arg("-u").arg(user).output().unwrap();

        match zfs_umount(dataset) {
            Ok(()) => return PamError::SUCCESS,
            Err(_) => return PamError::SESSION_ERR,
        }
    }
}

pam_module!(PamShavee);
