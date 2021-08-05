#[macro_use]
extern crate pamsm;

use pamsm::{Pam, PamError, PamFlags, PamServiceModule, PamLibExt};
use std::process::{Command, exit};

struct PamShavee;

impl PamServiceModule for PamShavee {
    fn open_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
    fn close_session(pam : Pam, _: PamFlags, _: Vec<String>) -> PamError {
        
        let mut dataset = String::from("zroot/data/home/");
        let p = Some("Username: ");
        let user = pam.get_user(p);
        let user = match user {
            Ok(i) => i,
            _ => exit(1),
        };

        let user = match user {
            Some(i) => i.to_str().unwrap(),
            _ => exit(1)
        };

        dataset.push_str(user);

        Command::new("pkill").arg("-u").arg(user).output().unwrap();
        Command::new("zfs").arg("umount").arg("-u").arg(dataset).output().unwrap();

        PamError::SUCCESS
    }
}

pam_module!(PamShavee);
