mod args;
mod filehash;
mod logic;
mod yubikey;
mod zfs;

use std::process::exit;

use crate::logic::{print_mode_file, print_mode_yubi, unlock_zfs_file, unlock_zfs_yubi};
use crate::{
    logic::{create_zfs_file, create_zfs_yubi},
    zfs::{zfs_create, zfs_mount},
};
use args::Sargs;
use sha2::{Digest, Sha512};

fn main() {
    let args = Sargs::new();
    let pass = rpassword::prompt_password_stderr("Dataset Password: ");
    let mut pass = match pass {
        Ok(pass) => pass,
        Err(error) => {
            eprintln!("Error: Failed to read Password");
            eprintln!("Error: {}", error);
            exit(1)
        }
    };
    pass.push_str("Aveesha");

    match args.umode.as_str() {
        "yubikey" => match args.mode.as_str() {
            "print" => print_mode_yubi(pass, args.yslot),
            "pam" | "mount" => unlock_zfs_yubi(pass, args.dataset, args.yslot),
            "create" => create_zfs_yubi(pass, args.dataset, args.yslot),
            _ => unreachable!(),
        },
        "file" => match args.mode.as_str() {
            "print" => print_mode_file(pass, &args.file, args.port),
            "pam" | "mount" | "load-key" => unlock_zfs_file(pass, args.file, args.dataset, args.port, args.mode),
            "create" => create_zfs_file(pass, args.file, args.dataset, args.port),
            _ => unreachable!(),
        },
        "password" => {
            let key = format!("{:x}", Sha512::digest(pass.as_bytes()));
            match args.mode.as_str() {
                "print" => println!("{}", key),
                "pam" | "mount" => zfs_mount(&key, args.dataset),
                "create" => zfs_create(&key, args.dataset),
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }
}
