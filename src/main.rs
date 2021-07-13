mod args;
mod filehash;
mod logic;
mod yubi;
mod zfs;

use crate::logic::{print_mode_file, print_mode_yubi, unlock_zfs_file, unlock_zfs_yubi};
use crate::{
    logic::{create_zfs_file, create_zfs_yubi},
    zfs::{zfs_create, zfs_mount},
};
use args::Sargs;
use sha2::{Digest, Sha512};

fn main() {
    let args = Sargs::new();
    let mut pass =
        rpassword::prompt_password_stderr("Dataset Password: ").expect("Failed to get Password");
    pass.push_str("shavee"); // Salt password

    match args.umode.as_str() {
        "yubikey" => match args.mode.as_str() {
            "print" => print_mode_yubi(&pass, args.yslot),
            "pam" => unlock_zfs_yubi(pass, args.dataset, args.yslot),
            "mount" => unlock_zfs_yubi(pass, args.dataset, args.yslot),
            "create" => create_zfs_yubi(pass, args.dataset, args.yslot),
            _ => unreachable!(),
        },
        "file" => match args.mode.as_str() {
            "print" => print_mode_file(&pass, &args.file, args.port),
            "pam" => unlock_zfs_file(pass, args.file, args.dataset, args.port),
            "mount" => unlock_zfs_file(pass, args.file, args.dataset, args.port),
            "create" => create_zfs_file(pass, args.file, args.dataset, args.port),
            _ => unreachable!(),
        },
        "password" => {
            let key = format!("{:x}", Sha512::digest(pass.as_bytes()));
            match args.mode.as_str() {
                "print" => {
                    println!("{}", key);
                }
                "pam" => zfs_mount(&key, args.dataset),
                "mount" => zfs_mount(&key, args.dataset),
                "create" => zfs_create(&key, args.dataset),
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }
}
