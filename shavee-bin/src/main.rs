mod args;

use args::Sargs;
use sha2::{Digest, Sha512};
use shavee_lib::logic::{create_zfs_file, create_zfs_yubi, unlock_zfs_pass};
use shavee_lib::logic::{print_mode_file, print_mode_yubi, unlock_zfs_file, unlock_zfs_yubi};
use shavee_lib::zfs::*;
use std::process::exit;

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
            "print" => match print_mode_yubi(pass, args.yslot) {
                Ok(()) => exit(0),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit(1)
                }
            },
            "pam" | "mount" => match unlock_zfs_yubi(pass, args.dataset, args.yslot) {
                Ok(()) => exit(0),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit(1)
                }
            },
            "create" => match create_zfs_yubi(pass, args.dataset, args.yslot) {
                Ok(()) => exit(0),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit(1)
                }
            },
            _ => unreachable!(),
        },
        "file" => match args.mode.as_str() {
            "print" => match print_mode_file(pass, &args.file, args.port) {
                Ok(()) => exit(0),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit(1)
                }
            },
            "pam" | "mount" => match unlock_zfs_file(pass, args.file, args.dataset, args.port) {
                Ok(()) => exit(0),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit(1)
                }
            },
            "create" => match create_zfs_file(pass, args.file, args.dataset, args.port) {
                Ok(()) => exit(0),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit(1)
                }
            },
            _ => unreachable!(),
        },
        "password" => {
            let key = format!("{:x}", Sha512::digest(pass.as_bytes()));
            match args.mode.as_str() {
                "print" => println!("{}", key),
                "pam" | "mount" => unlock_zfs_pass(key, args.dataset).unwrap(),
                "create" => match zfs_create(key, args.dataset) {
                    Ok(()) => (),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        exit(1)
                    }
                },
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }
}
