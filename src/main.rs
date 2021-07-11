mod filehash;
mod logic;
mod yubi;
mod zfs;

use crate::{
    logic::{create_zfs_file, create_zfs_yubi, port_check},
    zfs::{zfs_create, zfs_mount},
};
use clap::{crate_authors, crate_version, App, Arg};
use sha2::{Digest, Sha512};
use std::{env, process::exit};

use crate::logic::{print_mode_file, print_mode_yubi, unlock_zfs_file, unlock_zfs_yubi};

fn main() {
    let app = App::new("shavee")
        .about("shavee is a simple program designed as a ZFS 2FA encryption helper for PAM") // Define APP and args
        .author(crate_authors!())
        .version(crate_version!())
        .arg(
            Arg::with_name("yubikey")
                .long("yubi")
                .short("y")
                .help("Use Yubikey HMAC as Second factor.")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::with_name("keyfile")
                .short("f")
                .long("file")
                .help("<Keyfile location>")
                .required(false)
                .takes_value(true)
                .conflicts_with("yubikey"),
        )
        .arg(
            Arg::with_name("pam")
                .short("p")
                .long("pam")
                .takes_value(false)
                .required(false)
                .help("PAM mode"),
        )
        .arg(
            Arg::with_name("create")
                .short("c")
                .long("create")
                .takes_value(true)
                .value_name("create")
                .required(false)
                .conflicts_with("dir")
                .help("Create a new zfs Dataset with the derived key"),
        )
        .arg(
            Arg::with_name("port")
                .short("P")
                .long("port")
                .takes_value(true)
                .value_name("port")
                .required(false)
                .help("Network Port")
                .validator(port_check),
        )
        .arg(
            Arg::with_name("dir")
                .short("z")
                .long("dir")
                .takes_value(true)
                .value_name("dir")
                .required(false)
                .help("Base Directory eg. \"zroot/data/home/\""),
        );
    let arg = app.get_matches();
    let port: u32 = if arg.is_present("port") {
        arg.value_of("port")
            .expect("Invalid Port")
            .parse::<u32>()
            .expect("Invalid port")
    } else {
        let p: u32 = 99999;
        p
    };

    let mut pass = rpassword::prompt_password_stderr("Dataset Password: ").expect("Failed to get Password");
    pass.push_str("shavee"); // Salt password

    if arg.is_present("pam") {
        if !arg.is_present("dir") {
            eprintln!("ERROR: Specify base home dir with -z eg. \"zroot/data/home/\"");
            exit(1)
        };

        let mut dir = arg.value_of("dir").expect("Invalid dir").to_string();
        if !dir.ends_with('/') {
            dir.push('/');
        };

        let user = env::var("PAM_USER").expect("Var not found");
        dir.push_str(user.as_str());

        if arg.is_present("keyfile") {
            unlock_zfs_file(
                pass,
                arg.value_of("keyfile").expect("Invalide File").to_string(),
                dir,
                port,
            )
        } else if arg.is_present("yubikey") {
            unlock_zfs_yubi(pass, dir)
        } else {
            let key = Sha512::digest(pass.as_bytes());
            zfs_mount(
                &format!("{:x}", key),
                arg.value_of("dir").expect("Invalid Dataset").to_string(),
            );
        }
    } else if arg.is_present("create") {
        let dataset = arg
            .value_of("create")
            .expect("Invalid ZFS Dataset")
            .to_string();

        if arg.is_present("yubikey") {
            create_zfs_yubi(pass, dataset)
        } else if arg.is_present("keyfile") {
            create_zfs_file(
                pass,
                arg.value_of("keyfile")
                    .expect("Invalid Keyfile")
                    .to_string(),
                dataset,
                port,
            )
        } else {
            let key = Sha512::digest(pass.as_bytes());
            let mut dataset = arg
                .value_of("create")
                .expect("Invalid ZFS Dataset")
                .to_string();
            if dataset.ends_with("/") {
                dataset.pop();
            }
            zfs_create(&format!("{:x}", key), dataset);
        }
    } else {
        if arg.is_present("dir") {
            if arg.is_present("yubikey") {
                unlock_zfs_yubi(pass, arg.value_of("dir").unwrap().to_string())
            } else if arg.is_present("keyfile") {
                unlock_zfs_file(
                    pass,
                    arg.value_of("keyfile").expect("Invalid File.").to_string(),
                    arg.value_of("dir")
                        .expect("Invalid Dataset input.")
                        .to_string(),
                    port,
                )
            } else {
                let key = Sha512::digest(pass.as_bytes());
                zfs_mount(
                    &format!("{:x}", key),
                    arg.value_of("dir").expect("Invalid Dataset").to_string(),
                );
            }
        } else if arg.is_present("keyfile") {
            print_mode_file(
                &pass,
                &arg.value_of("keyfile").expect("Invalid File.").to_string(),
                port,
            );
        } else if arg.is_present("yubikey") {
            print_mode_yubi(&pass);
        } else {
            let key = Sha512::digest(pass.as_bytes());
            println!("{:x}", key);
        }
    }
}
