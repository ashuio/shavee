mod args;

use args::{Sargs, Mode, Umode};
use base64::encode_config;
use shavee_lib::logic::{create_zfs_file, create_zfs_yubi, unlock_zfs_pass};
use shavee_lib::logic::{print_mode_file, print_mode_yubi, unlock_zfs_file, unlock_zfs_yubi};
use shavee_lib::password::hash_argon2;
use shavee_lib::zfs::*;
use std::error::Error;
use std::process::exit;

// main() collect the arguments from command line, pass them to run() and print any error 
// message upon exiting the program
fn main() {
    let args = Sargs::new();

    // Only main() will terminate the executable with proper error message and code
    exit(match run(args){
        Ok(()) => 0,
        Err(error) => {
            eprintln!("Error: {}", error);
            1
        }
    });
}


fn run(args: Sargs) -> Result<(), Box<dyn Error>> {

    let pass = rpassword::prompt_password_stderr("Dataset Password: ")
        .map_err(|e| e.to_string())?;

    Ok(match args.umode {
        Umode::Yubikey => match args.mode {
            Mode::Print => print_mode_yubi(pass, args.yslot)?,
            Mode::Mount => unlock_zfs_yubi(pass, args.dataset, args.yslot)?,
            Mode::Create => create_zfs_yubi(pass, args.dataset, args.yslot)?,
        },
        Umode::File => match args.mode {
            Mode::Print => print_mode_file(pass, args.file, args.port)?,
            Mode::Mount => unlock_zfs_file(pass, args.file, args.dataset, args.port)?,
            Mode::Create => create_zfs_file(pass, args.file, args.dataset, args.port)?,
        },
        Umode::Password => {
            let key =  hash_argon2(pass.into_bytes())?;
            let key = encode_config(key, base64::STANDARD_NO_PAD);
            match args.mode {
                Mode::Print => println!("{}", key),
                Mode::Mount => unlock_zfs_pass(key, args.dataset)?,
                Mode::Create => zfs_create(key, args.dataset)?,
            }
        }
    })
}
