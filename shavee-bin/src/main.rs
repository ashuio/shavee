mod args;

use args::{Sargs, Mode, Umode};
use base64::encode_config;
use shavee_lib::logic::*;
use shavee_lib::password::hash_argon2;
use shavee_lib::filehash::get_filehash;
use shavee_lib::zfs::*;
use std::error::Error;
use std::process::exit;
use std::thread;

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

    // pre-initialize the handle and filehash and use them
    // if multithread is needed for file hash generation
    // if multithread file hash code called then handle must not be used
    // thus initializing it with an error message.
    let mut handle: thread::JoinHandle<Result<Vec<u8>, String>> =
        thread::spawn(|| Err(String::from(shavee_lib::logic::UNREACHABLE_CODE)) );
    let mut filehash : Vec<u8> = vec![]; //empty u8 vector
    
    // if in the file 2FA mode, then generate file hash in parallel
    // while user is entering password
    if args.umode == Umode::File {
        let file = args.file.clone()
                .expect(shavee_lib::logic::UNREACHABLE_CODE);
        let port = args.port.clone();

        // start the file hash thread
        handle = thread::spawn(move || {
                get_filehash(file, port)
                    .map_err(|e| e.to_string()) // map error to String
            });
    };

    // prompt user for password, if case of error terminate this function and
    // return the error to the calling function
    let pass = rpassword::prompt_password_stderr("Dataset Password: ")
        .map_err(|e| e.to_string())?;

    // if in the file 2FA mode, then wait for hash generation thread to finish 
    // and unwrap the result. In case of error, terminate this function and
    // return error to the calling function.
    if args.umode == Umode::File {
        filehash = handle.join()
            .unwrap()?;
    };

    Ok(match args.umode {
        Umode::Yubikey => match args.mode {
            Mode::Print => print_mode_yubi(pass, args.yslot)?,
            Mode::Mount => unlock_zfs_yubi(pass, args.dataset, args.yslot)?,
            Mode::Create => create_zfs_yubi(pass, args.dataset, args.yslot)?,
        },
        Umode::File => match args.mode {
            Mode::Print => print_mode_file(pass, filehash)?,
            Mode::Mount => unlock_zfs_file(pass, filehash, args.dataset)?,
            Mode::Create => create_zfs_file(pass, filehash, args.dataset)?,
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
