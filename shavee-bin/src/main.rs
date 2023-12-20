mod args;
use args::*;
use atty::Stream;
#[cfg(feature = "file")]
use shavee_core::filehash::get_filehash;
use shavee_core::zfs::Dataset;
use shavee_core::{structs::TwoFactorMode, zfs::resolve_recursive};
use std::collections::HashMap;
use std::io::stdin;
use std::sync::Mutex;

use std::ops::Deref;
use yubico_manager::config::{Config, Mode, Slot};
use yubico_manager::Yubico;

/// main() collect the arguments from command line, pass them to run() and print any
/// messages upon exiting the program
#[tokio::main]
async fn main() -> std::process::ExitCode {
    //initializing the logger
    shavee_core::trace_init(true);
    // parse the arguments
    shavee_core::trace("Parsing the arguments.");
    let args = CliArgs::new();
    shavee_core::trace("Arguments parsed successfully.");
    // Only main() will terminate the executable with proper message and code
    let code = match run(args).await {
        Ok(None) => {
            shavee_core::trace("Exited successfully with no message!");
            0
        } // exit with no error code
        Ok(passphrase) => {
            shavee_core::trace("Exited successfully with a message!");
            println!("{}", passphrase.unwrap()); // print password if asked
            0 // then exit with no error code
        }
        Err(error) => {
            shavee_core::error("Exited with an error message!");
            eprintln!("Error: {}", error); // print error message
            1 // then exit with generic error code 1
        }
    };
    std::process::exit(code);
}

async fn run(args: CliArgs) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mut password = String::new();

    // Check if input is piped and read accordingly

    if atty::is(Stream::Stdin) {
        password = rpassword::prompt_password("Dataset Password: ").map_err(|e| e.to_string())?;
    } else {
        stdin().read_line(&mut password)?;
    };

    let password = password.trim().to_string();

    // prompt user for password, in case of an error, terminate this function and
    // return the error to main()

    shavee_core::trace("Password has entered successfully.");

    shavee_core::trace("Operation Mode:");

    // Use this variable as the function return to be used for printing to stdio if needed.
    let mut exit_result: Option<String> = None;
    match args.operation {
        OperationMode::Auto { operation } => match operation {
            Operations::Mount {
                datasets,
                recursive,
            } => {
                let mut sets = datasets.clone();
                if recursive {
                    sets = resolve_recursive(datasets)?;
                }

                let mut maxlength: usize = 0;

                for d in sets.clone() {
                    let len = d.to_string().len();
                    if len > maxlength {
                        maxlength = len;
                    }
                }

                let sethashes = get_key_hash(sets.clone(), password, None).await?;
                let mut errors: Vec<(String, String)> = vec![];
                for d in sets {
                    let pass = sethashes.get(&d.to_string()).unwrap();
                    if pass.len() == 86 {
                        match d.loadkey(pass) {
                            Ok(_) => {
                                let _ = d.mount();
                            }
                            Err(_) => {}
                        }
                    } else {
                        errors.push((d.to_string(), pass.to_owned()));
                    }
                }

                if !errors.is_empty() {
                    eprintln!("\x1b[1m{:<maxlength$}    {}\x1b[0m", "Dataset", "Error");
                    eprintln!();
                    for error in errors {
                        eprintln!("{:<maxlength$}    {}", error.0, error.1);
                    }

                    let e = Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Failed to mount Datasets",
                    ));
                    return Err(e);
                }
                exit_result = None
            }
            Operations::PrintDataset {
                datasets,
                recursive,
                printwithname,
            } => {
                let mut sets = datasets.clone();
                if recursive {
                    sets = resolve_recursive(datasets)?;
                }
                let mut maxlength: usize = 0;
                if printwithname {
                    for d in sets.clone() {
                        let len = d.to_string().len();
                        if len > maxlength {
                            maxlength = len;
                        }
                    }
                    println!("\x1b[1m{:<maxlength$}    {}\x1b[0m", "Dataset", "Key");
                    println!();
                }

                let mut setnames: Vec<String> = vec![];

                for set in sets.clone() {
                    setnames.push(set.to_string())
                }

                let sethashes = get_key_hash(sets.clone(), password, None).await?;
                let mut errors: Vec<(String, String)> = vec![];
                for dataset in setnames {
                    let pass = sethashes.get(&dataset).unwrap();
                    if pass.len() == 86 {
                        if printwithname {
                            println!("{:<maxlength$}    {}", dataset, pass);
                        } else {
                            println!("{}", sethashes.get(&dataset).unwrap());
                        }
                    } else {
                        errors.push((dataset.to_string(), pass.to_owned()));
                    }
                }
                if !errors.is_empty() {
                    eprintln!("\x1b[1m{:<maxlength$}    {}\x1b[0m", "Dataset", "Error");
                    eprintln!();
                    for error in errors {
                        eprintln!("{:<maxlength$}    {}", error.0, error.1);
                    }

                    let e = Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Failed to mount Datasets",
                    ));
                    return Err(e);
                }
                exit_result = None
            }

            Operations::Create { .. } => {
                eprintln!("{}", shavee_core::UNREACHABLE_CODE);
            }
            Operations::PrintHelp => {
                eprintln!("{}", shavee_core::UNREACHABLE_CODE);
            }
        },

        OperationMode::Manual { operation } => {
            match operation {
                Operations::Create { datasets } => {
                    // Ask and check for password a second time if input is stdin
                    if atty::is(Stream::Stdin) {
                        let binding = rpassword::prompt_password("Retype  Password: ")
                            .map_err(|e| e.to_string())?;

                        if password != binding.to_string() {
                            return Err("Passwords do not match.".into());
                        }
                    };

                    for dataset in datasets.clone() {
                        shavee_core::trace(&format!(
                            "\tCreate ZFS dataset: \"{}\" using \"{:?}\" method.",
                            dataset.to_string(),
                            args.second_factor
                        ));
                    }

                    for dataset in datasets {
                        let salt = shavee_core::logic::generate_salt();
                        match args.second_factor.clone() {
                            #[cfg(feature = "yubikey")]
                            TwoFactorMode::Yubikey { yslot } => {
                                dataset
                                    .clone()
                                    .yubi_create(password.as_bytes(), yslot, &salt)?;
                            }
                            #[cfg(feature = "file")]
                            TwoFactorMode::File {
                                ref file,
                                port,
                                size,
                            } => {
                                let filehash = get_filehash(file.clone().as_str(), port, size)?;
                                dataset.clone().file_create(
                                    password.as_bytes(),
                                    filehash.clone(),
                                    &salt,
                                )?
                            }
                            TwoFactorMode::Password => {
                                let password_mode_hash = shavee_core::logic::password_mode_hash(
                                    &password.as_bytes(),
                                    &salt,
                                )?;
                                dataset.clone().create(&password_mode_hash)?;
                                // store generated random salt as base64 encoded in ZFS property
                            }
                        }
                        dataset.set_property_2fa(
                            args.second_factor.clone(),
                            &base64::Engine::encode(&shavee_core::logic::BASE64_ENGINE, salt),
                        )?;
                    }

                    exit_result = None;
                }
                Operations::Mount {
                    datasets,
                    recursive,
                } => {
                    for dataset in datasets.clone() {
                        shavee_core::trace(&format!(
                            "\tMount ZFS dataset: \"{}\".",
                            dataset.to_string()
                        ));
                    }
                    let mut sets = datasets;
                    if recursive {
                        sets = resolve_recursive(sets)?;
                    }
                    let mut maxlength: usize = 0;

                    for d in sets.clone() {
                        let len = d.to_string().len();
                        if len > maxlength {
                            maxlength = len;
                        }
                    }

                    let sethashes =
                        get_key_hash(sets.clone(), password, Some(args.second_factor)).await?;

                    let mut errors: Vec<(String, String)> = vec![];
                    for d in sets {
                        let pass = sethashes.get(&d.to_string()).unwrap();
                        if pass.len() == 86 {
                            match d.loadkey(pass) {
                                Ok(_) => {
                                    let _ = d.mount();
                                }
                                Err(_) => {}
                            }
                        } else {
                            errors.push((d.to_string(), pass.to_owned()));
                        }
                    }

                    if !errors.is_empty() {
                        eprintln!("\x1b[1m{:<maxlength$}    {}\x1b[0m", "Dataset", "Error");
                        eprintln!();
                        for error in errors {
                            eprintln!("{:<maxlength$}    {}", error.0, error.1);
                        }

                        let e = Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Failed to mount Datasets",
                        ));
                        return Err(e);
                    }
                    exit_result = None
                }
                Operations::PrintDataset {
                    datasets,
                    recursive,
                    printwithname,
                } => {
                    let mut sets = datasets.clone();
                    if recursive {
                        sets = resolve_recursive(datasets)?;
                    }
                    let mut maxlength: usize = 0;
                    if printwithname {
                        for d in sets.clone() {
                            let len = d.to_string().len();
                            if len > maxlength {
                                maxlength = len;
                            }
                        }
                        println!("\x1b[1m{:<maxlength$}    {}\x1b[0m", "Dataset", "Key");
                        println!();
                    }

                    let mut setnames: Vec<String> = vec![];

                    for set in sets.clone() {
                        setnames.push(set.to_string())
                    }

                    let sethashes =
                        get_key_hash(sets.clone(), password, Some(args.second_factor)).await?;
                    let mut errors: Vec<(String, String)> = vec![];
                    for dataset in setnames {
                        let pass = sethashes.get(&dataset).unwrap();
                        if pass.len() == 86 {
                            if printwithname {
                                println!("{:<maxlength$}    {}", dataset, pass);
                            } else {
                                println!("{}", sethashes.get(&dataset).unwrap());
                            }
                        } else {
                            errors.push((dataset.to_string(), pass.to_owned()));
                        }
                    }
                    if !errors.is_empty() {
                        eprintln!("\x1b[1m{:<maxlength$}    {}\x1b[0m", "Dataset", "Error");
                        eprintln!();
                        for error in errors {
                            eprintln!("{:<maxlength$}    {}", error.0, error.1);
                        }

                        let e = Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Failed to mount Datasets",
                        ));
                        return Err(e);
                    }
                    exit_result = None
                }
                Operations::PrintHelp => {
                    eprintln!("{}", shavee_core::UNREACHABLE_CODE);
                }
            };
        }
    };

    Ok(exit_result)
}

async fn get_key_hash(
    datasets: Vec<Dataset>,
    password: String,
    second_factor: Option<TwoFactorMode>,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut sethashes: HashMap<String, String> = HashMap::new();
    let yubikey_device = std::sync::Arc::new(Mutex::new(()));
    let mut handles = vec![];
    for d in datasets.clone() {
        let password = password.clone();
        let second_factor = second_factor.clone();
        let yubikey_device = yubikey_device.clone();
        let handle =
            tokio::spawn(async move { get_keys(d, password, second_factor, yubikey_device) });
        handles.push(handle);
    }

    for handle in handles {
        let val = match handle.await.unwrap() {
            Ok(val) => val,
            Err(e) => [e.0, e.1.to_string()],
        };
        sethashes.insert(val[0].clone(), val[1].clone());
    }
    Ok(sethashes)
}

fn get_keys(
    dataset: Dataset,
    password: String,
    second_factor: Option<TwoFactorMode>,
    yubikey_device: std::sync::Arc<Mutex<()>>,
) -> Result<[String; 2], (String, Box<dyn std::error::Error + Send>)> {
    let salt = match shavee_core::logic::get_salt(Some(&dataset)) {
        Ok(salt) => salt,
        Err(e) => {
            let e = Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ));
            return Err((dataset.to_string(), e));
        }
    };

    let second_factor = match second_factor.clone() {
        Some(sf) => sf,
        None => match dataset.get_property_2fa() {
            Ok(sf) => sf,
            Err(e) => {
                let e = Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ));
                return Err((dataset.to_string(), e));
            }
        },
    };

    let passphrase = match second_factor {
        #[cfg(feature = "yubikey")]
        TwoFactorMode::Yubikey { yslot } => {
            let mut yubi = Yubico::new();
            // Search for Yubikey

            let challenge = shavee_core::password::hash_argon2(&password.as_bytes(), &salt)
                .expect("Hash error"); // Prepare Challenge

            let lock = yubikey_device.lock().unwrap();
            let yubihash = match yubi.find_yubikey() {
                Ok(device) => {
                    let yslot = if yslot == 1 { Slot::Slot1 } else { Slot::Slot2 };

                    let config = Config::default() // Configure Yubikey
                        .set_vendor_id(device.vendor_id)
                        .set_product_id(device.product_id)
                        .set_variable_size(false)
                        .set_mode(Mode::Sha1)
                        .set_slot(yslot);

                    let hmac_result = yubi.challenge_response_hmac(&challenge, config);
                    drop(lock);
                    let hmac_result = match hmac_result {
                        Ok(y) => y,
                        Err(error) => return Err((dataset.to_string(), Box::new(error))),
                    };
                    let hash = hmac_result.deref().to_vec(); // Prepare and return encryption key as hex string
                    let finalhash = shavee_core::password::hash_argon2(&hash[..], &salt)
                        .expect("File Hash Error");
                    finalhash // Return the finalhash
                }
                Err(error) => return Err((dataset.to_string(), Box::new(error))),
            };

            base64::Engine::encode(&shavee_core::logic::BASE64_ENGINE, yubihash)
        }
        #[cfg(feature = "file")]
        TwoFactorMode::File {
            ref file,
            port,
            size,
        } => {
            let filehash = match get_filehash(file.clone().as_str(), port, size) {
                Ok(fh) => fh,
                Err(e) => {
                    let e = Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    ));
                    return Err((dataset.to_string(), e));
                }
            };
            match shavee_core::logic::file_key_calculation(
                &password.as_bytes(),
                filehash.clone(),
                &salt,
            ) {
                Ok(s) => s,
                Err(e) => {
                    let e = Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    ));
                    return Err((dataset.to_string(), e));
                }
            }
        }
        TwoFactorMode::Password => {
            match shavee_core::logic::password_mode_hash(&password.as_bytes(), &salt) {
                Ok(p) => p,
                Err(e) => {
                    let e = Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    ));
                    return Err((dataset.to_string(), e));
                }
            }
        }
    };

    Ok([dataset.to_string(), passphrase])
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use shavee_core::zfs::Dataset;
//     use std::io::Write;
//     use stdio_override;
//     use tempfile;

//     #[test]
//     fn integration_tests() {
//         // initializing logs
//         shavee_core::trace_init(false);
//         // All integration tests will be executed sequentially

//         // **Integration Test**: Print Password
//         {
//             // construct the needed Struct related to this unit test
//             let print_password = CliArgs {
//                 operation: OperationMode::Manual {
//                     operation: Operations::Print,
//                 },
//                 second_factor: TwoFactorMode::Password,
//             };

//             // use a temp file to override stdin for password entry
//             let mut password_file = tempfile::NamedTempFile::new()
//                 .expect("Couldn't make a temp file! Test terminating early!");

//             // generate the temp file and fill it with the password
//             // and feed "test" as password
//             password_file
//                 .write_all(b"test")
//                 .expect("Couldn't write to the temp file! Test terminating early!");

//             let password_file_path = password_file.into_temp_path();
//             let password_file_path = password_file_path
//                 .to_str()
//                 .expect("Unknown temp file path! Test terminating early!");

//             // feed password_file to stdin
//             let stdin_guard = stdio_override::StdinOverride::override_file(password_file_path);

//             // **Integration Test** run() function and capture its stdout output
//             let output = run(print_password);

//             // release stdin back to normal
//             drop(stdin_guard);

//             // **Integration test** check for graceful execution
//             let output = output.unwrap().unwrap();

//             // verify stdout with the expected result
//             assert_eq!(
//                 output,
//                 "LDa6mHK4xmv37cqoG8B+9M/ZIaEPLDhPQER6nuP7dw8mB1MoKoRkgZCbUNRwXvGwG2UkfWJUUEVOfWzUCCb8JA"
//             );
//             // expected output for "test" input
//         } // END **Integration Test**: Print Password

//         // **Integration Test**: Print File
//         #[cfg(feature = "file")]
//         {
//             // construct the needed Struct related to this unit test
//             let print_file = CliArgs {
//                 operation: OperationMode::Manual {
//                     operation: Operations::Print,
//                 },
//                 second_factor: TwoFactorMode::File {
//                     file: String::from("/dev/zero"), // Zeros
//                     size: Some(1 << 8),
//                     port: None,
//                 },
//             };

//             // use a temp file to override stdin for password entry
//             let mut password_file = tempfile::NamedTempFile::new()
//                 .expect("Couldn't make a temp file! Test terminating early!");

//             // generate the temp file and fill it with the password
//             // and feed "test" as password
//             password_file
//                 .write_all(b"test")
//                 .expect("Couldn't write to the temp file! Test terminating early!");

//             let password_file_path = password_file.into_temp_path();
//             let password_file_path = password_file_path
//                 .to_str()
//                 .expect("Unknown temp file path! Test terminating early!");

//             // feed password_file to stdin
//             let stdin_guard = stdio_override::StdinOverride::override_file(password_file_path);

//             // **Integration Test** run() function and capture its stdout output
//             let output = run(print_file);

//             // release stdin back to normal
//             drop(stdin_guard);

//             // **Integration test** check for graceful execution
//             let output = output.unwrap().unwrap();

//             // verify stdout with the expected result
//             assert_eq!(
//                 output,
//                 "oenvfi3+jMSy5kuOzbKzfAsBNi/jHFuD510Q43zJhVNJaBi35mvXEqeUPzdarV1mAlhkFG1C7NJ5/mEAWNOpgg"
//             );
//             // expected output for "test" input
//         } // END **Integration Test**: Print File

//         // **Integration Test**: Create from password then mount it
//         {
//             // This test will only run if there is root permission
//             if !nix::unistd::Uid::effective().is_root() {
//                 eprintln!("This test needs root permission. Terminating early!");
//                 return;
//             }

//             let (zpool_name, temp_folder) = prepare_zpool();
//             shavee_core::trace(&format!("Temp Zpool name: {:?}", zpool_name));
//             let mut zpool_with_dataset = zpool_name.to_owned();
//             zpool_with_dataset.push('/');
//             zpool_with_dataset.push_str(&random_string(3));
//             shavee_core::trace(&format!("Temp ZFS dataset path: {:?}", zpool_with_dataset));
//             let zfs_encrypted_dataset =
//                 Dataset::new(zpool_with_dataset).expect("ZFS name problem. Test terminated early!");
//             shavee_core::trace(&format!(
//                 "Temp encrypted ZFS dataset: {:?}",
//                 zfs_encrypted_dataset
//             ));

//             //Output of the Integration test will be stored in these variables to be validated
//             let create_password_output;
//             let mount_password_output;
//             let mount_key_already_loaded_output;

//             // **Integration Test**: create a new encrypted dataset from file
//             {
//                 // construct the needed Struct related to this unit test
//                 let create_password = CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Create {
//                             datasets: vec![zfs_encrypted_dataset.clone()],
//                         },
//                     },
//                     second_factor: TwoFactorMode::Password,
//                 };
//                 shavee_core::trace(&format!(
//                     "Simulated CLI arguments action: {:?}",
//                     create_password
//                 ));

//                 // use a temp file to override stdin for password entry
//                 let mut password_file = tempfile::NamedTempFile::new()
//                     .expect("Couldn't make a temp file! Test terminating early!");

//                 // generate the temp file and fill it with the password
//                 // and feed "test" as password
//                 password_file
//                     .write_all(b"test")
//                     .expect("Couldn't write to the temp file! Test terminating early!");

//                 let password_file_path = password_file.into_temp_path();
//                 let password_file_path = password_file_path
//                     .to_str()
//                     .expect("Unknown temp file path! Test terminating early!");

//                 // feed password_file to stdin
//                 let stdin_guard = stdio_override::StdinOverride::override_file(password_file_path);

//                 // **Integration Test** run() function and capture its stdout output
//                 create_password_output = run(create_password);
//                 shavee_core::trace(&format!(
//                     "Output of the cli command: {:?}",
//                     create_password_output
//                 ));

//                 // release stdin back to normal
//                 drop(stdin_guard);

//                 //umount and unload the ZFS key
//                 zfs_encrypted_dataset
//                     .umount()
//                     .expect("ZFS Dataset create from file Integration test failed!")
//                     .unloadkey()
//                     .expect("ZFS Dataset create from file Integration test failed!");
//             } // END of **Integration Test 1**: create a new encrypted dataset from password

//             // **Integration Test**: mount an encrypted dataset from password
//             {
//                 // construct the needed Struct related to this unit test
//                 let mount_password = CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Mount {
//                             datasets: vec![zfs_encrypted_dataset.clone()],
//                             recursive: false,
//                         },
//                     },
//                     second_factor: TwoFactorMode::Password,
//                 };
//                 shavee_core::trace(&format!(
//                     "Simulated CLI arguments action: {:?}",
//                     mount_password
//                 ));

//                 // use a temp file to override stdin for password entry
//                 let mut password_file = tempfile::NamedTempFile::new()
//                     .expect("Couldn't make a temp file! Test terminating early!");

//                 // generate the temp file and fill it with the password
//                 // and feed "test" as password
//                 password_file
//                     .write_all(b"test")
//                     .expect("Couldn't write to the temp file! Test terminating early!");

//                 let password_file_path = password_file.into_temp_path();
//                 let password_file_path = password_file_path
//                     .to_str()
//                     .expect("Unknown temp file path! Test terminating early!");

//                 // feed password_file to stdin
//                 let stdin_guard = stdio_override::StdinOverride::override_file(password_file_path);

//                 // **Integration Test** run() function and capture its stdout output
//                 mount_password_output = run(mount_password.clone());
//                 shavee_core::trace(&format!(
//                     "Output of the cli command: {:?}",
//                     mount_password_output
//                 ));

//                 //umount the ZFS only
//                 zfs_encrypted_dataset
//                     .umount()
//                     .expect("ZFS Dataset Mount from file Integration test failed!");

//                 // [Issue #22] try to mount again this time with key already loaded
//                 mount_key_already_loaded_output = run(mount_password);
//                 shavee_core::trace(&format!(
//                     "Output of the cli command: {:?}",
//                     mount_key_already_loaded_output
//                 ));

//                 // unload the ZFS key
//                 zfs_encrypted_dataset
//                     .unloadkey()
//                     .expect("ZFS Dataset unload key failed!");

//                 // release stdin back to normal
//                 drop(stdin_guard);
//             } // END of **Integration Test**: mount an encrypted dataset from password

//             //clean up and remove the dataset folder
//             cleanup_zpool(&zpool_name, temp_folder);

//             // **Integration Test** check for graceful execution
//             let create_output = create_password_output
//                 .expect("ZFS Dataset create from Password Integration test failed!");

//             // **Integration Test** check for graceful execution
//             let mount_output = mount_password_output
//                 .expect("ZFS Dataset mount from Password Integration test failed!");

//             let key_already_loaded_output = mount_key_already_loaded_output
//                 .expect_err("ZFS Dataset mount on an already loaded key Integration test failed!")
//                 .to_string();

//             // **Integration Test** verify stdout with the expected result
//             assert_eq!(create_output, None);
//             assert_eq!(mount_output, None);
//             assert_eq!(
//                 key_already_loaded_output,
//                 format!(
//                     "Key load error: Key already loaded for '{}'.\n",
//                     zfs_encrypted_dataset.to_string()
//                 )
//             );
//         } //END  **Integration Test**: Create from File then mount it

//         // **Integration Test**: Create from File then mount it
//         // This test will only run if there is root permission
//         #[cfg(feature = "file")]
//         {
//             // This test will only run if there is root permission
//             if !nix::unistd::Uid::effective().is_root() {
//                 eprintln!("This test needs root permission. Terminating early!");
//                 return;
//             }

//             let (zpool_name, temp_folder) = prepare_zpool();

//             let mut zpool_with_dataset = zpool_name.to_owned();
//             zpool_with_dataset.push('/');
//             zpool_with_dataset.push_str(&random_string(3));
//             let zfs_encrypted_dataset =
//                 Dataset::new(zpool_with_dataset).expect("ZFS name problem. Test terminated early!");

//             //Output of the Integration test will be stored in these variables to be validated
//             let create_file_output;
//             let mount_file_output;

//             // **Integration Test**: create a new encrypted dataset from file
//             {
//                 // construct the needed Struct related to this unit test
//                 let create_file = CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Create {
//                             datasets: vec![zfs_encrypted_dataset.clone()],
//                         },
//                     },
//                     second_factor: TwoFactorMode::File {
//                         file: String::from("/dev/zero"), // Zeros
//                         size: Some(1 << 8),
//                         port: None,
//                     },
//                 };

//                 // use a temp file to override stdin for password entry
//                 let mut password_file = tempfile::NamedTempFile::new()
//                     .expect("Couldn't make a temp file! Test terminating early!");

//                 // generate the temp file and fill it with the password
//                 // and feed "test" as password
//                 password_file
//                     .write_all(b"test")
//                     .expect("Couldn't write to the temp file! Test terminating early!");

//                 let password_file_path = password_file.into_temp_path();
//                 let password_file_path = password_file_path
//                     .to_str()
//                     .expect("Unknown temp file path! Test terminating early!");

//                 // feed password_file to stdin
//                 let stdin_guard = stdio_override::StdinOverride::override_file(password_file_path);

//                 // **Integration Test** run() function and capture its stdout output
//                 create_file_output = run(create_file);

//                 // release stdin back to normal
//                 drop(stdin_guard);

//                 //umount and unload the ZFS key
//                 zfs_encrypted_dataset
//                     .umount()
//                     .expect("ZFS Dataset create from file Integration test failed!")
//                     .unloadkey()
//                     .expect("ZFS Dataset create from file Integration test failed!");
//             } // END of **Integration Test 1**: create a new encrypted dataset from file

//             // **Integration Test**: mount an encrypted dataset from file
//             {
//                 // construct the needed Struct related to this unit test
//                 let mount_file = CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Mount {
//                             datasets: vec![zfs_encrypted_dataset.clone()],
//                             recursive: false,
//                         },
//                     },
//                     second_factor: TwoFactorMode::File {
//                         file: String::from("/dev/zero"), // Zeros
//                         size: Some(1 << 8),
//                         port: None,
//                     },
//                 };

//                 // use a temp file to override stdin for password entry
//                 let mut password_file = tempfile::NamedTempFile::new()
//                     .expect("Couldn't make a temp file! Test terminating early!");

//                 // generate the temp file and fill it with the password
//                 // and feed "test" as password
//                 password_file
//                     .write_all(b"test")
//                     .expect("Couldn't write to the temp file! Test terminating early!");

//                 let password_file_path = password_file.into_temp_path();
//                 let password_file_path = password_file_path
//                     .to_str()
//                     .expect("Unknown temp file path! Test terminating early!");

//                 // feed password_file to stdin
//                 let stdin_guard = stdio_override::StdinOverride::override_file(password_file_path);

//                 // **Integration Test** run() function and capture its stdout output
//                 mount_file_output = run(mount_file);

//                 // release stdin back to normal
//                 drop(stdin_guard);

//                 //umount and unload the ZFS key
//                 zfs_encrypted_dataset
//                     .umount()
//                     .expect("ZFS Dataset create from file Integration test failed!")
//                     .unloadkey()
//                     .expect("ZFS Dataset create from file Integration test failed!");
//             } // END of **Integration Test**: mount an encrypted dataset from file

//             //clean up and remove the dataset folder
//             cleanup_zpool(&zpool_name, temp_folder);

//             // **Integration Test** check for graceful execution
//             let create_output =
//                 create_file_output.expect("ZFS Dataset create from file Integration test failed!");

//             // **Integration Test** check for graceful execution
//             let mount_output =
//                 mount_file_output.expect("ZFS Dataset mount from file Integration test failed!");

//             // **Integration Test** verify stdout with the expected result
//             assert_eq!(create_output, None);
//             assert_eq!(mount_output, None);
//         } //END  **Integration Test**: Create from File then mount it

//         // TODO: Integration test for Yubikey modes are not implemented.
//     } // END all Integration Tests

//     /**********************************************************************
//      *  In this this section the supporting functions that are needed for *
//      *  Integration and unit tests are implemented.                       *
//      *********************************************************************/
//     fn random_string(length: u8) -> String {
//         use random_string::generate;

//         // for maximum compatibility limit the random character to ASCII alphabets
//         const CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
//         generate(length as usize, CHARSET)
//     }

//     // this function generates a temp folder and a zpool with a random name.
//     fn prepare_zpool() -> (String, std::path::PathBuf) {
//         // For ZFS related unit tests need root permission
//         // Check for root permission and exit early
//         if !nix::unistd::Uid::effective().is_root() {
//             panic!("Root permission is needed for integration tests! Tests terminated early!");
//         }

//         // Check for ZFS tools and exit early
//         std::process::Command::new("zpool")
//             .arg("version")
//             .spawn()
//             .expect("ZFS and ZPOOL tools must be installed. Test terminated early!");

//         // make a temp folder in the system temp directory
//         // this temp folder will be automatically deleted at the end of unit test
//         let temp_folder = tempfile::tempdir()
//             .expect("Couldn't make a temp folder! Test terminated early!")
//             .into_path();

//         // Use a random name to avoid modifying an existing ZFS pool and dataset
//         let zpool_name = random_string(30);

//         // Use a random mount point for Zpool alt_root
//         let mut zpool_alt_root = temp_folder.clone();
//         zpool_alt_root.push(random_string(5));

//         let mut zpool_path = temp_folder.clone();
//         zpool_path.push(zpool_name.clone());

//         // Generate a 512MB file which will be used as ZFS pool vdev
//         std::process::Command::new("truncate")
//             .arg("--size")
//             .arg("512M")
//             .arg(&zpool_path)
//             .spawn()
//             .expect("Cannot generate a temp file. Test terminated early!");

//         // create a new temporarily zpool using vdev
//         let command_output = std::process::Command::new("zpool")
//             .arg("create")
//             .arg(&zpool_name)
//             .arg(&zpool_path)
//             .arg("-R")
//             .arg(zpool_alt_root)
//             .status()
//             .expect("Zpool creation failed! Test terminated early!");

//         if !command_output.success() {
//             panic!("Zpool creation failed! Test terminated early!");
//         }

//         (zpool_name, temp_folder)
//     }

//     // this function removes zpool and cleans up the temp folder.
//     fn cleanup_zpool(zpool_name: &str, temp_folder: std::path::PathBuf) {
//         let command_output = std::process::Command::new("zpool")
//             .arg("export")
//             .arg(zpool_name)
//             .status()
//             .expect("Failed to export Zpool!");
//         if !command_output.success() {
//             panic!("Failed to export Zpool!");
//         }
//         std::process::Command::new("rm")
//             .arg("-rf")
//             .arg(temp_folder)
//             .spawn()
//             .expect("Temp folder clean up failed!");
//     }
// }
