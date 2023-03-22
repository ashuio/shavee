mod args;

use args::*;

/// main() collect the arguments from command line, pass them to run() and print any
/// messages upon exiting the program
fn main() -> std::process::ExitCode {
    //initializing the logger
    shavee_core::trace_init(true);
    // parse the arguments
    shavee_core::trace("Parsing the arguments.");
    let args = CliArgs::new();
    shavee_core::trace("Arguments parsed successfully.");
    // Only main() will terminate the executable with proper message and code
    let code = match run(args) {
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

fn run(args: CliArgs) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // Pre-initialize the handle and filehash and use them.
    // If multithread is needed for file hash generation
    // if multithread file hash code is not called then handle must not be used
    // thus initializing it with an error message.
    #[cfg(feature = "file")]
    let mut handle: std::thread::JoinHandle<Result<Vec<u8>, String>> =
        std::thread::spawn(|| Err(String::from(shavee_core::UNREACHABLE_CODE)));

    #[cfg(feature = "file")]
    let mut filehash: Vec<u8> = vec![]; //empty u8 vector

    // if in the file 2FA mode, then generate file hash in parallel
    // while user is entering password
    #[cfg(feature = "file")]
    if let TwoFactorMode::File {
        ref file,
        ref port,
        size,
    } = args.second_factor
    {
        shavee_core::trace("Hashing the provided file as a 2FA.");
        let port = port.clone();
        let file = file.clone();
        // start the file hash thread
        handle = std::thread::spawn(move || {
            shavee_core::filehash::get_filehash(&file, port, size).map_err(|e| e.to_string())
            // map error to String
        });
    };

    // prompt user for password, in case of an error, terminate this function and
    // return the error to main()
    let binding =
        rpassword::prompt_password_stderr("Dataset Password: ").map_err(|e| e.to_string())?;
    let password = binding.as_bytes();
    shavee_core::trace("Password has entered successfully.");

    // if in the file 2FA mode, then wait for hash generation thread to finish
    // and unwrap the result. In case of an error, terminate this function and
    // return error to main().
    #[cfg(feature = "file")]
    if let TwoFactorMode::File { .. } = args.second_factor {
        filehash = handle.join().unwrap()?;
        shavee_core::trace("File is hashed successfully");
    };

    shavee_core::trace("Operation Mode:");
    // Use this variable as the function return to be used for printing to stdio if needed.
    let exit_result: Option<String> = match args.operation {
        OperationMode::Create { dataset } => {
            shavee_core::trace(&format!(
                "\tCreate ZFS dataset: \"{}\" using \"{:?}\" method.",
                dataset.to_string(),
                args.second_factor
            ));
            let salt = shavee_core::logic::generate_salt();
            match args.second_factor {
                #[cfg(feature = "yubikey")]
                TwoFactorMode::Yubikey { yslot } => dataset.yubi_create(password, yslot, &salt)?,
                #[cfg(feature = "file")]
                TwoFactorMode::File { .. } => dataset.file_create(password, filehash, &salt)?,
                TwoFactorMode::Password => {
                    let password_mode_hash =
                        shavee_core::logic::password_mode_hash(&password, &salt)?;
                    dataset.create(&password_mode_hash)?;
                    // store generated random salt as base64 encoded in ZFS property
                    dataset.set_property(
                        shavee_core::ZFS_PROPERTY_SALT.to_owned(),
                        &base64::Engine::encode(&shavee_core::logic::BASE64_ENGINE, salt),
                    )?;
                }
            };
            None
        }
        OperationMode::Mount { dataset } => {
            shavee_core::trace(&format!(
                "\tMount ZFS dataset: \"{}\".",
                dataset.to_string()
            ));
            let salt = shavee_core::logic::get_salt(Some(&dataset))?;
            match args.second_factor {
                #[cfg(feature = "yubikey")]
                TwoFactorMode::Yubikey { yslot } => dataset.yubi_unlock(password, yslot, &salt)?,
                #[cfg(feature = "file")]
                TwoFactorMode::File { .. } => dataset.file_unlock(password, filehash, &salt)?,
                TwoFactorMode::Password => dataset
                    .pass_unlock(shavee_core::logic::password_mode_hash(&password, &salt)?)?,
            };
            None
        }
        OperationMode::Print => {
            shavee_core::trace("\tGenerate password.");
            let salt = shavee_core::logic::get_salt(None)?;
            let passphrase = match args.second_factor {
                #[cfg(feature = "yubikey")]
                TwoFactorMode::Yubikey { yslot } => {
                    shavee_core::logic::yubi_key_calculation(password, yslot, &salt)?
                }
                #[cfg(feature = "file")]
                TwoFactorMode::File { .. } => {
                    shavee_core::logic::file_key_calculation(&password, filehash, &salt)?
                }
                TwoFactorMode::Password => {
                    shavee_core::logic::password_mode_hash(&password, &salt)?
                }
            };
            Some(passphrase)
        }
    };

    Ok(exit_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shavee_core::zfs::Dataset;
    use std::io::Write;
    use stdio_override;
    use tempfile;

    #[test]
    fn integration_tests() {
        // initializing logs
        shavee_core::trace_init(false);
        // All integration tests will be executed sequentially

        // **Integration Test**: Print Password
        {
            // construct the needed Struct related to this unit test
            let print_password = CliArgs {
                operation: OperationMode::Print,
                second_factor: TwoFactorMode::Password,
            };

            // use a temp file to override stdin for password entry
            let mut password_file = tempfile::NamedTempFile::new()
                .expect("Couldn't make a temp file! Test terminating early!");

            // generate the temp file and fill it with the password
            // and feed "test" as password
            password_file
                .write_all(b"test")
                .expect("Couldn't write to the temp file! Test terminating early!");

            let password_file_path = password_file.into_temp_path();
            let password_file_path = password_file_path
                .to_str()
                .expect("Unknown temp file path! Test terminating early!");

            // feed password_file to stdin
            let stdin_guard = stdio_override::StdinOverride::override_file(password_file_path);

            // **Integration Test** run() function and capture its stdout output
            let output = run(print_password);

            // release stdin back to normal
            drop(stdin_guard);
            //clean up the temp files
            drop(password_file_path);

            // **Integration test** check for graceful execution
            let output = output.unwrap().unwrap();

            // verify stdout with the expected result
            assert_eq!(
            output,
            "LDa6mHK4xmv37cqoG8B+9M/ZIaEPLDhPQER6nuP7dw8mB1MoKoRkgZCbUNRwXvGwG2UkfWJUUEVOfWzUCCb8JA");
            // expected output for "test" input
        } // END **Integration Test**: Print Password

        // **Integration Test**: Print File
        #[cfg(feature = "file")]
        {
            // construct the needed Struct related to this unit test
            let print_file = CliArgs {
                operation: OperationMode::Print,
                second_factor: TwoFactorMode::File {
                    file: String::from("/dev/zero"), // Zeros
                    size: Some(1 << 8),
                    port: None,
                },
            };

            // use a temp file to override stdin for password entry
            let mut password_file = tempfile::NamedTempFile::new()
                .expect("Couldn't make a temp file! Test terminating early!");

            // generate the temp file and fill it with the password
            // and feed "test" as password
            password_file
                .write_all(b"test")
                .expect("Couldn't write to the temp file! Test terminating early!");

            let password_file_path = password_file.into_temp_path();
            let password_file_path = password_file_path
                .to_str()
                .expect("Unknown temp file path! Test terminating early!");

            // feed password_file to stdin
            let stdin_guard = stdio_override::StdinOverride::override_file(password_file_path);

            // **Integration Test** run() function and capture its stdout output
            let output = run(print_file);

            // release stdin back to normal
            drop(stdin_guard);
            //clean up the temp files
            drop(password_file_path);

            // **Integration test** check for graceful execution
            let output = output.unwrap().unwrap();

            // verify stdout with the expected result
            assert_eq!(
            output,
            "oenvfi3+jMSy5kuOzbKzfAsBNi/jHFuD510Q43zJhVNJaBi35mvXEqeUPzdarV1mAlhkFG1C7NJ5/mEAWNOpgg");
            // expected output for "test" input
        } // END **Integration Test**: Print File

        // **Integration Test**: Create from password then mount it
        {
            // This test will only run if there is root permission
            if !nix::unistd::Uid::effective().is_root() {
                eprintln!("This test needs root permission. Terminating early!");
                return;
            }

            let (zpool_name, temp_folder) = prepare_zpool();
            shavee_core::trace(&format!("Temp Zpool name: {:?}", zpool_name));
            let mut zpool_with_dataset = zpool_name.to_owned();
            zpool_with_dataset.push('/');
            zpool_with_dataset.push_str(&random_string(3));
            shavee_core::trace(&format!("Temp ZFS dataset path: {:?}", zpool_with_dataset));
            let zfs_encrypted_dataset =
                Dataset::new(zpool_with_dataset).expect("ZFS name problem. Test terminated early!");
            shavee_core::trace(&format!(
                "Temp encrypted ZFS dataset: {:?}",
                zfs_encrypted_dataset
            ));

            //Output of the Integration test will be stored in these variables to be validated
            let create_password_output;
            let mount_password_output;
            let mount_key_already_loaded_output;

            // **Integration Test**: create a new encrypted dataset from file
            {
                // construct the needed Struct related to this unit test
                let create_password = CliArgs {
                    operation: OperationMode::Create {
                        dataset: zfs_encrypted_dataset.clone(),
                    },
                    second_factor: TwoFactorMode::Password,
                };
                shavee_core::trace(&format!(
                    "Simulated CLI arguments action: {:?}",
                    create_password
                ));

                // use a temp file to override stdin for password entry
                let mut password_file = tempfile::NamedTempFile::new()
                    .expect("Couldn't make a temp file! Test terminating early!");

                // generate the temp file and fill it with the password
                // and feed "test" as password
                password_file
                    .write_all(b"test")
                    .expect("Couldn't write to the temp file! Test terminating early!");

                let password_file_path = password_file.into_temp_path();
                let password_file_path = password_file_path
                    .to_str()
                    .expect("Unknown temp file path! Test terminating early!");

                // feed password_file to stdin
                let stdin_guard = stdio_override::StdinOverride::override_file(password_file_path);

                // **Integration Test** run() function and capture its stdout output
                create_password_output = run(create_password);
                shavee_core::trace(&format!(
                    "Output of the cli command: {:?}",
                    create_password_output
                ));

                // release stdin back to normal
                drop(stdin_guard);
                //clean up the temp files
                drop(password_file_path);

                //umount and unload the ZFS key
                zfs_encrypted_dataset
                    .umount()
                    .expect("ZFS Dataset create from file Integration test failed!")
                    .unloadkey()
                    .expect("ZFS Dataset create from file Integration test failed!");
            } // END of **Integration Test 1**: create a new encrypted dataset from password

            // **Integration Test**: mount an encrypted dataset from password
            {
                // construct the needed Struct related to this unit test
                let mount_password = CliArgs {
                    operation: OperationMode::Mount {
                        dataset: zfs_encrypted_dataset.clone(),
                    },
                    second_factor: TwoFactorMode::Password,
                };
                shavee_core::trace(&format!(
                    "Simulated CLI arguments action: {:?}",
                    mount_password
                ));

                // use a temp file to override stdin for password entry
                let mut password_file = tempfile::NamedTempFile::new()
                    .expect("Couldn't make a temp file! Test terminating early!");

                // generate the temp file and fill it with the password
                // and feed "test" as password
                password_file
                    .write_all(b"test")
                    .expect("Couldn't write to the temp file! Test terminating early!");

                let password_file_path = password_file.into_temp_path();
                let password_file_path = password_file_path
                    .to_str()
                    .expect("Unknown temp file path! Test terminating early!");

                // feed password_file to stdin
                let stdin_guard = stdio_override::StdinOverride::override_file(password_file_path);

                // **Integration Test** run() function and capture its stdout output
                mount_password_output = run(mount_password.clone());
                shavee_core::trace(&format!(
                    "Output of the cli command: {:?}",
                    mount_password_output
                ));

                //umount the ZFS only
                zfs_encrypted_dataset
                    .umount()
                    .expect("ZFS Dataset Mount from file Integration test failed!");

                // [Issue #22] try to mount again this time with key already loaded
                mount_key_already_loaded_output = run(mount_password);
                shavee_core::trace(&format!(
                    "Output of the cli command: {:?}",
                    mount_key_already_loaded_output,
                ));

                // unload the ZFS key
                zfs_encrypted_dataset
                    .unloadkey()
                    .expect("ZFS Dataset unload key failed!");

                // release stdin back to normal
                drop(stdin_guard);
                //clean up the temp files
                drop(password_file_path);
            } // END of **Integration Test**: mount an encrypted dataset from password

            //clean up and remove the dataset folder
            cleanup_zpool(&zpool_name, temp_folder);

            // **Integration Test** check for graceful execution
            let create_output = create_password_output
                .expect("ZFS Dataset create from Password Integration test failed!");

            // **Integration Test** check for graceful execution
            let mount_output = mount_password_output
                .expect("ZFS Dataset mount from Password Integration test failed!");

            let key_already_loaded_output = mount_key_already_loaded_output
                .expect_err("ZFS Dataset mount on an already loaded key Integration test failed!")
                .to_string();

            // **Integration Test** verify stdout with the expected result
            assert_eq!(create_output, None);
            assert_eq!(mount_output, None);
            assert_eq!(
                key_already_loaded_output,
                format!(
                    "Key load error: Key already loaded for '{}'.\n",
                    zfs_encrypted_dataset.to_string()
                )
            );
        } //END  **Integration Test**: Create from File then mount it

        // **Integration Test**: Create from File then mount it
        // This test will only run if there is root permission
        #[cfg(feature = "file")]
        {
            // This test will only run if there is root permission
            if !nix::unistd::Uid::effective().is_root() {
                eprintln!("This test needs root permission. Terminating early!");
                return;
            }

            let (zpool_name, temp_folder) = prepare_zpool();

            let mut zpool_with_dataset = zpool_name.to_owned();
            zpool_with_dataset.push('/');
            zpool_with_dataset.push_str(&random_string(3));
            let zfs_encrypted_dataset =
                Dataset::new(zpool_with_dataset).expect("ZFS name problem. Test terminated early!");

            //Output of the Integration test will be stored in these variables to be validated
            let create_file_output;
            let mount_file_output;

            // **Integration Test**: create a new encrypted dataset from file
            {
                // construct the needed Struct related to this unit test
                let create_file = CliArgs {
                    operation: OperationMode::Create {
                        dataset: zfs_encrypted_dataset.clone(),
                    },
                    second_factor: TwoFactorMode::File {
                        file: String::from("/dev/zero"), // Zeros
                        size: Some(1 << 8),
                        port: None,
                    },
                };

                // use a temp file to override stdin for password entry
                let mut password_file = tempfile::NamedTempFile::new()
                    .expect("Couldn't make a temp file! Test terminating early!");

                // generate the temp file and fill it with the password
                // and feed "test" as password
                password_file
                    .write_all(b"test")
                    .expect("Couldn't write to the temp file! Test terminating early!");

                let password_file_path = password_file.into_temp_path();
                let password_file_path = password_file_path
                    .to_str()
                    .expect("Unknown temp file path! Test terminating early!");

                // feed password_file to stdin
                let stdin_guard = stdio_override::StdinOverride::override_file(password_file_path);

                // **Integration Test** run() function and capture its stdout output
                create_file_output = run(create_file);

                // release stdin back to normal
                drop(stdin_guard);
                //clean up the temp files
                drop(password_file_path);

                //umount and unload the ZFS key
                zfs_encrypted_dataset
                    .umount()
                    .expect("ZFS Dataset create from file Integration test failed!")
                    .unloadkey()
                    .expect("ZFS Dataset create from file Integration test failed!");
            } // END of **Integration Test 1**: create a new encrypted dataset from file

            // **Integration Test**: mount an encrypted dataset from file
            {
                // construct the needed Struct related to this unit test
                let mount_file = CliArgs {
                    operation: OperationMode::Mount {
                        dataset: zfs_encrypted_dataset.clone(),
                    },
                    second_factor: TwoFactorMode::File {
                        file: String::from("/dev/zero"), // Zeros
                        size: Some(1 << 8),
                        port: None,
                    },
                };

                // use a temp file to override stdin for password entry
                let mut password_file = tempfile::NamedTempFile::new()
                    .expect("Couldn't make a temp file! Test terminating early!");

                // generate the temp file and fill it with the password
                // and feed "test" as password
                password_file
                    .write_all(b"test")
                    .expect("Couldn't write to the temp file! Test terminating early!");

                let password_file_path = password_file.into_temp_path();
                let password_file_path = password_file_path
                    .to_str()
                    .expect("Unknown temp file path! Test terminating early!");

                // feed password_file to stdin
                let stdin_guard = stdio_override::StdinOverride::override_file(password_file_path);

                // **Integration Test** run() function and capture its stdout output
                mount_file_output = run(mount_file);

                // release stdin back to normal
                drop(stdin_guard);
                //clean up the temp files
                drop(password_file_path);

                //umount and unload the ZFS key
                zfs_encrypted_dataset
                    .umount()
                    .expect("ZFS Dataset create from file Integration test failed!")
                    .unloadkey()
                    .expect("ZFS Dataset create from file Integration test failed!");
            } // END of **Integration Test**: mount an encrypted dataset from file

            //clean up and remove the dataset folder
            cleanup_zpool(&zpool_name, temp_folder);

            // **Integration Test** check for graceful execution
            let create_output =
                create_file_output.expect("ZFS Dataset create from file Integration test failed!");

            // **Integration Test** check for graceful execution
            let mount_output =
                mount_file_output.expect("ZFS Dataset mount from file Integration test failed!");

            // **Integration Test** verify stdout with the expected result
            assert_eq!(create_output, None);
            assert_eq!(mount_output, None);
        } //END  **Integration Test**: Create from File then mount it

        // TODO: Integration test for Yubikey modes are not implemented.
    } // END all Integration Tests

    /**********************************************************************
     *  In this this section the supporting functions that are needed for *
     *  Integration and unit tests are implemented.                       *
     *********************************************************************/

    fn random_string(length: u8) -> String {
        use random_string::generate;

        // for maximum compatibility limit the random character to ASCII alphabets
        const CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        generate(length as usize, CHARSET)
    }

    // this function generates a temp folder and a zpool with a random name.
    fn prepare_zpool() -> (String, std::path::PathBuf) {
        // For ZFS related unit tests need root permission
        // Check for root permission and exit early
        if !nix::unistd::Uid::effective().is_root() {
            panic!("Root permission is needed for integration tests! Tests terminated early!");
        }

        // Check for ZFS tools and exit early
        std::process::Command::new("zpool")
            .arg("version")
            .spawn()
            .expect("ZFS and ZPOOL tools must be installed. Test terminated early!");

        // make a temp folder in the system temp directory
        // this temp folder will be automatically deleted at the end of unit test
        let temp_folder = tempfile::tempdir()
            .expect("Couldn't make a temp folder! Test terminated early!")
            .into_path();

        // Use a random name to avoid modifying an existing ZFS pool and dataset
        let zpool_name = random_string(30);

        // Use a random mount point for Zpool alt_root
        let mut zpool_alt_root = temp_folder.clone();
        zpool_alt_root.push(random_string(5));

        let mut zpool_path = temp_folder.clone();
        zpool_path.push(zpool_name.clone());

        // Generate a 512MB file which will be used as ZFS pool vdev
        std::process::Command::new("truncate")
            .arg("--size")
            .arg("512M")
            .arg(&zpool_path)
            .spawn()
            .expect("Cannot generate a temp file. Test terminated early!");

        // create a new temporarily zpool using vdev
        let command_output = std::process::Command::new("zpool")
            .arg("create")
            .arg(&zpool_name)
            .arg(&zpool_path)
            .arg("-R")
            .arg(zpool_alt_root)
            .status()
            .expect("Zpool creation failed! Test terminated early!");

        if !command_output.success() {
            panic!("Zpool creation failed! Test terminated early!");
        }

        (zpool_name, temp_folder)
    }

    // this function removes zpool and cleans up the temp folder.
    fn cleanup_zpool(zpool_name: &str, temp_folder: std::path::PathBuf) {
        let command_output = std::process::Command::new("zpool")
            .arg("export")
            .arg(zpool_name)
            .status()
            .expect("Failed to export Zpool!");
        if !command_output.success() {
            panic!("Failed to export Zpool!");
        }
        std::process::Command::new("rm")
            .arg("-rf")
            .arg(temp_folder)
            .spawn()
            .expect("Temp folder clean up failed!");
    }
}
