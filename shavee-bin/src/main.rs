mod args;

use args::*;
use base64;
#[cfg(feature = "file")]
use shavee_core::filehash;
#[cfg(any(feature = "yubikey", feature = "file"))]
use shavee_core::logic;
use shavee_core::password;
#[cfg(feature = "file")]
use std::thread;

// main() collect the arguments from command line, pass them to run() and print any
// messages upon exiting the program
fn main() {
    let args = CliArgs::new();

    // Only main() will terminate the executable with proper message and code
    let code = match run(args) {
        Ok(None) => 0, // exit with no error code
        Ok(passphrase) => {
            println!("{}", passphrase.unwrap()); // print password if asked
            0 // then exit with no error code
        }
        Err(error) => {
            eprintln!("Error: {}", error); // print error message
            1 // then exit with generic error code 1
        }
    };
    std::process::exit(code);
}

fn run(args: CliArgs) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // pre-initialize the handle and filehash and use them
    // if multithread is needed for file hash generation
    // if multithread file hash code is not called then handle must not be used
    // thus initializing it with an error message.
    #[cfg(feature = "file")]
    let mut handle: thread::JoinHandle<Result<Vec<u8>, String>> =
        thread::spawn(|| Err(String::from(shavee_core::UNREACHABLE_CODE)));

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
        let port = port.clone();
        let file = file.clone();
        // start the file hash thread
        handle = thread::spawn(move || {
            filehash::get_filehash(file, port, size).map_err(|e| e.to_string())
            // map error to String
        });
    };

    // prompt user for password, in case of an error, terminate this function and
    // return the error to main()
    let password =
        rpassword::prompt_password_stderr("Dataset Password: ").map_err(|e| e.to_string())?;

    // if in the file 2FA mode, then wait for hash generation thread to finish
    // and unwrap the result. In case of an error, terminate this function and
    // return error to main().
    #[cfg(feature = "file")]
    if let TwoFactorMode::File { .. } = args.second_factor {
        filehash = handle.join().unwrap()?;
    };

    // Use this variable as the function return to be used for printing to stdio if needed.
    let exit_result: Option<String> = match args.operation {
        OperationMode::Create { dataset } => {
            match args.second_factor {
                #[cfg(feature = "yubikey")]
                TwoFactorMode::Yubikey { yslot } => dataset.yubi_create(password, yslot)?,
                #[cfg(feature = "file")]
                TwoFactorMode::File { .. } => dataset.file_create(password, filehash)?,
                TwoFactorMode::Password => dataset.create(&password_mode_hash(&password)?)?,
            };
            None
        }
        OperationMode::Mount { dataset } => {
            match args.second_factor {
                #[cfg(feature = "yubikey")]
                TwoFactorMode::Yubikey { yslot } => dataset.yubi_unlock(password, yslot)?,
                #[cfg(feature = "file")]
                TwoFactorMode::File { .. } => dataset.file_unlock(password, filehash)?,
                TwoFactorMode::Password => dataset.pass_unlock(password_mode_hash(&password)?)?,
            };
            None
        }
        OperationMode::Print => Some(match args.second_factor {
            #[cfg(feature = "yubikey")]
            TwoFactorMode::Yubikey { yslot } => logic::yubi_key_calculation(password, yslot)?,
            #[cfg(feature = "file")]
            TwoFactorMode::File { .. } => logic::file_key_calculation(password, filehash)?,
            TwoFactorMode::Password => password_mode_hash(&password)?,
        }),
    };

    Ok(exit_result)
}

fn password_mode_hash(password: &String) -> Result<String, Box<dyn std::error::Error>> {
    let key = password::hash_argon2(password.clone().into_bytes())?;
    let passphrase = base64::encode_config(key, base64::STANDARD_NO_PAD);
    Ok(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shavee_core::zfs::Dataset;
    use std::io::Write;
    use stdio_override;
    use tempfile;

    #[test]
    fn password_mode_hash_test() {
        let password = String::from("test"); // use "test" as password
        let passphrase = password_mode_hash(&password)
            .expect("Couldn't generate the passphrase! Test terminating early!");

        assert_eq!(
            passphrase,
            "LDa6mHK4xmv37cqoG8B+9M/ZIaEPLDhPQER6nuP7dw8mB1MoKoRkgZCbUNRwXvGwG2UkfWJUUEVOfWzUCCb8JA");
        // expected output for "test" password
    }

    #[test]
    fn integration_tests() {
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
        // This test will only run if there is root persmission
        if nix::unistd::Uid::effective().is_root() {
            let (zpool_name, temp_folder) = prepare_zpool();

            let mut zpool_with_dataset = zpool_name.to_owned();
            zpool_with_dataset.push('/');
            zpool_with_dataset.push_str(&random_string(3));
            let zfs_encrypted_dataset =
                Dataset::new(zpool_with_dataset).expect("ZFS name problem. Test terminated early!");

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

                //umount the ZFS only
                zfs_encrypted_dataset
                    .umount()
                    .expect("ZFS Dataset Mount from file Integration test failed!");

                // [Issue #22] try to mount again this time with key already loaded
                mount_key_already_loaded_output = run(mount_password);

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
        // This test will only run if there is root persmission
        #[cfg(feature = "file")]
        if nix::unistd::Uid::effective().is_root() {
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
        let charset: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        generate(length as usize, charset)
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
