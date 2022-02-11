use std::io::prelude::*;
use std::process::Command;

use crate::UNREACHABLE_CODE;

pub fn zfs_loadkey(key: String, dataset: String) -> std::io::Result<()> {
    let mut zfs = Command::new("zfs") // Call zfs mount
        .arg("load-key")
        .arg("-L")
        .arg("prompt")
        .arg(&dataset)
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let zstdin = zfs
        .stdin // Supply encryption key via stdin
        .as_mut()
        .ok_or(std::io::Error::new(
            //convert None to an error
            std::io::ErrorKind::BrokenPipe,
            "Failed to lock stdin!",
        ))?;

    zstdin.write_all(&key.as_bytes())?;

    let result = zfs.wait()?;
    if !result.success() {
        let mut e: Vec<u8> = Vec::new();
        zfs.stderr.unwrap().read_to_end(&mut e).unwrap();
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            String::from_utf8_lossy(&e),
        ));
    }
    Ok(())
}

pub fn zfs_list(dataset: String) -> Result<Vec<String>, std::io::Error> {
    let zfs_list = Command::new("zfs")
        .arg("list")
        .arg("-H")
        .arg("-o")
        .arg("name")
        .arg("-r")
        .arg(&dataset)
        .output()?;

    if !zfs_list.status.success() {
        return Err(std::io::Error::new(
            // error kind is not known
            std::io::ErrorKind::Other,
            //stderr used to generate the error message.
            String::from_utf8_lossy(&zfs_list.stderr).to_string(),
        ));
    };

    let out = String::from_utf8(zfs_list.stdout).map_err(|error| {
        std::io::Error::new(
            // error kind is not known
            std::io::ErrorKind::InvalidInput,
            error,
        )
    })?;

    let list: Vec<String> = out.split_whitespace().map(|s| s.to_string()).collect();
    Ok(list)
}

pub fn zfs_create(key: String, dataset: String) -> std::io::Result<()> {
    // check if dataset already exists
    match zfs_list(dataset.clone()) {
        // if it exists, then change password
        Ok(list) => {
            for i in list {
                let mut zfs_changekey = Command::new("zfs")
                    .arg("change-key")
                    .arg("-o")
                    .arg("keylocation=prompt")
                    .arg("-o")
                    .arg("keyformat=passphrase")
                    .arg(&i)
                    .stdin(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?;

                let zstdin = zfs_changekey
                    .stdin // Supply encryption key via stdin
                    .as_mut()
                    .ok_or(
                        // convert None to an error
                        std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "Failed to get ZFS stdin!",
                        ),
                    )?;

                zstdin.write_all(&key.as_bytes())?;

                // capture the error message and pass it to the calling function
                let result = zfs_changekey.wait_with_output()?;
                if !result.status.success() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        String::from_utf8(result.stderr).expect(UNREACHABLE_CODE),
                    ));
                }
            }
        }
        // if dataset doesn't exists then create it
        Err(_) => {
            let mut zfs = Command::new("zfs") // Call zfs create
                .arg("create")
                .arg("-o")
                .arg("encryption=on")
                .arg("-o")
                .arg("keyformat=passphrase")
                .arg("-o")
                .arg("keylocation=prompt")
                .arg(&dataset)
                .stdin(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?;

            zfs.stdin // Supply encryption key via stdin
                .as_mut()
                .expect("failed to get zfs stdin!")
                .write_all(&key.as_bytes())
                .expect("Failed to write to stdin!");

            let result = zfs.wait()?;
            if !result.success() {
                let mut e: Vec<u8> = Vec::new();
                zfs.stderr
                    .expect("Failed to read stderr!")
                    .read_to_end(&mut e)
                    .expect("Failed to read from stderr!");
                let error = String::from_utf8_lossy(&e);
                return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, error));
            }
        }
    };
    Ok(())
}

pub fn zfs_mount(dataset: String) -> std::io::Result<()> {
    execute_zfs_subcommand_then_collect_result("mount", dataset)?;
    Ok(())
}

pub fn zfs_umount(dataset: String) -> std::io::Result<()> {
    execute_zfs_subcommand_then_collect_result("umount", dataset)?;
    Ok(())
}

pub fn zfs_unload_key(dataset: String) -> std::io::Result<()> {
    execute_zfs_subcommand_then_collect_result("unload-key", dataset)?;
    Ok(())
}

fn execute_zfs_subcommand_then_collect_result(
    subcommand: &str,
    dataset: String,
) -> std::io::Result<()> {
    let command_output = Command::new("zfs").arg(subcommand).arg(dataset).output()?;
    if !command_output.status.success() {
        return Err(std::io::Error::new(
            // error kind is not known
            std::io::ErrorKind::Other,
            //stderr used to generate the error message.
            String::from_utf8_lossy(&command_output.stderr).to_string(),
        ));
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn zfs_list_test() {
        // generate a temp zpool
        let (zpool_name, temp_folder) = prepare_zpool();
        // b/c of zpool creation process, the dataset name is the same as zpool
        let zfs_dataset = zpool_name.clone();

        // NOTE: the output will be evaluated **AFTER** clean up so the temp folder and
        // temp zpool can safely be removed.

        let test_output = zfs_list(zfs_dataset.clone());

        //clean up
        cleanup_zpool(zpool_name, temp_folder);

        // test the output against expected result.
        match test_output {
            Ok(result) => assert_eq!(result, vec![zfs_dataset]),
            Err(error) => panic!("Test failed: {:?}", error),
        }
    }

    #[test]
    fn zfs_create_test() {
        // generate a temp zpool
        let (zpool_name, temp_folder) = prepare_zpool();

        // b/c of zpool creation process, the dataset name is the same as zpool
        let zfs_dataset_unencrypted = zpool_name.clone();

        // NOTE: the output will be evaluated **AFTER** clean up so the temp folder and
        // temp zpool can safely be removed.

        // **TEST 1 **: zfs_create on a dataset that is not encrypted
        // This test is expected to fail
        let test_dataset_not_encrypted_must_fail_output =
            zfs_create(random_string(3), zfs_dataset_unencrypted.clone());

        // **TEST 2 **: zfs_create a new encrypted dataset
        let mut zfs_encrypted_dataset = zpool_name.clone();
        zfs_encrypted_dataset.push('/');
        zfs_encrypted_dataset.push_str(&random_string(3));
        let test_create_new_encrypted_dataset_output =
            zfs_create(random_string(8), zfs_encrypted_dataset.clone()); // min accepted key is 8 character

        // **TEST 3 **: zfs_create on an already encrypted dataset
        let test_already_encrypted_dataset_output =
            zfs_create(random_string(8), zfs_encrypted_dataset); // min accepted key is 8 character

        //clean up
        cleanup_zpool(zpool_name, temp_folder);

        // now it is time to test the outputs against expected results.

        // **TEST 1 **: zfs_create on a dataset that is not encrypted
        match test_dataset_not_encrypted_must_fail_output {
            Ok(_) => panic!("Unit test failed!"),
            Err(error) => assert_eq!(
                "Key change error: Dataset not encrypted.\n",
                error.to_string()
            ),
        }

        // **TEST 2 **: zfs_create a new encrypted dataset
        test_create_new_encrypted_dataset_output.expect("Unit test failed!");

        // **TEST 3 **: zfs_create on an already encrypted dataset
        test_already_encrypted_dataset_output.expect("Unit test failed!");
    }

    //These tests checks for a reported error on non-existing dataset
    #[test]
    fn dataset_does_not_exists_test() {
        // use a random name for dataset to assure it doesn't already exists!
        let dataset = random_string(30);
        let expected_error = format!("cannot open '{}': dataset does not exist\n", dataset);

        // test all functions in a separate assert_eq

        assert_eq!(
            execute_zfs_subcommand_then_collect_result("mount", dataset.clone())
                .unwrap_err()
                .to_string(),
            expected_error
        );

        assert_eq!(
            zfs_loadkey("passkey_not_important".to_string(), dataset.clone())
                .unwrap_err()
                .to_string(),
            expected_error
        );

        assert_eq!(
            zfs_list(dataset.clone()).unwrap_err().to_string(),
            expected_error
        );

        // NOTE: this test doesn't apply to zfs_create

        assert_eq!(
            zfs_mount(dataset.clone()).unwrap_err().to_string(),
            expected_error
        );

        assert_eq!(
            zfs_umount(dataset.clone()).unwrap_err().to_string(),
            expected_error
        );

        assert_eq!(
            zfs_unload_key(dataset.clone()).unwrap_err().to_string(),
            expected_error
        );
    }

    fn random_string(length: u8) -> String {
        use random_string::generate;

        // for maximum compatibility limit the random character to ASCII alphabets
        let charset: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        generate(length as usize, charset)
    }

    // this function generates a temp folder and a zpool with a random name.
    fn prepare_zpool() -> (String, PathBuf) {
        // For ZFS related unit tests need root permission
        // Check for root permission and exit early
        if !nix::unistd::Uid::effective().is_root() {
            panic!("Root permission is needed! Test terminated early!");
        }

        // Check for ZFS tools and exit early
        Command::new("zpool")
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
        Command::new("truncate")
            .arg("--size")
            .arg("512M")
            .arg(zpool_path.clone())
            .spawn()
            .expect("Cannot generate a temp file. Test terminated early!");

        // create a new temporarily zpool using vdev
        let command_output = Command::new("zpool")
            .arg("create")
            .arg(zpool_name.clone())
            .arg(zpool_path.clone())
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
    fn cleanup_zpool(zpool_name: String, temp_folder: PathBuf) {
        let command_output = Command::new("zpool")
            .arg("export")
            .arg(zpool_name)
            .status()
            .expect("Failed to export Zpool!");
        if !command_output.success() {
            panic!("Failed to export Zpool!");
        }
        Command::new("rm")
            .arg("-rf")
            .arg(temp_folder)
            .spawn()
            .expect("Temp folder clean up failed!");
    }
}
