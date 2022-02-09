use std::error::Error;
use std::io::prelude::*;
use std::process::Command;

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
        .as_mut();

    let zstdin = match zstdin {
        Some(i) => i,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Failed to lock stdin",
            ))
        }
    };

    zstdin.write_all(&key.as_bytes())?;

    let result = zfs.wait()?;
    if result.success() {
        return Ok(());
    } else {
        let mut e: Vec<u8> = Vec::new();
        zfs.stderr.unwrap().read_to_end(&mut e).unwrap();
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            String::from_utf8_lossy(&e),
        ));
    }
}

pub fn zfs_list(dataset: String) -> Result<Vec<String>, Box<dyn Error>> {
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
        )
        .into());
    };

    let out = String::from_utf8(zfs_list.stdout)?;

    let list = out.split_whitespace();
    let mut dlist: Vec<String> = Vec::new();

    for i in list {
        dlist.push(i.to_string());
    }

    return Ok(dlist);
}

pub fn zfs_create(key: String, dataset: Option<String>) -> std::io::Result<()> {
    let dataset = dataset.expect(crate::UNREACHABLE_CODE);
    let zfs_list = Command::new("zfs")
        .arg("list")
        .arg("-H")
        .arg("-o")
        .arg("name")
        .arg("-r")
        .arg(&dataset)
        .output()?;

    if zfs_list.status.success() {
        let list = String::from_utf8_lossy(&zfs_list.stdout);
        let list = list.split_whitespace();
        for i in list {
            let mut zfs_changekey = Command::new("zfs")
                .arg("change-key")
                .arg("-o")
                .arg("keylocation=prompt")
                .arg("-o")
                .arg("keyformat=passphrase")
                .arg(&i)
                .stdin(std::process::Stdio::piped())
                .spawn()?;

            let zstdin = zfs_changekey
                .stdin // Supply encryption key via stdin
                .as_mut();

            let zstdin = match zstdin {
                Some(i) => i,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "Failed to get ZFS stdin!",
                    ))
                }
            };

            zstdin.write_all(&key.as_bytes())?;

            let result = zfs_changekey.wait()?;
            if !result.success() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to change key!",
                ));
            }
        }
    } else {
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
            .expect("failed to get zfs stdin")
            .write_all(&key.as_bytes())
            .expect("Failed to write to stdin");

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

    #[test]
    fn zfs_functional_test() {
        /*
        This unit test, will need to setup a temp ZFS Pool
        to test the functions on it.
        It can only work if ZFS and ZPOOL are installed and root permission is given.
        */

        // Check for root permission and exit early
        if !nix::unistd::Uid::effective().is_root() {
            panic!("Root permission is needed! Test terminated early!");
        }

        // Check for ZFS tools and exit early
        Command::new("zpool")
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
        zpool_alt_root.push(random_string(10));

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
            .arg(zpool_name)
            .arg(zpool_path)
            .arg("-R")
            .arg(zpool_alt_root)
            .status()
            .expect("Zpool creation failed! Test terminated early!");

        if !command_output.success() {
            panic!("Zpool creation failed! Test terminated early!");
        }

        // now we can test the functions
        // test creating an encrypted dataset
        // use a random dataset and key
        let zfs_dataset = random_string(10);
        let zfs_key = random_string(10);

        zfs_create(zfs_key, Some(zfs_dataset)).expect("Test failed: zfs_create()");
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
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};

        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length as usize)
            .map(char::from)
            .collect()
    }
}
