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
