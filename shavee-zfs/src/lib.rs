use std::io::prelude::*;
use std::process::Command;

pub fn zfs_loadkey(key: String, dataset: String) -> Result<(), String> {
    let zfs = Command::new("zfs") // Call zfs mount
        .arg("load-key")
        .arg("-L")
        .arg("prompt")
        .arg(&dataset)
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let mut zfs = match zfs {
        Ok(z) => z,
        Err(error) => return Err(error.to_string()),
    };

    let zstdin = zfs
        .stdin // Supply encryption key via stdin
        .as_mut();

    let zstdin = match zstdin {
        Some(i) => i,
        None => return Err("Failed to get ZFS stdin".to_string()),
    };

    match zstdin.write_all(&key.as_bytes()) {
        Ok(()) => (),
        Err(error) => return Err(error.to_string()),
    };

    let result = zfs.wait();
    match result {
        Ok(res) => {
            if res.success() {
                return Ok(());
            } else {
                return Err("Failed to mount dataset".to_string());
            }
        }
        Err(error) => return Err(error.to_string()),
    };
}

pub fn zfs_list(dataset: String) -> Result<Vec<String>, String> {
    let zfs_list = Command::new("zfs")
        .arg("list")
        .arg("-H")
        .arg("-o")
        .arg("name")
        .arg("-r")
        .arg(&dataset)
        .output();

    let zfs_list = match zfs_list {
        Ok(z) => {
            if z.status.success() {
                z
            } else {
                return Err("Failed to get ZFS Dataset list".to_string());
            }
        }
        Err(error) => return Err(error.to_string()),
    };

    let out = String::from_utf8(zfs_list.stdout);
    let list = match out {
        Ok(o) => o,
        Err(error) => {
            return Err(error.to_string());
        }
    };

    let list = list.split_whitespace();
    let mut dlist: Vec<String> = Vec::new();

    for i in list {
        dlist.push(i.to_string());
    }

    return Ok(dlist);
}

pub fn zfs_mount(dataset: String) -> Result<(), String> {
    let zfs_mount = Command::new("zfs")
        .arg("mount")
        .arg(dataset)
        .stderr(std::process::Stdio::piped())
        .spawn();

    let mut zfs_mount = match zfs_mount {
        Ok(z) => z,
        Err(error) => return Err(error.to_string()),
    };

    let result = zfs_mount.wait();

    match result {
        Ok(ecode) => {
            if ecode.success() {
                return Ok(());
            } else {
                return Err("Failed to mount ZFS Dataset".to_string());
            }
        }
        Err(error) => return Err(error.to_string()),
    }
}

pub fn zfs_create(key: String, dataset: String) -> Result<(), String> {
    let zfs_list = Command::new("zfs")
        .arg("list")
        .arg("-H")
        .arg("-o")
        .arg("name")
        .arg("-r")
        .arg(&dataset)
        .output();

    match zfs_list {
        Ok(z) => {
            if z.status.success() {
                let list = String::from_utf8_lossy(&z.stdout);
                let list = list.split_whitespace();
                for i in list {
                    let zfs_changekey = Command::new("zfs")
                        .arg("change-key")
                        .arg("-o")
                        .arg("keylocation=prompt")
                        .arg("-o")
                        .arg("keyformat=passphrase")
                        .arg(&i)
                        .stdin(std::process::Stdio::piped())
                        .spawn();

                    let mut zfs_changekey = match zfs_changekey {
                        Ok(z) => z,
                        Err(error) => return Err(error.to_string()),
                    };

                    let zstdin = zfs_changekey
                        .stdin // Supply encryption key via stdin
                        .as_mut();

                    let zstdin = match zstdin {
                        Some(i) => i,
                        None => return Err("Failed to get ZFS stdin".to_string()),
                    };

                    match zstdin.write_all(&key.as_bytes()) {
                        Ok(()) => (),
                        Err(error) => return Err(error.to_string()),
                    };

                    let result = zfs_changekey.wait();
                    match result {
                        Ok(res) => {
                            if res.success() {
                                return Ok(());
                            } else {
                                return Err("Failed to change key".to_string());
                            }
                        }
                        Err(error) => return Err(error.to_string()),
                    };
                }
            } else {
                let zfs = Command::new("zfs") // Call zfs create
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
                    .spawn();

                let mut zfs = match zfs {
                    Ok(z) => z,
                    Err(error) => return Err(error.to_string()),
                };

                zfs.stdin // Supply encryption key via stdin
                    .as_mut()
                    .expect("failed to get zfs stdin")
                    .write_all(&key.as_bytes())
                    .expect("Failed to write to stdin");

                let result = zfs.wait();
                match result {
                    Ok(res) => {
                        if res.success() {
                            return Ok(());
                        } else {
                            let mut e: Vec<u8> = Vec::new();
                            zfs.stderr
                                .expect("Failed to read stderr")
                                .read_to_end(&mut e)
                                .expect("Failed to read from stderr");
                            let error = String::from_utf8_lossy(&e);
                            return Err(error.to_string());
                        }
                    }
                    Err(error) => return Err(error.to_string()),
                };
            }
        }
        Err(error) => return Err(error.to_string()),
    };

    Ok(())
}
