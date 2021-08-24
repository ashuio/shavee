use std::error::Error;
use std::io::prelude::*;
use std::process::Command;

pub fn zfs_loadkey(key: String, dataset: String) -> Result<(), Box<dyn Error>> {
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
        Err(error) => return Err(error.into()),
    };

    let zstdin = zfs
        .stdin // Supply encryption key via stdin
        .as_mut();

    let zstdin = match zstdin {
        Some(i) => i,
        None => return Err("Failed to lock stdin".to_string().into()),
    };

    zstdin.write_all(&key.as_bytes())?;

    let result = zfs.wait();
    match result {
        Ok(res) => {
            if res.success() {
                return Ok(());
            } else {
                return Err("Failed to mount dataset".to_string().into());
            }
        }
        Err(error) => return Err(error.into()),
    };
}

pub fn zfs_list(dataset: String) -> Result<Vec<String>, Box<dyn Error>> {
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
                return Err(String::from_utf8_lossy(&z.stderr).to_string().into());
            }
        }
        Err(error) => return Err(error.into()),
    };

    let out = String::from_utf8(zfs_list.stdout)?;

    let list = out.split_whitespace();
    let mut dlist: Vec<String> = Vec::new();

    for i in list {
        dlist.push(i.to_string());
    }

    return Ok(dlist);
}

pub fn zfs_create(key: String, dataset: Option<String>) -> Result<(), Box<dyn Error>> {
    let dataset = dataset
        .expect(crate::UNREACHABLE_CODE);
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
                        None => return Err("Failed to get ZFS stdin".into()),
                    };

                    zstdin.write_all(&key.as_bytes())?;

                    let result = zfs_changekey.wait();
                    match result {
                        Ok(res) => {
                            if res.success() {
                                return Ok(());
                            } else {
                                return Err("Failed to change key".into());
                            }
                        }
                        Err(error) => return Err(error.into()),
                    };
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
                            return Err(error.into());
                        }
                    }
                    Err(error) => return Err(error.into()),
                };
            }
        }
        Err(error) => return Err(error.into()),
    };

    Ok(())
}

pub fn zfs_mount(dataset: String) -> Result<(), Box<dyn Error>> {
    match Command::new("zfs").arg("mount").arg(dataset).output() {
        Ok(z) => {
            if z.status.success() {
                return Ok(());
            } else {
                return Err(String::from_utf8_lossy(&z.stderr).to_string().into());
            };
        }
        Err(i) => return Err(i.into()),
    };
}

pub fn zfs_umount(dataset: String) -> Result<(), Box<dyn Error>> {
    match Command::new("zfs").arg("umount").arg(dataset).output() {
        Ok(z) => {
            if z.status.success() {
                return Ok(());
            } else {
                return Err(String::from_utf8_lossy(&z.stderr).to_string().into());
            };
        }
        Err(i) => return Err(i.into()),
    };
}

pub fn zfs_unload_key(dataset: String) -> Result<(), Box<dyn Error>> {
    match Command::new("zfs").arg("unload-key").arg(dataset).output() {
        Ok(z) => {
            if z.status.success() {
                return Ok(());
            } else {
                return Err(String::from_utf8_lossy(&z.stderr).to_string().into());
            };
        }
        Err(i) => return Err(i.into()),
    };
}
