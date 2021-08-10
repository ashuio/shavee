use std::io::prelude::*;
use std::process::{exit, Command};

pub fn zfs_load_key(key: &String, dataset: String) {
    let mut dataset = dataset;
    if dataset.ends_with("/") {
        dataset.pop();
    };
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
        Err(error) => {
            eprintln!("Error: Failed to run zfs command for {}", dataset);
            eprintln!("Error: {}", error);
            exit(1)
        }
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
                eprintln!("Loading encryption key for Dataset {} ... [OK]", dataset);
            } else {
                let mut e: Vec<u8> = Vec::new();
                zfs.stderr
                    .expect("Failed to get stderr message")
                    .read_to_end(&mut e)
                    .expect("Failed to get stderr message");
                let error = String::from_utf8_lossy(&e);
                eprintln!("Loading encryption key for Dataset {} ... [FAIL]", dataset);
                eprintln!("Error: {}\n", error);
            }
        }
        Err(error) => {
            eprintln!("Error: ZFS load-key command failed");
            eprintln!("Error: {}", &error);
            exit(1)
        }
    };
}

pub fn zfs_mount(key: &String, dataset: String) {
    zfs_load_key(key, dataset.clone());
    let mut dataset = dataset;
    if dataset.ends_with("/") {
        dataset.pop();
    };
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
                let e = z.stderr;
                let error = String::from_utf8_lossy(&e);
                eprintln!("Error: Failed to get ZFS Dataset list");
                eprintln!("Error: {}", error);
                exit(1)
            }
        }
        Err(error) => {
            eprintln!("Error: Failed to run ZFS list command");
            eprintln!("Error: {}", error);
            exit(1)
        }
    };

    let out = String::from_utf8(zfs_list.stdout);
    let list = match out {
        Ok(o) => o,
        Err(error) => {
            eprintln!("Error: Failed to parse zfs list output");
            eprintln!("Error: {}", error);
            exit(1)
        }
    };
    let list = list.split_whitespace();

    for i in list {
        let zfs_mount = Command::new("zfs")
            .arg("mount")
            .arg(&i)
            .stderr(std::process::Stdio::piped())
            .spawn();

        let mut zfs_mount = match zfs_mount {
            Ok(z) => z,
            Err(error) => {
                eprintln!("Error: Failed to run ZFS command for {}", i);
                eprintln!("Error: {}", error);
                exit(1)
            }
        };

        let result = zfs_mount.wait();

        match result {
            Ok(res) => {
                if res.success() {
                    eprintln!("Mounting Dataset {} ... [OK]", i);
                } else {
                    let mut e: Vec<u8> = Vec::new();
                    zfs_mount
                        .stderr
                        .expect("Failed to get stderr essage")
                        .read_to_end(&mut e)
                        .expect("Failed to get stderr message");
                    let error = String::from_utf8_lossy(&e);
                    eprintln!("Mounting Dataset {} ... [FAIL]", i);
                    eprintln!("Error: {}\n", error);
                }
            }
            Err(error) => {
                eprintln!("Error: ZFS mount command failed");
                eprintln!("Error: {}", &error);
                exit(1)
            }
        };
    }
}

pub fn zfs_create(key: &String, dataset: String) {
    let mut dataset = dataset;
    if dataset.ends_with("/") {
        dataset.pop();
    };
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
                        Err(error) => {
                            eprintln!("Error: Failed to run ZFS change-key command for {}", i);
                            eprintln!("{}", error);
                            exit(1)
                        }
                    };

                    zfs_changekey
                        .stdin // Supply encryption key via stdin
                        .as_mut()
                        .expect("failed to get zfs stdin")
                        .write_all(&key.as_bytes())
                        .expect("Failed to write to stdin");

                    let result = zfs_changekey.wait();
                    match result {
                        Ok(res) => {
                            if res.success() {
                                eprintln!(
                                    "Dataset {} found, attempting to change key ... [OK]",
                                    &i
                                );
                            } else {
                                eprintln!(
                                    "Dataset {} found, attempting to change key ... [FAIL]",
                                    &i
                                );
                            }
                        }
                        Err(error) => {
                            eprint!("\n");
                            eprintln!("Error: ZFS change-key command failed");
                            eprintln!("Error: {}", &error);
                            exit(1)
                        }
                    };
                }
            } else {
                eprintln!("Dataset {} does not exist", dataset);
                eprintln!("Attempting to create a new one");

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
                    Err(error) => {
                        eprintln!("Error: Failed to run ZFS create command for {}", dataset);
                        eprintln!("{}", error);
                        exit(1)
                    }
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
                            eprintln!("Creating encrypted ZFS Dataset {} ... [OK]", dataset);
                        } else {
                            let mut e: Vec<u8> = Vec::new();
                            zfs.stderr
                                .expect("Failed to read stderr")
                                .read_to_end(&mut e)
                                .expect("Failed to read from stderr");
                            let error = String::from_utf8_lossy(&e);
                            eprintln!("Creating encrypted ZFS Dataset {} ... [FAIL]", &dataset);
                            eprintln!("Error: {}\n", error);
                        }
                    }
                    Err(error) => {
                        eprintln!("Error: ZFS create command failed");
                        eprintln!("Error: {}", &error);
                        exit(1)
                    }
                };
            }
        }
        Err(error) => {
            eprintln!("Error: Failed to run ZFS list command");
            eprintln!("Error: {}", error);
            exit(1)
        }
    };
}
