use std::io::prelude::*;
use std::process::{exit, Command};

pub fn zfs_mount(key: &String, dataset: String) {
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
            if !res.success() {
                eprintln!("Error: Failed to load encryption key for {}", dataset);
            }
        }
        Err(error) => {
            eprintln!("Error: ZFS load-key command failed");
            eprintln!("Error: {}", &error);
            exit(1)
        }
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
                eprintln!("Error: Failed to get ZFS Dataset list");
                eprintln!("Error: Is it valid?");
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
    let out = match out {
        Ok(o) => o,
        Err(error) => {
            eprintln!("Error: Failed to parse zfs list output");
            eprintln!("Error: {}",error);
            exit(1)
        }
    };
    let mut list: Vec<&str> = out.split("\n").collect();
    list.pop(); // Remove trailing blank element

    for i in list.into_iter() {
        let zfs_mount = Command::new("zfs").arg("mount").arg(&i).spawn();

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
                if !res.success() {
                    eprintln!("Error: Failed to mount {}", i);
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

    let zfs_list = match zfs_list {
        Ok(z) => {
            if z.status.success() {
                z
            } else {
                eprintln!("Error: Failed to get ZFS Dataset list");
                eprintln!("Error: Is it valid?");
                exit(1)
            }
        }
        Err(error) => {
            eprintln!("Error: Failed to run ZFS list command");
            eprintln!("Error: {}", error);
            exit(1)
        }
    };

    let out = String::from_utf8(zfs_list.stdout).expect("Failed to parse list output");
    
    let mut list: Vec<&str> = out.split("\n").collect();
    list.pop(); // Remove trailing blank element

    if list.len() > 0 {
        for i in list.into_iter() {
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
                    if !res.success() {
                        eprintln!("Error: Failed to change key for {}", dataset);
                    }
                }
                Err(error) => {
                    eprintln!("Error: ZFS change-key command failed");
                    eprintln!("Error: {}", &error);
                    exit(1)
                }
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
                if !res.success() {
                    eprintln!("Error: Failed to create encrypted dataset {}", dataset);   
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
