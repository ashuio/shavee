use std::io::prelude::*;
use std::process::Command;

pub fn zfs_mount(key: &String, dataset: String) {
    let mut dataset = dataset;
    if dataset.ends_with("/") {
        dataset.pop();
    };
    let mut zfs = Command::new("zfs") // Call zfs mount
        .arg("load-key")
        .arg("-L")
        .arg("prompt")
        .arg(&dataset)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("Failed zfs load-key");

    zfs.stdin // Supply encryption key via stdin
        .as_mut()
        .expect("failed to get zfs stdin")
        .write_all(&key.as_bytes())
        .expect("Failed to write to stdin");

    zfs.wait().expect("Failed to Load zfs key");

    let zfs_list = Command::new("zfs")
        .arg("list")
        .arg("-H")
        .arg("-o")
        .arg("name")
        .arg("-r")
        .arg(&dataset)
        .output()
        .expect("Failed to run list command");

    let out = String::from_utf8(zfs_list.stdout).expect("Failed to parse list output");

    let mut list: Vec<&str> = out.split("\n").collect();
    list.pop(); // Remove trailing blank element

    for i in list.into_iter() {
        let mut zfs_mount = Command::new("zfs")
            .arg("mount")
            .arg(&i)
            .spawn()
            .expect(format!("Failed to mount {}", &i).as_str());
        zfs_mount
            .wait()
            .expect(format!("Failed to mount {}", &i).as_str());
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
        .output()
        .expect("Failed to run list command");

    let out = String::from_utf8(zfs_list.stdout).expect("Failed to parse list output");

    let mut list: Vec<&str> = out.split("\n").collect();
    list.pop(); // Remove trailing blank element

    if list.len() > 0 {
        for i in list.into_iter() {
            let mut zfs_changekey = Command::new("zfs")
                .arg("change-key")
                .arg("-o")
                .arg("keylocation=prompt")
                .arg("-o")
                .arg("keyformat=passphrase")
                .arg(&i)
                .stdin(std::process::Stdio::piped())
                .spawn()
                .expect("Failed to change key");

            zfs_changekey
                .stdin // Supply encryption key via stdin
                .as_mut()
                .expect("failed to get zfs stdin")
                .write_all(&key.as_bytes())
                .expect("Failed to write to stdin");

            zfs_changekey.wait().expect("Failed to change zfs key");
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
            .spawn()
            .expect("Failed to create zfs dataset");

        zfs.stdin // Supply encryption key via stdin
            .as_mut()
            .expect("failed to get zfs stdin")
            .write_all(&key.as_bytes())
            .expect("Failed to write to stdin");

        zfs.wait().expect("Failed to create zfs dataset");
    }
}
