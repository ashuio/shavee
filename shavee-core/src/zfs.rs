use clap::crate_version;
use std::io::prelude::*;
use std::process::Command;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter};

use crate::structs::TwoFactorMode;
use crate::UNREACHABLE_CODE;

/// ZFS Properties used to store config
#[derive(Debug, Clone, PartialEq, Copy, EnumIter, Display)]
pub enum ZfsShaveeProperties {
    #[strum(serialize = "com.github.shavee:salt")]
    Salt,
    #[strum(serialize = "com.github.shavee:secondfactor")]
    SecondFactor,
    #[cfg(feature = "yubikey")]
    #[strum(serialize = "com.github.shavee:yubislot")]
    YubikeySlot,
    #[cfg(feature = "file")]
    #[strum(serialize = "com.github.shavee:filepath")]
    FilePath,
    #[cfg(feature = "file")]
    #[strum(serialize = "com.github.shavee:fileport")]
    FilePort,
    #[cfg(feature = "file")]
    #[strum(serialize = "com.github.shavee:filesize")]
    FileSize,
    #[strum(serialize = "com.github.shavee:version")]
    Version,
}

// ZFS Error Messages to ignore
const ZFS_ERROR_ALREADY_MOUNTED: &str = "filesystem already mounted";
const ZFS_ERROR_KEY_ALREADY_LOADED: &str = "Key already loaded";

pub struct DatasetProperty {
    property: ZfsShaveeProperties,
    value: Option<String>,
}

#[derive(Debug, PartialEq, Clone)]
/// Struct to store dataset
pub struct Dataset {
    dataset: String,
}

impl Dataset {
    /// Initialize the dataset
    /// first validate the correct ZFS naming requirements https://docs.oracle.com/cd/E26505_01/html/E37384/gbcpt.html
    pub fn new(dataset: String) -> Result<Self, std::io::Error> {
        crate::trace(&format!(
            "Validating the ZFS dataset name: \"{}\".",
            dataset
        ));
        let is_dataset_name_valid = dataset
            .chars()
            // only contain alphanumeric characters and - . : _
            .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | ':' | '.' | '/'));

        let does_name_start_alphanumeric = dataset
            .chars()
            //  must begin with an alphanumeric character
            .nth(0)
            .expect(crate::UNREACHABLE_CODE)
            .is_alphanumeric();

        // return error if the string is not a valid for dataset name
        if !(is_dataset_name_valid) || !(does_name_start_alphanumeric) {
            crate::trace("Name is invalid!");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ZFS Dataset name is not valid!",
            ));
        }
        crate::trace("Name is valid!");
        Ok(Self { dataset })
    }

    pub fn set_property_2fa(
        &self,
        args: crate::structs::TwoFactorMode,
        salt: &str,
    ) -> Result<(), std::io::Error> {
        let mut properties: Vec<DatasetProperty> = Vec::new();
        let prop_build: Vec<ZfsShaveeProperties> = ZfsShaveeProperties::iter().collect();

        #[cfg(feature = "file")]
        let mut filepath = String::from("-");
        #[cfg(feature = "file")]
        let mut fileport = String::from("-");
        #[cfg(feature = "file")]
        let mut filesize = String::from("-");
        #[cfg(feature = "yubikey")]
        let mut yubislot = String::from("-");

        let secondfactor = match args {
            #[cfg(feature = "yubikey")]
            TwoFactorMode::Yubikey { yslot } => {
                yubislot = String::from(yslot.to_string());
                String::from("Yubikey")
            }
            #[cfg(feature = "file")]
            TwoFactorMode::File { file, port, size } => {
                filepath = file;
                match port {
                    Some(s) => fileport = s.to_string(),
                    None => {}
                }
                match size {
                    Some(s) => filesize = s.to_string(),
                    None => {}
                }
                String::from("File")
            }
            TwoFactorMode::Password => String::from("Password"),
        };

        for p in prop_build {
            match p {
                ZfsShaveeProperties::Salt => properties.push(DatasetProperty {
                    property: p,
                    value: Some(salt.to_string()),
                }),
                ZfsShaveeProperties::SecondFactor => properties.push(DatasetProperty {
                    property: p,
                    value: Some(secondfactor.to_string()),
                }),
                #[cfg(feature = "yubikey")]
                ZfsShaveeProperties::YubikeySlot => properties.push(DatasetProperty {
                    property: p,
                    value: Some(yubislot.to_string()),
                }),
                #[cfg(feature = "file")]
                ZfsShaveeProperties::FilePath => properties.push(DatasetProperty {
                    property: p,
                    value: Some(filepath.to_string()),
                }),
                #[cfg(feature = "file")]
                ZfsShaveeProperties::FilePort => properties.push(DatasetProperty {
                    property: p,
                    value: Some(fileport.to_string()),
                }),
                #[cfg(feature = "file")]
                ZfsShaveeProperties::FileSize => properties.push(DatasetProperty {
                    property: p,
                    value: Some(filesize.to_string()),
                }),
                ZfsShaveeProperties::Version => properties.push(DatasetProperty {
                    property: p,
                    value: Some(crate_version!().to_string()),
                }),
            }
        }

        self.set_properties(properties)?;

        Ok(())
    }

    pub fn get_property_2fa(&self) -> Result<TwoFactorMode, std::io::Error> {
        let prop_build: Vec<ZfsShaveeProperties> = ZfsShaveeProperties::iter().collect();
        let input = self.get_properties(prop_build)?;

        #[cfg(feature = "file")]
        let mut filepath = String::new();
        #[cfg(feature = "file")]
        let mut fileport = String::new();
        #[cfg(feature = "file")]
        let mut filesize = String::new();
        let mut secondfactor = String::new();
        #[cfg(feature = "yubikey")]
        let mut yubislot = String::new();

        for i in input {
            match i.value {
                Some(s) => match i.property {
                    #[cfg(feature = "file")]
                    ZfsShaveeProperties::FilePath => {
                        filepath = s;
                    }
                    #[cfg(feature = "file")]
                    ZfsShaveeProperties::FilePort => {
                        fileport = s;
                    }
                    #[cfg(feature = "file")]
                    ZfsShaveeProperties::FileSize => {
                        filesize = s;
                    }
                    ZfsShaveeProperties::Salt => {}
                    ZfsShaveeProperties::SecondFactor => {
                        secondfactor = s;
                    }
                    ZfsShaveeProperties::Version => {}
                    #[cfg(feature = "yubikey")]
                    ZfsShaveeProperties::YubikeySlot => {
                        yubislot = s;
                    }
                },
                None => {}
            }
        }

        if secondfactor.as_str() == "Yubikey" {
            #[allow(unused_variables)]
            let result: Result<TwoFactorMode, std::io::Error> = Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Check Compiled Features",
            ));

            #[cfg(feature = "yubikey")]
            let out = TwoFactorMode::Yubikey {
                yslot: yubislot.parse::<u8>().expect("Invalid Yubikey Slot"),
            };
            #[cfg(feature = "yubikey")]
            let result = Ok(out);
            return result;
        } else if secondfactor.as_str() == "File" {
            #[cfg(feature = "file")]
            let mut port = None;
            #[cfg(feature = "file")]
            let mut size = None;

            #[cfg(feature = "file")]
            if !fileport.is_empty() {
                port = Some(fileport.parse::<u16>().expect("Invalid Port"));
            }

            #[cfg(feature = "file")]
            if !filesize.is_empty() {
                size = Some(filesize.parse::<u64>().expect("Invalid File Size"));
            }

            #[allow(unused_variables)]
            let result: Result<TwoFactorMode, std::io::Error> = Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Check enabled features",
            ));

            #[cfg(feature = "file")]
            let result = Ok(TwoFactorMode::File {
                file: filepath,
                port: port,
                size: size,
            });

            return result;
        } else if secondfactor.as_str() == "Password" {
            return Ok(TwoFactorMode::Password);
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Unknown Property Value".to_string(),
            ));
        }
    }

    // Convert the Dataset name to String
    pub fn to_string(&self) -> String {
        crate::trace(&format!(
            "Extracting the dataset's name: \"{}\".",
            self.dataset
        ));
        self.dataset.to_owned()
    }

    /// loads the encryption key
    pub fn loadkey(&self, passphrase: &str) -> Result<Self, std::io::Error> {
        crate::trace(&format!(
            "Loading the passphrase for the \"{}\" ZFS dataset.",
            self.dataset
        ));
        let mut zfs = Command::new("zfs") // Call zfs mount
            .arg("load-key")
            .arg("-L")
            .arg("prompt")
            .arg(&self.dataset)
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        crate::trace("Executing the ZFS load-key command!");
        let zstdin = zfs
            .stdin // Supply encryption key via stdin
            .as_mut()
            .ok_or(std::io::Error::new(
                //convert None to an error
                std::io::ErrorKind::BrokenPipe,
                "Failed to lock stdin!",
            ))?;

        zstdin.write_all(&passphrase.as_bytes())?;

        let result = zfs.wait_with_output()?;

        if !result.status.success() {
            let resulterr = String::from_utf8(result.stderr.clone()).expect(UNREACHABLE_CODE);
            if resulterr.find(ZFS_ERROR_KEY_ALREADY_LOADED).is_some() {
                return Ok(self.clone());
            } else {
                crate::error("Command failed!");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    String::from_utf8(result.stderr).expect(crate::UNREACHABLE_CODE),
                ));
            }
        }

        Ok(self.clone())
    }

    /// creates an encrypted ZFS dataset with passphrase
    pub fn create(&self, passphrase: &str) -> Result<(), std::io::Error> {
        crate::trace("Create the ZFS dataset.\tCheck if it already exists.");
        // check if dataset already exists
        match Dataset::list(&self) {
            // if it exists, then only change password
            Ok(list_datasets) => {
                crate::trace("Dataset already exists, only change passphrase.");
                let dataset = list_datasets[0].clone(); // Only use the first element
                let mut zfs_changekey = Command::new("zfs")
                    .arg("change-key")
                    .arg("-o")
                    .arg("keylocation=prompt")
                    .arg("-o")
                    .arg("keyformat=passphrase")
                    .arg(&dataset.dataset)
                    .stdin(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?;

                crate::trace("Executing the ZFS change-key commend!");

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

                zstdin.write_all(&passphrase.as_bytes())?;

                // capture the error message and pass it to the calling function
                let result = zfs_changekey.wait_with_output()?;
                if !result.status.success() {
                    crate::error("Command failed!");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        String::from_utf8(result.stderr).expect(crate::UNREACHABLE_CODE),
                    ));
                }
            }
            // if dataset doesn't exists then create it
            Err(_) => {
                crate::trace("Dataset doesn't exist. Creating it.");
                let mut zfs = Command::new("zfs") // Call zfs create
                    .arg("create")
                    .arg("-o")
                    .arg("encryption=on")
                    .arg("-o")
                    .arg("keyformat=passphrase")
                    .arg("-o")
                    .arg("keylocation=prompt")
                    .arg(&self.dataset)
                    .stdin(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?;

                crate::trace("Executing the ZFS create commend!");

                zfs.stdin // Supply encryption key via stdin
                    .as_mut()
                    .expect("failed to get zfs stdin!")
                    .write_all(&passphrase.as_bytes())
                    .expect("Failed to write to stdin!");

                let result = zfs.wait_with_output()?;

                if !result.status.success() {
                    crate::error("Command failed!");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        String::from_utf8(result.stderr).expect(crate::UNREACHABLE_CODE),
                    ));
                }
            }
        };
        crate::trace("ZFS create was executed successfully!");
        Ok(())
    }

    /// Generates a list of ZFS datasets
    pub fn list(&self) -> Result<Vec<Dataset>, std::io::Error> {
        crate::trace("Generating a list with a given name of a ZFS dataset.");
        let zfs_list = Command::new("zfs")
            .arg("list")
            .arg("-H")
            .arg("-o")
            .arg("name")
            .arg("-r")
            .arg(&self.dataset)
            .output()?;

        if !zfs_list.status.success() {
            crate::error("Command failed!");
            return Err(std::io::Error::new(
                // error kind is not known
                std::io::ErrorKind::Other,
                //stderr used to generate the error message.
                String::from_utf8_lossy(&zfs_list.stderr).to_string(),
            ));
        };

        let out = String::from_utf8(zfs_list.stdout).map_err(|error| {
            crate::trace("Unknown input!");
            std::io::Error::new(
                // error kind is not known
                std::io::ErrorKind::InvalidInput,
                error,
            )
        })?;

        // cast the list into a vector of Datasets
        Ok(out
            .split_whitespace()
            .map(|s| Dataset {
                dataset: s.to_string(),
            })
            .collect())
    }

    /// read ZFS dataset property and return it as Some().
    /// If the dataset property is empty "-" then returns None.
    /// Otherwise, it returns the error
    pub fn get_property(&self, dataset_property: String) -> Result<Option<String>, std::io::Error> {
        crate::trace("Getting the ZFS dataset property.");
        let mut zfs_get_property = Command::new("zfs")
            .arg("get")
            .arg("-H")
            .arg("-o")
            .arg("value")
            .arg(&dataset_property)
            .arg(&self.dataset)
            .output()?;

        if !zfs_get_property.status.success() {
            crate::error("Command failed!");
            return Err(std::io::Error::new(
                // error kind is not known
                std::io::ErrorKind::Other,
                //stderr used to generate the error message.
                String::from_utf8_lossy(&zfs_get_property.stderr).to_string(),
            ));
        }

        // remove the \n (newline) character at the end of the output
        let output_len = zfs_get_property.stdout.len().saturating_sub("\n".len());
        zfs_get_property.stdout.truncate(output_len);

        let output = String::from_utf8(zfs_get_property.stdout).map_err(|error| {
            std::io::Error::new(
                // error kind is not known
                std::io::ErrorKind::InvalidInput,
                error,
            )
        })?;

        crate::trace(&format!(
            "ZFS \"{}\" dataset property \"{}\" is \"{}\"!",
            &self.dataset, &dataset_property, output
        ));

        // checks for empty value and returns None
        if output == "-" {
            Ok(None)
        } else {
            Ok(Some(output))
        }
    }

    pub fn get_properties(
        &self,
        dataset_property: Vec<ZfsShaveeProperties>,
    ) -> Result<Vec<DatasetProperty>, std::io::Error> {
        crate::trace("Getting the ZFS dataset property.");
        let mut cmd: Vec<String> = Vec::new();

        let input = dataset_property.clone();

        for i in input {
            cmd.push(i.to_string());
        }

        let input = cmd.join(",");
        let mut zfs_get_property = Command::new("zfs")
            .arg("get")
            .arg("-H")
            .arg("-o")
            .arg("value")
            .arg("-p")
            .arg(&input)
            .arg(&self.dataset)
            .output()?;

        if !zfs_get_property.status.success() {
            crate::error("Command failed!");
            return Err(std::io::Error::new(
                // error kind is not known
                std::io::ErrorKind::Other,
                //stderr used to generate the error message.
                String::from_utf8_lossy(&zfs_get_property.stderr).to_string(),
            ));
        }

        // remove the \n (newline) character at the end of the output
        let output_len = zfs_get_property.stdout.len().saturating_sub("\n".len());
        zfs_get_property.stdout.truncate(output_len);

        let output = String::from_utf8(zfs_get_property.stdout).map_err(|error| {
            std::io::Error::new(
                // error kind is not known
                std::io::ErrorKind::InvalidInput,
                error,
            )
        })?;

        let mut out: Vec<Option<String>> =
            output.split('\n').map(|s| Some(s.to_string())).collect();

        for i in out.iter_mut() {
            match i {
                Some(s) => {
                    if s.starts_with("-") {
                        *i = None
                    }
                }
                None => {}
            }
        }
        let mut output: Vec<DatasetProperty> = Vec::new();
        let out = dataset_property.into_iter().zip(out.into_iter());

        for i in out {
            output.push(DatasetProperty {
                property: i.0,
                value: i.1,
            })
        }

        Ok(output)
    }

    /// Set ZFS dataset property

    pub fn set_properties(&self, properties: Vec<DatasetProperty>) -> Result<(), std::io::Error> {
        crate::trace("Setting the ZFS dataset property.");
        let mut command: Vec<String> = Vec::new();

        for i in properties {
            match i.value {
                Some(s) => {
                    command.push(format!("{}={}", i.property.to_string(), s));
                }
                None => {}
            }
        }

        let mut zfs_set_property = Command::new("zfs");
        zfs_set_property.arg("set");
        for c in command {
            zfs_set_property.arg(c);
        }

        let result = zfs_set_property.arg(&self.dataset).output()?;

        if !result.status.success() {
            crate::error("Command failed!");
            return Err(std::io::Error::new(
                // error kind is not known
                std::io::ErrorKind::Other,
                //stderr used to generate the error message.
                String::from_utf8_lossy(&result.stderr).to_string(),
            ));
        }
        Ok(())
    }

    pub fn set_property(
        &self,
        dataset_property: String,
        dataset_property_value: &str,
    ) -> Result<(), std::io::Error> {
        crate::trace("Setting the ZFS dataset property.");
        let mut dataset_property_eq_value = dataset_property.clone();
        // Concat to generate <property>=<value>
        dataset_property_eq_value.push_str("=");
        dataset_property_eq_value.push_str(dataset_property_value);
        let zfs_set_property = Command::new("zfs")
            .arg("set")
            .arg(dataset_property_eq_value)
            .arg(&self.dataset)
            .output()?;

        if !zfs_set_property.status.success() {
            crate::error("Command failed!");
            return Err(std::io::Error::new(
                // error kind is not known
                std::io::ErrorKind::Other,
                //stderr used to generate the error message.
                String::from_utf8_lossy(&zfs_set_property.stderr).to_string(),
            ));
        }
        Ok(())
    }

    /// Mounts the dataset
    pub fn mount(&self) -> Result<(), std::io::Error> {
        let output = Command::new("zfs")
            .arg("mount")
            .arg(&self.dataset)
            .output()?;

        if !output.status.success() {
            let errormsg = String::from_utf8(output.stderr.clone()).expect(UNREACHABLE_CODE);
            if errormsg.find(ZFS_ERROR_ALREADY_MOUNTED).is_some() {
                return Ok(());
            } else {
                crate::error("Command failed!");
                return Err(std::io::Error::new(
                    // error kind is not known
                    std::io::ErrorKind::Other,
                    //stderr used to generate the error message.
                    String::from_utf8_lossy(&output.stderr).to_string(),
                ));
            }
        };

        Ok(())
    }

    /// Unmount the dataset
    pub fn umount(&self) -> Result<Self, std::io::Error> {
        Dataset::simple_subcommand(self, "umount")
    }

    /// unloads the encryption key
    pub fn unloadkey(&self) -> Result<Self, std::io::Error> {
        Dataset::simple_subcommand(self, "unload-key")
    }

    pub fn unloadkeys(&self) -> Result<Self, std::io::Error> {
        let command_output = Command::new("zfs")
        .arg("unload-key")
        .arg("-r")
        .arg(&self.dataset)
        .output()?;

        if !command_output.status.success() {
            crate::error("Command failed!");
            return Err(std::io::Error::new(
                // error kind is not known
                std::io::ErrorKind::Other,
                //stderr used to generate the error message.
                String::from_utf8_lossy(&command_output.stderr).to_string(),
            ));
        };
        Ok(self.to_owned())
    }

    fn simple_subcommand(&self, subcommand: &str) -> Result<Self, std::io::Error> {
        crate::trace(&format!("Executing ZFS \"{}\" command.", subcommand));
        let command_output = Command::new("zfs")
            .arg(subcommand)
            .arg(&self.dataset)
            .output()?;
        if !command_output.status.success() {
            crate::error("Command failed!");
            return Err(std::io::Error::new(
                // error kind is not known
                std::io::ErrorKind::Other,
                //stderr used to generate the error message.
                String::from_utf8_lossy(&command_output.stderr).to_string(),
            ));
        };
        Ok(self.to_owned())
    }
}

pub fn resolve_recursive(datasets: Vec<Dataset>) -> Result<Vec<Dataset>, std::io::Error> {
    let mut sets: Vec<Dataset> = Vec::new();

    for set in datasets {
        let a = set.list()?;
        for d in a {
            sets.push(d.clone());
        }
    }
    Ok(sets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn zfs_to_string_test() {
        crate::trace_init(false);
        crate::trace("Checking for dataset to string conversaion:");
        let dataset_name = String::from("dataset/test");
        let dataset_struct = Dataset::new(dataset_name.clone()).unwrap();

        assert_eq!(dataset_name, dataset_struct.to_string());
    }

    #[test]
    fn zfs_name_validation() {
        crate::trace_init(false);

        crate::trace("Checking for invalid names:");
        // check for invalid names
        let invalid_names = [
            String::from("_invalid"),
            String::from("-invalid"),
            String::from(":invalid"),
            String::from(".invalid"),
            String::from("inva%lid"),
        ];
        for invalid_name in invalid_names {
            let error = Dataset::new(invalid_name).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }

        crate::trace("Checking for valid names:");
        // check for valid names
        let valid_names = [
            String::from("valid"),
            String::from("v8lid"),
            String::from("val:id"),
            String::from("val.id"),
            String::from("Val1d"),
            String::from("Val1d/data5et"),
        ];
        for valid_name in valid_names {
            let zfs_dataset = Dataset::new(valid_name.clone()).unwrap();
            assert_eq!(
                zfs_dataset,
                Dataset {
                    dataset: valid_name
                }
            );
        }
    }

    #[test]
    fn zfs_set_get_property_test() {
        crate::trace_init(false);
        // This test will only run if there is root permission
        if !nix::unistd::Uid::effective().is_root() {
            eprintln!("This test needs root permission. Terminating early!");
            return;
        }

        // generate a temp zpool
        let (zpool_name, temp_folder) = prepare_zpool();
        // b/c of zpool creation process, the dataset name is the same as zpool
        let zfs_dataset = Dataset {
            dataset: zpool_name.clone(),
        };

        // NOTE: the output will be evaluated **AFTER** clean up so the temp folder and
        // temp zpool can safely be removed.

        // **Test 1**: set property
        let test_set_property_output =
            zfs_dataset.set_property(String::from("com.github.shavee:unit_test"), "value_set");

        // **Test 2**: get property with value
        let test_get_property_output =
            zfs_dataset.get_property(String::from("com.github.shavee:unit_test"));

        // **Test 3**: get an empty property
        let test_get_empty_property_output =
            zfs_dataset.get_property(String::from("not.set:property"));

        //clean up
        cleanup_zpool(&zpool_name, temp_folder);

        // **Test 1**
        // test the output against expected result.
        test_set_property_output.expect("set_property(): Dataset set property failed!");

        // **Test 2**
        // test the output against expected result.
        assert_eq!(
            test_get_property_output.unwrap(),
            Some(String::from("value_set"))
        );

        // **Test 3**
        // test the output against expected result.
        assert_eq!(test_get_empty_property_output.unwrap(), None);
    }

    #[test]
    fn zfs_mount_umount_test() {
        crate::trace_init(false);
        // This test will only run if there is root permission
        if !nix::unistd::Uid::effective().is_root() {
            eprintln!("This test needs root permission. Terminating early!");
            return;
        }

        // generate a temp zpool
        let (zpool_name, temp_folder) = prepare_zpool();
        // b/c of zpool creation process, the dataset name is the same as zpool
        let zfs_dataset = Dataset {
            dataset: zpool_name.clone(),
        };

        // NOTE: the output will be evaluated **AFTER** clean up so the temp folder and
        // temp zpool can safely be removed.

        // **Test 1**: umount a dataset
        let test_umount_output = zfs_dataset.umount();

        // **Test 2**: umount an already unmounted dataset
        // This test is expected to fail!
        let test_already_unmounted_dataset_output = zfs_dataset.umount();

        // **Test 3**: mount an unmounted dataset
        let test_mount_output = zfs_dataset.mount();

        // **Test 4**: mount an already mounted dataset
        // This test is expected to fail!
        let test_already_mount_again_output = zfs_dataset.mount();

        //clean up
        cleanup_zpool(&zpool_name, temp_folder);

        // **Test 1**
        // test the output against expected result.
        test_umount_output.expect("umount(): Dataset umount failed!");

        // **Test 2** Expected to fail
        match test_already_unmounted_dataset_output {
            Ok(_) => panic!("umount() on an already unmounted dataset failed!"),
            Err(error) => assert_eq!(
                format!(
                    "cannot unmount '{}': not currently mounted\n",
                    zfs_dataset.dataset
                ),
                error.to_string()
            ),
        }

        // **Test 3**
        // test the output against expected result.
        test_mount_output.expect("mount(): Dataset mount failed!");

        // **Test 4** Expected to fail
        match test_already_mount_again_output {
            Ok(_) => panic!("mount() on an already mounted dataset failed!"),
            Err(error) => assert_eq!(
                format!(
                    "cannot mount '{}': filesystem already mounted\n",
                    zfs_dataset.dataset
                ),
                error.to_string()
            ),
        }
    }

    #[test]
    fn zfs_list_test() {
        crate::trace_init(false);
        // This test will only run if there is root permission
        if !nix::unistd::Uid::effective().is_root() {
            eprintln!("This test needs root permission. Terminating early!");
            return;
        }

        // generate a temp zpool
        let (zpool_name, temp_folder) = prepare_zpool();
        // b/c of zpool creation process, the dataset name is the same as zpool
        let zfs_dataset = Dataset {
            dataset: zpool_name.clone(),
        };

        // NOTE: the output will be evaluated **AFTER** clean up so the temp folder and
        // temp zpool can safely be removed.

        let test_output = zfs_dataset.list();

        //clean up
        cleanup_zpool(&zpool_name, temp_folder);

        // test the output against expected result.
        match test_output {
            Ok(result) => assert_eq!(
                result,
                vec![Dataset {
                    dataset: zpool_name
                }]
            ),
            Err(error) => panic!("list(): Test failed: {:?}", error),
        }
    }

    #[test]
    fn zfs_create_load_unload_key_test() {
        crate::trace_init(false);
        // This test will only run if there is root permission
        if !nix::unistd::Uid::effective().is_root() {
            eprintln!("This test needs root permission. Terminating early!");
            return;
        }

        // generate a temp zpool
        let (zpool_name, temp_folder) = prepare_zpool();

        // b/c of zpool creation process, the dataset name is the same as zpool
        let zfs_plan_dataset = Dataset {
            dataset: zpool_name.clone(),
        };

        // NOTE: the output will be evaluated **AFTER** clean up so the temp folder and
        // temp zpool can safely be removed.

        // **TEST 1**: create() on a dataset that is not encrypted
        // This test is expected to fail!
        let test_dataset_not_encrypted_must_fail_output =
            zfs_plan_dataset.create(&random_string(3));

        // **TEST 2**: create() a new encrypted dataset
        let mut zpool_with_dataset = zpool_name.to_owned();
        zpool_with_dataset.push('/');
        zpool_with_dataset.push_str(&random_string(3));
        let zfs_encrypted_dataset = Dataset {
            dataset: zpool_with_dataset,
        };
        let test_create_new_encrypted_dataset_output =
            zfs_encrypted_dataset.create(&random_string(8)); // min accepted key is 8 character

        // **TEST 3**: create() on an already encrypted dataset with a known passphrase
        // ZFS min accepted passphrase is 8 character
        let passphrase = random_string(8);
        let test_already_encrypted_dataset_output = zfs_encrypted_dataset.create(&passphrase);

        // **Test 4**: unloadkey() on a mounted dataset
        // This test is expected to fail!
        let test_unload_key_mounted_dataset_output = zfs_encrypted_dataset.unloadkey();

        // **Test 5**: unloadkey() on a unmounted dataset
        zfs_encrypted_dataset
            .umount()
            .expect("Test terminated unexpectedly early!");
        let test_unload_key_unmounted_dataset_output = zfs_encrypted_dataset.unloadkey();

        // **Test 6**: loadkey() on a unmounted dataset
        let test_load_key_unmounted_dataset_output = zfs_encrypted_dataset.loadkey(&passphrase);

        //clean up
        cleanup_zpool(&zpool_name, temp_folder);

        // now it is time to test the outputs against expected results.

        // **TEST 1**: create() on a dataset that is not encrypted
        match test_dataset_not_encrypted_must_fail_output {
            Ok(_) => panic!("create(): Set a new passphrase on an unencrypted dataset failed!"),
            Err(error) => assert_eq!(
                "Key change error: Dataset not encrypted.\n",
                error.to_string()
            ),
        }

        // **TEST 2**: create() a new encrypted dataset
        test_create_new_encrypted_dataset_output
            .expect("create(): Create new encrypted dataset failed!");

        // **TEST 3**: create() on an already encrypted dataset
        test_already_encrypted_dataset_output
            .expect("create(): Set a new passphrase on an encrypted dataset failed!");

        // **Test 4**: unloadkey() on a mounted dataset
        match test_unload_key_mounted_dataset_output {
            Ok(_) => panic!("unloadkey() on a mounted dataset failed!"),
            Err(error) => assert_eq!(
                format!(
                    "Key unload error: '{}' is busy.\n",
                    zfs_encrypted_dataset.dataset
                ),
                error.to_string()
            ),
        }

        // **Test 5**: unloadkey() on a unmounted dataset
        test_unload_key_unmounted_dataset_output.expect("unloadkey() failed!");

        // **Test 6**: zfs_loadkey() on a unmounted dataset
        test_load_key_unmounted_dataset_output.expect("loadkey() failed!");
    }

    //These tests checks for a reported error on non-existing dataset

    #[test]
    fn dataset_does_not_exists_test() {
        crate::trace_init(false);
        let zfs_version = Command::new("zpool").arg("version").spawn();
        match zfs_version {
            // Check for ZFS tools and exit early
            // This test will only run if the ZFS is installed
            Err(_) => {
                eprintln!("ZFS and ZPOOL tools must be installed. This test terminated early!");
                return;
            }
            Ok(_) => {
                // use a random name for dataset to assure it doesn't already exists!
                let zfs_dataset = Dataset {
                    dataset: random_string(30),
                };
                let expected_error = format!(
                    "cannot open '{}': dataset does not exist\n",
                    zfs_dataset.dataset
                );

                // test all functions in a separate assert_eq
                assert_eq!(
                    zfs_dataset
                        .loadkey(&"passkey_not_important".to_string())
                        .unwrap_err()
                        .to_string(),
                    expected_error
                );

                assert_eq!(zfs_dataset.list().unwrap_err().to_string(), expected_error);

                // NOTE: this test doesn't apply to zfs_create

                assert_eq!(zfs_dataset.mount().unwrap_err().to_string(), expected_error);

                assert_eq!(
                    zfs_dataset.umount().unwrap_err().to_string(),
                    expected_error
                );

                assert_eq!(
                    zfs_dataset.unloadkey().unwrap_err().to_string(),
                    expected_error
                );
            }
        }
    }

    /* In this this section the supporting functions that are needed for
     * unit tests are implemented. */

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
            .arg(&zpool_path)
            .spawn()
            .expect("Cannot generate a temp file. Test terminated early!");

        // create a new temporarily zpool using vdev
        let command_output = Command::new("zpool")
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
    fn cleanup_zpool(zpool_name: &str, temp_folder: PathBuf) {
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
