//! ZFS interactions for encryption management.
//!
//! This module provides tools to interact with ZFS datasets, including setting/getting properties,
//! mounting/unmounting, and creating new datasets with encryption.
//! It executes ZFS commands via `std::process::Command`.

use crate::{Error, Result};
use clap::crate_version;
use std::fmt;
use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter};

/// ZFS Properties used to store Shavee configuration.
/// These properties are stored on the dataset itself.
#[derive(Debug, Clone, PartialEq, Copy, EnumIter, Display)]
pub enum ZfsShaveeProperties {
    /// The salt used for key derivation (stored as base64).
    #[strum(serialize = "com.github.shavee:salt")]
    Salt,
    /// The second factor method used (Password, Yubikey, or File).
    #[strum(serialize = "com.github.shavee:secondfactor")]
    SecondFactor,
    /// The Yubikey HMAC slot (1 or 2).
    #[cfg(feature = "yubikey")]
    #[strum(serialize = "com.github.shavee:yubislot")]
    YubikeySlot,
    /// The Yubikey serial number.
    #[strum(serialize = "com.github.shavee:yubikeyserial")]
    YubikeySerial,
    /// Path to the key file (for File 2FA).
    #[cfg(feature = "file")]
    #[strum(serialize = "com.github.shavee:filepath")]
    FilePath,
    /// Port for remote key files.
    #[cfg(feature = "file")]
    #[strum(serialize = "com.github.shavee:fileport")]
    FilePort,
    /// Maximum bytes to read from the key file.
    #[cfg(feature = "file")]
    #[strum(serialize = "com.github.shavee:filesize")]
    FileSize,
    /// Shavee version used to create/update the dataset.
    #[strum(serialize = "com.github.shavee:version")]
    Version,
}

/// ZFS error messages that can be safely ignored under certain conditions.
const ZFS_ERROR_ALREADY_MOUNTED: &str = "filesystem already mounted";
const ZFS_ERROR_KEY_ALREADY_LOADED: &str = "Key already loaded";

/// A representation of a ZFS dataset.
#[derive(Debug, PartialEq, Clone)]
pub struct Dataset {
    name: String,
}

impl fmt::Display for Dataset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Dataset {
    /// Initializes a new Dataset instance after validating its name.
    ///
    /// # Arguments
    /// * `name` - The full path of the ZFS dataset (e.g., "zpool/home/user").
    pub fn new(name: String) -> Result<Self> {
        crate::trace(&format!("Validating ZFS dataset name: \"{}\"", name));

        // Check if characters are allowed in ZFS dataset names
        let is_valid_char =
            |c: char| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | ':' | '.' | '/');

        if name.is_empty()
            || !name.chars().all(is_valid_char)
            || !name.chars().next().map_or(false, |c| c.is_alphanumeric())
        {
            return Err(Error::InvalidInput(format!(
                "Invalid ZFS dataset name: {}",
                name
            )));
        }

        Ok(Self { name })
    }

    /// Returns the name of the dataset.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Sets multiple Shavee configuration properties on the ZFS dataset at once.
    ///
    /// # Arguments
    /// * `mode` - The 2FA mode configuration to store.
    /// * `salt` - The base64-encoded salt string.
    pub fn set_properties_2fa(
        &self,
        mode: crate::structs::TwoFactorMode,
        salt: &str,
    ) -> Result<()> {
        crate::trace(&format!(
            "Setting Shavee properties for dataset: {}",
            self.name
        ));

        // Iterate through all possible Shavee properties and set relevant ones
        for property in ZfsShaveeProperties::iter() {
            let value = match property {
                ZfsShaveeProperties::Salt => Some(salt.to_string()),
                ZfsShaveeProperties::Version => Some(crate_version!().to_string()),
                ZfsShaveeProperties::SecondFactor => match mode {
                    #[cfg(feature = "yubikey")]
                    crate::structs::TwoFactorMode::Yubikey { .. } => Some("Yubikey".to_string()),
                    #[cfg(feature = "file")]
                    crate::structs::TwoFactorMode::File { .. } => Some("File".to_string()),
                    crate::structs::TwoFactorMode::Password => Some("Password".to_string()),
                },
                ZfsShaveeProperties::YubikeySerial => {
                    if let crate::structs::TwoFactorMode::Yubikey {
                        serial: Some(s), ..
                    } = mode
                    {
                        Some(s.to_string())
                    } else {
                        None
                    }
                }
                ZfsShaveeProperties::YubikeySlot => {
                    if let crate::structs::TwoFactorMode::Yubikey { yslot: Some(s), .. } = mode {
                        Some(s.to_string())
                    } else {
                        None
                    }
                }
                ZfsShaveeProperties::FilePath => {
                    if let crate::structs::TwoFactorMode::File { file: ref f, .. } = mode {
                        Some(f.clone())
                    } else {
                        None
                    }
                }
                ZfsShaveeProperties::FilePort => {
                    if let crate::structs::TwoFactorMode::File { port: Some(p), .. } = mode {
                        Some(p.to_string())
                    } else {
                        None
                    }
                }
                ZfsShaveeProperties::FileSize => {
                    if let crate::structs::TwoFactorMode::File { size: Some(s), .. } = mode {
                        Some(s.to_string())
                    } else {
                        None
                    }
                }
            };

            if let Some(val) = value {
                self.set_property(&property.to_string(), &val)?;
            }
        }
        Ok(())
    }

    /// Reconstructs the `TwoFactorMode` by reading Shavee properties from the ZFS dataset.
    /// Used for auto-detecting how to unlock a dataset.
    pub fn get_property_2fa(&self) -> Result<crate::structs::TwoFactorMode> {
        let second_factor = self
            .get_property(&ZfsShaveeProperties::SecondFactor.to_string())?
            .ok_or_else(|| {
                Error::Zfs(format!("Missing second factor property on {}", self.name))
            })?;

        match second_factor.as_str() {
            #[cfg(feature = "yubikey")]
            "Yubikey" => {
                let yslot = self
                    .get_property(&ZfsShaveeProperties::YubikeySlot.to_string())?
                    .and_then(|s| s.parse::<u8>().ok());
                let serial = self
                    .get_property(&ZfsShaveeProperties::YubikeySerial.to_string())?
                    .and_then(|s| s.parse::<u32>().ok());
                Ok(crate::structs::TwoFactorMode::Yubikey { yslot, serial })
            }
            #[cfg(feature = "file")]
            "File" => {
                let file = self
                    .get_property(&ZfsShaveeProperties::FilePath.to_string())?
                    .ok_or_else(|| {
                        Error::Zfs(format!("Missing file path property on {}", self.name))
                    })?;
                let port = self
                    .get_property(&ZfsShaveeProperties::FilePort.to_string())?
                    .and_then(|s| s.parse::<u16>().ok());
                let size = self
                    .get_property(&ZfsShaveeProperties::FileSize.to_string())?
                    .and_then(|s| s.parse::<u64>().ok());
                Ok(crate::structs::TwoFactorMode::File { file, port, size })
            }
            "Password" => Ok(crate::structs::TwoFactorMode::Password),
            _ => Err(Error::Zfs(format!(
                "Unknown second factor mode: {}",
                second_factor
            ))),
        }
    }

    /// Sets a single ZFS property on the dataset.
    pub fn set_property(&self, property: &str, value: &str) -> Result<()> {
        let status = Command::new("zfs")
            .args(["set", &format!("{}={}", property, value), &self.name])
            .status()?;

        if !status.success() {
            return Err(Error::Zfs(format!(
                "Failed to set property {} on {}",
                property, self.name
            )));
        }
        Ok(())
    }

    /// Retrieves a single ZFS property value from the dataset.
    /// Returns `Ok(None)` if the property doesn't exist or is empty.
    pub fn get_property(&self, property: &str) -> Result<Option<String>> {
        let output = Command::new("zfs")
            .args(["get", "-H", "-o", "value", property, &self.name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("dataset does not exist") || stderr.contains("invalid property") {
                return Ok(None);
            }
            return Err(Error::Zfs(format!(
                "Failed to get property {}: {}",
                property, stderr
            )));
        }

        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if value == "-" || value.is_empty() {
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }

    /// Loads the encryption key for this dataset.
    /// Passphrase is provided via stdin.
    pub fn load_key(&self, passphrase: &str) -> Result<()> {
        let mut child = Command::new("zfs")
            .args(["load-key", &self.name])
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        // Pipe the passphrase to the command's stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(passphrase.as_bytes())?;
            stdin.write_all(b"\n")?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore if key is already loaded
            if !stderr.contains(ZFS_ERROR_KEY_ALREADY_LOADED) {
                return Err(Error::Zfs(format!(
                    "Failed to load key for {}: {}",
                    self.name, stderr
                )));
            }
        }
        Ok(())
    }

    /// Unloads the encryption key for this dataset.
    ///
    /// # Arguments
    /// * `recursive` - If true, unloads keys for all child datasets as well.
    pub fn unload_key(&self, recursive: bool) -> Result<()> {
        let mut cmd = Command::new("zfs");
        cmd.arg("unload-key");
        if recursive {
            cmd.arg("-r");
        }
        let status = cmd.arg(&self.name).status()?;

        if !status.success() {
            return Err(Error::Zfs(format!(
                "Failed to unload key for {}",
                self.name
            )));
        }
        Ok(())
    }

    /// Mounts the ZFS dataset.
    pub fn mount(&self) -> Result<()> {
        let output = Command::new("zfs").args(["mount", &self.name]).output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore if already mounted
            if !stderr.contains(ZFS_ERROR_ALREADY_MOUNTED) {
                return Err(Error::Zfs(format!(
                    "Failed to mount {}: {}",
                    self.name, stderr
                )));
            }
        }
        Ok(())
    }

    /// Unmounts the ZFS dataset.
    pub fn unmount(&self) -> Result<()> {
        let status = Command::new("zfs").args(["unmount", &self.name]).status()?;

        if !status.success() {
            return Err(Error::Zfs(format!("Failed to unmount {}", self.name)));
        }
        Ok(())
    }

    /// Creates a new encrypted dataset or updates the encryption key of an existing one.
    pub fn create(&self, passphrase: &str) -> Result<()> {
        match self.exists()? {
            true => {
                crate::trace("Dataset exists, updating encryption key");
                let mut child = Command::new("zfs")
                    .args([
                        "change-key",
                        "-o",
                        "keylocation=prompt",
                        "-o",
                        "keyformat=passphrase",
                        &self.name,
                    ])
                    .stdin(std::process::Stdio::piped())
                    .spawn()?;

                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(passphrase.as_bytes())?;
                    stdin.write_all(b"\n")?;
                }

                if !child.wait()?.success() {
                    return Err(Error::Zfs(format!(
                        "Failed to update key for {}",
                        self.name
                    )));
                }
            }
            false => {
                crate::trace("Dataset does not exist, creating new encrypted dataset");
                let mut child = Command::new("zfs")
                    .args([
                        "create",
                        "-o",
                        "encryption=on",
                        "-o",
                        "keyformat=passphrase",
                        "-o",
                        "keylocation=prompt",
                        &self.name,
                    ])
                    .stdin(std::process::Stdio::piped())
                    .spawn()?;

                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(passphrase.as_bytes())?;
                    stdin.write_all(b"\n")?;
                }

                if !child.wait()?.success() {
                    return Err(Error::Zfs(format!(
                        "Failed to create dataset {}",
                        self.name
                    )));
                }
            }
        }
        Ok(())
    }

    /// Checks if the dataset exists using `zfs list`.
    pub fn exists(&self) -> Result<bool> {
        let status = Command::new("zfs")
            .args(["list", "-H", &self.name])
            .status()?;
        Ok(status.success())
    }

    /// Lists child datasets recursively.
    pub fn list_recursive(&self) -> Result<Vec<Dataset>> {
        let output = Command::new("zfs")
            .args(["list", "-H", "-o", "name", "-r", &self.name])
            .output()?;

        if !output.status.success() {
            return Err(Error::Zfs(format!(
                "Failed to list datasets for {}",
                self.name
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let datasets = stdout
            .lines()
            .filter_map(|line| Dataset::new(line.to_string()).ok())
            .collect();

        Ok(datasets)
    }
}

/// Resolves a list of datasets to include all their child datasets recursively.
pub fn resolve_recursive(datasets: &[Dataset]) -> Result<Arc<[Dataset]>> {
    let mut resolved = Vec::new();
    for dataset in datasets {
        resolved.extend(dataset.list_recursive()?);
    }
    Ok(Arc::from(resolved))
}

/// Finds the maximum name length among a list of datasets for aligned printing.
pub fn get_max_namesize(datasets: &[Dataset]) -> usize {
    datasets.iter().map(|d| d.name().len()).max().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dataset_new_valid() {
        let name = "zpool/home/user".to_string();
        let ds = Dataset::new(name.clone()).unwrap();
        assert_eq!(ds.name(), name);
    }

    #[test]
    fn test_dataset_new_invalid_chars() {
        let result = Dataset::new("zpool/home/user space".to_string());
        assert!(matches!(result, Err(Error::InvalidInput(_))));

        let result = Dataset::new("zpool/home/user@1".to_string());
        assert!(matches!(result, Err(Error::InvalidInput(_))));
    }

    #[test]
    fn test_dataset_new_invalid_start() {
        let result = Dataset::new("-zpool/home".to_string());
        assert!(matches!(result, Err(Error::InvalidInput(_))));

        let result = Dataset::new("/zpool/home".to_string());
        assert!(matches!(result, Err(Error::InvalidInput(_))));
    }

    #[test]
    fn test_dataset_new_empty() {
        let result = Dataset::new("".to_string());
        assert!(matches!(result, Err(Error::InvalidInput(_))));
    }

    #[test]
    fn test_get_max_namesize() {
        let ds1 = Dataset::new("pool/a".to_string()).unwrap(); // length 6
        let ds2 = Dataset::new("pool/longer_name".to_string()).unwrap(); // length 16
        let ds3 = Dataset::new("pool/b".to_string()).unwrap(); // length 6

        let datasets = vec![ds1, ds2, ds3];
        assert_eq!(get_max_namesize(&datasets), 16);
    }

    #[test]
    fn test_get_max_namesize_empty() {
        let datasets: Vec<Dataset> = vec![];
        assert_eq!(get_max_namesize(&datasets), 0);
    }
}
