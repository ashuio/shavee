//! Data structures for Shavee configuration.

/// Supported second-factor authentication modes.
#[derive(Debug, Clone, PartialEq)]
pub enum TwoFactorMode {
    /// Use a Yubikey HMAC-SHA1 challenge-response.
    #[cfg(feature = "yubikey")]
    Yubikey {
        /// Optional Yubikey slot (1 or 2).
        yslot: Option<u8>,
        /// Optional Yubikey serial number.
        serial: Option<u32>,
    },
    /// Use a local or remote file hash.
    #[cfg(feature = "file")]
    File {
        /// The file path or URL.
        file: String,
        /// Optional port for remote files (SFTP/HTTP).
        port: Option<u16>,
        /// Optional maximum number of bytes to read from the file.
        size: Option<u64>,
    },
    /// No second factor, only password.
    Password,
}
