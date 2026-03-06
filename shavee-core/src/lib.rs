//! Shavee Core: A library for ZFS dataset encryption management.
//!
//! This library provides the core logic for generating encryption keys for ZFS datasets
//! using various 2FA methods like Yubikeys and files.

pub mod filehash;
pub mod logic;
pub mod password;
pub mod structs;
pub mod yubikey;
pub mod zfs;

use std::fmt;

/// Predefined message for unreachable code paths.
pub const UNREACHABLE_CODE: &str =
    "Panic! Something unexpected happened! Please help by reporting it as a bug.";

/// Static salt for backward compatibility with earlier versions.
pub const STATIC_SALT: &str = "This Project is Dedicated to Tamanna.";

/// Name of the environment variable used to store a custom salt.
pub const ENV_SALT_VARIABLE: &str = "SHAVEE_SALT";

/// Length of the random salt in bytes.
/// Must be at least 16 bytes for security.
pub const RANDOM_SALT_LEN: usize = 32;

/// Core error type for the Shavee library.
#[derive(Debug)]
pub enum Error {
    /// Errors originating from ZFS command execution.
    Zfs(String),
    /// Errors related to password hashing or KDF operations.
    Crypto(String),
    /// Errors related to Yubikey interaction.
    Yubikey(String),
    /// Errors related to file or network I/O.
    Io(std::io::Error),
    /// Errors related to cURL operations (remote files).
    Curl(curl::Error),
    /// Errors related to invalid input arguments.
    InvalidInput(String),
    /// Generic error with a message.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Zfs(m) => write!(f, "ZFS error: {}", m),
            Error::Crypto(m) => write!(f, "Crypto error: {}", m),
            Error::Yubikey(m) => write!(f, "Yubikey error: {}", m),
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Curl(e) => write!(f, "cURL error: {}", e),
            Error::InvalidInput(m) => write!(f, "Invalid input: {}", m),
            Error::Other(m) => write!(f, "Error: {}", m),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<curl::Error> for Error {
    fn from(err: curl::Error) -> Self {
        Error::Curl(err)
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::Other(err)
    }
}

/// Result type alias for Shavee core operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Parses file and size arguments, typically from CLI input.
///
/// # Arguments
/// * `args` - A slice of strings containing the file path and optionally a size limit.
///
/// # Returns
/// A tuple containing the file path and an optional size limit in bytes.
pub fn parse_file_size_arguments(args: &[String]) -> Result<(String, Option<u64>)> {
    if args.is_empty() {
        return Err(Error::InvalidInput("Missing file argument".to_string()));
    }

    let file = args[0].clone();
    let size = if args.len() > 1 {
        Some(args[1].parse::<u64>().map_err(|_| {
            Error::InvalidInput(format!("\"{}\" is not a valid size (must be u64)", args[1]))
        })?)
    } else {
        None
    };

    Ok((file, size))
}

/// Initializes the logging system if the "trace" feature is enabled.
///
/// # Arguments
/// * `_is_test` - Whether the logger is being initialized for a test environment.
pub fn trace_init(_is_test: bool) {
    #[cfg(feature = "trace")]
    {
        if _is_test {
            let _ = env_logger::builder().is_test(true).try_init();
        } else {
            env_logger::init();
        }
    }
}

/// Logs a trace message if the "trace" feature is enabled.
pub fn trace(_message: &str) {
    #[cfg(feature = "trace")]
    log::trace!("{}", _message);
}

/// Logs an error message if the "trace" feature is enabled.
pub fn error(_message: &str) {
    #[cfg(feature = "trace")]
    log::error!("{}", _message);
}
