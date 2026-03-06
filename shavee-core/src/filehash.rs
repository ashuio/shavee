//! File-based 2FA: hashing a file's content to derive an encryption key.
//!
//! This module supports both local files and remote files via HTTP, HTTPS, and SFTP.
//! It uses `curl` for remote transfers and `BufReader` for efficient local I/O.

use crate::Result;
use curl::easy::Easy;
use std::io::{BufReader, Read};

/// Maximum buffer capacity for reading files (16 MB).
/// Prevents excessive memory usage for very large files.
const MAX_BUFFER_CAPACITY: usize = 1 << 24;

/// Generates a hash from a file's content (local or remote).
///
/// This is a high-level entry point that dispatches to either `get_filehash_local`
/// or `get_filehash_remote` based on the file path prefix.
///
/// # Arguments
/// * `file` - The file path or URL (http://, https://, sftp://).
/// * `port` - Optional port for remote files.
/// * `size` - Optional maximum number of bytes to read from the file.
/// * `salt` - The salt used for final Argon2 hashing.
///
/// # Returns
/// A `Result` containing the derived key as a `Vec<u8>`.
pub fn get_filehash(
    file: &str,
    port: Option<u16>,
    size: Option<u64>,
    salt: &[u8],
) -> Result<Vec<u8>> {
    crate::trace(&format!(
        "Generating hash from file: {} (size limit: {:?})",
        file, size
    ));

    // Determine if the file is remote based on its protocol prefix
    if file.starts_with("https://") || file.starts_with("http://") || file.starts_with("sftp://") {
        crate::trace("File location is remote.");
        get_filehash_remote(file, port, size, salt)
    } else {
        crate::trace("File location is local.");
        get_filehash_local(file, size, salt)
    }
}

/// Reads and hashes a local file.
///
/// Uses `BufReader` with a capacity optimized for the requested `size` limit
/// to ensure efficient reading.
fn get_filehash_local(path: &str, size: Option<u64>, salt: &[u8]) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;

    // Optimize buffer capacity: don't allocate more than needed if size is small
    let buffer_capacity = match size {
        Some(s) if s < MAX_BUFFER_CAPACITY as u64 => s as usize,
        _ => MAX_BUFFER_CAPACITY,
    };

    let mut reader = BufReader::with_capacity(buffer_capacity, file);
    let mut hash_input = Vec::new();

    // Read up to 'size' bytes or until EOF
    if let Some(limit) = size {
        let mut handle = reader.take(limit);
        handle.read_to_end(&mut hash_input)?;
    } else {
        reader.read_to_end(&mut hash_input)?;
    }

    // Derive final key using Argon2
    crate::password::hash_argon2(&hash_input, salt)
}

/// Reads and hashes a remote file using cURL.
///
/// Supports HTTP, HTTPS, and SFTP. The transfer stops early if `size` is reached.
fn get_filehash_remote(
    url: &str,
    port: Option<u16>,
    size: Option<u64>,
    salt: &[u8],
) -> Result<Vec<u8>> {
    let mut hash_input = Vec::new();
    let mut handle = Easy::new();
    handle.url(url)?;

    // Set custom port if provided
    if let Some(p) = port {
        handle.port(p)?;
    }

    {
        let mut transfer = handle.transfer();
        // Register a callback to handle incoming data chunks
        transfer.write_function(|data| {
            if let Some(limit) = size {
                let remaining = limit.saturating_sub(hash_input.len() as u64);
                if remaining == 0 {
                    // Signal cURL to stop the transfer
                    return Ok(0);
                }
                // Append only up to the remaining limit
                let to_write = std::cmp::min(data.len(), remaining as usize);
                hash_input.extend_from_slice(&data[..to_write]);
                Ok(to_write)
            } else {
                // No limit, just append all data
                hash_input.extend_from_slice(data);
                Ok(data.len())
            }
        })?;

        // Execute the transfer
        transfer.perform()?;
    }

    // Derive final key using Argon2
    crate::password::hash_argon2(&hash_input, salt)
}
