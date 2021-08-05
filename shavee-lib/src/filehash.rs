use curl;
use sha2::{Digest, Sha512};
use std::io::{BufRead, BufReader};

pub fn get_filehash(file: String, port: u16) -> Result<Vec<u8>, String> {
    if file.starts_with("https://") || file.starts_with("http://") || file.starts_with("sftp://") {
        get_filehash_http_sftp(file, port)
    } else {
        get_filehash_local(file)
    }
}

pub fn get_filehash_local(file: String) -> Result<Vec<u8>, String> {
    let f = std::fs::File::open(&file);
    let f = match f {
        Ok(f) => f,
        Err(error) => return Err(error.to_string()),
    };

    let cap: usize = 131072 * 128;
    let mut reader = BufReader::with_capacity(cap, f);
    let mut hasher = Sha512::new();
    loop {
        let length = {
            let buffer = reader.fill_buf();
            let buffer = match buffer {
                Ok(b) => b,
                Err(error) => return Err(error.to_string()),
            };
            hasher.update(buffer);
            buffer.len()
        };
        if length == 0 {
            break;
        }
        reader.consume(length);
    }
    Ok(hasher.finalize().to_vec())
}

pub fn get_filehash_http_sftp(file: String, port: u16) -> Result<Vec<u8>, String> {
    let mut rfile = curl::easy::Easy::new();
    let mut filehash = Sha512::new();
    rfile.url(file.as_str()).expect("Invalid URL");

    if port > 0 {
        match rfile.port(port) {
            Ok(()) => (),
            Err(e) => return Err(e.to_string()),
        }
    }

    match rfile.fail_on_error(true) {
        Ok(()) => (),
        Err(e) => return Err(e.to_string()),
    }

    {
        let mut transfer = rfile.transfer();
        match transfer.write_function(|new_data| {
            filehash.update(new_data);
            Ok(new_data.len())
        }) {
            Ok(()) => (),
            Err(e) => return Err(e.to_string()),
        }

        match transfer.perform() {
            Ok(r) => r,
            Err(error) => {
                return Err(error.to_string());
            }
        };
    }
    return Ok(filehash.finalize().to_vec());
}
