use curl;
use sha2::{Digest, Sha512};
use std::{io::Read, process::exit};

pub fn get_filehash(file: &String, port: u16) -> Vec<u8> {
    if file.starts_with("https://")
        || file.starts_with("http://")
        || file.starts_with("sftp://")
    {
        get_filehash_http_sftp(&file, port)
    } else {
        let f = std::fs::File::open(&file);
        let mut f = match f {
            Ok(f) => f,
            Err(error) => {
                eprintln!("Error: Failed to open file {}", file);
                eprintln!("Error: {}", error);
                exit(1)
            }
        };
        let mut filehash: Vec<u8> = Vec::new();
        let result = f.read_to_end(&mut filehash);
        match result {
            Ok(k) => eprintln!("Succesfully read {} bytes from {}",k,file),
            Err(error) => {
                eprintln!("Error: Failed to read file {}",file);
                eprintln!("Error: {}",error);
                exit(1)
            }
        };
        Sha512::digest(&filehash).to_vec()
    }
}

pub fn get_filehash_http_sftp(file: &String, port: u16) -> Vec<u8> {
    let mut rfile = curl::easy::Easy::new();
    let mut data = Vec::new();
    rfile.url(file).expect("Invalid URL");

    if port > 0 {
        rfile.port(port).expect("Failed to set port on curl handler");
    }
    rfile
        .fail_on_error(true)
        .expect("Failed to set fail on error on curl handler");
    {
        let mut transfer = rfile.transfer();
        transfer
            .write_function(|new_data| {
                data.extend_from_slice(new_data);
                Ok(new_data.len())
            })
            .expect("Failed to Download file");
        let result = transfer.perform();
        match result {
            Ok(r) => r,
            Err(error) => {
                eprintln!("Error: Failed to get remote file");
                eprintln!("Error: {}", error);
                exit(1)
            }
        };
    }
    Sha512::digest(data.as_ref()).to_vec()
}
