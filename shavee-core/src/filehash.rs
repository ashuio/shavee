use curl;
use sha2::{Digest, Sha512};
use std::io::{self, BufRead, BufReader};

// max capacity must be a u32 number to be safely casted into usize independent of 32/64bit systems
const MAX_BUFFER_CAPACITY: u32 = 1 << 24;

pub fn get_filehash(
    file: String,
    port: Option<u16>,
    size: Option<u64>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if file.starts_with("https://") || file.starts_with("http://") || file.starts_with("sftp://") {
        get_filehash_http_sftp(file, port, size).map_err(Into::into)
    } else {
        get_filehash_local(file, size).map_err(Into::into)
    }
}

fn get_filehash_local(file: String, size: Option<u64>) -> Result<Vec<u8>, io::Error> {
    let file_handle = std::fs::File::open(&file)?;

    let mut remaining_bytes = size.clone();

    // defult buffer capacity
    let mut buffer_capacity = MAX_BUFFER_CAPACITY as usize;

    // if "size" argument has provided, then check for its value and if its value is smaller than
    // current buffer capacity then use "size" value for buffer capacity. Otherwise keep the default
    if let Some(s) = size {
        // depending on the system, usize is either 32 or 64bits and can be safely casted into u64
        // however the other way is only possible if u64 variable is smaller than 32bits
        if s < buffer_capacity as u64 {
            // if "size" is smaller than default buffer capacity (const u32)
            buffer_capacity = s as usize; // then buffer capacity will be reduced to "size"
        };
    };

    let mut reader = BufReader::with_capacity(buffer_capacity, file_handle);
    let mut hasher = Sha512::new();

    // If "size" argument is passed then exit loop when unread remaining bytes are 0
    // if no "size" argument (None), then the loop only exits if the file is completely processed (length == 0)
    while remaining_bytes != Some(0) {
        let mut length = {
            // try to fill buffer and on failures exit function with error message
            let buffer = reader.fill_buf()?;
            hasher.update(buffer);
            buffer.len()
        };

        // exit out of loop if reached end of file.
        if length == 0 {
            break;
        }

        // Only if "size" argument is passed, then count the number of processed bytes
        // If no "size" argument (None) then skip the byte counting.
        if let Some(r) = remaining_bytes {
            // as long as the remaining bytes are bigger than buffer, process buffer
            // and substract it from remaining
            if r >= length as u64 {
                remaining_bytes = Some(r - length as u64);
            }
            //otherwise process only up to the remaining bytes and exit the loop
            else {
                length = r as usize;
                remaining_bytes = Some(0);
            }
        }
        // read length number of bytes
        reader.consume(length);
    }
    // upon success generate hash and return as Ok(vector)
    Ok(hasher.finalize().to_vec())
}

fn get_filehash_http_sftp(
    file: String,
    port: Option<u16>,
    size: Option<u64>,
) -> Result<Vec<u8>, curl::Error> {
    let mut rfile = curl::easy::Easy::new();
    let mut filehash = Sha512::new();
    rfile.url(file.as_str()).expect("Invalid URL");

    if port.is_some() {
        rfile.port(port.unwrap())?;
    }
    if size.is_some() {
        let range = format!("0-{}", size.unwrap());
        rfile.range(&range[..])?;
    }

    rfile.fail_on_error(true)?;
    {
        let mut transfer = rfile.transfer();
        transfer.write_function(|new_data| {
            filehash.update(new_data);
            Ok(new_data.len())
        })?;
        transfer.perform()?;
    }
    return Ok(filehash.finalize().to_vec());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::prelude::*;
    use std::os::unix::prelude::PermissionsExt;
    use tempfile;

    #[test]
    fn local_file_hash() {
        // Check for root permission and exit early
        if nix::unistd::Uid::effective().is_root() {
            panic!("Test must not run under Root permission! Test terminated early!");
        }

        // defining a struct that will hold intput arguments
        // and their output hash results
        // need to use io::ErrorKind (instead of io:Error) which supports PartialEq
        #[derive(Debug, PartialEq)]
        struct FileHashResultPair {
            file: String,
            size: Option<u64>,
            hash_result: Result<Vec<u8>, io::ErrorKind>,
        }

        // each entry of the array holds the input/output struct
        // use SHA512 to hash a fix and known file that is not supposed to change as test reference
        // NOTE: These tests will fail if any of these files changes.
        let file_hash_result_pairs = [
            FileHashResultPair {
                file: String::from("can_be_deleted.txt"),
                size: None,
                hash_result: Ok(vec![
                    151, 32, 184, 60, 202, 224, 90, 60, 197, 34, 2, 158, 175, 149, 203, 186, 104,
                    129, 90, 15, 210, 92, 87, 121, 209, 152, 85, 171, 231, 42, 7, 23, 47, 68, 173,
                    1, 147, 112, 247, 149, 181, 52, 64, 220, 94, 197, 103, 139, 124, 253, 180, 130,
                    87, 22, 146, 141, 51, 10, 47, 233, 163, 16, 124, 123,
                ]),
            },
            FileHashResultPair {
                file: String::from("can_be_deleted.txt"),
                size: Some(1 << 8), // size bigger than file
                hash_result: Ok(vec![
                    151, 32, 184, 60, 202, 224, 90, 60, 197, 34, 2, 158, 175, 149, 203, 186, 104,
                    129, 90, 15, 210, 92, 87, 121, 209, 152, 85, 171, 231, 42, 7, 23, 47, 68, 173,
                    1, 147, 112, 247, 149, 181, 52, 64, 220, 94, 197, 103, 139, 124, 253, 180, 130,
                    87, 22, 146, 141, 51, 10, 47, 233, 163, 16, 124, 123,
                ]),
            },
            FileHashResultPair {
                file: String::from("can_be_deleted.txt"),
                size: Some(1 << 63), // 64bit hash size
                hash_result: Ok(vec![
                    151, 32, 184, 60, 202, 224, 90, 60, 197, 34, 2, 158, 175, 149, 203, 186, 104,
                    129, 90, 15, 210, 92, 87, 121, 209, 152, 85, 171, 231, 42, 7, 23, 47, 68, 173,
                    1, 147, 112, 247, 149, 181, 52, 64, 220, 94, 197, 103, 139, 124, 253, 180, 130,
                    87, 22, 146, 141, 51, 10, 47, 233, 163, 16, 124, 123,
                ]),
            },
            FileHashResultPair {
                file: String::from("can_be_deleted.txt"),
                size: Some(2), // hash size smaller than file size
                hash_result: Ok(vec![
                    228, 239, 180, 180, 23, 58, 126, 30, 72, 208, 65, 207, 22, 167, 157, 234, 141,
                    138, 136, 133, 187, 83, 207, 2, 140, 214, 242, 176, 75, 117, 70, 219, 172, 126,
                    182, 37, 220, 176, 115, 126, 76, 109, 67, 142, 0, 180, 108, 22, 228, 137, 166,
                    137, 86, 28, 144, 73, 28, 52, 171, 85, 27, 203, 99, 41,
                ]),
            },
            FileHashResultPair {
                file: String::from("can_be_deleted.txt"),
                size: Some(0), // zero hash size
                hash_result: Ok(vec![
                    207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214,
                    32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208,
                    209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49,
                    189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62,
                ]),
            },
            FileHashResultPair {
                file: String::from("zero_size.txt"), //zero size file
                size: None,
                hash_result: Ok(vec![
                    207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214,
                    32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208,
                    209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49,
                    189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62,
                ]),
            },
            FileHashResultPair {
                file: String::from("zero_size.txt"), //zero size file
                size: Some(222),                     // size bigger than file
                hash_result: Ok(vec![
                    207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214,
                    32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208,
                    209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49,
                    189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62,
                ]),
            },
            FileHashResultPair {
                file: String::from("/dev/zero"), // Zeros with no size limit
                size: Some(1 << 8),              // Put limit on hash size
                hash_result: Ok(vec![
                    105, 63, 149, 213, 131, 131, 166, 22, 45, 42, 171, 73, 235, 96, 57, 93, 204,
                    75, 178, 34, 149, 18, 12, 175, 63, 33, 227, 3, 144, 3, 35, 11, 40, 124, 86,
                    106, 3, 199, 160, 202, 90, 204, 174, 210, 19, 60, 112, 11, 28, 179, 248, 46,
                    223, 138, 220, 189, 220, 146, 180, 249, 251, 153, 16, 198,
                ]),
            },
            /* // this entry significantly increases test time
            FileHashResultPair {
                file: String::from("/dev/zero"), // Zeros with no size limit
                size: Some(1 << 34),             // Very large hash size (64bits)
                hash_result: Ok(vec![
                    13, 186, 138, 161, 49, 41, 63, 12, 151, 49, 59, 122, 116, 237, 203, 235, 0,
                    212, 46, 1, 236, 69, 210, 102, 149, 176, 17, 18, 57, 179, 136, 45, 161, 205,
                    169, 236, 52, 95, 145, 184, 230, 126, 195, 211, 183, 237, 186, 136, 104, 186,
                    123, 230, 237, 157, 132, 255, 222, 7, 108, 235, 249, 17, 181, 211,
                ]),
            },*/
            FileHashResultPair {
                file: String::from("does_not_exists"), //Not Found
                size: None,
                hash_result: Err(io::ErrorKind::NotFound),
            },
            FileHashResultPair {
                file: String::from("does_not_exists"), //Not Found
                size: Some(11 << 5),                   // hash size for a Not Found
                hash_result: Err(io::ErrorKind::NotFound),
            },
            FileHashResultPair {
                file: String::from("no_read_permission.txt"), //no read permission
                size: None,
                hash_result: Err(io::ErrorKind::PermissionDenied),
            },
            FileHashResultPair {
                file: String::from("no_read_permission.txt"), //no read permission
                size: Some(111),                              // hash size for no read permission
                hash_result: Err(io::ErrorKind::PermissionDenied),
            },
        ];

        // make a temp folder in the system temp directory
        // this temp folder will be automatically deleted at the end of unit test
        let temp_folder = tempfile::tempdir()
            .expect("Couldn't make a temp folder! Test terminating early!")
            .into_path();

        // zero_size.txt file needed for hash test
        let mut test_file = temp_folder.clone();
        test_file.push("zero_size.txt");
        // Create file and open a file in write-only mode
        let mut file = File::create(&test_file).expect("Couldn't create temp file!");
        // Write the 0 byte to the test file
        file.write_all("".as_bytes()).expect("Couldn't write!");

        // can_be_deleted.txt file needed for hash test
        let mut test_file = temp_folder.clone();
        test_file.push("can_be_deleted.txt");
        // Create file and open a file in write-only mode
        let mut file = File::create(&test_file).expect("Couldn't create temp file!");
        // Write the 0 byte to test file
        file.write_all("You can delete this file safely!".as_bytes())
            .expect("Couldn't write!");

        // no_read_permission.txt file needed for hash test
        // copy can_be_deleted.txt to no_read_permission.txt then remove read permission
        let mut no_read_test_file = temp_folder.clone();
        no_read_test_file.push("no_read_permission.txt");
        fs::copy(&test_file, &no_read_test_file).expect("Couldn't copy test file!");
        let mut permissions = fs::metadata(&no_read_test_file)
            .expect("Couldn't get permissions!")
            .permissions();
        permissions.set_mode(0o200); // remove read access
        fs::set_permissions(no_read_test_file, permissions).expect("Couldn't set permissions!");

        for index in 0..file_hash_result_pairs.len() {
            let mut file = temp_folder.clone();
            file.push(file_hash_result_pairs[index].file.clone());
            let size = file_hash_result_pairs[index].size.clone();

            match get_filehash_local(file.into_os_string().into_string().unwrap(), size)
                .map_err(|e| e.kind())
            {
                Ok(v) => assert_eq!(
                    v,
                    file_hash_result_pairs[index].hash_result.clone().unwrap()
                ),
                Err(e) => assert_eq!(
                    e,
                    file_hash_result_pairs[index]
                        .hash_result
                        .clone()
                        .unwrap_err()
                ),
            };
        }

        // clean up to delete the temp folder
        std::process::Command::new("rm")
            .arg("-rf")
            .arg(temp_folder)
            .spawn()
            .expect("Temp folder clean up failed!");
    }

    #[test]
    fn remote_file_hash() {

        // Check for Nix package builder before running the unit test [issue #27]
        if std::env::var("postInstall").is_ok() {
            eprintln!("Nix package environment detected. Unit test is skipped.");
            return;
        }

        // defining a struct that will hold intput arguments
        // and their output hash results
        #[derive(Debug, PartialEq)]
        struct FilePortHashResultPair {
            file: String,
            size: Option<u64>,
            port: Option<u16>,
            hash_result: Result<Vec<u8>, curl::Error>,
        }

        // each entry of the array holds the input/output struct
        // use SHA512 to hash a fix and known file that is not supposed to change as test reference
        // NOTE: These tests will fail if any of these files changes.
        let file_hash_result_pairs = [
            FilePortHashResultPair {
                file: String::from(
                    "https://raw.githubusercontent.com/ashuio/shavee/master/LICENSE",
                ),
                size: None,
                port: None,
                hash_result: Ok(vec![
                    114, 198, 213, 139, 67, 213, 120, 43, 163, 13, 255, 110, 191, 190, 203, 251,
                    149, 28, 124, 127, 251, 14, 155, 0, 181, 106, 178, 75, 235, 244, 197, 242, 51,
                    230, 184, 174, 82, 132, 6, 213, 33, 91, 98, 211, 223, 239, 228, 8, 236, 29, 70,
                    188, 168, 158, 241, 251, 66, 152, 199, 6, 79, 85, 98, 12,
                ]),
            },
            FilePortHashResultPair {
                file: String::from(
                    "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
                ),
                size: None,
                port: Some(443),
                hash_result: Ok(vec![
                    243, 179, 171, 62, 99, 81, 226, 91, 92, 24, 130, 190, 168, 211, 126, 250, 221,
                    192, 234, 114, 191, 21, 59, 176, 103, 104, 143, 119, 90, 38, 129, 13, 50, 181,
                    79, 1, 75, 241, 206, 188, 127, 233, 48, 66, 216, 91, 24, 181, 180, 83, 227, 34,
                    209, 84, 188, 85, 213, 204, 39, 84, 176, 223, 180, 178,
                ]),
            },
            FilePortHashResultPair {
                file: String::from(
                    "http://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
                ),
                size: None,
                port: Some(80),
                hash_result: Ok(vec![
                    207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214,
                    32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208,
                    209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49,
                    189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62,
                ]),
            },
            FilePortHashResultPair {
                file: String::from(
                    "https://raw.githubusercontent.com/ashuio/shavee/master/LICENSEEEE",
                ), //file doesn't exists
                size: Some(1 << 10),
                port: None,
                hash_result: Err(curl::Error::new(22)), //CURLE_HTTP_RETURNED_ERROR
            },
            FilePortHashResultPair {
                file: String::from(
                    "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
                ),
                size: Some(1 << 32),
                port: Some(80),                         //Wrong port for SSL
                hash_result: Err(curl::Error::new(35)), //CURLE_SSL_CONNECT_ERROR
            },
            FilePortHashResultPair {
                file: String::from("http://www.w3.ggg"), // host doesn't exists
                size: Some(5),
                port: None,
                hash_result: Err(curl::Error::new(6)), //CURLE_COULDNT_RESOLVE_HOST
            },
            FilePortHashResultPair {
                file: String::from(
                    "http://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
                ),
                size: Some(2048),
                port: Some(23),                         //FTP port used for HTTP
                hash_result: Err(curl::Error::new(28)), //CURLE_HTTP_RETURNED_ERROR
            },
            FilePortHashResultPair {
                file: String::from(
                    "https://raw.githubusercontent.com/ashuio/shavee/master/LICENSEEEE",
                ), //file doesn't exists
                size: Some(98),
                port: None,
                hash_result: Err(curl::Error::new(22)), //CURLE_HTTP_RETURNED_ERROR
            },
            FilePortHashResultPair {
                file: String::from(
                    "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
                ),
                size: Some(69820),
                port: Some(80),                         //Wrong port for SSL
                hash_result: Err(curl::Error::new(35)), //CURLE_SSL_CONNECT_ERROR
            },
            FilePortHashResultPair {
                file: String::from("http://www.w3.ggg"), // host doesn't exists
                size: Some(0),
                port: None,
                hash_result: Err(curl::Error::new(6)), //CURLE_COULDNT_RESOLVE_HOST
            },
            FilePortHashResultPair {
                file: String::from(
                    "http://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
                ),
                size: Some(256),
                port: Some(23),                         //FTP port used for HTTP
                hash_result: Err(curl::Error::new(28)), //CURLE_HTTP_RETURNED_ERROR
            },
        ];

        for index in 0..file_hash_result_pairs.len() {
            let file = file_hash_result_pairs[index].file.clone();
            let port = file_hash_result_pairs[index].port;
            let size = file_hash_result_pairs[index].size;
            println!("{:?}", index); // in case of test failure shows which index caused it

            match get_filehash_http_sftp(file, port, size) {
                Ok(v) => assert_eq!(
                    v,
                    file_hash_result_pairs[index].hash_result.clone().unwrap()
                ),
                // to avoid variation between different error messages implementation compare only the curl error codes
                Err(e) => assert_eq!(
                    e.code(),
                    file_hash_result_pairs[index]
                        .hash_result
                        .clone()
                        .unwrap_err()
                        .code()
                ),
            };
        }
    }

    #[test]
    fn get_filehash_unit_test() {

        // Check for Nix package builder before running the unit test [issue #27]
        if std::env::var("postInstall").is_ok() {
            eprintln!("Nix package environment detected. Unit test is skipped.");
            return;
        }
        // Check for root permission and exit early
        if nix::unistd::Uid::effective().is_root() {
            eprintln!("Test must not run under Root permission! Test terminated early!");
            return;
        }

        // defining a struct that will hold intput arguments
        // port number for remote files (it will be ignored for local files)
        // and their output hash results
        struct FilePortHashResultPair {
            file: String,
            size: Option<u64>,
            port: Option<u16>,
            hash_result: Result<Vec<u8>, String>,
        }

        // each entry of the array holds the input/output struct
        // use SHA512 to hash a fix and known file that is not supposed to change as test reference
        // NOTE: These tests will fail if any of these files changes.
        let file_hash_result_pairs = [
            FilePortHashResultPair {
                file: String::from("can_be_deleted.txt"),
                size: Some(1024),
                port: None,
                hash_result: Ok(vec![
                    151, 32, 184, 60, 202, 224, 90, 60, 197, 34, 2, 158, 175, 149, 203, 186, 104,
                    129, 90, 15, 210, 92, 87, 121, 209, 152, 85, 171, 231, 42, 7, 23, 47, 68, 173,
                    1, 147, 112, 247, 149, 181, 52, 64, 220, 94, 197, 103, 139, 124, 253, 180, 130,
                    87, 22, 146, 141, 51, 10, 47, 233, 163, 16, 124, 123,
                ]),
            },
            FilePortHashResultPair {
                file: String::from("zero_size.txt"), //zero size file
                size: Some(2048),
                port: None,
                hash_result: Ok(vec![
                    207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214,
                    32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208,
                    209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49,
                    189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62,
                ]),
            },
            FilePortHashResultPair {
                file: String::from("does_not_exists"), //Not Found
                size: Some(512),
                port: None,
                hash_result: Err(io::Error::from_raw_os_error(2).to_string()),
            },
            FilePortHashResultPair {
                file: String::from("no_read_permission.txt"), //no read permission
                size: Some(128),
                port: None,
                hash_result: Err(io::Error::from_raw_os_error(13).to_string()),
            },
            FilePortHashResultPair {
                file: String::from(
                    "https://raw.githubusercontent.com/ashuio/shavee/master/LICENSE",
                ),
                size: Some(1 << 11),
                port: None,
                hash_result: Ok(vec![
                    114, 198, 213, 139, 67, 213, 120, 43, 163, 13, 255, 110, 191, 190, 203, 251,
                    149, 28, 124, 127, 251, 14, 155, 0, 181, 106, 178, 75, 235, 244, 197, 242, 51,
                    230, 184, 174, 82, 132, 6, 213, 33, 91, 98, 211, 223, 239, 228, 8, 236, 29, 70,
                    188, 168, 158, 241, 251, 66, 152, 199, 6, 79, 85, 98, 12,
                ]),
            },
            FilePortHashResultPair {
                file: String::from(
                    "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
                ),
                size: None,
                port: Some(443),
                hash_result: Ok(vec![
                    243, 179, 171, 62, 99, 81, 226, 91, 92, 24, 130, 190, 168, 211, 126, 250, 221,
                    192, 234, 114, 191, 21, 59, 176, 103, 104, 143, 119, 90, 38, 129, 13, 50, 181,
                    79, 1, 75, 241, 206, 188, 127, 233, 48, 66, 216, 91, 24, 181, 180, 83, 227, 34,
                    209, 84, 188, 85, 213, 204, 39, 84, 176, 223, 180, 178,
                ]),
            },
            FilePortHashResultPair {
                file: String::from(
                    "http://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
                ),
                size: Some(1 << 15),
                port: Some(80),
                hash_result: Ok(vec![
                    207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214,
                    32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208,
                    209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49,
                    189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62,
                ]),
            },
            FilePortHashResultPair {
                file: String::from(
                    "https://raw.githubusercontent.com/ashuio/shavee/master/LICENSEEEE",
                ), //file doesn't exists
                size: Some(1 << 10),
                port: None,
                hash_result: Err(curl::Error::new(22).to_string()), //CURLE_HTTP_RETURNED_ERROR
            },
            FilePortHashResultPair {
                file: String::from(
                    "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
                ),
                size: Some(1 << 16),
                port: Some(80), //Wrong port for SSL
                hash_result: Err(curl::Error::new(35).to_string()), //CURLE_SSL_CONNECT_ERROR
            },
            FilePortHashResultPair {
                file: String::from("http://www.w3.ggg"), // host doesn't exists
                size: None,
                port: None,
                hash_result: Err(curl::Error::new(6).to_string()), //CURLE_COULDNT_RESOLVE_HOST
            },
            FilePortHashResultPair {
                file: String::from(
                    "http://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
                ),
                size: Some(200 * 1 << 10),                          //200kB
                port: Some(23),                                     //FTP port used for HTTP
                hash_result: Err(curl::Error::new(28).to_string()), //CURLE_HTTP_RETURNED_ERROR
            },
        ];

        // make a temp folder in the system temp directory
        // this temp folder will be automatically deleted at the end of unit test
        let temp_folder = tempfile::tempdir()
            .expect("Couldn't make a temp folder! Test terminating early!")
            .into_path();

        // zero_size.txt file needed for hash test
        let mut test_file = temp_folder.clone();
        test_file.push("zero_size.txt");
        // Create file and open a file in write-only mode
        let mut file = File::create(&test_file).expect("Couldn't create temp file!");
        // Write the 0 byte to the test file
        file.write_all("".as_bytes()).expect("Couldn't write!");

        // can_be_deleted.txt file needed for hash test
        let mut test_file = temp_folder.clone();
        test_file.push("can_be_deleted.txt");
        // Create file and open a file in write-only mode
        let mut file = File::create(&test_file).expect("Couldn't create temp file!");
        // Write the 0 byte to test file
        file.write_all("You can delete this file safely!".as_bytes())
            .expect("Couldn't write!");

        // no_read_permission.txt file needed for hash test
        // copy can_be_deleted.txt to no_read_permission.txt then remove read permission
        let mut no_read_test_file = temp_folder.clone();
        no_read_test_file.push("no_read_permission.txt");
        fs::copy(&test_file, &no_read_test_file).expect("Couldn't copy test file!");
        let mut permissions = fs::metadata(&no_read_test_file)
            .expect("Couldn't get permissions!")
            .permissions();
        permissions.set_mode(0o200); // remove read access
        fs::set_permissions(no_read_test_file, permissions).expect("Couldn't set permissions!");

        for index in 0..file_hash_result_pairs.len() {
            let mut file = file_hash_result_pairs[index].file.clone();

            if !(file.starts_with("https://")
                || file.starts_with("http://")
                || file.starts_with("sftp://"))
            {
                let mut receive_file = temp_folder.clone();
                receive_file.push(file);
                file = receive_file.into_os_string().into_string().unwrap();
            }

            println!("{:?}", index); // in case of test failure it shows which index caused it
            let port = file_hash_result_pairs[index].port;
            let size = file_hash_result_pairs[index].size;
            match get_filehash(file, port, size) {
                Ok(v) => assert_eq!(
                    v,
                    file_hash_result_pairs[index].hash_result.clone().unwrap()
                ),
                Err(e) => {
                    // Because of differences in the error message implementation systems
                    // only compare the first few characters
                    let truncate_size = 5;
                    assert_eq!(
                        e.to_string().truncate(truncate_size),
                        file_hash_result_pairs[index]
                            .hash_result
                            .clone()
                            .unwrap_err()
                            .truncate(truncate_size)
                    );
                }
            };
        }

        // clean up to delete the temp folder
        std::process::Command::new("rm")
            .arg("-rf")
            .arg(temp_folder)
            .spawn()
            .expect("Temp folder clean up failed!");
    }
}
