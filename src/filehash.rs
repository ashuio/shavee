//MIT License

/*
Copyright (c) 2021 Google LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

use curl;
use sha2::{Digest, Sha512};
use std::{
    io::{BufRead, BufReader, self},
    process::exit,
};

/// This function based on its input decides how to generate SHA512 hash.
/// On errors, handles error codes, prints them to stderr before terminating.
/// Because this function can terminate the program, invalid inputs can cause
/// interruption of the unit tests.
pub fn get_filehash(file: &String, port: u16) -> Vec<u8> {
    eprintln!("Reading file from {}", file);
    if file.starts_with("https://")
        || file.starts_with("http://")
        || file.starts_with("sftp://") {
            match get_remote_file_hash(&file, port) {
                Ok(v ) => v,
                Err(error) => {
                    eprintln!("Error: Failed to get remote file {}: \n\t{}", file, error);
                    exit(1);    // TODO: Move exit() to main.rs
                }
        }   
    }
    else {
        match get_local_file_hash(&file) {
            Ok(v) => v,
            Err(error) => {
                eprintln!("Error in accessing {}: \n\t{}", file, error);
                exit(1);    // TODO: Move exit() to main.rs and 
            }
        }
    }
}

// Refactored the code to two separate functions each generate a hash or
// reports an error code.
// '?' to catch errors and return them to the calling function

/// Generate SHA512 hash from a file on a local location.
/// On success, returns the hash as a vector wrapped with Ok()
/// On failure. returns io::Error code.
fn get_local_file_hash(file: &String) -> Result<Vec<u8>, io::Error> {
    let inner_file = std::fs::File::open(&file)?;
    let buffer_capacity: usize = 131072 * 128;
    let mut reader = BufReader::with_capacity(buffer_capacity, inner_file);
    let mut hasher = Sha512::new();
    loop {
        let length = {
            let buffer = reader.fill_buf()?;
            hasher.update(buffer);
            buffer.len()
        };
        if length == 0 {
            break;
        }
        reader.consume(length);
    }
    // On success, wrap the result with Ok()
    Ok(hasher.finalize().to_vec())
}

// Generate SHA512 hash from a file on a remote server
/// On success, returns the hash as a vector wrapped with Ok()
/// On failure. returns curl::Error code.
fn get_remote_file_hash(file: &String, port: u16) -> Result<Vec<u8>, curl::Error> {
    let mut rfile = curl::easy::Easy::new();
    let mut filehash = Sha512::new();
    rfile.url(file)?; //.expect("Invalid URL");

    // if port is specified, then use it. Otherwise default port for each transport
    // protocol will be used by curl.
    if port > 0 {
        rfile.port(port)?
    }
    rfile.fail_on_error(true)?;
    {   // receive the file from the remote server
        let mut transfer = rfile.transfer();
        transfer.write_function(|new_data| {
            filehash.update(new_data);
            Ok(new_data.len())
            })?;
        transfer.perform()?;
    }
    // On success, return result wrapped with Ok().
    Ok(filehash.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // the unit tests must be done sequentially, because the test files must be
    // generated before unit tests can use them for its testing.
    use serial_test::serial;

    #[test]
    #[serial]
    fn local_file_hash() {

        // generate files used during unit test
        prepare_files();

        // defining a struct that will hold intput arguments
        // and their output hash results
        // need to use io::ErrorKind (instead of io:Error) which supports PartialEq
        #[derive(Debug, PartialEq)]
        struct FileHashResultPair {
            file: String,
            hash_result: Result<Vec<u8>, io::ErrorKind>
        }

        // each entry of the array holds the input/output struct
        // use SHA512 to hash a fix and known file that is not supposed to change as test reference
        // NOTE: These tests will fail if any of these files changes.
        let file_hash_result_pairs = [
            FileHashResultPair {
                file: String::from("LICENSE"),  //This project license file NOTE: Modifying license of this project will cause unit test failure
                hash_result: Ok(vec![114, 198, 213, 139, 67, 213, 120, 43, 163, 13, 255, 110, 191, 190, 203, 251, 149, 28, 124, 127, 251, 14, 155, 0, 181, 106, 178, 75, 235, 244, 197, 242, 51, 230, 184, 174, 82, 132, 6, 213, 33, 91, 98, 211, 223, 239, 228, 8, 236, 29, 70, 188, 168, 158, 241, 251, 66, 152, 199, 6, 79, 85, 98, 12]),
            },
            FileHashResultPair {
                file: String::from("tmp/zero_size.txt"),  //zero size file
                hash_result: Ok(vec![207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214, 32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208, 209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49, 189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62]),
            },
            FileHashResultPair {
                file: String::from("tmp/does_not_exists"),  //Not Found
                hash_result: Err(io::ErrorKind::NotFound),
            },
            FileHashResultPair {
                file: String::from("tmp/no_read_permission.txt"),  //no read permission
                hash_result: Err(io::ErrorKind::PermissionDenied),
            },
        ];

        for index in 0..file_hash_result_pairs.len() {
            let file = &file_hash_result_pairs[index].file;

            // remember that get_local_file_hash() error needs to be mapped to ErrorKind
            match get_local_file_hash(file)
                .map_err(|e| e.kind()) {
                    Ok(v) => assert_eq!(
                        v,
                        file_hash_result_pairs[index].hash_result.clone().unwrap()
                    ),
                    Err(e) => assert_eq!(
                        e,
                        file_hash_result_pairs[index].hash_result.clone().unwrap_err()
                    ),
            };
        }

        // remove files used for this unit test
        clean_up();
    }

    #[test]
    // this unit test doesn't need local test files and can be executed in parallel to the others.
    fn remote_file_hash() {

        // defining a struct that will hold intput arguments
        // and their output hash results
        #[derive(Debug, PartialEq)]
        struct FilePortHashResultPair {
            file: String,
            port: u16,
            hash_result: Result<Vec<u8>, curl::Error>
        }

        // each entry of the array holds the input/output struct
        // use SHA512 to hash a fix and known file that is not supposed to change as test reference
        // NOTE: These tests will fail if any of these files changes.
        let file_hash_result_pairs = [
            FilePortHashResultPair {
                file: String::from("https://raw.githubusercontent.com/ashuio/shavee/master/LICENSE"),
                port: 0,
                hash_result: Ok(vec![114, 198, 213, 139, 67, 213, 120, 43, 163, 13, 255, 110, 191, 190, 203, 251, 149, 28, 124, 127, 251, 14, 155, 0, 181, 106, 178, 75, 235, 244, 197, 242, 51, 230, 184, 174, 82, 132, 6, 213, 33, 91, 98, 211, 223, 239, 228, 8, 236, 29, 70, 188, 168, 158, 241, 251, 66, 152, 199, 6, 79, 85, 98, 12]),
            },
            FilePortHashResultPair {
                file: String::from("https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf"),
                port: 443,
                hash_result: Ok(vec![243, 179, 171, 62, 99, 81, 226, 91, 92, 24, 130, 190, 168, 211, 126, 250, 221, 192, 234, 114, 191, 21, 59, 176, 103, 104, 143, 119, 90, 38, 129, 13, 50, 181, 79, 1, 75, 241, 206, 188, 127, 233, 48, 66, 216, 91, 24, 181, 180, 83, 227, 34, 209, 84, 188, 85, 213, 204, 39, 84, 176, 223, 180, 178]),
            },
            FilePortHashResultPair {
                file: String::from("http://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf"),
                port: 80,
                hash_result: Ok(vec![243, 179, 171, 62, 99, 81, 226, 91, 92, 24, 130, 190, 168, 211, 126, 250, 221, 192, 234, 114, 191, 21, 59, 176, 103, 104, 143, 119, 90, 38, 129, 13, 50, 181, 79, 1, 75, 241, 206, 188, 127, 233, 48, 66, 216, 91, 24, 181, 180, 83, 227, 34, 209, 84, 188, 85, 213, 204, 39, 84, 176, 223, 180, 178]),
            },
            FilePortHashResultPair {
                file: String::from("https://raw.githubusercontent.com/ashuio/shavee/master/LICENSEEEE"),    //file doesn't exists
                port: 0,
                hash_result: Err(curl::Error::new(22)), //CURLE_HTTP_RETURNED_ERROR
            },
            FilePortHashResultPair {
                file: String::from("https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf"),
                port: 80,   //Wrong port for SSL
                hash_result: Err(curl::Error::new(35)), //CURLE_SSL_CONNECT_ERROR
            },
            FilePortHashResultPair {
                file: String::from("http://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf"),
                port: 23,   //FTP port used for HTTP 
                hash_result: Err(curl::Error::new(28)), //CURLE_OPERATION_TIMEDOUT
            },
            FilePortHashResultPair {
                file: String::from("http://www.w3.ggg"), // host doesn't exists
                port: 0,
                hash_result: Err(curl::Error::new(6)), //CURLE_COULDNT_RESOLVE_HOST
            },
        ];

        for index in 0..file_hash_result_pairs.len() {
            let file = &file_hash_result_pairs[index].file;
            let port = file_hash_result_pairs[index].port;

            match get_remote_file_hash(file, port) {
                Ok(v) => assert_eq!(
                    v,
                    file_hash_result_pairs[index].hash_result.clone().unwrap()
                ),
                // compare only the curl error codes
                Err(e) => assert_eq!(
                    e.code(),
                    file_hash_result_pairs[index].hash_result.clone().unwrap_err().code()
                ),
            };
        }
    }


    // Because get_filehash() terminates the program on errors, only Ok() entries will be
    // used for unit tests. This is OK for now, considering that the other unit tests check for errors.
    #[test]
    #[serial]
    fn pub_get_filehash() {

        // generate files used during unit test
        prepare_files();

        struct FilePortHashResultPair {
            file: String,
            port: u16,
            hash_result: Vec<u8>,
        }

        let file_hash_result_pairs = [
            FilePortHashResultPair {
                file: String::from("https://raw.githubusercontent.com/ashuio/shavee/master/LICENSE"),
                port: 0,
                hash_result: vec![114, 198, 213, 139, 67, 213, 120, 43, 163, 13, 255, 110, 191, 190, 203, 251, 149, 28, 124, 127, 251, 14, 155, 0, 181, 106, 178, 75, 235, 244, 197, 242, 51, 230, 184, 174, 82, 132, 6, 213, 33, 91, 98, 211, 223, 239, 228, 8, 236, 29, 70, 188, 168, 158, 241, 251, 66, 152, 199, 6, 79, 85, 98, 12],
            },
            FilePortHashResultPair {
                file: String::from("https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf"),
                port: 443,
                hash_result: vec![243, 179, 171, 62, 99, 81, 226, 91, 92, 24, 130, 190, 168, 211, 126, 250, 221, 192, 234, 114, 191, 21, 59, 176, 103, 104, 143, 119, 90, 38, 129, 13, 50, 181, 79, 1, 75, 241, 206, 188, 127, 233, 48, 66, 216, 91, 24, 181, 180, 83, 227, 34, 209, 84, 188, 85, 213, 204, 39, 84, 176, 223, 180, 178],
            },
            FilePortHashResultPair {
                file: String::from("http://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf"),
                port: 80,
                hash_result: vec![243, 179, 171, 62, 99, 81, 226, 91, 92, 24, 130, 190, 168, 211, 126, 250, 221, 192, 234, 114, 191, 21, 59, 176, 103, 104, 143, 119, 90, 38, 129, 13, 50, 181, 79, 1, 75, 241, 206, 188, 127, 233, 48, 66, 216, 91, 24, 181, 180, 83, 227, 34, 209, 84, 188, 85, 213, 204, 39, 84, 176, 223, 180, 178],
            },
            FilePortHashResultPair {
                file: String::from("LICENSE"),  //This project license file NOTE: Modifying license of this project will cause unit test failure
                port: 0,
                hash_result: vec![114, 198, 213, 139, 67, 213, 120, 43, 163, 13, 255, 110, 191, 190, 203, 251, 149, 28, 124, 127, 251, 14, 155, 0, 181, 106, 178, 75, 235, 244, 197, 242, 51, 230, 184, 174, 82, 132, 6, 213, 33, 91, 98, 211, 223, 239, 228, 8, 236, 29, 70, 188, 168, 158, 241, 251, 66, 152, 199, 6, 79, 85, 98, 12],
            },
            FilePortHashResultPair {
                file: String::from("tmp/zero_size.txt"),  //zero size file
                port: 443,
                hash_result: vec![207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214, 32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208, 209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49, 189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62],
            },
        ];

        for index in 0..file_hash_result_pairs.len() {
            let file = &file_hash_result_pairs[index].file;
            let port = file_hash_result_pairs[index].port;

            assert_eq!(
                get_filehash(file, port),
                file_hash_result_pairs[index].hash_result);
        };

        // remove files used for unit test
        clean_up();
    }

    // prepare test files for the unit tests
    fn prepare_files() {
        use std::fs::{self, File};
        use std::io::prelude::*;
        use std::path::Path;
        use std::os::unix::prelude::PermissionsExt;


        // folder for location of testing files
        // TODO: Use system temp_dir location instead of making a new folder
        let tests_folder = Path::new("tmp");
        // if the folder doesn't exist, it will be made.
        if !tests_folder.is_dir() {
            fs::create_dir(&tests_folder)
                .expect(format!("Panic! {} cannot be accessed!",tests_folder.display()).as_str());
        };

        // zero_size.txt file needed for hash test
        let test_file_path = Path::new("tmp/zero_size.txt");
        let display = test_file_path.display();
        // if it exists, then delete it
        if test_file_path.is_file() {
            fs::remove_file(&test_file_path)
                .expect(format!("Panic! {} cannot be accessed!",display).as_str());
        };
        // Create file and open a file in write-only mode
        let mut file = File::create(&test_file_path)
            .expect(format!("Couldn't create {}!", display).as_str());

        // Write the 0 byte to `file`
        file.write_all("".as_bytes())
            .expect(format!("Couldn't write to {}!", display).as_str());


        // no_read_permission.txt file needed for hash test
        let test_file_path = Path::new("tmp/no_read_permission.txt");
        let display = test_file_path.display();
        // if it exists, then delete it
        if test_file_path.is_file() {
            fs::remove_file(&test_file_path)
                .expect(format!("Panic! {} cannot be accessed!",display).as_str());
        };
        // Create file and open a file in write-only mode
        let mut file = File::create(&test_file_path)
            .expect(format!("Couldn't create {}!", display).as_str());
        // Write the known string to `file`
        file.write_all("You can delete this file safely!".as_bytes())
            .expect(format!("Couldn't write to {}.", display).as_str());
        // remove read permission
        let mut permissions = fs::metadata(test_file_path)
            .expect(format!("Couldn't get permissions of {}!", display).as_str())
            .permissions();
        permissions.set_mode(0o200);    // remove read access
        fs::set_permissions("tmp/no_read_permission.txt", permissions)
            .expect(format!("Couldn't set permissions of {}!", display).as_str());
    }

    // deletes the files and tmp folder
    fn clean_up() {
        use std::fs;
        const CLEANUP_FAILED: &str ="Panic! Failed in cleaning up!";
        fs::remove_file("tmp/no_read_permission.txt")
            .expect(CLEANUP_FAILED);
        fs::remove_file("tmp/zero_size.txt")
            .expect(CLEANUP_FAILED);
        fs::remove_dir("tmp")
            .expect(CLEANUP_FAILED)
    }
}
