pub mod filehash;
pub mod logic;
pub mod password;
pub mod yubikey;
pub mod zfs;

pub const UNREACHABLE_CODE: &str =
    "Panic! Something unexpected happened! Please help by reporting it as a bug.";

use clap;

pub fn parse_file_size_arguments(
    file_size_argument: Vec<&str>,
) -> Result<(Option<String>, Option<u64>), clap::Error> {
    // first [0] value is the file name
    // it is a required field for "--file" and its existence already checked by clap
    let file = Some(file_size_argument[0].to_string());

    // If user entered SIZE arg value, it will be wrapped with Some(), otherwise None will be returned
    let size = match file_size_argument.len() {
        // if there is only 1 entry then it is file name and size is set to None
        number_of_entries if number_of_entries == 1 => None,
        // if there are 2 entries, then 2nd entry is size
        number_of_entries if number_of_entries == 2 => {
            // if "--file" has two entries, then 2nd [1] is size
            let second_entry = file_size_argument[1];
            // however the size entry needs to be validated and return error if it is not a u64 value
            match second_entry.parse::<u64>() {
                // wrap the parsed entry with Some()
                Ok(size_arg) => Some(size_arg),

                // on error return invalid value kind
                Err(_) => {
                    let error_message =
                        format!(r#""{}" is not valid for SIZE argument."#, second_entry);

                    return Err(clap::Error::raw(
                        clap::ErrorKind::InvalidValue,
                        &error_message[..],
                    ));
                }
            }
        }

        // clap checks against number of entries must not allow any other value than 1 and 2 entries
        _ => {
            return Err(clap::Error::raw(
                clap::ErrorKind::InvalidValue,
                UNREACHABLE_CODE,
            ));
        }
    };

    // Function Return values wrap with OK indicating no error
    Ok((file, size))
}

pub fn port_check(v: &str) -> Result<(), String> {
    if v.parse::<u16>().is_ok() && v.parse::<u16>().unwrap() != 0 {
        Ok(())
    } else {
        let error_message = format!(r#""{}" is an invalid port number!"#, v);
        Err(error_message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    //This tests port_check() function for the valid ports
    #[test]
    fn port_check_test() {
        //Few examples of valid ports. Important to have the boundary values tested.
        let valid_ports = ["1", "80", "65535"];
        for valid_port in valid_ports {
            match port_check(valid_port) {
                Err(_) => panic!("The port number {} should have been accepted!", valid_port),
                Ok(()) => continue,
            }
        }

        //Few examples of invalid ports. Important to have the boundary values tested.
        //Port 0 is reserved by IANA, it is technically invalid to use.
        let invalid_ports = ["-1", "65536", "a", "0"];
        for invalid_port in invalid_ports {
            match port_check(invalid_port) {
                Ok(()) => panic!(
                    "The port number {} should not have been accepted!",
                    invalid_port
                ),
                Err(_) => continue,
            }
        }
    }

    #[test]
    fn parse_file_size_arguments_test() {
        // test for when both file and size is provided
        assert_eq!(
            parse_file_size_arguments(vec!["./shavee", "2048"]).unwrap(),
            (Some(String::from("./shavee")), Some(2048 as u64))
        );

        // test for when only file is provided
        assert_eq!(
            parse_file_size_arguments(vec!["./shavee"]).unwrap(),
            (Some(String::from("./shavee")), None)
        );

        // test for when there is an empty input
        assert_eq!(
            parse_file_size_arguments(vec![""]).unwrap(),
            (Some(String::from("")), None)
        );

        // test for reporting error when size is invalid
        parse_file_size_arguments(vec!["./shavee", "ten"]).unwrap_err();

        // test for reporting error when more than 2 entries are provided
        parse_file_size_arguments(vec!["./shavee", "2048", "ten"]).unwrap_err();
    }
}
