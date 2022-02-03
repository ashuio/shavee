pub mod filehash;
pub mod logic;
pub mod password;
pub mod yubikey;
pub mod zfs;

pub const UNREACHABLE_CODE: &str =
    "Panic! Something unexpected happened! Please help by reporting it as a bug.";

use clap;

// TODO: Write unit test
pub fn parse_file_size_arguments(
    values: clap::Values,
) -> Result<(Option<String>, Option<u64>), clap::Error> {
    // initiate size to None. If user entered SIZE arg value, then will fill it with Some()
    let mut size = None;

    // convert the values to a vector
    let file_size_argument: Vec<_> = values.collect();

    // first [0] value is the file name
    // it is a required field for "--file" and its existence already checked by clap
    let file = Some(file_size_argument[0].to_string());

    // if "--file" has two entries, then 2nd [1] is size
    if file_size_argument.len() == 2 {
        let second_entry = file_size_argument[1];

        // however the size entry needs to be validated and return error if it is not a u64 value
        let size_check = match second_entry.parse::<u64>() {
            Err(_) => {
                let error_message =
                    format!(r#""{}" is not valid for SIZE argument."#, second_entry);

                //TODO: "with_description" is depreciated.
                #[allow(deprecated)]
                return Err(clap::Error::with_description(
                    error_message.to_string(),
                    clap::ErrorKind::InvalidValue,
                ));
            }
            Ok(u) => u,
        };

        // wrap the parsed entry with Some()
        size = Some(size_check);
    }

    Ok((file, size))
}

pub fn port_check(v: &str) -> Result<(), String> {
    if v.parse::<u16>().is_ok() && v.parse::<u16>().unwrap() != 0 {
        return Ok(());
    } else {
        let error_message = format!(r#""{}" is an invalid port number!"#, v);
        return Err(error_message);
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
}
