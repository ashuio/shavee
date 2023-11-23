pub mod filehash;
pub mod logic;
pub mod password;
pub mod structs;
pub mod yubikey;
pub mod zfs;

pub const UNREACHABLE_CODE: &str =
    "Panic! Something unexpected happened! Please help by reporting it as a bug.";

/// Static salt for backward compatibility
pub const STATIC_SALT: &str = "This Project is Dedicated to Aveesha.";

/// Name of Shell Environment variable for storing salt
pub const ENV_SALT_VARIABLE: &str = "SHAVEE_SALT";

/// Len of the random salt (in Bytes)
/// It must be bigger than 16 bytes
pub const RANDOM_SALT_LEN: usize = 32;

use clap;
#[cfg(feature = "trace")]
use env_logger;
#[cfg(feature = "trace")]
use log;

/// first [0] value is the file name
/// it is a required field for "--file" and its existence already checked by clap
pub fn parse_file_size_arguments(
    file_size_argument: Vec<&String>,
) -> Result<(Option<String>, Option<u64>), clap::Error> {
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
                        clap::error::ErrorKind::InvalidValue,
                        &error_message[..],
                    ));
                }
            }
        }

        // clap checks against number of entries must not allow any other value than 1 and 2 entries
        _ => {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                UNREACHABLE_CODE,
            ));
        }
    };

    // Function Return values wrap with OK indicating no error
    Ok((file, size))
}

/// Generates debug logs if "trace" feature is enabled in `Cargo.toml`
/// RUST_LOG environment variable needs to be set to "debug" or "trace"
pub fn trace_init(_test: bool) -> () {
    #[cfg(feature = "trace")]
    if _test {
        env_logger::init();
    } else {
        let _ = env_logger::builder().is_test(true).try_init();
    }
    #[cfg(not(feature = "trace"))]
    ();
}

pub fn trace(_message: &str) -> () {
    #[cfg(feature = "trace")]
    log::trace!("{}", _message);
    #[cfg(not(feature = "trace"))]
    ();
}

pub fn error(_message: &str) -> () {
    #[cfg(feature = "trace")]
    log::error!("{}", _message);
    #[cfg(not(feature = "trace"))]
    ();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_file_size_arguments_test() {
        crate::trace_init(false);
        // test for when both file and size is provided
        assert_eq!(
            parse_file_size_arguments(vec![&"./shavee".to_string(), &"2048".to_string()]).unwrap(),
            (Some(String::from("./shavee")), Some(2048 as u64))
        );

        // test for when only file is provided
        assert_eq!(
            parse_file_size_arguments(vec![&"./shavee".to_string()]).unwrap(),
            (Some(String::from("./shavee")), None)
        );

        // test for when there is an empty input
        assert_eq!(
            parse_file_size_arguments(vec![&"".to_string()]).unwrap(),
            (Some(String::from("")), None)
        );

        // test for reporting error when size is invalid
        parse_file_size_arguments(vec![&"./shavee".to_string(), &"ten".to_string()]).unwrap_err();

        // test for reporting error when more than 2 entries are provided
        parse_file_size_arguments(vec![
            &"./shavee".to_string(),
            &"2048".to_string(),
            &"ten".to_string(),
        ])
        .unwrap_err();
    }
}
