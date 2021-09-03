pub mod filehash;
pub mod logic;
pub mod password;
pub mod yubikey;
pub mod zfs;

pub const UNREACHABLE_CODE: &str =
    "Panic! Something unexpected happened! Please help by reporting it as a bug.";

use clap;
use std::ffi::OsString;

#[derive(Debug, PartialEq)]
pub enum Umode {
    Yubikey {
        yslot: u8,
    },
    File {
        file: String,
        port: Option<u16>,
        size: Option<u64>,
    },
    Password,
}

#[derive(Debug, PartialEq)]
pub enum Mode {
    Create { dataset: String },
    Mount { dataset: String },
    Print,
}

pub fn common_args<I, T>(specific_args: clap::App, args: I) -> Result<(Mode, Umode), clap::Error>
where
    I: Iterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let app = specific_args
    .arg(
        clap::Arg::with_name("yubikey")
            .long("yubi")
            .short("y")
            .help("Use Yubikey HMAC as second factor")
            .required(false)
            .takes_value(false)
            .conflicts_with("keyfile"), // yubikey xor keyfile, not both. 
    )
    .arg(
        clap::Arg::with_name("slot")
            .short("s")
            .long("slot")
            .help("Yubikey HMAC Slot")
            .takes_value(true)
            .value_name("HMAC slot")
            .possible_values(&["1", "2"])   // putting limit on acceptable inputs
            .required(false)
            .requires("yubikey"),   // it must be accompanied by yubikey option
    )
    .arg(
        clap::Arg::with_name("keyfile")
            .short("f")
            .long("file")
            .help("Use any file as second factor, takes filepath, SFTP or a HTTP(S) location as an argument. \
            If SIZE is entered, the first SIZE in bytes will be used to generate hash. It must be number between \
            1 and 2^(64).")
            .required(false)
            .takes_value(true)
            .value_name("FILE|ADDRESS [SIZE]")
            .max_values(2)
            .conflicts_with("yubikey"), // keyfile xor yubikey, not both.
    )
    .arg(
        clap::Arg::with_name("port")
            .short("P")
            .long("port")
            .takes_value(true)
            .value_name("port number")
            .required(false)
            .requires("keyfile")    // port must be accompanied by keyfile option
            .validator(port_check)  // validate that port parameter is "valid"
            .help("Set port for HTTP(S) and SFTP requests"),
    );

    // in order to be able to write unit tests, getting the arg matches
    // shouldn't cause new_from() to exit or panic.
    let arg = app.get_matches_from_safe(args)?;

    // check for keyfile argument if parse them if needed.
    // otherwise fill them with None
    let (file, size) = match arg.values_of("keyfile") {
        Some(value) => parse_file_size_arguments(value)?,
        None => (None, None),
    };

    // if zset arg is entered, then its value will be used
    // NOTE: validating dataset is done by zfs module
    let dataset = match arg.value_of("zset").map(str::to_string) {
        Some(mut s) => {
            if s.ends_with("/") {
                s.pop();
            };
            Some(s)
        }
        None => None,
    };

    // The port arguments are <u16> or None (not entered by user)
    let port = arg
        .value_of("port")
        .map(|p| p.parse::<u16>().expect(UNREACHABLE_CODE));

    // The accepted slot arguments are Some (1 or 2) or None (not entered by user)
    // Default value if not entered is 2
    let yslot = match arg.value_of("slot") {
        // exceptions should not happen, because the entry is already validated by clap
        Some(s) => s.parse::<u8>().expect(UNREACHABLE_CODE),
        None => 2,
    };

    let umode = if arg.is_present("yubikey") {
        Umode::Yubikey { yslot }
    } else if arg.is_present("keyfile") {
        let file = file.expect(UNREACHABLE_CODE);
        Umode::File { file, port, size }
    } else {
        Umode::Password
    };

    let mode = if arg.is_present("create") {
        let dataset = dataset.expect(UNREACHABLE_CODE);
        Mode::Create { dataset }
    } else if arg.is_present("zset") {
        let dataset = dataset.expect(UNREACHABLE_CODE);
        Mode::Mount { dataset }
    } else {
        Mode::Print
    };
    Ok((mode, umode))
}

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
                return Err(clap::Error::with_description(
                    &error_message[..],
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

pub fn port_check(v: String) -> Result<(), String> {
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
            match port_check(valid_port.to_string()) {
                Err(_) => panic!("The port number {} should have been accepted!", valid_port),
                Ok(()) => continue,
            }
        }

        //Few examples of invalid ports. Important to have the boundary values tested.
        //Port 0 is reserved by IANA, it is technically invalid to use.
        let invalid_ports = ["-1", "65536", "a", "0"];
        for invalid_port in invalid_ports {
            match port_check(invalid_port.to_string()) {
                Ok(()) => panic!(
                    "The port number {} should not have been accepted!",
                    invalid_port
                ),
                Err(_) => continue,
            }
        }
    }
}
