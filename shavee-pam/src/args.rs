use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg};
use std::env;
use std::ffi::OsString;

#[derive(Debug, PartialEq)]
pub enum Mode {
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

pub struct Pargs {
    pub mode: Mode,
    pub dataset: String,
}

impl Pargs {
    // new() function calls new_from() to parse the arguments
    // using this method, it is possible to write unit tests for
    // valid and invalid arguments
    // Read more at:
    // "Command line parsing with clap" https://www.fpcomplete.com/rust/command-line-parsing-clap/
    //
    // No need for the new function in PAM module
    // 
    // pub fn new() -> Self {
    //     Self::new_from(std::env::args_os().into_iter()).unwrap_or_else(|e| e.exit())
    // }

    // new_from() function parses and validates the inputs
    pub fn new_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: Iterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let app = App::new(crate_name!())
            .about(crate_description!()) // Define APP and args
            .author(crate_authors!())
            .version(crate_version!())
            .arg(
                Arg::with_name("yubikey")
                    .long("yubi")
                    .short("y")
                    .help("Use Yubikey HMAC as second factor")
                    .required(false)
                    .takes_value(false)
                    .conflicts_with("keyfile"), // yubikey xor keyfile, not both. 
            )
            .arg(
                Arg::with_name("slot")
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
                Arg::with_name("keyfile")
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
                Arg::with_name("port")
                    .short("P")
                    .long("port")
                    .takes_value(true)
                    .value_name("port number")
                    .required(false)
                    .requires("keyfile")    // port must be accompanied by keyfile option
                    .validator(port_check)  // validate that port parameter is "valid"
                    .help("Set port for HTTP(S) and SFTP requests"),
            )
            .arg(
                Arg::with_name("zset")
                    .short("z")
                    .long("zset")
                    .takes_value(true)
                    .value_name("ZFS dataset")
                    .required(true)
                    .next_line_help(true)   // long help description will be printed in the next line
                    .help("ZFS Dataset eg. \"zroot/data/home\"\n\
                    If present in conjunction with any of the other options, it will try to unlock and mount the \
                    given dataset with the derived key instead of printing it. Takes zfs dataset path as argument. \
                    It will automatically append username in PAM mode."),
            );

        // in order to be able to write unit tests, getting the arg matches
        // shouldn't cause new_from() to exit or panic.
        // PANICS in Prototype code

        let arg = app.get_matches_from_safe(args)?;

        let mut dataset = arg.value_of("zset").unwrap().to_string();

        if dataset.ends_with("/") {
            dataset.pop(); // Sanitise dataset value
        };

        if arg.is_present("yubikey") {
            let slot: u8 = if arg.is_present("slot") {
                arg.value_of("slot").unwrap().parse::<u8>().unwrap()
            } else {
                2
            };
            return Ok(Pargs {
                mode: Mode::Yubikey { yslot: slot },
                dataset: dataset,
            });
        } else if arg.is_present("keyfile") {
            let (file, size) = match arg.values_of("keyfile") {
                Some(value) => parse_file_size_arguments(value)?,
                None => (None, None),
            };
            let port = match arg.value_of("port") {
                Some(e) => Some(e.parse::<u16>().unwrap()),
                None => None,
            };

            return Ok(Pargs {
                mode: Mode::File {
                    file: file.unwrap(),
                    port: port,
                    size: size,
                },
                dataset: dataset,
            });
        }
        // Password if nothing is specified
        else {
            return Ok(Pargs {
                mode: Mode::Password,
                dataset: dataset,
            });
        }
    }
}

// TODO: Write unit test
fn parse_file_size_arguments(
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

fn port_check(v: String) -> Result<(), String> {
    if v.parse::<u16>().is_ok() && v.parse::<u16>().unwrap() != 0 {
        return Ok(());
    } else {
        let error_message = format!(r#""{}" is an invalid port number!"#, v);
        return Err(error_message);
    }
}
