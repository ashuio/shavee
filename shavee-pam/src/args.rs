use clap::{App, Arg};
use shavee_lib;
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

pub struct Pargs {
    pub umode: Umode,
    pub dataset: String,
}

impl Pargs {
    // new_from() function parses and validates the inputs
    pub fn new_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: Iterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let pam_app = App::new("libshavee_pam.so")
        .arg(
            clap::Arg::with_name("verbose")
                .long("verbose")
                .short("v")
                .help("Enables verbose error messages.")
                .required(false)
                .takes_value(false)
        )
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
                .validator(shavee_lib::port_check)  // validate that port parameter is "valid"
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
                    given dataset with the derived key instead of printing it. Takes zfs dataset path as argument and \
                    it will automatically append login username"),
            );

        // in order to be able to write unit tests, getting the arg matches
        // shouldn't cause new_from() to exit or panic.
        let arg = pam_app.get_matches_from_safe(args)?;

        // check for keyfile argument if parse them if needed.
        // otherwise fill them with None
        let (file, size) = match arg.values_of("keyfile") {
            Some(value) => shavee_lib::parse_file_size_arguments(value)?,
            None => (None, None),
        };

        // if zset arg is entered, then its value will be used
        // NOTE: validating dataset is done by zfs module
        let dataset = match arg.value_of("zset").map(str::to_string) {
            Some(mut s) => {
                if s.ends_with("/") {
                    s.pop();
                };
                s
            }
            None => {
                let error_message = r#"Dataset must be specified!"#;
                return Err(clap::Error::with_description(
                    error_message,
                    clap::ErrorKind::EmptyValue,
                ));
            }
        };

        // The port arguments are <u16> or None (not entered by user)
        let port = arg
            .value_of("port")
            .map(|p| p.parse::<u16>().expect(shavee_lib::UNREACHABLE_CODE));

        // The accepted slot arguments are Some (1 or 2) or None (not entered by user)
        // Default value if not entered is 2
        let yslot = match arg.value_of("slot") {
            // exceptions should not happen, because the entry is already validated by clap
            Some(s) => s.parse::<u8>().expect(shavee_lib::UNREACHABLE_CODE),
            None => 2,
        };

        let umode = if arg.is_present("yubikey") {
            Umode::Yubikey { yslot }
        } else if arg.is_present("keyfile") {
            let file = file.expect(shavee_lib::UNREACHABLE_CODE);
            Umode::File { file, port, size }
        } else {
            Umode::Password
        };

        Ok(Pargs { umode, dataset })
    }
}
