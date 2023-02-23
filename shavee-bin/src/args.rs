//TODO (Issue #16): Implement clap_config() once it is ported to clap 3.0
use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg};
use shavee_core::zfs::Dataset;

#[derive(Debug, Clone, PartialEq)]
pub enum TwoFactorMode {
    #[cfg(feature = "yubikey")]
    Yubikey {
        yslot: u8,
    },
    #[cfg(feature = "file")]
    File {
        file: String,
        port: Option<u16>,
        size: Option<u64>,
    },
    Password,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OperationMode {
    Create { dataset: Dataset },
    Mount { dataset: Dataset },
    Print,
}
#[derive(Debug, Clone, PartialEq)]
pub struct CliArgs {
    pub operation: OperationMode,
    pub second_factor: TwoFactorMode,
}

impl CliArgs {
    // new() function calls new_from() to parse the arguments
    // using this method, it is possible to write unit tests for
    // valid and invalid arguments
    // Read more at:
    // "Command line parsing with clap" https://www.fpcomplete.com/rust/command-line-parsing-clap/
    pub fn new() -> Self {
        Self::new_from(std::env::args_os().into_iter()).unwrap_or_else(|e| e.exit())
    }

    // new_from() function parses and validates the inputs
    fn new_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: Iterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cli_app = App::new(crate_name!())
            .about(crate_description!()) // Define APP and args
            .author(crate_authors!())
            .version(crate_version!())
            .arg(
                Arg::new("create")
                    .short('c')
                    .long("create")
                    .takes_value(false)
                    .required(false)
                    .requires("zset")
                    .next_line_help(true)   // long help description will be printed in the next line
                    .help("Create/Change key of a ZFS dataset with the derived encryption key. Must be used with --zset"),
            )
            .arg(
                Arg::new("zset")
                    .short('z')
                    .long("zset")
                    .takes_value(true)
                    .value_name("ZFS dataset")
                    .required(false)
                    .next_line_help(true)   // long help description will be printed in the next line
                    .help("ZFS Dataset eg. \"zroot/data/home\"\n\
                    If present in conjunction with any of the other options, it will try to unlock and mount the \
                    given dataset with the derived key instead of printing it. Takes zfs dataset path as argument."),
            )
            .arg(
                Arg::new("yubikey")
                    .long("yubi")
                    .short('y')
                    .help("Use Yubikey HMAC as second factor")
                    .required(false)
                    .takes_value(false)
                    .hide(!cfg!(feature = "yubikey")) // hide it in help if feature is disabled
                    .conflicts_with("keyfile"), // yubikey xor keyfile, not both.
            )
            .arg(
                Arg::new("slot")
                    .short('s')
                    .long("slot")
                    .help("Yubikey HMAC Slot")
                    .takes_value(true)
                    .value_name("HMAC slot")
                    .possible_values(&["1", "2"]) // putting limit on acceptable inputs
                    .hide(!cfg!(feature = "yubikey")) // hide it in help if feature is disabled
                    .required(false)
                    .requires("yubikey"), // it must be accompanied by yubikey option
            )
            .arg(
                Arg::new("keyfile")
                    .short('f')
                    .long("file")
                    .help("Use any file as second factor, takes filepath, SFTP or a HTTP(S) location as an argument. \
                    If SIZE is entered, the first SIZE in bytes will be used to generate hash. It must be number between \
                    1 and 2^(64).")
                    .hide(!cfg!(feature = "file")) // hide it in help if feature is disabled
                    .required(false)
                    .takes_value(true)
                    .value_name("FILE|ADDRESS [SIZE]")
                    .max_values(2)
                    .conflicts_with("yubikey"), // keyfile xor yubikey, not both.
            )
            .arg(
                Arg::new("port")
                    .short('P')
                    .long("port")
                    .takes_value(true)
                    .value_name("port number")
                    .hide(!cfg!(feature = "file"))  // hide it in help if feature is disabled
                    .required(false)
                    .requires("keyfile")    // port must be accompanied by keyfile option
                    .validator(shavee_core::port_check)  // validate that port parameter is "valid"
                    .help("Set port for HTTP(S) and SFTP requests"),
            );

        // in order to be able to write unit tests, getting the arg matches
        // shouldn't cause new_from() to exit or panic.
        let arg = cli_app.try_get_matches_from(args)?;

        // check for keyfile argument if parse them if needed.
        // otherwise fill them with None
        #[cfg(feature = "file")]
        let (file, size) = match arg.values_of("keyfile") {
            Some(values) => {
                // convert the values to a vector
                let file_size_argument: Vec<&str> = values.collect();
                shavee_core::parse_file_size_arguments(file_size_argument)?
            }
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
        #[cfg(feature = "file")]
        let port = arg
            .value_of("port")
            .map(|p| p.parse::<u16>().expect(shavee_core::UNREACHABLE_CODE));

        // The accepted slot arguments are Some (1 or 2) or None (not entered by user)
        // Default value if not entered is 2
        #[cfg(feature = "yubikey")]
        let yslot = match arg.value_of("slot") {
            // exceptions should not happen, because the entry is already validated by clap
            Some(s) => s.parse::<u8>().expect(shavee_core::UNREACHABLE_CODE),
            None => 2,
        };

        let operation = if arg.is_present("create") {
            let dataset = Dataset::new(dataset.expect(shavee_core::UNREACHABLE_CODE))?;
            OperationMode::Create { dataset }
        } else if arg.is_present("zset") {
            let dataset = Dataset::new(dataset.expect(shavee_core::UNREACHABLE_CODE))?;
            OperationMode::Mount { dataset }
        } else {
            OperationMode::Print
        };

        // The default mode is Password.
        #[allow(unused_mut)]
        let mut second_factor = TwoFactorMode::Password;

        // if yubikey feature is enabled, check for Yubikey 2FA mode.
        if arg.is_present("yubikey") {
            if !cfg!(feature = "yubikey") {
                return Err(clap::Error::raw(
                    clap::ErrorKind::ArgumentNotFound,
                    "Yubikey feature is disabled at compile.",
                ));
            }
            #[cfg(feature = "yubikey")]
            {
                second_factor = TwoFactorMode::Yubikey { yslot };
            }
        };

        // if file feature is enabled, check for file 2FA mode
        if arg.is_present("keyfile") {
            if !cfg!(feature = "file") {
                return Err(clap::Error::raw(
                    clap::ErrorKind::ArgumentNotFound,
                    "File 2FA feature is disabled at compile.",
                ));
            }
            #[cfg(feature = "file")]
            {
                let file = file.expect(shavee_core::UNREACHABLE_CODE);
                second_factor = TwoFactorMode::File { file, port, size };
            }
        };

        Ok(CliArgs {
            operation,
            second_factor,
        })
    }
}

// This section implements unit tests for the functions in this module.
// Any code change in this module must pass unit tests below.
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn input_args_check() {
        // defining a struct that will hold intput arguments
        // and their output result
        struct ArgResultPair<'a> {
            arg: Vec<&'a str>,
            result: CliArgs,
        }

        // each entry of the array holds the input/output struct
        let valid_arguments_results_pairs = [
            ArgResultPair {
                arg: vec![], // no argument
                result: CliArgs {
                    operation: OperationMode::Print,
                    second_factor: TwoFactorMode::Password,
                },
            },
            ArgResultPair {
                arg: vec!["-z", "zroot/test"], // -z zroot/test
                result: CliArgs {
                    operation: OperationMode::Mount {
                        dataset: Dataset::new("zroot/test".to_string()).unwrap(),
                    },
                    second_factor: TwoFactorMode::Password,
                },
            },
            ArgResultPair {
                arg: vec!["-c", "-z", "zroot/test"], // -c -z zroot/test
                result: CliArgs {
                    operation: OperationMode::Create {
                        dataset: Dataset::new("zroot/test".to_string()).unwrap(),
                    },
                    second_factor: TwoFactorMode::Password,
                },
            },
            ArgResultPair {
                arg: vec!["--create", "--zset", "zroot/test/"], // --create --zset zroot/test/
                result: CliArgs {
                    operation: OperationMode::Create {
                        dataset: Dataset::new("zroot/test".to_string()).unwrap(),
                    },
                    second_factor: TwoFactorMode::Password,
                },
            },
            #[cfg(feature = "yubikey")]
            ArgResultPair {
                arg: vec!["-y", "-s", "1", "-c", "-z", "zroot/test/"], // -y -s 1 -c -z zroot/test/
                result: CliArgs {
                    operation: OperationMode::Create {
                        dataset: Dataset::new("zroot/test".to_string()).unwrap(),
                    },
                    second_factor: TwoFactorMode::Yubikey { yslot: 1 },
                },
            },
            #[cfg(feature = "yubikey")]
            ArgResultPair {
                arg: vec!["-y"], // -y
                result: CliArgs {
                    operation: OperationMode::Print,
                    second_factor: TwoFactorMode::Yubikey { yslot: 2 },
                },
            },
            #[cfg(feature = "yubikey")]
            ArgResultPair {
                arg: vec!["-y", "-s", "1"], // -y -s 1
                result: CliArgs {
                    operation: OperationMode::Print,
                    second_factor: TwoFactorMode::Yubikey { yslot: 1 },
                },
            },
            #[cfg(feature = "yubikey")]
            ArgResultPair {
                arg: vec!["--yubi", "--slot", "2"], // --yubi --slot 2
                result: CliArgs {
                    operation: OperationMode::Print,
                    second_factor: TwoFactorMode::Yubikey { yslot: 2 },
                },
            },
            #[cfg(feature = "file")]
            ArgResultPair {
                // test entry for size argument
                arg: vec!["--file", "./shavee", "2048"], // --file ./shavee 2048
                result: CliArgs {
                    operation: OperationMode::Print,
                    second_factor: TwoFactorMode::File {
                        file: String::from("./shavee"),
                        port: None,
                        size: Some(2048),
                    },
                },
            },
            #[cfg(feature = "file")]
            ArgResultPair {
                // test entry for size argument
                arg: vec!["--port", "80", "-f", "./shavee", "4096"], // --port 80 --file ./shavee 4096
                result: CliArgs {
                    operation: OperationMode::Print,
                    second_factor: TwoFactorMode::File {
                        file: String::from("./shavee"),
                        port: Some(80),
                        size: Some(4096),
                    },
                },
            },
            #[cfg(feature = "file")]
            ArgResultPair {
                arg: vec!["--file", "./shavee"], // --file ./shavee
                result: CliArgs {
                    operation: OperationMode::Print,
                    second_factor: TwoFactorMode::File {
                        file: String::from("./shavee"),
                        port: None,
                        size: None,
                    },
                },
            },
            #[cfg(feature = "file")]
            ArgResultPair {
                arg: vec!["--port", "80", "-f", "./shavee"], // --port 80 --file ./shavee
                result: CliArgs {
                    operation: OperationMode::Print,
                    second_factor: TwoFactorMode::File {
                        file: String::from("./shavee"),
                        port: Some(80),
                        size: None,
                    },
                },
            },
            #[cfg(feature = "file")]
            ArgResultPair {
                arg: vec!["-P", "443", "-f", "./shavee"], // -P 443 --file ./shavee
                result: CliArgs {
                    operation: OperationMode::Print,
                    second_factor: TwoFactorMode::File {
                        file: String::from("./shavee"),
                        port: Some(443),
                        size: None,
                    },
                },
            },
            #[cfg(feature = "file")]
            ArgResultPair {
                arg: vec!["-f", "./shavee", "-z", "zroot/test"], // -f ./shavee -z zroot/test
                result: CliArgs {
                    operation: OperationMode::Mount {
                        dataset: Dataset::new("zroot/test".to_string()).unwrap(),
                    },
                    second_factor: TwoFactorMode::File {
                        file: String::from("./shavee"),
                        port: None,
                        size: None,
                    },
                },
            },
        ];

        for index in 0..valid_arguments_results_pairs.len() {
            let mut args = Vec::new();
            //note: the first argument is always the executable name: crate_name!()
            args.push(crate_name!());
            args.extend(valid_arguments_results_pairs[index].arg.clone());
            assert_eq!(
                CliArgs::new_from(args.iter()).unwrap(),
                valid_arguments_results_pairs[index].result
            );
        }

        // For the invalid arguments, there is no output struct and we only check for error

        let invalid_arguments = [
            vec!["--zset"],   // --zset
            vec!["-P"],       // -P
            vec!["-c"],       // -c
            vec!["--create"], // --create
            #[cfg(feature = "yubikey")]
            vec!["-s"], // -s
            #[cfg(feature = "yubikey")]
            vec!["--slot"], // --slot
            #[cfg(feature = "yubikey")]
            vec!["--slot", "2"], // --slot 2
            #[cfg(feature = "yubikey")]
            vec!["-y", "-s", "3"], // -y -s 3
            #[cfg(feature = "file")]
            vec!["--file"], // --file
            #[cfg(feature = "file")]
            vec!["-f"], // -f
            #[cfg(feature = "file")]
            vec!["--port", "80"], // --port 80
            #[cfg(feature = "file")]
            vec!["-z"], // -z
            #[cfg(feature = "file")]
            vec!["-P", "0", "-f", "./shavee"], // -P 0 -f ./shavee
            #[cfg(any(feature = "file", feature = "yubikey"))]
            vec!["-y", "-f", "./shavee"], // -y -f ./shavee
            // The following tests that error is returned when yubikey 2fa is disabled at compile
            #[cfg(not(feature = "yubikey"))]
            vec!["-y", "-s", "1", "-c", "-z", "zroot/test/"], // -y -s 1 -c -z zroot/test/
            #[cfg(not(feature = "yubikey"))]
            vec!["-y"], // -y
            #[cfg(not(feature = "yubikey"))]
            vec!["-y", "-s", "1"], // -y -s 1
            #[cfg(not(feature = "yubikey"))]
            vec!["--yubi", "--slot", "2"], // --yubi --slot 2
            // The following tests that error is returned when file 2fa is disabled at compile
            #[cfg(not(feature = "file"))]
            vec!["--file", "./shavee", "2048"], // --file ./shavee 2048
            #[cfg(not(feature = "file"))]
            vec!["--port", "80", "-f", "./shavee", "4096"], // --port 80 --file ./shavee 4096
            #[cfg(not(feature = "file"))]
            vec!["--file", "./shavee"], // --file ./shavee
            #[cfg(not(feature = "file"))]
            vec!["--port", "80", "-f", "./shavee"], // --port 80 --file ./shavee
            #[cfg(not(feature = "file"))]
            vec!["-P", "443", "-f", "./shavee"], // -P 443 --file ./shavee
            #[cfg(not(feature = "file"))]
            vec!["-f", "./shavee", "-z", "zroot/test"], // -f ./shavee -z zroot/test
        ];

        for index in 0..invalid_arguments.len() {
            let mut args = Vec::new();
            //note: the first argument is always the executable name: crate_name!()
            args.push(crate_name!());
            args.extend(invalid_arguments[index].clone());
            CliArgs::new_from(args.iter()).unwrap_err();
        }
    }
}
