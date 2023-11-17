use std::u16;

use clap::builder::PossibleValuesParser;
//TODO (Issue #16): Implement clap_config() once it is ported to clap 3.0
use clap::{crate_authors, crate_description, crate_name, crate_version, Arg, ArgMatches, Command};
use shavee_core::structs::TwoFactorMode;
use shavee_core::zfs::Dataset;

#[derive(Debug, Clone, PartialEq)]
pub enum Operations {
    Create {
        dataset: Dataset,
    },
    Mount {
        dataset: Dataset,
        recursive: bool,
    },
    PrintDataset {
        dataset: Dataset,
        recursive: bool,
        printwithname: bool,
    },
    Print,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OperationMode {
    Auto { operation: Operations },
    Manual { operation: Operations },
}

#[derive(Debug, Clone, PartialEq)]
pub struct CliArgs {
    pub operation: OperationMode,
    pub second_factor: shavee_core::structs::TwoFactorMode,
}

/// new() function calls new_from() to parse the arguments
/// using this method, it is possible to write unit tests for
/// valid and invalid arguments
/// Read more at:
/// "Command line parsing with clap" https://www.fpcomplete.com/rust/command-line-parsing-clap/
impl CliArgs {
    pub fn new() -> Self {
        Self::new_from(std::env::args_os().into_iter()).unwrap_or_else(|e| e.exit())
    }

    /// new_from() function parses and validates the inputs
    fn new_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: Iterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let possible_values_slot = ["1", "2"].iter();
        let cli_app = Command::new(crate_name!())
            .about(crate_description!()) // Define APP and args
            .author(crate_authors!())
            .version(crate_version!())
            .arg(
                Arg::new("create")
                    .short('c')
                    .num_args(0)
                    .long("create")
                    .required(false)
                    .requires("zset")
                    .next_line_help(true)   // long help description will be printed in the next line
                    .help("Create/Change key of a ZFS dataset with the derived encryption key. Must be used with --zset"),
            )
            .arg(
                Arg::new("zset")
                    .short('z')
                    .num_args(1)
                    .long("zset")
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
                    .num_args(0)
                    .help("Use Yubikey HMAC as second factor")
                    .required(false)
                    .hide(!cfg!(feature = "yubikey")) // hide it in help if feature is disabled
                    .conflicts_with("keyfile"), // yubikey xor keyfile, not both.
            )
            .arg(
                Arg::new("slot")
                    .short('s')
                    .num_args(1)
                    .long("slot")
                    .help("Yubikey HMAC Slot")
                    .value_name("HMAC slot")
                    .default_value("2")
                    .value_parser(PossibleValuesParser::new(possible_values_slot))
                    .hide(!cfg!(feature = "yubikey")) // hide it in help if feature is disabled
                    .required(false)
                    .requires("yubikey"), // it must be accompanied by yubikey option
            )
            .arg(
                Arg::new("print")
                    .short('p')
                    .long("print")
                    .num_args(0)
                    .help("Print Secret key for a Dataset")
                    .required(false)
                    .requires("zset")
            )
            .arg(
                Arg::new("mount")
                    .short('m')
                    .long("mount")
                    .num_args(0)
                    .help("Unlock and Mount Dataset")
                    .required(false)
                    .requires("zset")
            )
            .arg(
                Arg::new("printwithname")
                    .short('d')
                    .long("dataset")
                    .help("Print Secret with Dataset name.")
                    .required(false)
                    .requires("zset")
                    .num_args(0)
                    .requires("print")
            )
            .arg(
                Arg::new("auto")
                    .short('a')
                    .long("auto")
                    .help("Try to automatically guess the unlock config for a dataset")
                    .required(false)
                    .requires("zset")
                    .num_args(0)
                    .requires("recursivegroup")
            )
            .arg(
                Arg::new("recursive")
                    .short('r')
                    .long("recursive")
                    .help("Perform Mount or Print Operations recursively")
                    .required(false)
                    .requires("zset")
                    .num_args(0)
                    .requires("recursivegroup")
            )
            .group(clap::ArgGroup::new("recursivegroup")
            .args(&["mount", "print","create"])
            .multiple(false))
            .arg(
                Arg::new("keyfile")
                    .short('f')
                    .long("file")
                    .help("Use any file as second factor, takes filepath, SFTP or a HTTP(S) location as an argument. \
                    If SIZE is entered, the first SIZE in bytes will be used to generate hash. It must be number between \
                    1 and 2^(64).")
                    .hide(!cfg!(feature = "file")) // hide it in help if feature is disabled
                    .required(false)
                    .value_name("FILE|ADDRESS [SIZE]")
                    .num_args(1..=2)
                    .conflicts_with("yubikey"), // keyfile xor yubikey, not both.
            )
            .arg(
                Arg::new("port")
                    .short('P')
                    .long("port")
                    .num_args(1)
                    .value_name("port number")
                    .hide(!cfg!(feature = "file"))  // hide it in help if feature is disabled
                    .required(false)
                    .requires("keyfile")
                    .value_parser(clap::value_parser!(u16))    // port must be accompanied by keyfile option
                    .help("Set port for HTTP(S) and SFTP requests"),
            );

        // in order to be able to write unit tests, getting the arg matches
        // shouldn't cause new_from() to exit or panic.
        let arg = cli_app.try_get_matches_from(args)?;

        // check for keyfile argument if parse them if needed.
        // otherwise fill them with None
        #[cfg(feature = "file")]
        let fileargs = arg.get_many("keyfile");
        let (file, size) = match fileargs {
            Some(s) => {
                let a: Vec<&String> = s.collect();
                shavee_core::parse_file_size_arguments(a).expect("Arg Pass error")
            }
            None => (None, None),
        };

        // if zset arg is entered, then its value will be used
        // NOTE: validating dataset is done by zfs module

        let datasetvalue: Option<&String> = arg.get_one("zset");
        let dataset = match datasetvalue {
            Some(d) => {
                let mut d = d.to_owned();
                if d.ends_with("/") {
                    d.pop();
                };
                Some(d.to_owned())
            }
            None => None,
        };

        // The port arguments are <u16> or None (not entered by user)
        #[cfg(feature = "file")]
        let port: Option<&u16> = arg.get_one("port");
        let port = match port {
            Some(p) => {
                let mut p = Some(p.to_owned());
                if p == Some(0) {
                    p = None
                }
                p
            }
            None => None,
        };

        // The accepted slot arguments are Some (1 or 2) or None (not entered by user)
        // Default value if not entered is 2
        #[cfg(feature = "yubikey")]
        let yslot: Option<&String> = arg.get_one("slot");
        let yslot = match yslot {
            Some(s) => s.to_owned(),
            None => 2.to_string(),
        };
        let yslot: u8 = yslot.parse::<u8>().expect("Invalid Port!");

        let operation = if cmdpresent(&arg, "create") {
            let dataset = Dataset::new(dataset.expect(shavee_core::UNREACHABLE_CODE))?;
            Operations::Create { dataset }
        } else if cmdpresent(&arg, "mount") {
            let dataset = Dataset::new(dataset.expect(shavee_core::UNREACHABLE_CODE))?;
            if cmdpresent(&arg, "recursive") {
                Operations::Mount {
                    dataset: dataset,
                    recursive: true,
                }
            } else {
                Operations::Mount {
                    dataset: dataset,
                    recursive: false,
                }
            }
        } else if cmdpresent(&arg, "print") {
            let dataset = Dataset::new(dataset.expect(shavee_core::UNREACHABLE_CODE))?;
            let mut recursive = false;
            let mut printwithname = false;
            if cmdpresent(&arg, "recursive") {
                recursive = true;
            }
            if cmdpresent(&arg, "printwithname") {
                printwithname = true;
            }
            Operations::PrintDataset {
                dataset: dataset,
                recursive: recursive,
                printwithname: printwithname,
            }
        } else {
            Operations::Print
        };

        let operationmode = if cmdpresent(&arg, "auto") {
            OperationMode::Auto {
                operation: operation,
            }
        } else {
            OperationMode::Manual {
                operation: operation,
            }
        };

        // The default mode is Password.
        #[allow(unused_mut)]
        let mut second_factor = TwoFactorMode::Password;
        // if yubikey feature is enabled, check for Yubikey 2FA mode.
        if cmdpresent(&arg, "yubikey") {
            if !cfg!(feature = "yubikey") {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "Yubikey feature is disabled at compile.",
                ));
            }
            #[cfg(feature = "yubikey")]
            {
                second_factor = TwoFactorMode::Yubikey { yslot };
            }
        };

        // if file feature is enabled, check for file 2FA mode
        if cmdpresent(&arg, "keyfile") {
            if !cfg!(feature = "file") {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
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
            operation: operationmode,
            second_factor: second_factor,
        })
    }
}

fn cmdpresent(args: &ArgMatches, cmd: &str) -> bool {
    match args.value_source(cmd) {
        Some(s) => {
            if s == clap::parser::ValueSource::CommandLine {
                return true;
            }
        }
        None => return false,
    };

    false
}
// This section implements unit tests for the functions in this module.
// Any code change in this module must pass unit tests below.

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn input_args_check() {
        // defining a struct that will hold input arguments
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
                    operation: OperationMode::Manual {
                        operation: Operations::Print,
                    },
                    second_factor: TwoFactorMode::Password,
                },
            },
            ArgResultPair {
                arg: vec!["-m", "-z", "zroot/test"], // -z zroot/test
                result: CliArgs {
                    operation: OperationMode::Manual {
                        operation: Operations::Mount {
                            dataset: Dataset::new("zroot/test".to_string()).unwrap(),
                            recursive: false,
                        },
                    },
                    second_factor: TwoFactorMode::Password,
                },
            },
            ArgResultPair {
                arg: vec!["-c", "-z", "zroot/test"], // -c -z zroot/test
                result: CliArgs {
                    operation: OperationMode::Manual {
                        operation: Operations::Create {
                            dataset: Dataset::new("zroot/test".to_string()).unwrap(),
                        },
                    },
                    second_factor: TwoFactorMode::Password,
                },
            },
            ArgResultPair {
                arg: vec!["--create", "--zset", "zroot/test/"], // --create --zset zroot/test/
                result: CliArgs {
                    operation: OperationMode::Manual {
                        operation: Operations::Create {
                            dataset: Dataset::new("zroot/test".to_string()).unwrap(),
                        },
                    },
                    second_factor: TwoFactorMode::Password,
                },
            },
            #[cfg(feature = "yubikey")]
            ArgResultPair {
                arg: vec!["-y", "-s", "1", "-c", "-z", "zroot/test/"], // -y -s 1 -c -z zroot/test/
                result: CliArgs {
                    operation: OperationMode::Manual {
                        operation: Operations::Create {
                            dataset: Dataset::new("zroot/test".to_string()).unwrap(),
                        },
                    },
                    second_factor: TwoFactorMode::Yubikey { yslot: 1 },
                },
            },
            #[cfg(feature = "yubikey")]
            ArgResultPair {
                arg: vec!["-y"], // -y
                result: CliArgs {
                    operation: OperationMode::Manual {
                        operation: Operations::Print,
                    },
                    second_factor: TwoFactorMode::Yubikey { yslot: 2 },
                },
            },
            #[cfg(feature = "yubikey")]
            ArgResultPair {
                arg: vec!["-y", "-s", "1"], // -y -s 1
                result: CliArgs {
                    operation: OperationMode::Manual {
                        operation: Operations::Print,
                    },
                    second_factor: TwoFactorMode::Yubikey { yslot: 1 },
                },
            },
            #[cfg(feature = "yubikey")]
            ArgResultPair {
                arg: vec!["--yubi", "--slot", "2"], // --yubi --slot 2
                result: CliArgs {
                    operation: OperationMode::Manual {
                        operation: Operations::Print,
                    },
                    second_factor: TwoFactorMode::Yubikey { yslot: 2 },
                },
            },
            #[cfg(feature = "file")]
            ArgResultPair {
                // test entry for size argument
                arg: vec!["--file", "./shavee", "2048"], // --file ./shavee 2048
                result: CliArgs {
                    operation: OperationMode::Manual {
                        operation: Operations::Print,
                    },
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
                    operation: OperationMode::Manual {
                        operation: Operations::Print,
                    },
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
                    operation: OperationMode::Manual {
                        operation: Operations::Print,
                    },
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
                    operation: OperationMode::Manual {
                        operation: Operations::Print,
                    },
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
                    operation: OperationMode::Manual {
                        operation: Operations::Print,
                    },
                    second_factor: TwoFactorMode::File {
                        file: String::from("./shavee"),
                        port: Some(443),
                        size: None,
                    },
                },
            },
            #[cfg(feature = "file")]
            ArgResultPair {
                arg: vec!["-m", "-f", "./shavee", "-z", "zroot/test"], // -f ./shavee -z zroot/test
                result: CliArgs {
                    operation: OperationMode::Manual {
                        operation: Operations::Mount {
                            dataset: Dataset::new("zroot/test".to_string()).unwrap(),
                            recursive: false,
                        },
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
