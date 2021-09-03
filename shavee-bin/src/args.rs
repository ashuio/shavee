use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg};
use shavee_lib::{Umode,Mode, common_args};
use std::env;
use std::ffi::OsString;

#[derive(Debug, PartialEq)]
pub struct Sargs {
    pub mode: Mode,
    pub umode: Umode,
}

impl Sargs {
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
        T: Into<OsString> + Clone,
    {
        let cli_app = App::new(crate_name!())
            .about(crate_description!()) // Define APP and args
            .author(crate_authors!())
            .version(crate_version!())
            .arg(
                Arg::with_name("create")
                    .short("c")
                    .long("create")
                    .takes_value(false)
                    .required(false)
                    .requires("zset")
                    .next_line_help(true)   // long help description will be printed in the next line
                    .help("Create/Change key of a ZFS dataset with the derived encryption key. Must be used with --zset"),
            )
            .arg(
                Arg::with_name("zset")
                    .short("z")
                    .long("zset")
                    .takes_value(true)
                    .value_name("ZFS dataset")
                    .required(false)
                    .next_line_help(true)   // long help description will be printed in the next line
                    .help("ZFS Dataset eg. \"zroot/data/home\"\n\
                    If present in conjunction with any of the other options, it will try to unlock and mount the \
                    given dataset with the derived key instead of printing it. Takes zfs dataset path as argument."),
            );
        let (mode, umode) = common_args(cli_app, args)?;
        Ok(Sargs { mode, umode })
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
            result: Sargs,
        }

        // each entry of the array holds the input/output struct
        let valid_arguments_results_pairs = [
            ArgResultPair {
                arg: vec![], // no argument
                result: Sargs {
                    mode: Mode::Print,
                    umode: Umode::Password,
                },
            },
            ArgResultPair {
                arg: vec!["-y"], // -y
                result: Sargs {
                    mode: Mode::Print,
                    umode: Umode::Yubikey { yslot: 2 },
                },
            },
            ArgResultPair {
                arg: vec!["-y", "-s", "1"], // -y -s 1
                result: Sargs {
                    mode: Mode::Print,
                    umode: Umode::Yubikey { yslot: 1 },
                },
            },
            ArgResultPair {
                arg: vec!["--yubi", "--slot", "2"], // --yubi --slot 2
                result: Sargs {
                    mode: Mode::Print,
                    umode: Umode::Yubikey { yslot: 2 },
                },
            },
            ArgResultPair {
                // test entry for size argument
                arg: vec!["--file", "./shavee", "2048"], // --file ./shavee 2048
                result: Sargs {
                    mode: Mode::Print,
                    umode: Umode::File {
                        file: String::from("./shavee"),
                        port: None,
                        size: Some(2048),
                    },
                },
            },
            ArgResultPair {
                // test entry for size argument
                arg: vec!["--port", "80", "-f", "./shavee", "4096"], // --port 80 --file ./shavee 4096
                result: Sargs {
                    mode: Mode::Print,
                    umode: Umode::File {
                        file: String::from("./shavee"),
                        port: Some(80),
                        size: Some(4096),
                    },
                },
            },
            ArgResultPair {
                arg: vec!["--file", "./shavee"], // --file ./shavee
                result: Sargs {
                    mode: Mode::Print,
                    umode: Umode::File {
                        file: String::from("./shavee"),
                        port: None,
                        size: None,
                    },
                },
            },
            ArgResultPair {
                arg: vec!["--port", "80", "-f", "./shavee"], // --port 80 --file ./shavee
                result: Sargs {
                    mode: Mode::Print,
                    umode: Umode::File {
                        file: String::from("./shavee"),
                        port: Some(80),
                        size: None,
                    },
                },
            },
            ArgResultPair {
                arg: vec!["-P", "443", "-f", "./shavee"], // -P 443 --file ./shavee
                result: Sargs {
                    mode: Mode::Print,
                    umode: Umode::File {
                        file: String::from("./shavee"),
                        port: Some(443),
                        size: None,
                    },
                },
            },
            ArgResultPair {
                arg: vec!["-z", "zroot/test"], // -z zroot/test
                result: Sargs {
                    mode: Mode::Mount {
                        dataset: String::from("zroot/test"),
                    },
                    umode: Umode::Password,
                },
            },
            ArgResultPair {
                arg: vec!["-f", "./shavee", "-z", "zroot/test"], // -f ./shavee -z zroot/test
                result: Sargs {
                    mode: Mode::Mount {
                        dataset: String::from("zroot/test"),
                    },
                    umode: Umode::File {
                        file: String::from("./shavee"),
                        port: None,
                        size: None,
                    },
                },
            },
            ArgResultPair {
                arg: vec!["-c", "-z", "zroot/test"], // -c -z zroot/test
                result: Sargs {
                    mode: Mode::Create {
                        dataset: String::from("zroot/test"),
                    },
                    umode: Umode::Password,
                },
            },
            ArgResultPair {
                arg: vec!["--create", "--zset", "zroot/test/"], // --create --zset zroot/test/
                result: Sargs {
                    mode: Mode::Create {
                        dataset: String::from("zroot/test"),
                    },
                    umode: Umode::Password,
                },
            },
            ArgResultPair {
                arg: vec!["-y", "-s", "1", "-c", "-z", "zroot/test/"], // -y -s 1 -c -z zroot/test/
                result: Sargs {
                    mode: Mode::Create {
                        dataset: String::from("zroot/test"),
                    },
                    umode: Umode::Yubikey { yslot: 1 },
                },
            },
        ];

        for index in 0..valid_arguments_results_pairs.len() {
            let mut args = Vec::new();
            //note: the first argument is always the executable name: crate_name!()
            args.push(crate_name!());
            args.extend(valid_arguments_results_pairs[index].arg.clone());
            assert_eq!(
                Sargs::new_from(args.iter()).unwrap(),
                valid_arguments_results_pairs[index].result
            );
        }

        // For the invalid arguments, there is no output struct and we only check for error

        let invalid_arguments = [
            vec!["-s"],                        // -s
            vec!["--slot"],                    // --slot
            vec!["--slot", "2"],               // --slot 2
            vec!["-y", "-s", "3"],             // -y -s 3
            vec!["--file"],                    // --file
            vec!["-f"],                        // -f
            vec!["-y", "-f", "./shavee"],      // -y -f ./shavee
            vec!["-z"],                        // -z
            vec!["--zset"],                    // --zset
            vec!["--port", "80"],              // --port 80
            vec!["-P"],                        // -P
            vec!["-P", "0", "-f", "./shavee"], // -P 0 -f ./shavee
            vec!["-c"],                        // -c
            vec!["--create"],                  // --create
        ];

        for index in 0..invalid_arguments.len() {
            let mut args = Vec::new();
            //note: the first argument is always the executable name: crate_name!()
            args.push(crate_name!());
            args.extend(invalid_arguments[index].clone());
            Sargs::new_from(args.iter()).unwrap_err();
        }
    }
}
