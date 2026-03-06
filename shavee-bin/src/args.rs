use std::sync::Arc;

use clap::builder::{PossibleValuesParser, ValueParser};
use clap::{
    Arg, ArgAction, ArgGroup, ArgMatches, Command, crate_authors, crate_description, crate_name,
    crate_version,
};
use shavee_core::structs::TwoFactorMode;
use shavee_core::zfs::Dataset;

// CLAP Args Validation
const YUBI_SLOTS: [&str; 2] = ["1", "2"];
// CLAP ENV Args
const SHAVEE_CREATE: &str = "SHAVEE_CREATE";
const SHAVEE_YUBIKEY: &str = "SHAVEE_YUBIKEY";
const SHAVEE_MODE_PRINT: &str = "SHAVEE_MODE_PRINT";
const SHAVEE_RECURSIVE: &str = "SHAVEE_MODE_RECURSIVE";
const SHAVEE_AUTO_DETECT: &str = "SHAVEE_AUTO_DETECT";
const SHAVEE_MODE_PRINT_WITH_NAME: &str = "SHAVEE_MODE_PRINT_WITH_NAME";
const SHAVEE_MODE_MOUNT: &str = "SHAVEE_MODE_MOUNT";
const SHAVEE_YUBIKEY_SLOT: &str = "SHAVEE_YUBIKEY_SLOT";
const SHAVEE_ZFS_DATASET: &str = "SHAVEE_ZFS_DATASET";
const SHAVEE_ZFS_KEYFILE: &str = "SHAVEE_ZFS_KEYFILE";
const SHAVEE_FILE_PORT: &str = "SHAVEE_FILE_PORT";

#[derive(Debug, Clone, PartialEq)]
pub enum Operations {
    Create {
        datasets: Arc<[Dataset]>,
    },
    Mount {
        datasets: Arc<[Dataset]>,
        recursive: bool,
    },
    PrintDataset {
        datasets: Arc<[Dataset]>,
        recursive: bool,
        printwithname: bool,
    },
    PrintHelp,
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
        let matches = cli().try_get_matches_from(args)?;
        Self::from_matches(&matches)
    }

    fn from_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        let datasets = parse_datasets(matches)?;
        let datasets: Arc<[Dataset]> = datasets.into();

        let operation = if matches.get_flag("create") {
            Operations::Create { datasets }
        } else if matches.get_flag("mount") {
            Operations::Mount {
                datasets,
                recursive: matches.get_flag("recursive"),
            }
        } else if matches.get_flag("print") {
            Operations::PrintDataset {
                datasets,
                recursive: matches.get_flag("recursive"),
                printwithname: matches.get_flag("printwithname"),
            }
        } else {
            Operations::PrintHelp
        };

        let operation = if matches.get_flag("auto") {
            OperationMode::Auto { operation }
        } else {
            OperationMode::Manual { operation }
        };

        let second_factor = parse_second_factor(matches)?;

        Ok(CliArgs {
            operation,
            second_factor,
        })
    }
}

fn cli() -> Command {
    Command::new(crate_name!())
        .about(crate_description!())
        .author(crate_authors!())
        .version(crate_version!())
        .arg_required_else_help(true)
        .args([
            Arg::new("create")
                .short('c')
                .long("create")
                .env(SHAVEE_CREATE)
                .action(ArgAction::SetTrue)
                .requires("zset")
                .next_line_help(true)
                .help("Create/Change key of a ZFS dataset with the derived encryption key. Must be used with --zset"),
            Arg::new("zset")
                .short('z')
                .long("zset")
                .env(SHAVEE_ZFS_DATASET)
                .num_args(1..)
                .value_name("ZFS dataset")
                .required(true)
                .next_line_help(true)
                .help("ZFS Dataset eg. \"zroot/data/home\"\n\
                       If present in conjunction with any of the other options, it will try to unlock and mount the \
                       given dataset with the derived key instead of printing it. Takes zfs dataset path as argument."),
            Arg::new("yubikey")
                .short('y')
                .long("yubi")
                .env(SHAVEE_YUBIKEY)
                .num_args(0..=1)
                .value_name("Yubikey Serial")
                .value_parser(ValueParser::new(yubikey_serial_parser))
                .help("Use Yubikey HMAC as second factor")
                .hide(!cfg!(feature = "yubikey"))
                .conflicts_with("keyfile"),
            Arg::new("slot")
                .short('s')
                .long("slot")
                .env(SHAVEE_YUBIKEY_SLOT)
                .num_args(1)
                .help("Yubikey HMAC Slot")
                .value_name("HMAC slot")
                .default_value("2")
                .value_parser(PossibleValuesParser::new(YUBI_SLOTS))
                .hide(!cfg!(feature = "yubikey"))
                .requires("yubikey"),
            Arg::new("print")
                .short('p')
                .long("print")
                .env(SHAVEE_MODE_PRINT)
                .action(ArgAction::SetTrue)
                .help("Print Secret key for a Dataset")
                .requires("zset"),
            Arg::new("mount")
                .short('m')
                .long("mount")
                .env(SHAVEE_MODE_MOUNT)
                .action(ArgAction::SetTrue)
                .help("Unlock and Mount Dataset")
                .requires("zset"),
            Arg::new("printwithname")
                .short('d')
                .long("dataset")
                .env(SHAVEE_MODE_PRINT_WITH_NAME)
                .action(ArgAction::SetTrue)
                .help("Print Secret with Dataset name.")
                .requires("zset")
                .requires("print"),
            Arg::new("auto")
                .short('a')
                .long("auto")
                .env(SHAVEE_AUTO_DETECT)
                .action(ArgAction::SetTrue)
                .help("Try to automatically guess the unlock config for a dataset")
                .conflicts_with("create")
                .requires("zset")
                .requires("recursivegroup"),
            Arg::new("recursive")
                .short('r')
                .long("recursive")
                .env(SHAVEE_RECURSIVE)
                .action(ArgAction::SetTrue)
                .help("Perform Mount or Print Operations recursively")
                .requires("zset")
                .requires("recursivegroup"),
            Arg::new("keyfile")
                .short('f')
                .long("file")
                .env(SHAVEE_ZFS_KEYFILE)
                .help("Use any file as second factor, takes filepath, SFTP or a HTTP(S) location as an argument. \
                       If SIZE is entered, the first SIZE in bytes will be used to generate hash. It must be number between \
                       1 and 2^(64).")
                .hide(!cfg!(feature = "file"))
                .value_name("FILE|ADDRESS [SIZE]")
                .num_args(1..=2)
                .conflicts_with("yubikey"),
            Arg::new("port")
                .short('P')
                .long("port")
                .env(SHAVEE_FILE_PORT)
                .num_args(1)
                .value_name("port number")
                .hide(!cfg!(feature = "file"))
                .requires("keyfile")
                .value_parser(clap::value_parser!(u16))
                .help("Set port for HTTP(S) and SFTP requests"),
        ])
        .group(
            ArgGroup::new("recursivegroup")
                .args(["mount", "print"])
                .multiple(false),
        )
}

fn parse_datasets(matches: &ArgMatches) -> Result<Vec<Dataset>, clap::Error> {
    matches
        .get_many::<String>("zset")
        .unwrap_or_default()
        .map(|s| {
            let d = s.trim_end_matches('/');
            Dataset::new(d.to_string())
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| clap::Error::raw(clap::error::ErrorKind::InvalidValue, e.to_string()))
}

fn parse_second_factor(matches: &ArgMatches) -> Result<TwoFactorMode, clap::Error> {
    if matches.contains_id("yubikey") {
        if !cfg!(feature = "yubikey") {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::MissingRequiredArgument,
                "Yubikey feature is disabled at compile.",
            ));
        }

        #[cfg(feature = "yubikey")]
        {
            let yslot = matches
                .get_one::<String>("slot")
                .and_then(|s| s.parse::<u8>().ok());
            let serial = matches.get_one::<u32>("yubikey").copied();
            return Ok(TwoFactorMode::Yubikey { yslot, serial });
        }
    }

    if matches.contains_id("keyfile") {
        if !cfg!(feature = "file") {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::MissingRequiredArgument,
                "File feature is disabled at compile.",
            ));
        }

        #[cfg(feature = "file")]
        {
            let file_args: Vec<String> = matches
                .get_many::<String>("keyfile")
                .expect("keyfile present but no values")
                .cloned()
                .collect();

            let (file, size) = shavee_core::parse_file_size_arguments(&file_args).map_err(|e| {
                clap::Error::raw(clap::error::ErrorKind::InvalidValue, e.to_string())
            })?;

            if file.starts_with('.') {
                eprintln!("File PATH must be absolute eg. \"/mnt/a/test.jpg\"");
                return Err(clap::Error::new(clap::error::ErrorKind::ValueValidation));
            }

            let port = matches.get_one::<u16>("port").copied().filter(|&p| p != 0);

            return Ok(TwoFactorMode::File { file, port, size });
        }
    }

    Ok(TwoFactorMode::Password)
}

fn yubikey_serial_parser(serial: &str) -> Result<u32, std::io::Error> {
    if serial.len() != 8 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid Serial Length",
        ));
    }
    serial
        .parse::<u32>()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid Serial"))
}
// This section implements unit tests for the functions in this module.
// Any code change in this module must pass unit tests below.

// #[cfg(test)]
// mod tests {
//     use super::*;
//     #[test]
//     fn input_args_check() {
//         // defining a struct that will hold input arguments
//         // and their output result
//         struct ArgResultPair<'a> {
//             arg: Vec<&'a str>,
//             result: CliArgs,
//         }

//         // each entry of the array holds the input/output struct
//         let valid_arguments_results_pairs = [
//             ArgResultPair {
//                 arg: vec![], // no argument
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Print,
//                     },
//                     second_factor: TwoFactorMode::Password,
//                 },
//             },
//             ArgResultPair {
//                 arg: vec!["-m", "-z", "zroot/test"], // -z zroot/test
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Mount {
//                             datasets: vec![Dataset::new("zroot/test".to_string()).unwrap()],
//                             recursive: false,
//                         },
//                     },
//                     second_factor: TwoFactorMode::Password,
//                 },
//             },
//             ArgResultPair {
//                 arg: vec!["-c", "-z", "zroot/test"], // -c -z zroot/test
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Create {
//                             datasets: vec![Dataset::new("zroot/test".to_string()).unwrap()],
//                         },
//                     },
//                     second_factor: TwoFactorMode::Password,
//                 },
//             },
//             ArgResultPair {
//                 arg: vec!["--create", "--zset", "zroot/test/"], // --create --zset zroot/test/
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Create {
//                             datasets: vec![Dataset::new("zroot/test".to_string()).unwrap()],
//                         },
//                     },
//                     second_factor: TwoFactorMode::Password,
//                 },
//             },
//             #[cfg(feature = "yubikey")]
//             ArgResultPair {
//                 arg: vec!["-y", "-s", "1", "-c", "-z", "zroot/test/"], // -y -s 1 -c -z zroot/test/
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Create {
//                             datasets: vec![Dataset::new("zroot/test".to_string()).unwrap()],
//                         },
//                     },
//                     second_factor: TwoFactorMode::Yubikey { yslot: 1 },
//                 },
//             },
//             #[cfg(feature = "yubikey")]
//             ArgResultPair {
//                 arg: vec!["-y"], // -y
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Print,
//                     },
//                     second_factor: TwoFactorMode::Yubikey { yslot: 2 },
//                 },
//             },
//             #[cfg(feature = "yubikey")]
//             ArgResultPair {
//                 arg: vec!["-y", "-s", "1"], // -y -s 1
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Print,
//                     },
//                     second_factor: TwoFactorMode::Yubikey { yslot: 1 },
//                 },
//             },
//             #[cfg(feature = "yubikey")]
//             ArgResultPair {
//                 arg: vec!["--yubi", "--slot", "2"], // --yubi --slot 2
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Print,
//                     },
//                     second_factor: TwoFactorMode::Yubikey { yslot: 2 },
//                 },
//             },
//             #[cfg(feature = "file")]
//             ArgResultPair {
//                 // test entry for size argument
//                 arg: vec!["--file", "./shavee", "2048"], // --file ./shavee 2048
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Print,
//                     },
//                     second_factor: TwoFactorMode::File {
//                         file: String::from("./shavee"),
//                         port: None,
//                         size: Some(2048),
//                     },
//                 },
//             },
//             #[cfg(feature = "file")]
//             ArgResultPair {
//                 // test entry for size argument
//                 arg: vec!["--port", "80", "-f", "./shavee", "4096"], // --port 80 --file ./shavee 4096
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Print,
//                     },
//                     second_factor: TwoFactorMode::File {
//                         file: String::from("./shavee"),
//                         port: Some(80),
//                         size: Some(4096),
//                     },
//                 },
//             },
//             #[cfg(feature = "file")]
//             ArgResultPair {
//                 arg: vec!["--file", "./shavee"], // --file ./shavee
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Print,
//                     },
//                     second_factor: TwoFactorMode::File {
//                         file: String::from("./shavee"),
//                         port: None,
//                         size: None,
//                     },
//                 },
//             },
//             #[cfg(feature = "file")]
//             ArgResultPair {
//                 arg: vec!["--port", "80", "-f", "./shavee"], // --port 80 --file ./shavee
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Print,
//                     },
//                     second_factor: TwoFactorMode::File {
//                         file: String::from("./shavee"),
//                         port: Some(80),
//                         size: None,
//                     },
//                 },
//             },
//             #[cfg(feature = "file")]
//             ArgResultPair {
//                 arg: vec!["-P", "443", "-f", "./shavee"], // -P 443 --file ./shavee
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Print,
//                     },
//                     second_factor: TwoFactorMode::File {
//                         file: String::from("./shavee"),
//                         port: Some(443),
//                         size: None,
//                     },
//                 },
//             },
//             #[cfg(feature = "file")]
//             ArgResultPair {
//                 arg: vec!["-m", "-f", "./shavee", "-z", "zroot/test"], // -f ./shavee -z zroot/test
//                 result: CliArgs {
//                     operation: OperationMode::Manual {
//                         operation: Operations::Mount {
//                             datasets: vec![Dataset::new("zroot/test".to_string()).unwrap()],
//                             recursive: false,
//                         },
//                     },
//                     second_factor: TwoFactorMode::File {
//                         file: String::from("./shavee"),
//                         port: None,
//                         size: None,
//                     },
//                 },
//             },
//         ];

//         for index in 0..valid_arguments_results_pairs.len() {
//             let mut args = Vec::new();
//             //note: the first argument is always the executable name: crate_name!()
//             args.push(crate_name!());
//             args.extend(valid_arguments_results_pairs[index].arg.clone());
//             assert_eq!(
//                 CliArgs::new_from(args.iter()).unwrap(),
//                 valid_arguments_results_pairs[index].result
//             );
//         }

//         // For the invalid arguments, there is no output struct and we only check for error

//         let invalid_arguments = [
//             vec!["--zset"],   // --zset
//             vec!["-P"],       // -P
//             vec!["-c"],       // -c
//             vec!["--create"], // --create
//             #[cfg(feature = "yubikey")]
//             vec!["-s"], // -s
//             #[cfg(feature = "yubikey")]
//             vec!["--slot"], // --slot
//             #[cfg(feature = "yubikey")]
//             vec!["--slot", "2"], // --slot 2
//             #[cfg(feature = "yubikey")]
//             vec!["-y", "-s", "3"], // -y -s 3
//             #[cfg(feature = "file")]
//             vec!["--file"], // --file
//             #[cfg(feature = "file")]
//             vec!["-f"], // -f
//             #[cfg(feature = "file")]
//             vec!["--port", "80"], // --port 80
//             #[cfg(feature = "file")]
//             vec!["-z"], // -z
//             #[cfg(any(feature = "file", feature = "yubikey"))]
//             vec!["-y", "-f", "./shavee"], // -y -f ./shavee
//             // The following tests that error is returned when yubikey 2fa is disabled at compile
//             #[cfg(not(feature = "yubikey"))]
//             vec!["-y", "-s", "1", "-c", "-z", "zroot/test/"], // -y -s 1 -c -z zroot/test/
//             #[cfg(not(feature = "yubikey"))]
//             vec!["-y"], // -y
//             #[cfg(not(feature = "yubikey"))]
//             vec!["-y", "-s", "1"], // -y -s 1
//             #[cfg(not(feature = "yubikey"))]
//             vec!["--yubi", "--slot", "2"], // --yubi --slot 2
//             // The following tests that error is returned when file 2fa is disabled at compile
//             #[cfg(not(feature = "file"))]
//             vec!["--file", "./shavee", "2048"], // --file ./shavee 2048
//             #[cfg(not(feature = "file"))]
//             vec!["--port", "80", "-f", "./shavee", "4096"], // --port 80 --file ./shavee 4096
//             #[cfg(not(feature = "file"))]
//             vec!["--file", "./shavee"], // --file ./shavee
//             #[cfg(not(feature = "file"))]
//             vec!["--port", "80", "-f", "./shavee"], // --port 80 --file ./shavee
//             #[cfg(not(feature = "file"))]
//             vec!["-P", "443", "-f", "./shavee"], // -P 443 --file ./shavee
//             #[cfg(not(feature = "file"))]
//             vec!["-f", "./shavee", "-z", "zroot/test"], // -f ./shavee -z zroot/test
//         ];

//         for index in 0..invalid_arguments.len() {
//             let mut args = Vec::new();
//             //note: the first argument is always the executable name: crate_name!()
//             args.push(crate_name!());
//             args.extend(invalid_arguments[index].clone());
//             CliArgs::new_from(args.iter()).unwrap_err();
//         }
//     }
// }
