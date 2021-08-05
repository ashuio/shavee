/*
MIT License

Copyright (c) 2021 Google LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/ 

const UNREACHABLE_CODE : &str = "Panic! Something unexpected happened! Please help by reporting it as a bug.";

use std::env;
use std::ffi::OsString;
use clap::{App, Arg, crate_authors, crate_description, crate_name, crate_version};

#[derive(Debug, PartialEq)]

pub struct Sargs {
    pub mode: String,
    pub port: u16,
    pub file: String,       // TODO: use Option() to avoid need for NULL
    pub yslot: u8,
    pub umode: String,
    pub dataset: String,    // TODO: use Option() to avoid need for NULL
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
                    .help("Use any file as second factor, takes filepath, SFTP or a HTTP(S) location as an argument")
                    .required(false)
                    .takes_value(true)
                    .value_name("FILE or ADDRESS")
                    .conflicts_with("yubikey"), // keyfile xor yubikey, not both.
            )
            .arg(
                Arg::with_name("pam")
                    .short("p")
                    .long("pam")
                    .takes_value(false)
                    .required(false)
                    .help("Enable PAM mode")
                    .conflicts_with("create")
                    .requires("user")   // It requires PAM_USER env variable
                    .requires("zset"),  // PAM must be accompanied by zset dataset
            )
            .arg(   // PAM_USER evn variable is validated and captured using clap
                Arg::with_name("user")
                    .help("Error: PAM_USER environment variable in not set")
                    .value_name("PAM_USER environment variable")
                    .takes_value(true)
                    .required(false)
                    .env("PAM_USER")
                    .hide_env_values(true)
                    .hidden(true),
            )
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
                    .required(false)
                    .next_line_help(true)   // long help description will be printed in the next line
                    .help("ZFS Dataset eg. \"zroot/data/home\"\n\
                    If present in conjunction with any of the other options, it will try to unlock and mount the \
                    given dataset with the derived key instead of printing it. Takes zfs dataset path as argument. \
                    It will automatically append username in PAM mode."),
            );
        
        // in order to be able to write unit tests, getting the arg matches
        // shouldn't cause new_from() to exit or panic.
        let arg = app.get_matches_from_safe(args)?;

        // if keyfile arg is entered, then its value will be used
        // if not, then pass "NULL"
        // // exceptions should not happen, because the entry is already validated by clap
        let file = match arg.value_of("keyfile") {
            Some(s) => s.to_string(),
            None => "NULL".to_string(),
        };

        // if zset arg is entered, then its value will be used
        // if not, then pass "NULL"
        // NOTE: validating dataset is done in zfs.rs module
        let mut dataset = match arg.value_of("zset") {
            Some(s) => {
                let mut s = s.to_string();
                // remove the trailing '/' from dataset if entered
                if s.ends_with("/") {
                    s.pop();
                }
                s 
            },
            None => "NULL".to_string(),
        };

        // The port arguments are <u16> or None (not entered by user)
        // If None, then 0 is passed back
        let port: u16 = match arg.value_of("port") {
            // exceptions should not happen, because the entry is already validated by clap
            Some(s)   => s.parse::<u16>().expect(UNREACHABLE_CODE), 
            None  => 0,
        };

        // The accepted slot arguments are Some (1 or 2) or None (not entered by user)
        // Default value if not entered is 2
        let yslot = match arg.value_of("slot") {
            // exceptions should not happen, because the entry is already validated by clap
            Some(s)   => s.parse::<u8>().expect (UNREACHABLE_CODE), 
            None  => 2,
        };

        let mode = if arg.is_present("pam") {
                // If PAM mode is enabled, then the user name from PAM_USER
                // environment variable is added to the end of ZFS dataset
                // before it is mounted.
                // Clap has already validated PAM_USER existence.
                dataset.push('/');
                dataset.push_str(env::var("PAM_USER").expect(UNREACHABLE_CODE).as_str());
                String::from("pam")
            } else if arg.is_present("create") {
                String::from("create")
            } else if arg.is_present("zset") {
                String::from("mount")
            } else {
                String::from("print")
        };

        let umode = if arg.is_present("yubikey") {
                String::from("yubikey")
            } else if arg.is_present("keyfile") {
                String::from("file")
            } else {
                String::from("password")
        };

        Ok(Sargs {
            mode,
            port,
            file,
            yslot,
            umode,
            dataset,
        })
    }
}

fn port_check(v: String) -> Result<(), String> {
    if v.parse::<u16>().is_ok() && v.parse::<u16>().unwrap() != 0 {
        return Ok(());
    } else {
        return Err(String::from("Error: Invalid port"));
    }
}

// This section implements unit tests for the functions in this module.
// Any code change in this module must pass unit tests below.
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
                Err(_) => panic!("The port number {} should have been accepted!",valid_port),
                Ok(()) => continue,
           }
        }

        //Few examples of invalid ports. Important to have the boundary values tested.
	    //Port 0 is reserved by IANA, it is technically invalid to use.
        let invalid_ports = ["-1", "65536", "a", "0"];
        for invalid_port in invalid_ports {
            match port_check(invalid_port.to_string()) {
                Ok(()) => panic!("The port number {} should not have been accepted!",invalid_port),
                Err(_) => continue,
           }
        }
    }
    
    #[test]
    fn input_args_check() {

        // defining a struct that will hold intput arguments 
        // and their output result
        struct ArgResultPair<'a> {
            arg: Vec<&'a str>,
            result: Sargs,
        }

        // Set environment variable for PAM unit test
        env::set_var("PAM_USER", "shavee");

        // each entry of the array holds the input/output struct
        let valid_arguments_results_pairs = [
            ArgResultPair {
                arg: vec![],    // no argument
                result: Sargs {
                    mode: String::from("print"),
                    port: 0,
                    file: "NULL".to_string(),
                    yslot: 2,
                    umode: String::from("password"),
                    dataset: "NULL".to_string()
                }
            },
            ArgResultPair {
                arg: vec!["-y"],    // -y
                result: Sargs {
                    mode: String::from("print"),
                    port: 0,
                    file: "NULL".to_string(),
                    yslot: 2,
                    umode: String::from("yubikey"),
                    dataset: "NULL".to_string()
                }
            },
            ArgResultPair {
                arg: vec!["-y", "-s", "1"], // -y -s 1
                result: Sargs {
                    mode: String::from("print"),
                    port: 0,
                    file: "NULL".to_string(),
                    yslot: 1,
                    umode: String::from("yubikey"),
                    dataset: "NULL".to_string()
                }
            },
            ArgResultPair {
                arg: vec!["--yubi", "--slot", "2"], // --yubi --slot 2
                result: Sargs {
                    mode: String::from("print"),
                    port: 0,
                    file: "NULL".to_string(),
                    yslot: 2,
                    umode: String::from("yubikey"),
                    dataset: "NULL".to_string()
                }
            },
            ArgResultPair {
                arg: vec!["--file", "./shavee"],    // --file ./shavee
                result: Sargs {
                    mode: String::from("print"),
                    port: 0,
                    file: String::from("./shavee"),
                    yslot: 2,
                    umode: String::from("file"),
                    dataset: "NULL".to_string()
                }
            },
            ArgResultPair {
                arg: vec!["--port", "80", "-f", "./shavee"],    // --port 80 --file ./shavee
                result: Sargs {
                    mode: String::from("print"),
                    port: 80,
                    file: String::from("./shavee"),
                    yslot: 2,
                    umode: String::from("file"),
                    dataset: "NULL".to_string()
                }
            },
            ArgResultPair {
                arg: vec!["-P", "443", "-f", "./shavee"],   // -P 443 --file ./shavee
                result: Sargs {
                    mode: String::from("print"),
                    port: 443,
                    file: String::from("./shavee"),
                    yslot: 2,
                    umode: String::from("file"),
                    dataset: "NULL".to_string()
                }
            },
            ArgResultPair {
                arg: vec!["-z", "zroot/test"],  // -z zroot/test
                result: Sargs {
                    mode: String::from("mount"),
                    port: 0,
                    file: "NULL".to_string(),
                    yslot: 2,
                    umode: String::from("password"),
                    dataset: String::from("zroot/test")
                }
            },
            ArgResultPair {
                arg: vec!["--pam", "-z", "zroot/test"], // --pam -z zroot/test (and PAM_USER env)
                result: Sargs {
                    mode: String::from("pam"),
                    port: 0,
                    file: "NULL".to_string(),
                    yslot: 2,
                    umode: String::from("password"),
                    dataset: String::from("zroot/test/shavee")  // Check if PAM_USER is appended.
                }
            },
            ArgResultPair {
                arg: vec!["-p", "-f", "./shavee", "-z", "zroot/test"],// -p -f ./shavee -z zroot/test (and PAM_USER env)
                result: Sargs {
                    mode: String::from("pam"),
                    port: 0,
                    file: String::from("./shavee"),
                    yslot: 2,
                    umode: String::from("file"),
                    dataset: String::from("zroot/test/shavee")  // Check if PAM_USER is appended.
                }
            },
            ArgResultPair {
                arg: vec!["-c", "-z", "zroot/test"],    // -c -z zroot/test
                result: Sargs {
                    mode: String::from("create"),
                    port: 0,
                    file: "NULL".to_string(),
                    yslot: 2,
                    umode: String::from("password"),
                    dataset: String::from("zroot/test")
                }
            },
            ArgResultPair {
                arg: vec!["--create", "--zset", "zroot/test/"], // --create --zset zroot/test/
                result: Sargs {
                    mode: String::from("create"),
                    port: 0,
                    file: "NULL".to_string(),
                    yslot: 2,
                    umode: String::from("password"),
                    dataset: String::from("zroot/test")
                }
            },
            ArgResultPair {
                arg: vec!["-y", "-s", "1", "-c", "-z", "zroot/test/"], // -y -s 1 -c -z zroot/test/
                result: Sargs {
                    mode: String::from("create"),
                    port: 0,
                    file: "NULL".to_string(),
                    yslot: 1,
                    umode: String::from("yubikey"),
                    dataset: String::from("zroot/test")
                }
            },
        ];

        for index in 0..valid_arguments_results_pairs.len() {
            let mut args = Vec::new();
            //note: the first argument is always the executable name: crate_name!()
            args.push(crate_name!());
            args.extend(valid_arguments_results_pairs[index].arg.clone());
            assert_eq!(
                Sargs::new_from(args.iter()).unwrap(),
                valid_arguments_results_pairs[index].result);
        }

        // For the invalid arguments, there is no output struct and we only check for error
        env::remove_var("PAM_USER");   // assure lack of PAM_USER env causes failure
        let invalid_arguments = [
            vec!["-s"],                          // -s
            vec!["--slot"],                      // --slot
            vec!["--slot", "2"],                 // --slot 2
            vec!["-y", "-s", "3"],               // -y -s 3
            vec!["--file"],                      // --file
            vec!["-f"],                          // -f
            vec!["-y", "-f", "./shavee"],        // -y -f ./shavee
            vec!["-z"],                          // -z
            vec!["--zset"],                      // --zset
            vec!["--pam"],                       // --pam
            vec!["-p"],                          // -p
            vec!["--port", "80"],                // --port 80
            vec!["-P"],                          // -P
            vec!["-P", "0", "-f", "./shavee"],   // -P 0 -f ./shavee
            vec!["-c"],                          // -c
            vec!["--create"],                    // --create
            vec!["-p", "-c", "-z", "zroot/test"],// --pam -c -z zroot/test
            vec!["-p", "-z", "zroot/test"],      // --pam -z zroot/test (no PAM_USER)
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
