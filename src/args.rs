use std::{env, process::exit};

use clap::{crate_authors, crate_version, App, Arg};

pub struct Sargs {
    pub mode: String,
    pub port: u16,
    pub file: String,
    pub yslot: u8,
    pub umode: String,
    pub dataset: String,
}

impl Sargs {
    pub fn new() -> Self {
        let app = App::new("shavee")
            .about("shavee is a simple program designed as a ZFS 2FA encryption helper for PAM") // Define APP and args
            .author(crate_authors!())
            .version(crate_version!())
            .arg(
                Arg::with_name("yubikey")
                    .long("yubi")
                    .short("y")
                    .help("Use Yubikey HMAC as Second factor.")
                    .required(false)
                    .takes_value(false),
            )
            .arg(
                Arg::with_name("slot")
                    .short("s")
                    .long("slot")
                    .help("Yubikey HMAC Slot")
                    .takes_value(true)
                    .required(false),
            )
            .arg(
                Arg::with_name("keyfile")
                    .short("f")
                    .long("file")
                    .help("<Keyfile location>")
                    .required(false)
                    .takes_value(true)
                    .conflicts_with("yubikey"),
            )
            .arg(
                Arg::with_name("pam")
                    .short("p")
                    .long("pam")
                    .takes_value(false)
                    .required(false)
                    .help("PAM mode"),
            )
            .arg(
                Arg::with_name("create")
                    .short("c")
                    .long("create")
                    .takes_value(true)
                    .value_name("create")
                    .required(false)
                    .conflicts_with("zset")
                    .help("Create a new zfs Dataset with the derived key"),
            )
            .arg(
                Arg::with_name("port")
                    .short("P")
                    .long("port")
                    .takes_value(true)
                    .value_name("port")
                    .required(false)
                    .validator(port_check)
                    .help("Network Port"),
            )
            .arg(
                Arg::with_name("zset")
                    .short("z")
                    .long("zset")
                    .takes_value(true)
                    .value_name("zset")
                    .required(false)
                    .help("ZFS Dataset eg. \"zroot/data/home/\""),
            );
        let arg = app.get_matches();
        let mut file = String::from("NULL");
        let mut dataset = String::from("NULL");

        let port: u16 = if arg.is_present("port") {
            arg.value_of("port")
                .expect("Invalid Port")
                .parse::<u16>()
                .expect("Invalid port")
        } else {
            0
        };

        let yslot = if arg.is_present("slot")
            && arg.value_of("slot").expect("Invalid slot value").eq("1")
        {
            1
        } else {
            2 // Default Yubikey HMAC slot
        };

        let mode = if arg.is_present("pam") {
            if !arg.is_present("zset") {
                eprintln!("Error: specify zfs dataset to use with pam");
                exit(1);
            };
            dataset = arg
                .value_of("zset")
                .expect("Invalid ZFS dataset")
                .to_string();
            if dataset.ends_with("/") {
                dataset.pop();
            };
            let user = env::var("PAM_USER");
            let user = match user {
                Ok(u) => u,
                Err(error) => {
                    eprintln!("Error: PAM_USER Environment variable not found");
                    eprintln!("Error: {}", error);
                    exit(1)
                }
            };
            dataset.push('/');
            dataset.push_str(user.as_str());
            String::from("pam")
        } else if arg.is_present("create") {
            dataset = arg.value_of("create").expect("Inavlid Dataset").to_string();
            String::from("create")
        } else if arg.is_present("zset") {
            dataset = arg
                .value_of("zset")
                .expect("Invalid ZFS Dataset")
                .to_string();
            String::from("mount")
        } else {
            String::from("print")
        };

        let umode = if arg.is_present("yubikey") {
            String::from("yubikey")
        } else if arg.is_present("keyfile") {
            file = arg
                .value_of("keyfile")
                .expect("Invalid keyfile")
                .to_string();
            String::from("file")
        } else {
            String::from("password")
        };

        Sargs {
            mode,
            port,
            file,
            yslot,
            umode,
            dataset,
        }
    }
}

fn port_check(v: String) -> Result<(), String> {
    if v.parse::<u16>().is_ok() && v.parse::<u16>().unwrap() != 0 {
        return Ok(());
    } else {
        return Err(String::from("Error: Inavlid port number"));
    }
}

// This section implements unit tests for the fuctions in this module.
#[cfg(test)]
mod tests {
    use super::*;

    //This tests port_check() function for the valid ports
    #[test]
    fn port_checked_is_valid() {
        //Few examples of valid ports. Important to have the boundry values tested.
        let valid_ports = vec!["1", "80", "65535"];
        for valid_port in valid_ports.iter() {
            match port_check(valid_port.to_string()) {
                Err(_) => panic!("The port number {} should have been accepted!",valid_port),
                Ok(()) => continue,
           }
        }
    }
    
    
    //This tests port_check() function for the invalid ports
    #[test]
    fn port_checked_is_invalid() {
        //Few examples of valid ports. Important to have the boundry values tested.
	    //Port 0 is reserved by IANA, it is technically invalid to use.
        let invalid_ports = vec!["-1", "65536", "a", "0"];
        for invalid_port in invalid_ports.iter() {
            match port_check(invalid_port.to_string()) {
                Ok(()) => panic!("The port number {} not should have been accepted!",invalid_port),
                Err(_) => continue,
           }
        }
    }
}
