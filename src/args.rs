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

        if arg.is_present("pam") && !arg.is_present("zset") {
            eprintln!("Error: specify zfs dataset to use with pam");
            exit(1);
        };

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

        if dataset.ends_with("/") {
            dataset.pop();
        };

        if arg.is_present("pam") {
            let user = env::var("PAM_USER").expect("PAM_USER Var not found");
            dataset.push('/');
            dataset.push_str(user.as_str());
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
    if v.parse::<u16>().is_ok() {
        return Ok(());
    } else {
        return Err(String::from("Inavlid port number"));
    }
}
