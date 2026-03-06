mod args;
use args::*;
use atty::Stream;
use challenge_response::{ChallengeResponse, Device};
#[cfg(feature = "file")]
use shavee_core::filehash;
use shavee_core::structs::TwoFactorMode;
use shavee_core::yubikey;
use shavee_core::zfs::{self, Dataset};
use std::collections::HashMap;
use std::io::stdin;
use std::sync::{Arc, Mutex};

/// main() collect the arguments from command line, pass them to run() and print any
/// messages upon exiting the program
#[tokio::main]
async fn main() -> std::process::ExitCode {
    //initializing the logger
    shavee_core::trace_init(true);
    // parse the arguments
    shavee_core::trace("Parsing the arguments.");
    let args = CliArgs::new();
    shavee_core::trace("Arguments parsed successfully.");
    // Only main() will terminate the executable with proper message and code
    let code = match run(args).await {
        Ok(None) => {
            shavee_core::trace("Exited successfully with no message!");
            0
        } // exit with no error code
        Ok(Some(passphrase)) => {
            shavee_core::trace("Exited successfully with a message!");
            println!("{}", passphrase); // print password if asked
            0 // then exit with no error code
        }
        Err(error) => {
            shavee_core::error("Exited with an error message!");
            eprintln!("Error: {}", error); // print error message
            1 // then exit with generic error code 1
        }
    };
    std::process::exit(code);
}

async fn run(args: CliArgs) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let password = get_password("Dataset Password: ")?;
    shavee_core::trace("Password has been entered successfully.");
    shavee_core::trace("Operation Mode:");

    match args.operation {
        OperationMode::Auto { operation } => process_mount_print(operation, password, None).await,
        OperationMode::Manual { operation } => match operation {
            Operations::Create { datasets } => {
                process_create(datasets, password, args.second_factor).await
            }
            _ => process_mount_print(operation, password, Some(args.second_factor)).await,
        },
    }
}

fn get_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    let password = if atty::is(Stream::Stdin) {
        rpassword::prompt_password(prompt).map_err(|e| e.to_string())?
    } else {
        let mut input = String::new();
        stdin().read_line(&mut input)?;
        input
    };
    Ok(password.trim().to_string())
}

async fn process_create(
    datasets: Arc<[Dataset]>,
    password: String,
    second_factor: TwoFactorMode,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if atty::is(Stream::Stdin) {
        let confirm =
            rpassword::prompt_password("Retype  Password: ").map_err(|e| e.to_string())?;
        if password != confirm.trim() {
            return Err("Passwords do not match.".into());
        }
    }

    for dataset in datasets.iter() {
        shavee_core::trace(&format!(
            "\tCreate ZFS dataset: \"{}\" using \"{:?}\" method.",
            dataset.to_string(),
            second_factor
        ));
    }

    for dataset in datasets.iter() {
        let salt = shavee_core::logic::generate_salt();
        let mut current_sf = second_factor.clone();

        match &second_factor {
            #[cfg(feature = "yubikey")]
            TwoFactorMode::Yubikey { yslot, serial } => {
                let yubikey = if serial.is_none() {
                    let key = ChallengeResponse::new()?.find_device()?;
                    current_sf = TwoFactorMode::Yubikey {
                        yslot: *yslot,
                        serial: key.serial,
                    };
                    key
                } else {
                    ChallengeResponse::new()?.find_device_from_serial(serial.unwrap())?
                };
                let yubikey = Mutex::new(yubikey);
                dataset.yubi_create(password.as_bytes(), *yslot, &yubikey, &salt)?;
            }
            #[cfg(feature = "file")]
            TwoFactorMode::File { file, port, size } => {
                let filehash = shavee_core::filehash::get_filehash(file, *port, *size, &salt)?;
                dataset.file_create(password.as_bytes(), filehash, &salt)?;
            }
            TwoFactorMode::Password => {
                let hash = shavee_core::logic::password_mode_hash(password.as_bytes(), &salt)?;
                dataset.create(&hash)?;
            }
        }

        dataset.set_properties_2fa(
            current_sf,
            &base64::Engine::encode(&shavee_core::logic::BASE64_ENGINE, salt),
        )?;
    }

    Ok(None)
}

async fn process_mount_print(
    operation: Operations,
    password: String,
    second_factor: Option<TwoFactorMode>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let (datasets, recursive, print_with_name) = match operation {
        Operations::Mount {
            datasets,
            recursive,
        } => (datasets, recursive, None),
        Operations::PrintDataset {
            datasets,
            recursive,
            printwithname,
        } => (datasets, recursive, Some(printwithname)),
        _ => return Ok(None),
    };

    let sets = if recursive {
        zfs::resolve_recursive(&datasets)?
    } else {
        datasets
    };

    let yubikeys = yubikey::fetch_yubikeys().ok();
    let sethashes = get_key_hash(&sets, password, yubikeys, second_factor).await?;

    let mut errors = Vec::new();
    let maxlength = zfs::get_max_namesize(&sets);

    if let Some(true) = print_with_name {
        println!("\x1b[1m{:<maxlength$}    {}\x1b[0m", "Dataset", "Key");
        println!();
    }

    for dataset in sets.iter() {
        let name = dataset.to_string();
        if let Some(pass) = sethashes.get(&name) {
            if pass.len() == 86 {
                if let Some(with_name) = print_with_name {
                    if with_name {
                        println!("{:<maxlength$}    {}", name, pass);
                    } else {
                        println!("{}", pass);
                    }
                } else {
                    if dataset.load_key(pass).is_ok() {
                        let _ = dataset.mount();
                    }
                }
            } else {
                errors.push((name, pass.clone()));
            }
        }
    }

    if !errors.is_empty() {
        eprintln!("\x1b[1m{:<maxlength$}    {}\x1b[0m", "Dataset", "Error");
        eprintln!();
        for (name, err) in errors {
            eprintln!("{:<maxlength$}    {}", name, err);
        }
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to process some Datasets",
        )));
    }

    Ok(None)
}

async fn get_key_hash(
    datasets: &Arc<[Dataset]>,
    password: String,
    yubikeys: Option<Arc<[Mutex<Device>]>>,
    second_factor: Option<TwoFactorMode>,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut sethashes: HashMap<String, String> = HashMap::new();
    let mut handles = vec![];
    for d in datasets.iter() {
        let password = password.clone();
        let second_factor = second_factor.clone();
        let yubikeys = yubikeys.clone();
        let d = d.clone();
        let handle = tokio::spawn(async move { get_keys(d, password, second_factor, yubikeys) });
        handles.push(handle);
    }

    for handle in handles {
        let val = match handle.await.unwrap() {
            Ok(val) => val,
            Err(e) => [e.0, e.1.to_string()],
        };
        sethashes.insert(val[0].clone(), val[1].clone());
    }
    Ok(sethashes)
}

fn get_keys(
    dataset: Dataset,
    password: String,
    second_factor: Option<TwoFactorMode>,
    yubikeys: Option<Arc<[Mutex<Device>]>>,
) -> Result<[String; 2], (String, Box<dyn std::error::Error + Send>)> {
    let salt = shavee_core::logic::get_salt(Some(&dataset)).map_err(|e| {
        (
            dataset.to_string(),
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )) as Box<dyn std::error::Error + Send>,
        )
    })?;

    let second_factor = match second_factor {
        Some(sf) => sf,
        None => dataset.get_property_2fa().map_err(|e| {
            (
                dataset.to_string(),
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )) as Box<dyn std::error::Error + Send>,
            )
        })?,
    };

    let passphrase = match second_factor {
        #[cfg(feature = "yubikey")]
        TwoFactorMode::Yubikey { yslot, serial } => {
            let yubikey = yubikeys
                .as_ref()
                .and_then(|keys| {
                    if let Some(s) = serial {
                        shavee_core::yubikey::yubikey_get_from_serial(&keys[..], s)
                            .ok()
                            .or_else(|| keys.first())
                    } else {
                        keys.first()
                    }
                })
                .ok_or_else(|| {
                    (
                        dataset.to_string(),
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Device Not Found",
                        )) as Box<dyn std::error::Error + Send>,
                    )
                })?;

            let yubihash = yubikey::yubikey_get_hash(password.as_bytes(), yslot, &salt, yubikey)
                .map_err(|e| {
                    (
                        dataset.to_string(),
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        )) as Box<dyn std::error::Error + Send>,
                    )
                })?;

            base64::Engine::encode(&shavee_core::logic::BASE64_ENGINE, yubihash)
        }
        #[cfg(feature = "file")]
        TwoFactorMode::File { file, port, size } => {
            let filehash = filehash::get_filehash(&file, port, size, &salt).map_err(|e| {
                (
                    dataset.to_string(),
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )) as Box<dyn std::error::Error + Send>,
                )
            })?;
            shavee_core::logic::file_key_calculation(password.as_bytes(), filehash, &salt).map_err(
                |e| {
                    (
                        dataset.to_string(),
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        )) as Box<dyn std::error::Error + Send>,
                    )
                },
            )?
        }
        TwoFactorMode::Password => {
            shavee_core::logic::password_mode_hash(password.as_bytes(), &salt).map_err(|e| {
                (
                    dataset.to_string(),
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )) as Box<dyn std::error::Error + Send>,
                )
            })?
        }
    };

    Ok([dataset.to_string(), passphrase])
}
