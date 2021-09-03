use clap::{App, Arg};
use shavee_lib::{common_args, Mode, Umode};
use std::ffi::OsString;

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
        let app = App::new("libshavee_pam.so")
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
        let (mode, umode) = common_args(app, args)?;

        let dataset = match mode {
            Mode::Create { dataset } => dataset,
            Mode::Mount { dataset } => dataset,
            Mode::Print => {
                let error_message = r#"Dataset must be specified!"#;
                return Err(clap::Error::with_description(
                    error_message,
                    clap::ErrorKind::EmptyValue));
            },
        };

        Ok(Pargs { umode, dataset })
    }
}
