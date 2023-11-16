
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
