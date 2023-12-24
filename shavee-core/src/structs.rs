// Struct to store the second factor config
#[derive(Debug, Clone, PartialEq)]
pub enum TwoFactorMode {
    #[cfg(feature = "yubikey")]
    Yubikey {
        yslot: Option<u8>,
        serial: Option<u32>,
    },
    #[cfg(feature = "file")]
    File {
        file: String,
        port: Option<u16>,
        size: Option<u64>,
    },
    Password,
}
