#[repr(u8)]
#[non_exhaustive]
pub enum SessionType {
    Shell = 0x00,
    Upload = 0x01,
    Download = 0x02,
}

impl SessionType {
    #[must_use]
    pub fn from_u8(byte: [u8; 1]) -> Option<Self> {
        match byte[0] {
            0x00 => Some(Self::Shell),
            0x01 => Some(Self::Upload),
            0x02 => Some(Self::Download),
            _ => None,
        }
    }
}

pub const SCP_ERROR: [u8; 1] = [0xFF];
pub const SCP_CONTINUE: [u8; 1] = [0x00];
pub const SCP_SUCCESS: [u8; 1] = [0x01];

pub mod handshake {
    pub const KEYGEN: [u8; 6] = *b"Keygen";
    pub const CHURCH: [u8; 6] = *b"Church";
    pub const PRAISE_THE_CODE: [u8; 16] = *b"PRAISE THE CODE!";
}
