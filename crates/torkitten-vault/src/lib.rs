#![forbid(unsafe_code)]

mod cipher;
mod key;
mod store;

pub use cipher::{EncryptedSecret, VaultCipher};
pub use key::VaultKey;
pub use store::{
    AuthAccountRecord, DeviceRecord, PasskeyRecord, PublicationSettings, SessionRecord, Store,
    StoreError,
};
