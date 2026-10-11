use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

type HmacSha256 = Hmac<Sha256>;
type Error = Box<dyn std::error::Error>;
const KEY_BYTES: usize = 32;
pub const FIM_KEY_FILE: &str = "fim-hmac.key";
pub const PERSIST_KEY_FILE: &str = "persist-hmac.key";

pub struct Key([u8; KEY_BYTES]);

impl Drop for Key {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub fn key_path_for(
    override_path: Option<&Path>,
    default_file_name: &str,
) -> Result<PathBuf, Error> {
    if let Some(path) = override_path {
        if !path.is_absolute() {
            return Err("--hmac-key must be an absolute path".into());
        }
        return Ok(path.to_path_buf());
    }
    Ok(crate::private_store::config_home()?
        .join("sentinel/keys")
        .join(default_file_name))
}

pub fn ensure_key_for(
    override_path: Option<&Path>,
    default_file_name: &str,
) -> Result<PathBuf, Error> {
    let path = key_path_for(override_path, default_file_name)?;
    let parent = path.parent().ok_or("HMAC key path has no parent")?;
    crate::private_store::ensure_private_directory(parent, true, "HMAC key")?;
    if path.exists() {
        load(&path)?;
        return Ok(path);
    }

    let mut bytes = [0u8; KEY_BYTES];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    match crate::private_store::atomic_write(&path, &bytes, false) {
        Ok(()) => {}
        Err(_error) if path.exists() => {
            bytes.fill(0);
            load(&path)?;
            return Ok(path);
        }
        Err(error) => return Err(error),
    }
    bytes.fill(0);
    Ok(path)
}

pub fn key_path(override_path: Option<&Path>) -> Result<PathBuf, Error> {
    key_path_for(override_path, FIM_KEY_FILE)
}

pub fn ensure_key(override_path: Option<&Path>) -> Result<PathBuf, Error> {
    ensure_key_for(override_path, FIM_KEY_FILE)
}

pub fn load(path: &Path) -> Result<Key, Error> {
    let mut file = crate::private_store::open_private_read(path, "HMAC key")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() != KEY_BYTES {
        bytes.fill(0);
        return Err(format!(
            "Invalid HMAC key length in {}; expected 32 bytes",
            path.display()
        )
        .into());
    }
    let mut key = [0u8; KEY_BYTES];
    key.copy_from_slice(&bytes);
    bytes.fill(0);
    Ok(Key(key))
}

pub fn key_id(key: &Key) -> String {
    let digest = crate::hash_files::hash_bytes(&key.0);
    hex::encode(&digest[..8])
}

pub fn sign(key: &Key, domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts 256-bit keys");
    mac.update(domain);
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

pub fn verify(key: &Key, domain: &[u8], payload: &[u8], tag: &[u8]) -> Result<(), Error> {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts 256-bit keys");
    mac.update(domain);
    mac.update(payload);
    mac.verify_slice(tag)
        .map_err(|_| "HMAC verification failed; authenticated data or key was changed".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_detects_payload_and_key_changes() {
        let first = Key([1; KEY_BYTES]);
        let second = Key([2; KEY_BYTES]);
        let tag = sign(&first, b"domain", b"payload");
        assert!(verify(&first, b"domain", b"payload", &tag).is_ok());
        assert!(verify(&first, b"other-domain", b"payload", &tag).is_err());
        assert!(verify(&first, b"domain", b"changed", &tag).is_err());
        assert!(verify(&second, b"domain", b"payload", &tag).is_err());
    }
}
