use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub type Error = Box<dyn std::error::Error>;

pub fn uid() -> u32 {
    // geteuid has no arguments or preconditions.
    unsafe { libc::geteuid() }
}

pub fn state_home() -> Result<PathBuf, Error> {
    if let Some(value) = std::env::var_os("XDG_STATE_HOME") {
        return absolute(PathBuf::from(value), "XDG_STATE_HOME");
    }
    let home = std::env::var_os("HOME").ok_or("HOME is unavailable; set XDG_STATE_HOME")?;
    Ok(absolute(PathBuf::from(home), "HOME")?.join(".local/state"))
}

pub fn config_home() -> Result<PathBuf, Error> {
    if let Some(value) = std::env::var_os("XDG_CONFIG_HOME") {
        return absolute(PathBuf::from(value), "XDG_CONFIG_HOME");
    }
    let home = std::env::var_os("HOME").ok_or("HOME is unavailable; set XDG_CONFIG_HOME")?;
    Ok(absolute(PathBuf::from(home), "HOME")?.join(".config"))
}

fn absolute(path: PathBuf, variable: &str) -> Result<PathBuf, Error> {
    if !path.is_absolute() {
        return Err(format!("{variable} must be an absolute path").into());
    }
    Ok(path)
}

pub fn ensure_private_directory(path: &Path, recursive: bool, label: &str) -> Result<(), Error> {
    match DirBuilder::new()
        .recursive(recursive)
        .mode(0o700)
        .create(path)
    {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != uid() || metadata.mode() & 0o077 != 0 {
        return Err(format!(
            "Unsafe {label} directory: {} must be private, owned by the current user, and not a symlink",
            path.display()
        )
        .into());
    }
    Ok(())
}

pub fn validate_private_file(file: &File, label: &str) -> Result<(), Error> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(format!(
            "Unsafe {label}: expected a private, single-link regular file owned by the current user"
        )
        .into());
    }
    Ok(())
}

pub fn open_private_read(path: &Path, label: &str) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    validate_private_file(&file, label)?;
    Ok(file)
}

pub fn atomic_write(path: &Path, bytes: &[u8], replace: bool) -> Result<(), Error> {
    let now = crate::read_files::Timestamp::now();
    let temp = path.with_extension(format!(
        "{}.{}.{}.tmp",
        std::process::id(),
        now.seconds,
        now.nanos
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = (|| -> Result<(), Error> {
        file.write_all(bytes)?;
        file.sync_all()?;
        if replace {
            fs::rename(&temp, path)?;
        } else {
            fs::hard_link(&temp, path)?;
        }
        File::open(
            path.parent()
                .ok_or("private file has no parent directory")?,
        )?
        .sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(temp);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn private_storage_rejects_links_and_public_files() {
        let root = std::env::temp_dir().join(format!(
            "sentinel-private-store-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        ensure_private_directory(&root, true, "test").unwrap();
        let path = root.join("value");
        atomic_write(&path, b"secret", false).unwrap();
        assert!(open_private_read(&path, "test file").is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(open_private_read(&path, "test file").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
