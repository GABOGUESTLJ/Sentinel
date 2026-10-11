use crate::hash_files;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, Metadata, OpenOptions},
    io,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
}

impl Timestamp {
    pub fn now() -> Self {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => Self {
                seconds: duration.as_secs() as i64,
                nanos: duration.subsec_nanos(),
            },
            Err(error) => {
                let duration = error.duration();
                let fractional = duration.subsec_nanos();
                Self {
                    seconds: -(duration.as_secs() as i64) - i64::from(fractional != 0),
                    nanos: if fractional == 0 {
                        0
                    } else {
                        1_000_000_000 - fractional
                    },
                }
            }
        }
    }
    pub fn utc(self) -> String {
        let seconds: libc::time_t = self.seconds;
        let mut result = std::mem::MaybeUninit::<libc::tm>::uninit();
        // Both pointers are valid; gmtime_r initializes result on success.
        let ptr = unsafe { libc::gmtime_r(&seconds, result.as_mut_ptr()) };
        if ptr.is_null() {
            return format!("unix:{}.{:09}", self.seconds, self.nanos);
        }
        let result = unsafe { result.assume_init() };
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
            i64::from(result.tm_year) + 1900,
            result.tm_mon + 1,
            result.tm_mday,
            result.tm_hour,
            result.tm_min,
            result.tm_sec,
            self.nanos
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    File,
    Directory,
    Symlink,
    Fifo,
    Socket,
    BlockDevice,
    CharDevice,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Identity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub kind: Kind,
    pub hash: Option<[u8; 32]>,
    pub target: Option<Vec<u8>>,
    pub size: Option<u64>,
    pub modified: Option<Timestamp>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub device: Option<u64>,
    #[serde(default)]
    pub filesystem_device: Option<u64>,
    #[serde(default)]
    pub inode: Option<u64>,
}

impl Entry {
    pub fn identity(&self) -> Option<Identity> {
        Some(Identity {
            device: self.filesystem_device?,
            inode: self.inode?,
        })
    }
}

pub fn classify(meta: &Metadata) -> Kind {
    let kind = meta.file_type();
    if kind.is_file() {
        Kind::File
    } else if kind.is_dir() {
        Kind::Directory
    } else if kind.is_symlink() {
        Kind::Symlink
    } else if kind.is_fifo() {
        Kind::Fifo
    } else if kind.is_socket() {
        Kind::Socket
    } else if kind.is_block_device() {
        Kind::BlockDevice
    } else if kind.is_char_device() {
        Kind::CharDevice
    } else {
        Kind::Other
    }
}

fn stable(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

pub fn read_entry(path: &Path) -> io::Result<Entry> {
    let before = fs::symlink_metadata(path)?;
    let kind = classify(&before);
    let mut entry = Entry {
        hash: None,
        target: None,
        size: (kind == Kind::File).then_some(before.len()),
        // Parent directory mtime changes with children: avoid duplicate parent alerts.
        modified: (kind != Kind::Directory).then_some(Timestamp {
            seconds: before.mtime(),
            nanos: before.mtime_nsec() as u32,
        }),
        mode: before.mode() & 0o7777,
        uid: before.uid(),
        gid: before.gid(),
        device: matches!(kind, Kind::BlockDevice | Kind::CharDevice).then_some(before.rdev()),
        filesystem_device: Some(before.dev()),
        inode: Some(before.ino()),
        kind,
    };
    if entry.kind == Kind::File {
        // Reject swapped symlinks; a replacement FIFO must not block open().
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let opened = file.metadata()?;
        if !opened.is_file() || !stable(&before, &opened) {
            return Err(io::Error::other("file replaced before it could be read"));
        }
        entry.hash = Some(hash_files::hash_reader(&mut file)?);
        if !stable(&opened, &file.metadata()?) {
            return Err(io::Error::other("file modified while it was being read"));
        }
    } else if entry.kind == Kind::Symlink {
        entry.target = Some(fs::read_link(path)?.as_os_str().as_bytes().to_vec());
    }
    if !stable(&before, &fs::symlink_metadata(path)?) {
        return Err(io::Error::other("entry modified while it was being read"));
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utc_dates_cover_epoch_and_pre_epoch() {
        assert_eq!(
            Timestamp {
                seconds: 0,
                nanos: 0
            }
            .utc(),
            "1970-01-01T00:00:00.000000000Z"
        );
        assert_eq!(
            Timestamp {
                seconds: -1,
                nanos: 1
            }
            .utc(),
            "1969-12-31T23:59:59.000000001Z"
        );
        assert_eq!(
            Timestamp {
                seconds: 1709164800,
                nanos: 0
            }
            .utc(),
            "2024-02-29T00:00:00.000000000Z"
        );
    }

    #[test]
    fn character_device_is_metadata_only() {
        let entry = read_entry(Path::new("/dev/null")).unwrap();
        assert_eq!(entry.kind, Kind::CharDevice);
        assert!(entry.hash.is_none());
        assert!(entry.device.is_some());
    }
}
