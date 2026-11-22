//! Plugin (experimental): files. The program reaches the roots' files by path, through the
//! guest's host-backed files: Landlock confines every path to the roots ([`Files::setup`], in
//! lockdown after `no_new_privs`), and the rows below allow the calls on them, each fd and
//! directory fd at or above the floor `n` (one this plugin's `openat` made, never a kept one,
//! never `AT_FDCWD`). Paths are pointers seccomp can't read: Landlock is what confines them.

use std::io;
use std::os::fd::{OwnedFd, RawFd};
use std::path::PathBuf;

use libc::seccomp_data;
use seccomp_fn_verify::calls::{Call, CallExt};
use seccomp_fn_verify::expr::Cond;
use rustix::fs::{Mode as FsMode, OFlags};

use super::Plugin;
use crate::{Error, Result};

// Flags the rows compare with, libc's, as the typed view's fields have them (`flags`: an `int`).
const O_RDONLY: i32 = libc::O_RDONLY;
const O_WRONLY: i32 = libc::O_WRONLY;
const O_RDWR: i32 = libc::O_RDWR;
const O_CREAT: i32 = libc::O_CREAT;
const O_EXCL: i32 = libc::O_EXCL;
const O_TRUNC: i32 = libc::O_TRUNC;
const O_APPEND: i32 = libc::O_APPEND;
const O_DIRECTORY: i32 = libc::O_DIRECTORY;
const O_NOFOLLOW: i32 = libc::O_NOFOLLOW;
/// Every `openat`'s: nonblocking (a FIFO or a device must not block the open), close-on-exec.
const O_NB: i32 = libc::O_NONBLOCK | libc::O_CLOEXEC;
const AT_SYMLINK_NOFOLLOW: i32 = libc::AT_SYMLINK_NOFOLLOW;
const AT_REMOVEDIR: i32 = libc::AT_REMOVEDIR;
/// A created file's or directory's mode, or a new one (`umode_t`): below `S_ISGID` (0o2000), so
/// neither it nor `S_ISUID` (the sticky bit may be).
const MODE_MAX: u16 = 0o1777;
/// include/uapi/linux/fs.h's `RENAME_EXCHANGE` (libc has it for glibc only): with 0 and
/// `RENAME_NOREPLACE` (1) the flags `renameat2` may have; `RENAME_WHITEOUT` is 4.
const RENAME_EXCHANGE: u32 = 2;

/// A file plugin's access ([`Files::root`]): which rows the filter has, and which rights
/// Landlock gives a root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fs {
    /// No file plugin: no row opens a file.
    #[default]
    Off,
    /// Reading files and directories under the roots: no call that changes one.
    ReadOnly,
    /// Reading, writing, making and removing them.
    ReadWrite,
}

/// The file plugin: roots, each read-only or read-write, confined by Landlock.
#[derive(Clone, Debug, Default)]
pub struct Files {
    roots: Vec<(PathBuf, Fs)>,
    no_landlock: bool,
}

impl Files {
    /// No roots yet.
    pub fn new() -> Self {
        Files::default()
    }

    /// The program may reach `root` and what is under it, by path, with `access` (not
    /// [`Fs::Off`]): the rows are read-only ones if every root is read-only, and lockdown applies
    /// a Landlock ruleset, just before the filter, that allows exactly the roots (read-only:
    /// reading files and directories; read-write: also writing, truncating, making and removing
    /// files, directories and symlinks, and renaming between roots; never a device, FIFO or
    /// socket node made, and no device ioctl where the kernel's Landlock has the right).
    /// Lockdown refuses if the kernel has no Landlock, or not the rights the access needs
    /// ([`Files::no_landlock`]).
    pub fn root(mut self, root: impl Into<PathBuf>, access: Fs) -> Self {
        if access != Fs::Off {
            self.roots.push((root.into(), access));
        }
        self
    }

    /// The opt-out of Landlock: the rows go in without a ruleset, and the roots confine
    /// nothing. Only for a process whose file access is already scoped (a container's own
    /// filesystem); without it lockdown refuses on a kernel without Landlock (or where a seccomp
    /// profile hides it: ENOSYS, EPERM), or whose Landlock lacks a right the access needs
    /// (read-write: `REFER`, ABI 2, and `TRUNCATE`, ABI 3).
    pub fn no_landlock(mut self, on: bool) -> Self {
        self.no_landlock = on;
        self
    }

    /// The rows' access: the widest of the roots.
    fn access(&self) -> Fs {
        self.roots.iter().map(|r| r.1).max().unwrap_or(Fs::Off)
    }

    fn landlock(&self) -> bool {
        !self.roots.is_empty() && !self.no_landlock
    }
}

impl Plugin for Files {
    fn check(&self) -> Result<()> {
        if self.landlock() {
            landlock_abi(self.access())?;
        }
        Ok(())
    }

    /// The roots' Landlock ruleset (it needs `no_new_privs`).
    fn setup(&self) -> Result<()> {
        if self.landlock() {
            restrict_to_roots(landlock_abi(self.access())?, &self.roots)?;
        }
        Ok(())
    }

    fn rows(&self, n: u32) -> Option<Cond> {
        match self.access() {
            Fs::Off => None,
            a => Some(rows(n, a == Fs::ReadWrite)),
        }
    }
}

/// The rows: whether they allow `d`. `n` is the floor (each fd and directory fd at or above it,
/// as the kernel reads it: an `unsigned int` fd, an `int` directory fd, so never `AT_FDCWD`);
/// `writes` the read-write rows.
pub(crate) fn files(d: &seccomp_data, n: u32, writes: bool) -> bool {
    let opened = |fd: u32| fd >= n;
    let opened_dir = |dfd: i32| dfd >= n as i32;
    match d.call() {
        // The close of an fd this plugin opened, never a kept one (the guest answers that).
        Call::Close { fd } => opened(fd),
        // A file by its path (absolute, or relative to a directory the plugin opened), within
        // the roots (Landlock). Always `O_NONBLOCK` and `O_CLOEXEC`: an open never waits (a
        // FIFO's, a device's); the runtime clears `O_NONBLOCK` after its `fstat` finds a regular
        // file or a directory (the runtime's, not a guarantee: it avoids a hang). A path's
        // metadata is this open, then `fstat` (no `statx`, `newfstatat`, `fstatfs`: the guest
        // fakes statfs). Read-only: `O_RDONLY`, with any of `O_DIRECTORY`, `O_NOFOLLOW`.
        // Read-write also: `O_WRONLY` or `O_RDWR` with `O_TRUNC` or `O_APPEND`, and `O_CREAT`
        // (`O_EXCL` with it) for each access mode, the mode without `S_ISUID` or `S_ISGID` (the
        // kernel ignores it without `O_CREAT`: pinned anyway). Never `O_PATH`, `O_TMPFILE`,
        // `O_DIRECT`.
        Call::Openat { dfd, flags, mode, .. } => {
            opened_dir(dfd)
                && mode <= MODE_MAX
                && (flags == O_RDONLY | O_NB
                    || flags == O_RDONLY | O_NOFOLLOW | O_NB
                    || flags == O_RDONLY | O_DIRECTORY | O_NB
                    || flags == O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NB
                    || writes
                        && (flags == O_RDONLY | O_CREAT | O_NB
                            || flags == O_RDONLY | O_CREAT | O_EXCL | O_NB
                            || flags == O_WRONLY | O_NB
                            || flags == O_WRONLY | O_TRUNC | O_NB
                            || flags == O_WRONLY | O_APPEND | O_NB
                            || flags == O_WRONLY | O_CREAT | O_NB
                            || flags == O_WRONLY | O_CREAT | O_TRUNC | O_NB
                            || flags == O_WRONLY | O_CREAT | O_APPEND | O_NB
                            || flags == O_WRONLY | O_CREAT | O_EXCL | O_NB
                            || flags == O_RDWR | O_NB
                            || flags == O_RDWR | O_TRUNC | O_NB
                            || flags == O_RDWR | O_APPEND | O_NB
                            || flags == O_RDWR | O_CREAT | O_NB
                            || flags == O_RDWR | O_CREAT | O_TRUNC | O_NB
                            || flags == O_RDWR | O_CREAT | O_APPEND | O_NB
                            || flags == O_RDWR | O_CREAT | O_EXCL | O_NB))
        }
        // An opened file's metadata, entries and bytes at an offset (no `lseek`: files are read
        // and written only with `pread64`/`pwrite64`, at offsets the guest kernel keeps, so the
        // host's shared offset is never used and no host thread's seek races another's read;
        // `read`/`write` are for sockets and stdio).
        Call::Fstat { fd, .. } | Call::Getdents64 { fd, .. } | Call::Pread64 { fd, .. } => opened(fd),
        // A symlink's target.
        Call::Readlinkat { dfd, .. } => opened_dir(dfd),
        // Read-write: a directory made, or a mode changed: no `S_ISUID`, `S_ISGID`.
        Call::Mkdirat { dfd, mode, .. } | Call::Fchmodat { dfd, mode, .. } => writes && opened_dir(dfd) && mode <= MODE_MAX,
        // Read-write: a name removed (a file's; with `AT_REMOVEDIR` a directory's).
        Call::Unlinkat { dfd, flag, .. } => writes && opened_dir(dfd) && (flag == 0 || flag == AT_REMOVEDIR),
        // Read-write: a rename, flags 0, `RENAME_NOREPLACE` or `RENAME_EXCHANGE` (no
        // `RENAME_WHITEOUT`).
        Call::Renameat2 { olddfd, newdfd, flags, .. } => writes && opened_dir(olddfd) && opened_dir(newdfd) && flags <= RENAME_EXCHANGE,
        // Read-write: a symlink made.
        Call::Symlinkat { newdfd, .. } => writes && opened_dir(newdfd),
        // Read-write: a path's times (a path given: a null one is the directory fd's own),
        // flags 0 or `AT_SYMLINK_NOFOLLOW`.
        Call::Utimensat { dfd, filename, flags, .. } => {
            writes && opened_dir(dfd) && !filename.is_null() && (flags == 0 || flags == AT_SYMLINK_NOFOLLOW)
        }
        // Read-write: an opened file's size, sync, and bytes at an offset.
        Call::Ftruncate { fd, .. } | Call::Fsync { fd, .. } | Call::Pwrite64 { fd, .. } => writes && opened(fd),
        _ => false,
    }
}

/// [`files`]'s rows, as the combinator's sub-filter (`crate::filter`).
pub(crate) fn rows(n: u32, writes: bool) -> Cond {
    seccomp_fn::rows!(files(d, n, writes))
}

// Landlock's (include/uapi/linux/landlock.h; not in libc): the calls, and the fs rights.
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_CHAR: u64 = 1 << 6;
const MAKE_DIR: u64 = 1 << 7;
const MAKE_REG: u64 = 1 << 8;
const MAKE_SOCK: u64 = 1 << 9;
const MAKE_FIFO: u64 = 1 << 10;
const MAKE_BLOCK: u64 = 1 << 11;
const MAKE_SYM: u64 = 1 << 12;
/// ABI 2.
const REFER: u64 = 1 << 13;
/// ABI 3.
const TRUNCATE: u64 = 1 << 14;
/// ABI 5.
const IOCTL_DEV: u64 = 1 << 15;

/// The kernel's Landlock ABI version, if it has the rights `access` needs (read-write: `REFER`,
/// ABI 2, and `TRUNCATE`, ABI 3); an error if not, or if it has none: disabled, or hidden by a
/// seccomp profile (Docker's older ones answer ENOSYS or EPERM). `IOCTL_DEV` (ABI 5) is used
/// where there.
fn landlock_abi(access: Fs) -> Result<u32> {
    const OPT_OUT: &str = "where file access is already scoped (a container's own filesystem) set \
                           Files::no_landlock, or map the files into the guest instead (unsharek's `map`)";
    // SAFETY: the version query reads nothing.
    let v = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0usize, LANDLOCK_CREATE_RULESET_VERSION) };
    if v < 1 {
        return Err(Error::Landlock(format!("unavailable ({}): the roots need it; {OPT_OUT}", io::Error::last_os_error())));
    }
    let need = if access == Fs::ReadWrite { 3 } else { 1 };
    if v < need {
        return Err(Error::Landlock(format!(
            "ABI {v}: read-write roots need ABI 3 (REFER for a rename between directories, TRUNCATE); {OPT_OUT}"
        )));
    }
    Ok(v as u32)
}

/// Every fs right the kernel's Landlock (`abi`) knows: all handled, so each is denied but where
/// a root's rule allows it.
fn handled(abi: u32) -> u64 {
    let mut r = EXECUTE | WRITE_FILE | READ_FILE | READ_DIR | REMOVE_DIR | REMOVE_FILE | MAKE_CHAR | MAKE_DIR | MAKE_REG | MAKE_SOCK | MAKE_FIFO | MAKE_BLOCK | MAKE_SYM;
    if abi >= 2 {
        r |= REFER;
    }
    if abi >= 3 {
        r |= TRUNCATE;
    }
    if abi >= 5 {
        r |= IOCTL_DEV;
    }
    r
}

/// A root's rights: read-only, reading files and directories (not executing: no exec reaches the
/// host); read-write, also writing, truncating, making and removing regular files, directories
/// and symlinks, and renaming (`REFER`). Never a device, FIFO or socket node, nor a device's
/// ioctl.
fn rights(abi: u32, access: Fs) -> u64 {
    let ro = READ_FILE | READ_DIR;
    let rw = ro | WRITE_FILE | REMOVE_DIR | REMOVE_FILE | MAKE_DIR | MAKE_REG | MAKE_SYM | REFER | TRUNCATE;
    let r = match access {
        Fs::Off => 0,
        Fs::ReadOnly => ro,
        Fs::ReadWrite => rw,
    };
    r & handled(abi)
}

/// Step 7b: a ruleset handling every right, a rule per root (opened `O_PATH` here, closed before
/// the filter), enforced on this thread (the only one).
fn restrict_to_roots(abi: u32, roots: &[(std::path::PathBuf, Fs)]) -> Result<()> {
    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }
    #[repr(C, packed)]
    struct PathBeneath {
        allowed_access: u64,
        parent_fd: i32,
    }
    let attr = RulesetAttr { handled_access_fs: handled(abi) };
    // SAFETY: the kernel reads `attr` (its first field: the size given).
    let rs = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &attr as *const RulesetAttr, std::mem::size_of::<RulesetAttr>(), 0u32) };
    if rs < 0 {
        return Err(Error::Landlock(format!("create_ruleset: {}", io::Error::last_os_error())));
    }
    // SAFETY: the ruleset fd, just made, ours.
    let rs = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(rs as RawFd) };
    for (root, access) in roots {
        let dir = rustix::fs::open(root, OFlags::PATH | OFlags::CLOEXEC, FsMode::empty())
            .map_err(|e| Error::Landlock(format!("root {}: {e}", root.display())))?;
        let mut allowed = rights(abi, *access);
        // A file as a root: only a file's rights (Landlock refuses a directory's on it).
        if rustix::fs::fstat(&dir).is_ok_and(|st| rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::Directory) {
            allowed &= EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;
        }
        let rule = PathBeneath { allowed_access: allowed, parent_fd: std::os::fd::AsRawFd::as_raw_fd(&dir) };
        // SAFETY: the kernel reads `rule`; both fds are open.
        let r = unsafe {
            libc::syscall(libc::SYS_landlock_add_rule, std::os::fd::AsRawFd::as_raw_fd(&rs), LANDLOCK_RULE_PATH_BENEATH, &rule as *const PathBeneath, 0u32)
        };
        if r != 0 {
            return Err(Error::Landlock(format!("root {}: {}", root.display(), io::Error::last_os_error())));
        }
    }
    // SAFETY: restricts this thread (the process's only one) by the ruleset.
    if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, std::os::fd::AsRawFd::as_raw_fd(&rs), 0u32) } != 0 {
        return Err(Error::Landlock(format!("restrict_self: {}", io::Error::last_os_error())));
    }
    Ok(())
}

