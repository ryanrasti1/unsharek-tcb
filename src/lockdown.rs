//! Lockdown: the moment the process stops being the host's. [`lockdown`] makes the steps of
//! `Sandbox::configure_and_lockdown`'s comment (and README.md's "Design"), in its order, with ordinary syscalls (nothing
//! traps yet: no filter is in). The first check is the thread count, so nothing can open an fd,
//! map memory or make a thread behind the later ones.

use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use seccomp_fn::{InstallError, SockFilter};

use crate::filter;
use crate::{Config, Confined, Error, Mode, Result};

fn os(what: &'static str) -> impl FnOnce(io::Error) -> Error {
    move |source| Error::Os { what, source }
}

fn last_os(what: &'static str) -> Error {
    os(what)(io::Error::last_os_error())
}

/// How long the last lockdown's checks (steps 1-4: threads, fds, mappings, the close) took, in ns: for
/// measuring, not a policy.
static CHECK_NS: AtomicU64 = AtomicU64::new(0);

#[doc(hidden)]
pub fn check_ns() -> u64 {
    CHECK_NS.load(Ordering::Relaxed)
}

pub(crate) fn lockdown<C: Confined + ?Sized>(config: Config, guest: &C) -> Result<()> {
    let mode = config.mode;
    let guest_fds: Vec<RawFd> = guest.host_fds().to_vec();
    let grants = config.fds.clone();
    // The kept fds: the grants, and the guest's. The filter is compiled first: it allocates,
    // and checks nothing.
    let mut all = config;
    all.fds.extend(guest_fds.iter().copied());
    // SAFETY: getpid.
    let pid = unsafe { libc::getpid() } as u32;
    let prog = filter::filter(&all, pid, guest.gate_ip());

    let t = Instant::now();
    // The checks read /proc/self: it must be the kernel's procfs, not whatever is mounted there
    // (a FUSE or tmpfs at /proc could answer anything).
    proc_is_procfs()?;
    // 1. One thread.
    one_thread()?;
    // 2. The guest's fds: an eventfd each (a CPU token), or in fork mode a pidfd (init's: each
    // forked process polls it to end with init; PR_SET_PDEATHSIG would need a prctl after
    // lockdown, and the pidfd is only polled: no pidfd_send_signal or waitid is allowed).
    // Nothing else: a file, a socket, a pipe posing as one would get read and write without the
    // caller's grant.
    for &fd in &guest_fds {
        let kind = fd_kind(fd).map_err(|_| Error::NotOpen(fd))?;
        let ok = kind == "anon_inode:[eventfd]" || (mode == Mode::Fork && kind == "anon_inode:[pidfd]");
        if !ok {
            return Err(Error::FdKind { fd, kind });
        }
    }
    for &fd in &grants {
        // SAFETY: fcntl on an fd number, which may not be open.
        if fd < 0 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(Error::NotOpen(fd));
        }
    }
    // 3. Every mapping.
    check_maps(mode)?;
    // 4. Every other fd closed, not refused (a CLI inherits stray fds): between and above the
    // kept ones.
    let mut keep: Vec<RawFd> = all.fds.clone();
    keep.sort_unstable();
    keep.dedup();
    close_except(&keep)?;
    CHECK_NS.store(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
    // 5. No core dump, not dumpable.
    let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: sets a limit of this process.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } != 0 {
        return Err(last_os("RLIMIT_CORE"));
    }
    // SAFETY: sets a flag of this process.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(last_os("PR_SET_DUMPABLE"));
    }
    // 6. Capabilities.
    drop_capabilities()?;
    // 7. no_new_privs: unprivileged seccomp needs it, and no exec gains anything after.
    // SAFETY: sets a flag of this process.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(last_os("PR_SET_NO_NEW_PRIVS"));
    }
    // 8. The filter, with TSYNC.
    install(&prog)
}

/// `/proc/self` is on procfs (`PROC_SUPER_MAGIC`).
fn proc_is_procfs() -> Result<()> {
    const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;
    // SAFETY: statfs into a local.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path; the kernel writes `st`.
    if unsafe { libc::statfs(c"/proc/self".as_ptr(), &mut st) } != 0 {
        return Err(last_os("/proc/self"));
    }
    if st.f_type != PROC_SUPER_MAGIC {
        return Err(Error::Os { what: "/proc", source: io::Error::other(format!("not procfs (f_type {:#x})", st.f_type)) });
    }
    Ok(())
}

/// Step 1. A thread just joined (exobox's image builders) is still listed while it finishes
/// exiting: a few milliseconds' grace, then the others are named.
fn one_thread() -> Result<()> {
    // SAFETY: gettid.
    let me = unsafe { libc::gettid() };
    let mut others = vec![];
    for _ in 0..20 {
        others = std::fs::read_dir("/proc/self/task")
            .map_err(os("/proc/self/task"))?
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
            .filter(|&tid| tid != me)
            .collect();
        if others.is_empty() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    others.sort_unstable();
    Err(Error::Threads(others))
}

/// `/proc/self/fd/<fd>`'s link: what the fd is (`anon_inode:[eventfd]`, `socket:[123]`, a path).
fn fd_kind(fd: RawFd) -> io::Result<String> {
    let link = std::fs::read_link(format!("/proc/self/fd/{fd}"))?;
    Ok(link.to_string_lossy().into_owned())
}

/// Step 3: `close_range` between and above `keep` (sorted, deduplicated).
fn close_except(keep: &[RawFd]) -> Result<()> {
    let close = |lo: u32, hi: u32| {
        // SAFETY: closes fds of this process; the kept ones are outside the range.
        if unsafe { libc::syscall(libc::SYS_close_range, lo, hi, 0) } != 0 { Err(last_os("close_range")) } else { Ok(()) }
    };
    let mut next: u32 = 0;
    for &fd in keep {
        let fd = fd as u32;
        if fd > next {
            close(next, fd - 1)?;
        }
        next = fd + 1;
    }
    close(next, u32::MAX)
}

/// Step 4: every line of `/proc/self/maps` is one of
/// - private (`p`): the process's own copy, whatever it was mapped from (a file's bytes are
///   disclosed, never written back);
/// - shared and not writable: the file's bytes, read (and `mprotect`, which could make it
///   writable, is no call the filter allows);
/// - fork mode only: shared anonymous memory (`/dev/zero (deleted)`, the kernel's shmem, device
///   0:x), which the guest's processes share among themselves.
///
/// Anything else is refused: above all a writable shared mapping of a host file (or of a memfd,
/// `/memfd:…`, or SysV shm, or a device), through which the program could write what the host
/// reads.
fn check_maps(mode: Mode) -> Result<()> {
    let maps = std::fs::read_to_string("/proc/self/maps").map_err(os("/proc/self/maps"))?;
    for line in maps.lines() {
        if !map_ok(line, mode) {
            return Err(Error::Mapping(line.to_owned()));
        }
    }
    Ok(())
}

/// One `/proc/self/maps` line (`lo-hi perms offset dev inode [path]`), judged as [`check_maps`]
/// says.
pub fn map_ok(line: &str, mode: Mode) -> bool {
    let mut f = line.splitn(6, ' ');
    let (Some(_range), Some(perms), Some(_off), Some(dev), Some(_inode)) = (f.next(), f.next(), f.next(), f.next(), f.next())
    else {
        return false;
    };
    let path = f.next().unwrap_or("").trim_start();
    let p = perms.as_bytes();
    if p.len() != 4 {
        return false;
    }
    match (p[1], p[3]) {
        (_, b'p') => true,
        (b'-', b's') => true,
        (b'w', b's') => mode == Mode::Fork && path == "/dev/zero (deleted)" && dev.starts_with("00:"),
        _ => false,
    }
}

/// `struct __user_cap_header_struct` and `__user_cap_data_struct` (linux/capability.h).
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
const CAP_VERSION_3: u32 = 0x2008_0522;
const CAP_SETPCAP: u32 = 8;

fn capget() -> Result<[CapData; 2]> {
    let mut h = CapHeader { version: CAP_VERSION_3, pid: 0 };
    let mut d = [CapData::default(); 2];
    // SAFETY: the kernel writes two data structs (version 3).
    if unsafe { libc::syscall(libc::SYS_capget, &mut h, d.as_mut_ptr()) } != 0 {
        return Err(last_os("capget"));
    }
    Ok(d)
}

/// Step 6. The bounding set is dropped where the process may (it holds `CAP_SETPCAP`); an
/// unprivileged process can't, and needn't: with nothing permitted, `no_new_privs` and no exec
/// through the filter, the bounding set bounds nothing it could gain. Then ambient, effective,
/// permitted and inheritable cleared, and checked empty: lockdown fails if any isn't.
fn drop_capabilities() -> Result<()> {
    let d = capget()?;
    let has_setpcap = d[0].effective & (1 << CAP_SETPCAP) != 0;
    if has_setpcap {
        for cap in 0..64 {
            // SAFETY: reads the bounding set; EINVAL past the last capability.
            let r = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
            if r < 0 {
                break;
            }
            // SAFETY: drops one capability from the bounding set.
            if r == 1 && unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } != 0 {
                return Err(last_os("PR_CAPBSET_DROP"));
            }
        }
    }
    // SAFETY: clears the ambient set (EINVAL on kernels without it: none to clear).
    if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } != 0
        && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL)
    {
        return Err(last_os("PR_CAP_AMBIENT_CLEAR_ALL"));
    }
    if d.iter().any(|c| c.effective | c.permitted | c.inheritable != 0) {
        let mut h = CapHeader { version: CAP_VERSION_3, pid: 0 };
        let none = [CapData::default(); 2];
        // SAFETY: the kernel reads two data structs; lowering every set is always permitted.
        if unsafe { libc::syscall(libc::SYS_capset, &mut h, none.as_ptr()) } != 0 {
            return Err(last_os("capset"));
        }
    }
    let d = capget()?;
    if d.iter().any(|c| c.effective | c.permitted | c.inheritable != 0) {
        return Err(Error::Capabilities("some remain after capset".into()));
    }
    for cap in 0..64 {
        // SAFETY: reads the ambient set.
        let r = unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET, cap, 0, 0) };
        if r < 0 {
            break;
        }
        if r == 1 {
            return Err(Error::Capabilities(format!("ambient capability {cap} remains")));
        }
    }
    Ok(())
}

/// `insns` installed (`SECCOMP_SET_MODE_FILTER`), with TSYNC on every thread of the process (a
/// failure to sync is lockdown's failure).
fn install(insns: &[SockFilter]) -> Result<()> {
    seccomp_fn::install(insns, true).map_err(|e| match e {
        InstallError::TooLong(n) => Error::Filter(format!("{n} instructions")),
        InstallError::Os(source) => Error::Os { what: "seccomp", source },
        InstallError::Thread(tid) => Error::Threads(vec![tid]),
    })
}
