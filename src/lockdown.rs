//! Lockdown: the moment the process stops being the host's. [`lockdown`] makes the steps of
//! `crate::lockdown`'s comment (and README.md's "Design"), in its order, with ordinary syscalls (nothing
//! traps yet: no filter is in). The first check is the thread count, so nothing can open an fd,
//! map memory or make a thread behind the later ones.

use std::io;
use std::os::fd::{OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use libc::sock_filter as SockFilter;
use rustix::fs::{Mode as FsMode, OFlags};
use rustix::io::Errno;
use rustix::process::{DumpableBehavior, Resource, Rlimit};
use rustix::thread::{CapabilitySet, CapabilitySets};

use crate::filter;
use crate::{Config, Error, Fds, Fs, Mode, Result};

fn os(what: &'static str) -> impl FnOnce(io::Error) -> Error {
    move |source| Error::Os { what, source }
}

fn last_os(what: &'static str) -> Error {
    os(what)(io::Error::last_os_error())
}

/// rustix's error, as [`os`].
fn rx(what: &'static str) -> impl FnOnce(Errno) -> Error {
    move |e| Error::Os { what, source: e.into() }
}

/// How long the last lockdown's checks (steps 1-3: threads, fds, mappings) took, in ns: for
/// measuring, not a policy.
static CHECK_NS: AtomicU64 = AtomicU64::new(0);

#[doc(hidden)]
pub fn check_ns() -> u64 {
    CHECK_NS.load(Ordering::Relaxed)
}

/// How long the last lockdown's paranoia check took, in ns (0: off).
static PARANOIA_NS: AtomicU64 = AtomicU64::new(0);

#[doc(hidden)]
pub fn paranoia_ns() -> u64 {
    PARANOIA_NS.load(Ordering::Relaxed)
}

pub(crate) fn lockdown(config: Config) -> Result<Fds> {
    let mode = config.mode;
    let gate = config.gate.ok_or(Error::NoGate)?;
    let guest_fds: Vec<RawFd> = config.guest_fds.clone();
    let grants = config.fds.clone();
    // The kept fds: the grants and the guest's, and their new numbers. The filter is compiled
    // first (it allocates, and checks nothing), for the floor `n`.
    let mut keep: Vec<RawFd> = grants.iter().chain(&guest_fds).copied().collect();
    keep.sort_unstable();
    keep.dedup();
    let fds = renumbered(&keep);
    let prog = filter::filter(mode, fds.n as u64, config.ppoll_max, gate, config.fs(), config.net);
    // Plugin: fs. Landlock is there (refused now, before anything changes, if not).
    let landlock = if config.fs_roots.is_empty() || config.no_landlock { None } else { Some(landlock_abi(config.fs())?) };

    {
        // Every read of /proc is through this one fd, checked to be the kernel's procfs (not
        // whatever is mounted at /proc: a FUSE or tmpfs there could answer anything), and its
        // process to be this one (step 1 finds this thread's tid in it). Closed before step 4.
        let proc = proc_self()?;
        // 0. The assumptions, best-effort.
        if config.paranoia {
            let t = Instant::now();
            paranoia(&proc, mode, &keep)?;
            PARANOIA_NS.store(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
        } else {
            PARANOIA_NS.store(0, Ordering::Relaxed);
        }
        let t = Instant::now();
        // 1. One thread.
        one_thread(&proc)?;
        // 2. The guest's fds: an eventfd each (a CPU token), or in fork mode a pidfd (init's: each
        // forked process polls it to end with init; PR_SET_PDEATHSIG would need a prctl after
        // lockdown, and the pidfd is only polled: no pidfd_send_signal or waitid is allowed).
        // Nothing else: a file, a socket, a pipe posing as one would get read and write without
        // the caller's grant.
        for &fd in &guest_fds {
            let kind = fd_kind(&proc, fd).map_err(|_| Error::NotOpen(fd))?;
            let ok = kind == "anon_inode:[eventfd]" || (mode == Mode::Fork && kind == "anon_inode:[pidfd]");
            if !ok {
                return Err(Error::FdKind { fd, kind });
            }
        }
        for &fd in &grants {
            // Open: /proc/self/fd has it, as for the guest's (no fd borrowed unsafely).
            if fd < 0 || fd_kind(&proc, fd).is_err() {
                return Err(Error::NotOpen(fd));
            }
        }
        // 3. Every mapping.
        check_maps(&proc, mode)?;
        CHECK_NS.store(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }
    // 4. Every other fd closed, not refused (a CLI inherits stray fds), and the kept ones moved
    // to `0..n`.
    close_except(&keep)?;
    compact(&fds)?;
    // 5. No core dump, not dumpable.
    rustix::process::setrlimit(Resource::Core, Rlimit { current: Some(0), maximum: Some(0) }).map_err(rx("RLIMIT_CORE"))?;
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(rx("PR_SET_DUMPABLE"))?;
    // 6. Capabilities.
    drop_capabilities()?;
    // 7. no_new_privs: unprivileged seccomp needs it, and no exec gains anything after.
    rustix::thread::set_no_new_privs(true).map_err(rx("PR_SET_NO_NEW_PRIVS"))?;
    // 7b. Plugin: fs. The roots' Landlock ruleset (it needs no_new_privs).
    if let Some(abi) = landlock {
        restrict_to_roots(abi, &config.fs_roots)?;
    }
    // 8. The filter, with TSYNC.
    install(&prog)?;
    Ok(fds)
}

/// The kept fds' new numbers (`keep` sorted, deduplicated): those below `n` stay, the others
/// take the free numbers below `n`, lowest first, in order.
fn renumbered(keep: &[RawFd]) -> Fds {
    let n = keep.len() as RawFd;
    let mut free = (0..n).filter(|fd| keep.binary_search(fd).is_err());
    let map = keep.iter().map(|&fd| (fd, if fd < n { fd } else { free.next().unwrap_or(fd) })).collect();
    Fds { n, map }
}

/// Step 4's moves: each kept fd at or above `n` duplicated to its new number (close-on-exec as
/// it was), then everything at or above `n` closed. After [`close_except`], so every new number
/// is free; each is checked open after.
fn compact(fds: &Fds) -> Result<()> {
    for &(old, new) in &fds.map {
        if old == new {
            continue;
        }
        // SAFETY: fcntl and dup3 on this process's fds; `new` is free (step 4 closed it).
        let fl = unsafe { libc::fcntl(old, libc::F_GETFD) };
        if fl < 0 {
            return Err(last_os("F_GETFD"));
        }
        let cloexec = if fl & libc::FD_CLOEXEC != 0 { libc::O_CLOEXEC } else { 0 };
        // SAFETY: as above.
        if unsafe { libc::dup3(old, new, cloexec) } != new {
            return Err(last_os("dup3"));
        }
    }
    let n = fds.n as u32;
    // SAFETY: closes this process's fds at or above `n`: none is kept any more.
    if unsafe { libc::syscall(libc::SYS_close_range, n, u32::MAX, 0) } != 0 {
        return Err(last_os("close_range"));
    }
    for fd in 0..fds.n {
        // SAFETY: fcntl on this process's fd.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(Error::NotOpen(fd));
        }
    }
    Ok(())
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
                           Config::no_landlock, or map the files into the guest instead (unsharek's `map`)";
    // SAFETY: the version query reads nothing.
    let v = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0usize, LANDLOCK_CREATE_RULESET_VERSION) };
    if v < 1 {
        return Err(Error::Landlock(format!("unavailable ({}): the fs plugin's roots need it; {OPT_OUT}", io::Error::last_os_error())));
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

/// `/proc/self`, opened once: a directory on procfs (`PROC_SUPER_MAGIC`).
fn proc_self() -> Result<OwnedFd> {
    const PROC_SUPER_MAGIC: i64 = 0x9fa0;
    let proc = rustix::fs::open("/proc/self", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, FsMode::empty())
        .map_err(rx("/proc/self"))?;
    let st = rustix::fs::fstatfs(&proc).map_err(rx("/proc/self"))?;
    if st.f_type as i64 != PROC_SUPER_MAGIC {
        return Err(Error::Os { what: "/proc", source: io::Error::other(format!("not procfs (f_type {:#x})", st.f_type)) });
    }
    Ok(proc)
}

/// `name` under `dir`, read whole.
fn read_at(dir: &OwnedFd, name: &str) -> io::Result<String> {
    let f = rustix::fs::openat(dir, name, OFlags::RDONLY | OFlags::CLOEXEC, FsMode::empty())?;
    let mut s = String::new();
    io::Read::read_to_string(&mut std::fs::File::from(f), &mut s)?;
    Ok(s)
}

/// The numeric entries of directory `name` under `dir` (tids, pids).
fn numbers_at(dir: &OwnedFd, name: &str) -> io::Result<Vec<i32>> {
    let d = rustix::fs::openat(dir, name, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, FsMode::empty())?;
    let mut out = vec![];
    for e in rustix::fs::Dir::read_from(&d)? {
        if let Some(n) = e?.file_name().to_str().ok().and_then(|n| n.parse::<i32>().ok()) {
            out.push(n);
        }
    }
    Ok(out)
}

/// Step 1. A thread just joined (unsharek's image builders) is still listed while it finishes
/// exiting: a few milliseconds' grace, then the others are named. This thread must be listed:
/// else `/proc` is another pid namespace's, and its `self` isn't this process.
fn one_thread(proc: &OwnedFd) -> Result<()> {
    let me = rustix::thread::gettid().as_raw_nonzero().get();
    let mut others = vec![];
    for _ in 0..20 {
        let tids = numbers_at(proc, "task").map_err(os("/proc/self/task"))?;
        if !tids.contains(&me) {
            return Err(Error::Os { what: "/proc/self/task", source: io::Error::other(format!("tid {me} not listed: another pid namespace's /proc")) });
        }
        others = tids.into_iter().filter(|&tid| tid != me).collect();
        if others.is_empty() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    others.sort_unstable();
    Err(Error::Threads(others))
}

/// `/proc/self/fd/<fd>`'s link: what the fd is (`anon_inode:[eventfd]`, `socket:[123]`, a path).
fn fd_kind(proc: &OwnedFd, fd: RawFd) -> io::Result<String> {
    let link = rustix::fs::readlinkat(proc, format!("fd/{fd}"), Vec::new())?;
    Ok(link.to_string_lossy().into_owned())
}

/// Step 0: the crate's "Assumptions", as far as /proc shows them. Best-effort: a process whose
/// entries this one may not read is skipped.
fn paranoia(proc: &OwnedFd, mode: Mode, keep: &[RawFd]) -> Result<()> {
    let bad = |s: String| Err(Error::Paranoia(s));
    // No tracer: it could change the memory and registers lockdown checked.
    let status = read_at(proc, "status").map_err(os("/proc/self/status"))?;
    if let Some(t) = status.lines().find_map(|l| l.strip_prefix("TracerPid:"))
        && t.trim() != "0" {
            return bad(format!("traced by pid {}", t.trim()));
        }
    // No kept fd of a kind no caller means to give: read and write on it would reach past the
    // sandbox (another process's memory, the kernel's) or act asynchronously (io_uring).
    for &fd in keep {
        let Ok(kind) = fd_kind(proc, fd) else { continue };
        let refused = ["anon_inode:[io_uring]", "anon_inode:[userfaultfd]", "anon_inode:[perf_event]", "anon_inode:[fanotify]", "anon_inode:seccomp notify", "anon_inode:bpf-", "/dev/mem", "/dev/kmem", "/dev/port"];
        let proc_mem = kind.starts_with("/proc/") && kind.ends_with("/mem");
        // A writable fd of /proc or /sys: the kernel's state (a sysctl, another process's).
        let writable = read_at(proc, &format!("fdinfo/{fd}"))
            .ok()
            .and_then(|i| i.lines().find_map(|l| l.strip_prefix("flags:").map(|f| u32::from_str_radix(f.trim(), 8).unwrap_or(0))))
            .is_some_and(|f| f & libc::O_ACCMODE as u32 != libc::O_RDONLY as u32);
        let kernel_state = writable && (kind.starts_with("/proc/") || kind.starts_with("/sys/"));
        if refused.iter().any(|r| kind.starts_with(r)) || proc_mem || kernel_state {
            return bad(format!("kept fd {fd} is {kind:?}"));
        }
    }
    // The other processes, by their /proc entries (`..` of /proc/self: /proc itself).
    let me = rustix::process::getpid().as_raw_nonzero().get();
    let root = rustix::fs::openat(proc, "..", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, FsMode::empty()).map_err(rx("/proc"))?;
    let pids: Vec<i32> = numbers_at(&root, ".").map_err(os("/proc"))?.into_iter().filter(|&p| p != me).collect();
    // No other process with this address space (a `CLONE_VM` child that isn't a thread, a
    // `vfork` parent): TSYNC doesn't reach it, and it would run unfiltered on memory the program
    // writes. kcmp(KCMP_VM) 0 is the same mm; ENOSYS (no CONFIG_KCMP) ends the look.
    const KCMP_VM: i32 = 1;
    for &pid in &pids {
        // SAFETY: kcmp compares two processes' mms; it reads nothing of ours.
        let r = unsafe { libc::syscall(libc::SYS_kcmp, me, pid, KCMP_VM, 0, 0) };
        if r == 0 {
            return bad(format!("pid {pid} shares this process's memory"));
        }
        if r < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS) {
            break;
        }
    }
    // Fork mode: no other process maps the shared anonymous memory (by its device and inode).
    if mode == Mode::Fork {
        let maps = read_at(proc, "maps").map_err(os("/proc/self/maps"))?;
        let shared: Vec<String> = maps.lines().filter(|l| l.contains(" rw-s ") && l.ends_with("/dev/zero (deleted)")).filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 5).then(|| format!(" {} {} ", f[3], f[4]))
        }).collect();
        if !shared.is_empty() {
            for &pid in &pids {
                let Ok(theirs) = read_at(&root, &format!("{pid}/maps")) else { continue };
                if let Some(l) = theirs.lines().find(|l| shared.iter().any(|k| l.contains(k.as_str()))) {
                    return bad(format!("pid {pid} maps this process's shared memory: {l}"));
                }
            }
        }
    }
    Ok(())
}

/// Step 4: `close_range` between and above `keep` (sorted, deduplicated).
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

/// Step 3: every line of `/proc/self/maps` is one of
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
fn check_maps(proc: &OwnedFd, mode: Mode) -> Result<()> {
    let maps = read_at(proc, "maps").map_err(os("/proc/self/maps"))?;
    let shm = shm_dev()?;
    for line in maps.lines() {
        if !map_ok(line, mode, &shm) {
            return Err(Error::Mapping(line.to_owned()));
        }
    }
    Ok(())
}

/// The kernel's shmem device, as /proc/self/maps writes it (`00:01`): a memfd's, which is on the
/// same internal mount as `MAP_SHARED | MAP_ANONYMOUS` memory. A tmpfs file named `/dev/zero`,
/// deleted, has the same path and a `00:` device too, but not this one.
fn shm_dev() -> Result<String> {
    let fd = rustix::fs::memfd_create("unsharek-tcb", rustix::fs::MemfdFlags::CLOEXEC).map_err(rx("memfd_create"))?;
    let st = rustix::fs::fstat(&fd).map_err(rx("memfd fstat"))?;
    Ok(format!("{:02x}:{:02x}", rustix::fs::major(st.st_dev), rustix::fs::minor(st.st_dev)))
}

/// One `/proc/self/maps` line (`lo-hi perms offset dev inode [path]`), judged as [`check_maps`]
/// says; `shm` the shmem device ([`shm_dev`]).
pub fn map_ok(line: &str, mode: Mode, shm: &str) -> bool {
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
        (b'w', b's') => mode == Mode::Fork && path == "/dev/zero (deleted)" && dev == shm,
        _ => false,
    }
}

/// The process's capability sets (`capget`).
fn capget() -> Result<CapabilitySets> {
    rustix::thread::capabilities(None).map_err(rx("capget"))
}

/// Capability number `n`, as rustix takes one.
fn cap(n: u32) -> CapabilitySet {
    CapabilitySet::from_bits_retain(1 << n)
}

/// Any capability in any of the three sets.
fn any(d: &CapabilitySets) -> bool {
    !(d.effective | d.permitted | d.inheritable).is_empty()
}

/// Step 6. The bounding set is dropped where the process may (it holds `CAP_SETPCAP`); an
/// unprivileged process can't, and needn't: with nothing permitted, `no_new_privs` and no exec
/// through the filter, the bounding set bounds nothing it could gain. Then ambient, effective,
/// permitted and inheritable cleared, and checked empty: lockdown fails if any isn't.
fn drop_capabilities() -> Result<()> {
    use rustix::thread::{capability_is_in_ambient_set, capability_is_in_bounding_set};
    let d = capget()?;
    if d.effective.contains(CapabilitySet::SETPCAP) {
        for n in 0..64 {
            // Reads the bounding set; EINVAL past the last capability.
            let Ok(set) = capability_is_in_bounding_set(cap(n)) else { break };
            if set {
                rustix::thread::remove_capability_from_bounding_set(cap(n)).map_err(rx("PR_CAPBSET_DROP"))?;
            }
        }
    }
    // Clears the ambient set (EINVAL on kernels without it: none to clear).
    match rustix::thread::clear_ambient_capability_set() {
        Err(e) if e != Errno::INVAL => return Err(rx("PR_CAP_AMBIENT_CLEAR_ALL")(e)),
        _ => {}
    }
    if any(&d) {
        // Lowering every set is always permitted.
        let none = CapabilitySets { effective: CapabilitySet::empty(), permitted: CapabilitySet::empty(), inheritable: CapabilitySet::empty() };
        rustix::thread::set_capabilities(None, none).map_err(rx("capset"))?;
    }
    if any(&capget()?) {
        return Err(Error::Capabilities("some remain after capset".into()));
    }
    for n in 0..64 {
        // Reads the ambient set; EINVAL past the last capability.
        let Ok(set) = capability_is_in_ambient_set(cap(n)) else { break };
        if set {
            return Err(Error::Capabilities(format!("ambient capability {n} remains")));
        }
    }
    Ok(())
}

/// `insns` installed (`SECCOMP_SET_MODE_FILTER`), with TSYNC on every thread of the process (a
/// failure to sync is lockdown's failure).
fn install(insns: &[SockFilter]) -> Result<()> {
    let len = u16::try_from(insns.len()).map_err(|_| Error::Filter(format!("{} instructions", insns.len())))?;
    // the kernel only reads the instructions
    let fprog = libc::sock_fprog { len, filter: insns.as_ptr() as *mut SockFilter };
    // SAFETY: seccomp reads `fprog` and the instructions, both live for the call.
    let r = unsafe {
        libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, libc::SECCOMP_FILTER_FLAG_TSYNC, &fprog as *const libc::sock_fprog)
    };
    if r < 0 {
        return Err(Error::Os { what: "seccomp", source: std::io::Error::last_os_error() });
    }
    // With TSYNC, a positive result is the id of a thread that couldn't be synced.
    if r != 0 {
        return Err(Error::Threads(vec![r as i32]));
    }
    Ok(())
}
