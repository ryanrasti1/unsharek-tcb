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

use crate::plugin::Plugin;
use crate::{Config, Error, Kind, Mode, Result, filter};

pub(crate) fn os(what: &'static str) -> impl FnOnce(io::Error) -> Error {
    move |source| Error::Os { what, source }
}

fn last_os(what: &'static str) -> Error {
    os(what)(io::Error::last_os_error())
}

/// rustix's error, as [`os`].
pub(crate) fn rx(what: &'static str) -> impl FnOnce(Errno) -> Error {
    move |e| Error::Os { what, source: e.into() }
}

/// How long the last lockdown's checks took, in ns: steps 1-3 (threads, fds, mappings), step 2
/// (threads and fds), and the paranoia check (0: off). For measuring, not a policy.
static CHECK_NS: AtomicU64 = AtomicU64::new(0);
static FD_NS: AtomicU64 = AtomicU64::new(0);
static PARANOIA_NS: AtomicU64 = AtomicU64::new(0);

/// The last lockdown's times, in ns: (checks, threads and fds, paranoia).
#[cfg(feature = "testing")]
pub fn times_ns() -> (u64, u64, u64) {
    (CHECK_NS.load(Ordering::Relaxed), FD_NS.load(Ordering::Relaxed), PARANOIA_NS.load(Ordering::Relaxed))
}

pub(crate) fn lockdown(config: Config, plugins: &[&dyn Plugin]) -> Result<()> {
    let mode = config.mode;
    // The kept fds, each with its declared kind (a plugin's kept as grants are): exactly 0..n,
    // the caller put them there (no renumbering here). The filter is compiled first (it
    // allocates, and checks nothing).
    let mut keep: Vec<(RawFd, Kind)> = config.fds.iter().copied().chain(plugins.iter().flat_map(|p| p.kept().iter().map(|k| (k.0, Kind::Any)))).collect();
    keep.sort_by_key(|k| k.0);
    keep.dedup_by_key(|k| k.0);
    let n = keep.len() as RawFd;
    if let Some(gap) = (0..n).find(|&i| keep[i as usize].0 != i) {
        return Err(Error::Gap { gap, n });
    }
    // The mode's own, by declared kind: eventfds (the CPU tokens) only in threaded and fork mode;
    // a pidfd (init's: each forked process polls it to end with init) only in fork mode.
    for &(fd, kind) in &keep {
        let ok = match kind {
            Kind::Any => true,
            Kind::Eventfd => mode != Mode::Coroutine,
            Kind::Pidfd => mode == Mode::Fork,
        };
        if !ok {
            return Err(Error::ModeKind { fd, kind, mode });
        }
    }
    let subs = plugins.iter().filter_map(|p| p.rows(n as u32)).collect();
    let prog = filter::program(mode, config.gate, subs);
    // What the plugins need of the kernel (the file plugin's Landlock): refused now, before
    // anything changes, if not there.
    for p in plugins {
        p.check()?;
    }

    {
        // Every read of /proc is through this one fd, checked to be the kernel's procfs (not
        // whatever is mounted at /proc: a FUSE or tmpfs there could answer anything), and its
        // process to be this one (step 1 finds this thread's tid in it). Closed by step 4.
        let proc = proc_self(n)?;
        // 0. The assumptions, best-effort (paranoia.rs).
        if config.paranoia {
            let t = Instant::now();
            crate::paranoia::check(&proc, mode)?;
            PARANOIA_NS.store(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
        } else {
            PARANOIA_NS.store(0, Ordering::Relaxed);
        }
        let t = Instant::now();
        // 1. One thread.
        one_thread(&proc)?;
        // 2. Each kept fd open (F_GETFD), of its declared kind, and of no kind refused.
        for &(fd, kind) in &keep {
            // SAFETY: fcntl on this process's fd.
            let link = if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 { None } else { fd_kind(&proc, fd).ok() };
            let Some(link) = link else { return Err(Error::NotOpen(fd)) };
            let declared = match kind {
                Kind::Any => true,
                Kind::Eventfd => link == "anon_inode:[eventfd]",
                Kind::Pidfd => link == "anon_inode:[pidfd]",
            };
            if !declared || refused_kind(&proc, fd, &link) {
                return Err(Error::FdKind { fd, kind, link });
            }
        }
        FD_NS.store(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
        // 3. Every mapping.
        check_maps(&proc, mode)?;
        CHECK_NS.store(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }
    // 4. Every fd at or above `n` closed, /proc's among them (not refused: a CLI inherits stray
    // fds). After it, no row frees a number below `n` (no close of one, no dup), so by the
    // kernel's lowest-free rule every fd made later is at or above `n`.
    // SAFETY: closes this process's fds at or above `n`: none is kept.
    if unsafe { libc::syscall(libc::SYS_close_range, n as u32, u32::MAX, 0) } != 0 {
        return Err(last_os("close_range"));
    }
    // 5. No core dump, not dumpable.
    rustix::process::setrlimit(Resource::Core, Rlimit { current: Some(0), maximum: Some(0) }).map_err(rx("RLIMIT_CORE"))?;
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(rx("PR_SET_DUMPABLE"))?;
    // 6. Capabilities: CAP_DAC_OVERRIDE would let the file plugin's openat read root-only files
    // inside its roots; otherwise defence in depth.
    drop_capabilities()?;
    // 7. no_new_privs: unprivileged seccomp needs it, and no exec gains anything after.
    rustix::thread::set_no_new_privs(true).map_err(rx("PR_SET_NO_NEW_PRIVS"))?;
    // 7b. Each plugin's setup (the file plugin's Landlock ruleset of its roots: it needs
    // no_new_privs).
    for p in plugins {
        p.setup()?;
    }
    // 8. The filter, with TSYNC.
    install(&prog)?;
    Ok(())
}

/// `/proc/self`, opened once: a directory on procfs (`PROC_SUPER_MAGIC`).
fn proc_self(n: RawFd) -> Result<OwnedFd> {
    const PROC_SUPER_MAGIC: i64 = 0x9fa0;
    let open = rustix::fs::open("/proc/self", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, FsMode::empty())
        .map_err(rx("/proc/self"))?;
    // At or above `n`: below it, in a kept fd's number closed, it would pass for that fd.
    let proc = rustix::io::fcntl_dupfd_cloexec(&open, n).map_err(rx("/proc/self"))?;
    drop(open);
    let st = rustix::fs::fstatfs(&proc).map_err(rx("/proc/self"))?;
    if st.f_type as i64 != PROC_SUPER_MAGIC {
        return Err(Error::Os { what: "/proc", source: io::Error::other(format!("not procfs (f_type {:#x})", st.f_type)) });
    }
    Ok(proc)
}

/// `name` under `dir`, read whole.
pub(crate) fn read_at(dir: &OwnedFd, name: &str) -> io::Result<String> {
    let f = rustix::fs::openat(dir, name, OFlags::RDONLY | OFlags::CLOEXEC, FsMode::empty())?;
    let mut s = String::new();
    io::Read::read_to_string(&mut std::fs::File::from(f), &mut s)?;
    Ok(s)
}

/// The numeric entries of directory `name` under `dir` (tids, pids).
pub(crate) fn numbers_at(dir: &OwnedFd, name: &str) -> io::Result<Vec<i32>> {
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
pub(crate) fn fd_kind(proc: &OwnedFd, fd: RawFd) -> io::Result<String> {
    let link = rustix::fs::readlinkat(proc, format!("fd/{fd}"), Vec::new())?;
    Ok(link.to_string_lossy().into_owned())
}

/// Step 2: kinds no caller means to give, refused on every kept fd: read and write on one would
/// reach past the sandbox (another process's memory, the kernel's state) or act asynchronously
/// (io_uring). `kind` is its `/proc/self/fd` link.
fn refused_kind(proc: &OwnedFd, fd: RawFd, kind: &str) -> bool {
    const REFUSED: [&str; 9] = [
        "anon_inode:[io_uring]",
        "anon_inode:[userfaultfd]",
        "anon_inode:[perf_event]",
        "anon_inode:[fanotify]",
        "anon_inode:seccomp notify",
        "anon_inode:bpf-",
        "/dev/mem",
        "/dev/kmem",
        "/dev/port",
    ];
    let proc_mem = kind.starts_with("/proc/") && kind.ends_with("/mem");
    // A writable fd of /proc or /sys: the kernel's state (a sysctl, another process's).
    let kernel_state = (kind.starts_with("/proc/") || kind.starts_with("/sys/"))
        && read_at(proc, &format!("fdinfo/{fd}"))
            .ok()
            .and_then(|i| i.lines().find_map(|l| l.strip_prefix("flags:").map(|f| u32::from_str_radix(f.trim(), 8).unwrap_or(0))))
            .is_none_or(|f| f & libc::O_ACCMODE as u32 != libc::O_RDONLY as u32);
    REFUSED.iter().any(|r| kind.starts_with(r)) || proc_mem || kernel_state
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
pub(crate) fn map_ok(line: &str, mode: Mode, shm: &str) -> bool {
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
