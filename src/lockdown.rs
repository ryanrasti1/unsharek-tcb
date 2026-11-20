//! Lockdown: the moment the process stops being the host's. [`lockdown`] makes the steps of
//! `Sandbox::configure_and_lockdown`'s comment (and README.md's "Design"), in its order, with ordinary syscalls (nothing
//! traps yet: no filter is in). The first check is the thread count, so nothing can open an fd,
//! map memory or make a thread behind the later ones.

use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use libc::sock_filter as SockFilter;
use rustix::io::Errno;
use rustix::process::{DumpableBehavior, Resource, Rlimit};
use rustix::thread::{CapabilitySet, CapabilitySets};

use crate::filter;
use crate::{Config, Confined, Error, Mode, Result};

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
    all.fds.extend(all.recv_fds);
    let ctl = all.recv_fds.map_or(filter::NO_CTL, |fd| fd as u64);
    let pid = rustix::process::getpid().as_raw_nonzero().get() as u32;
    let prog = filter::filter(all.mode, pid as u64, all.ppoll_max, guest.gate_ip(), ctl);

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
        // Open: /proc/self/fd has it, as for the guest's (no fd borrowed unsafely).
        if fd < 0 || fd_kind(fd).is_err() {
            return Err(Error::NotOpen(fd));
        }
    }
    // Plugin: capnweb. The control socket is a unix seqpacket socket: `recvmsg` on it brings in
    // only what its peer (the provider's process) sends, in whole messages.
    if let Some(fd) = all.recv_fds {
        control_socket(fd)?;
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
    rustix::process::setrlimit(Resource::Core, Rlimit { current: Some(0), maximum: Some(0) }).map_err(rx("RLIMIT_CORE"))?;
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(rx("PR_SET_DUMPABLE"))?;
    // 6. Capabilities.
    drop_capabilities()?;
    // 7. no_new_privs: unprivileged seccomp needs it, and no exec gains anything after.
    rustix::thread::set_no_new_privs(true).map_err(rx("PR_SET_NO_NEW_PRIVS"))?;
    // 8. The filter, with TSYNC.
    install(&prog)
}

/// The control socket ([`Config::recv_fds`]): open, `AF_UNIX`, `SOCK_SEQPACKET`.
fn control_socket(fd: RawFd) -> Result<()> {
    if fd < 0 || fd_kind(fd).is_err() {
        return Err(Error::NotOpen(fd));
    }
    // SAFETY: `fd` is open (above), borrowed for the two getsockopts only.
    let s = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    let (domain, kind) = (rustix::net::sockopt::socket_domain(s), rustix::net::sockopt::socket_type(s));
    match (domain, kind) {
        (Ok(rustix::net::AddressFamily::UNIX), Ok(rustix::net::SocketType::SEQPACKET)) => Ok(()),
        _ => Err(Error::FdKind { fd, kind: fd_kind(fd).unwrap_or_default() }),
    }
}

/// `/proc/self` is on procfs (`PROC_SUPER_MAGIC`).
fn proc_is_procfs() -> Result<()> {
    const PROC_SUPER_MAGIC: i64 = 0x9fa0;
    let st = rustix::fs::statfs("/proc/self").map_err(rx("/proc/self"))?;
    if st.f_type as i64 != PROC_SUPER_MAGIC {
        return Err(Error::Os { what: "/proc", source: io::Error::other(format!("not procfs (f_type {:#x})", st.f_type)) });
    }
    Ok(())
}

/// Step 1. A thread just joined (unsharek's image builders) is still listed while it finishes
/// exiting: a few milliseconds' grace, then the others are named.
fn one_thread() -> Result<()> {
    let me = rustix::thread::gettid().as_raw_nonzero().get();
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
