//! Lockdown: the moment the process stops being the host's. [`lockdown`] makes the exact steps of
//! `crate::lockdown`'s comment (and README.md's "Design"), in its order, with ordinary syscalls
//! (nothing traps yet: no filter is in). What it can only look at, not enforce, is paranoia's
//! (paranoia.rs), best-effort.

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
use crate::{Config, Error, Expect, Result, filter};

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

/// How long the last lockdown's checks took, in ns: step 1 (each kept fd open), and paranoia's (0:
/// off). For measuring, not a policy.
static FD_NS: AtomicU64 = AtomicU64::new(0);
static PARANOIA_NS: AtomicU64 = AtomicU64::new(0);

/// The last lockdown's times, in ns: (kept fds open, paranoia).
#[cfg(feature = "testing")]
pub fn times_ns() -> (u64, u64) {
    (FD_NS.load(Ordering::Relaxed), PARANOIA_NS.load(Ordering::Relaxed))
}

pub(crate) fn lockdown(config: Config, plugins: &[&dyn Plugin]) -> Result<()> {
    let mode = config.mode;
    // The kept fds, each with what the caller declares it (a plugin's kept as grants are).
    let mut keep: Vec<(RawFd, Expect)> =
        config.fds.iter().cloned().chain(plugins.iter().flat_map(|p| p.kept().iter().map(|k| (k.0, Expect::Any)))).collect();
    keep.sort_by_key(|k| k.0);
    keep.dedup_by_key(|k| k.0);
    let n = keep.len() as RawFd;
    // 1. Exactly 0..n (the caller put them there: no renumbering here), each open.
    if let Some(gap) = (0..n).find(|&i| keep[i as usize].0 != i) {
        return Err(Error::Gap { gap, n });
    }
    let t = Instant::now();
    for &(fd, _) in &keep {
        // SAFETY: fcntl on this process's fd.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(Error::NotOpen(fd));
        }
    }
    FD_NS.store(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
    // The filter is compiled first (it allocates, and checks nothing).
    let rows = plugins.iter().map(|p| p.rows()).fold(crate::plugin::Rows::default(), |a, r| crate::plugin::Rows {
        fs: a.fs.max(r.fs),
        net: a.net || r.net,
    });
    let prog = filter::filter(mode, n as u64, config.gate, rows.fs, rows.net);
    // What the plugins need of the kernel (the file plugin's Landlock): refused now, before
    // anything changes, if not there.
    for p in plugins {
        p.check()?;
    }
    // Paranoia, best-effort (paranoia.rs): threads, the kept fds' kinds, the mappings, a tracer,
    // a process sharing the memory.
    if config.paranoia {
        let t = Instant::now();
        crate::paranoia::check(mode, n, &keep)?;
        PARANOIA_NS.store(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
    } else {
        PARANOIA_NS.store(0, Ordering::Relaxed);
    }
    // 2. Every fd at or above `n` closed (not refused: a CLI inherits stray fds). After it, no row
    // frees a number below `n` (no close of one, no dup), so by the kernel's lowest-free rule
    // every fd made later is at or above `n`.
    // SAFETY: closes this process's fds at or above `n`: none is kept.
    if unsafe { libc::syscall(libc::SYS_close_range, n as u32, u32::MAX, 0) } != 0 {
        return Err(last_os("close_range"));
    }
    // 3. No core dump, not dumpable.
    rustix::process::setrlimit(Resource::Core, Rlimit { current: Some(0), maximum: Some(0) }).map_err(rx("RLIMIT_CORE"))?;
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(rx("PR_SET_DUMPABLE"))?;
    // 4. Capabilities dropped (CAP_DAC_OVERRIDE would let the file plugin's openat read root-only
    // files inside its roots; otherwise defence in depth), then no_new_privs: unprivileged
    // seccomp needs it, and no exec gains anything after.
    drop_capabilities()?;
    if config.paranoia {
        crate::paranoia::no_capabilities()?;
    }
    rustix::thread::set_no_new_privs(true).map_err(rx("PR_SET_NO_NEW_PRIVS"))?;
    // 5. Each plugin's setup (the file plugin's Landlock ruleset of its roots: it needs
    // no_new_privs).
    for p in plugins {
        p.setup()?;
    }
    // 6. The filter, with TSYNC.
    install(&prog)?;
    Ok(())
}

/// `/proc/self`, opened once: a directory on procfs (`PROC_SUPER_MAGIC`).
pub(crate) fn proc_self(n: RawFd) -> Result<OwnedFd> {
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

/// The process's capability sets (`capget`).
pub(crate) fn capget() -> Result<CapabilitySets> {
    rustix::thread::capabilities(None).map_err(rx("capget"))
}

/// Capability number `n`, as rustix takes one.
pub(crate) fn cap(n: u32) -> CapabilitySet {
    CapabilitySet::from_bits_retain(1 << n)
}

/// Any capability in any of the three sets.
pub(crate) fn any(d: &CapabilitySets) -> bool {
    !(d.effective | d.permitted | d.inheritable).is_empty()
}

/// Step 4. The bounding set is dropped where the process may (it holds `CAP_SETPCAP`); an
/// unprivileged process can't, and needn't: with nothing permitted, `no_new_privs` and no exec
/// through the filter, the bounding set bounds nothing it could gain. Then ambient, effective,
/// permitted and inheritable cleared (paranoia checks them empty after).
fn drop_capabilities() -> Result<()> {
    use rustix::thread::capability_is_in_bounding_set;
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
