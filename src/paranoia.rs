//! Paranoia (`Config::paranoia`, on by default): a best-effort look at the crate's
//! "Assumptions", what lockdown can look at but not enforce: one thread, each kept fd's kind (as
//! declared, and none refused), the mappings, a tracer, another process sharing this one's
//! memory, shared memory an ancestor maps too; and, after lockdown drops them, no capability
//! left. Every read of /proc is through one fd of `/proc/self`, checked to be procfs. A process
//! whose /proc entries this one may not read is skipped. lockdown.rs holds the exact steps.

use std::io;
use std::os::fd::{OwnedFd, RawFd};

use rustix::fs::{Mode as FsMode, OFlags};

use crate::lockdown::{any, cap, capget, numbers_at, os, proc_self, read_at, rx};
use crate::{Error, Expect, Mode, Result};

/// The check, before lockdown closes anything: `keep` the kept fds, `0..n`, each as declared.
pub(crate) fn check(mode: Mode, n: RawFd, keep: &[(RawFd, Expect)]) -> Result<()> {
    // Every read of /proc is through this one fd, checked to be the kernel's procfs (not
    // whatever is mounted at /proc: a FUSE or tmpfs there could answer anything), and its
    // process to be this one (`one_thread` finds this thread's tid in it). At or above `n`:
    // lockdown's close_range closes it.
    let proc = proc_self(n)?;
    let proc = &proc;
    one_thread(proc)?;
    for (fd, expect) in keep {
        let link = fd_kind(proc, *fd).map_err(os("/proc/self/fd"))?;
        let declared = match expect {
            Expect::Any => true,
            Expect::Is(prefix) => link.starts_with(prefix.as_str()),
        };
        if !declared || refused_kind(proc, *fd, &link) {
            return Err(Error::FdKind { fd: *fd, expect: expect.clone(), link });
        }
    }
    check_maps(proc, mode)?;
    let bad = |s: String| Err(Error::Paranoia(s));
    // No tracer: it could change the memory and registers lockdown checked.
    let status = read_at(proc, "status").map_err(os("/proc/self/status"))?;
    if let Some(t) = status.lines().find_map(|l| l.strip_prefix("TracerPid:"))
        && t.trim() != "0" {
            return bad(format!("traced by pid {}", t.trim()));
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
    // Fork mode: the shared anonymous memory is the sandbox's own. Memory shared from elsewhere
    // was inherited (a MAP_SHARED mapping survives fork): so no ancestor maps the same memory
    // (by its device and inode). Ancestors only, not every process: reading every process's
    // maps took seconds with many sandboxes running.
    if mode == Mode::Fork {
        let maps = read_at(proc, "maps").map_err(os("/proc/self/maps"))?;
        let shared: Vec<String> = maps
            .lines()
            .filter(|l| l.contains(" rw-s ") && l.ends_with("/dev/zero (deleted)"))
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                (f.len() >= 5).then(|| format!(" {} {} ", f[3], f[4]))
            })
            .collect();
        let mut pid = me;
        while !shared.is_empty() && pid > 1 {
            let Some(ppid) = read_at(&root, &format!("{pid}/status"))
                .ok()
                .and_then(|s| s.lines().find_map(|l| l.strip_prefix("PPid:").and_then(|p| p.trim().parse::<i32>().ok())))
            else {
                break;
            };
            pid = ppid;
            if pid <= 0 {
                break;
            }
            let Ok(theirs) = read_at(&root, &format!("{pid}/maps")) else { continue };
            if let Some(l) = theirs.lines().find(|l| shared.iter().any(|k| l.contains(k.as_str()))) {
                return bad(format!("pid {pid} (an ancestor) maps this process's shared memory: {l}"));
            }
        }
    }
    Ok(())
}

/// One thread. A thread just joined (unsharek's image builders) is still listed while it finishes
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

/// Kinds no caller means to give, refused on every kept fd: read and write on one would
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

/// Every line of `/proc/self/maps` is one of
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

/// After lockdown drops them: no capability in any set, none ambient.
pub(crate) fn no_capabilities() -> Result<()> {
    use rustix::thread::capability_is_in_ambient_set;
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
