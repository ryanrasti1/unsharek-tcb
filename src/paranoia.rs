//! Paranoia (`Config::paranoia`, on by default): a best-effort look at the crate's
//! "Assumptions", the ones lockdown can't check exactly: a tracer, another process sharing this
//! one's memory, shared memory an ancestor maps too. A process whose /proc entries this one may
//! not read is skipped. Every exact check is lockdown's (lockdown.rs).

use std::io;
use std::os::fd::OwnedFd;

use rustix::fs::{Mode as FsMode, OFlags};

use crate::lockdown::{numbers_at, os, read_at, rx};
use crate::{Error, Mode, Result};

/// The check, through `proc` (lockdown's `/proc/self`).
pub(crate) fn check(proc: &OwnedFd, mode: Mode) -> Result<()> {
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

