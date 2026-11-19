//! The filter: which host syscalls the process may make after lockdown, each argument pinned.
//! Built per mode from the grants and the guest's own fds, compiled by seccompiler (Firecracker's),
//! installed by [`crate::lockdown`].
//!
//! **Shape.** A short hand-written gate check, then seccompiler's allowlist:
//! 1. arch is not x86-64, or the x32 bit is set: KILL_PROCESS (the allowlist knows only x86-64
//!    numbers, and must not judge another ABI's);
//! 2. the instruction pointer is not the gate's ([`crate::Confined::gate_ip`]): TRAP, the
//!    program's call, served in-process by the runtime's SIGSYS handler. Every thread and process
//!    made after lockdown inherits the filter, so this is how all of them are served;
//! 3. seccompiler's program over [`rules`]: a call that matches a rule is ALLOW, anything else
//!    the deny action (KILL_PROCESS, or ERRNO(EPERM) for [`crate::Deny::Errno`]).
//!
//! **Why the gate check is not trusted.** Its only verdicts are TRAP and KILL, never ALLOW: so
//! whatever it decides, and whatever the gate's address (the guest's value, which a reviewer
//! needn't trust), the host makes only calls the allowlist allows. A reviewer checks the twelve
//! instructions of [`gate_check`] return nothing but TRAP and KILL, and then reads [`rules`].
//! There is one filter; no `prctl`, `seccomp` or syscall-user-dispatch rule is in it.

use std::collections::BTreeMap;
use std::os::fd::RawFd;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen as Len, SeccompCmpOp as Op, SeccompCondition as Cond,
    SeccompFilter, SeccompRule, TargetArch,
};

use crate::{Access, Deny, Mode};

/// One classic-BPF instruction (`struct sock_filter`, include/uapi/linux/filter.h).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// What the filter pins: this process's pid, and every fd `read` or `write` may reach.
#[derive(Clone, Debug)]
pub(crate) struct Pins {
    /// The sandbox's own host pid: the one process `kill` may signal.
    pub pid: u32,
    /// Each fd and what may be done on it (the caller's grants, and the guest's fds, read and
    /// write). One entry per fd.
    pub fds: Vec<(RawFd, Access)>,
}

// Syscall numbers (arch/x86/entry/syscalls/syscall_64.tbl), from libc.
const READ: i64 = libc::SYS_read;
const WRITE: i64 = libc::SYS_write;

/// The flags of a host thread's `clone`: a thread of this process, its tid cleared at its end.
pub const CLONE_THREAD_FLAGS: u64 = (libc::CLONE_VM
    | libc::CLONE_FS
    | libc::CLONE_FILES
    | libc::CLONE_SIGHAND
    | libc::CLONE_THREAD
    | libc::CLONE_SYSVSEM
    | libc::CLONE_CHILD_CLEARTID) as u64;
/// The most pollfds one `ppoll` may pass.
pub const PPOLL_FDS: u64 = 8;

fn eq(arg: u8, v: u64) -> Cond {
    Cond::new(arg, Len::Qword, Op::Eq, v).expect("an argument index below 6")
}

/// `lo <= arg <= hi`, compared as 64 bits.
fn within(arg: u8, lo: u64, hi: u64) -> Vec<Cond> {
    vec![Cond::new(arg, Len::Qword, Op::Ge, lo).unwrap(), Cond::new(arg, Len::Qword, Op::Le, hi).unwrap()]
}

fn rule(conds: Vec<Cond>) -> SeccompRule {
    SeccompRule::new(conds).expect("a rule with conditions")
}

/// The fds `access` allows `nr` on (`read` for [`Access::Read`] and [`Access::ReadWrite`], `write`
/// for the other two), as inclusive runs of consecutive fds: one rule per run, so a guest's 129
/// token eventfds (made one after the other) are one comparison pair, not 129.
fn runs(fds: &[(RawFd, Access)], write: bool) -> Vec<(u64, u64)> {
    let mut v: Vec<u64> = fds
        .iter()
        .filter(|(fd, a)| *fd >= 0 && if write { a.writes() } else { a.reads() })
        .map(|&(fd, _)| fd as u64)
        .collect();
    v.sort_unstable();
    v.dedup();
    let mut out: Vec<(u64, u64)> = vec![];
    for fd in v {
        match out.last_mut() {
            Some((_, hi)) if *hi + 1 == fd => *hi = fd,
            _ => out.push((fd, fd)),
        }
    }
    out
}

/// The allowlist: syscall number to the rules any one of which allows it (a rule's conditions
/// all hold; no rules: the number alone). Everything a mode's runtime makes and nothing else;
/// each entry widens what a compromised program can do through the gate, so each says why.
pub(crate) fn rules(mode: Mode, pins: &Pins) -> BTreeMap<i64, Vec<SeccompRule>> {
    let threads = mode != Mode::Coroutine;
    let mut r: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    // The SIGSYS handler's return (the runtime's restorer jumps to the gate's `syscall`), and a
    // new host thread's start (its frame, built from a trapped `clone`'s).
    r.insert(libc::SYS_rt_sigreturn, vec![]);
    // Ending the process.
    r.insert(libc::SYS_exit_group, vec![]);
    // The granted fds and the guest's own: `read` and `write` on exactly those the access allows
    // (stdio among them, as the caller granted it: the program's stdin read, stdout and stderr
    // written by the runtime on its behalf; the CPU tokens' eventfds, blocked on and handed over).
    for (write, nr) in [(false, READ), (true, WRITE)] {
        for (lo, hi) in runs(&pins.fds, write) {
            let conds = if lo == hi { vec![eq(0, lo)] } else { within(0, lo, hi) };
            r.entry(nr).or_default().push(rule(conds));
        }
    }
    // Ending it by a signal: the guest's process died of one (its default action), and the
    // sandbox dies of the same, as the program would natively. Only this process, only a signal
    // number: the program can end the sandbox anyway. In fork mode the pid is init's process's,
    // the sandbox's.
    let mut kill = vec![eq(0, pins.pid as u64)];
    kill.extend(within(1, 1, 64));
    r.insert(libc::SYS_kill, vec![rule(kill)]);
    // The one wait: idle to the next timer, a thread's timed sleep on its eventfd, and the fds
    // it waits for (stdin, held fds, passed fds the guest polls). Up to PPOLL_FDS pollfds and no
    // signal mask (a mask would let the gate change the host's blocked signals, SIGSYS among
    // them). Which fds can't be pinned (they are in memory the filter doesn't see), and needn't
    // be: ppoll only reports readiness, it moves no data.
    let mut ppoll = within(1, 0, PPOLL_FDS);
    ppoll.push(eq(3, 0));
    r.insert(libc::SYS_ppoll, vec![rule(ppoll)]);
    // No memory call in any mode (no mmap, no madvise): the program's memory is the arena,
    // reserved before; madvise beside other threads' page faults is the Dirty-COW race class.
    if threads {
        // A host thread per program thread: exactly one flag set, all 64 bits (no namespaces, no
        // CLONE_SETTLS, no vfork, no unknown high bits).
        r.entry(libc::SYS_clone).or_default().push(rule(vec![eq(0, CLONE_THREAD_FLAGS)]));
        // A host thread's end, after its program thread's: status 0 only.
        r.insert(libc::SYS_exit, vec![rule(vec![eq(0, 0)])]);
    }
    if mode == Mode::Fork {
        // The host fork behind a program's fork: flags exactly SIGCHLD and no new stack; from a
        // forked process, CLONE_PARENT too, so every process is a host child of init's, whose
        // SIGCHLD sees any of them die (a sibling, not a new authority).
        let sigchld = libc::SIGCHLD as u64;
        for flags in [sigchld, libc::CLONE_PARENT as u64 | sigchld] {
            r.entry(libc::SYS_clone).or_default().push(rule(vec![eq(0, flags), eq(1, 0)]));
        }
    }
    r
}

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JGE_K: u16 = 0x35;
const RET_K: u16 = 0x06;
pub(crate) const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub(crate) const RET_TRAP: u32 = 0x0003_0000;
#[cfg(test)]
pub(crate) const RET_ERRNO: u32 = 0x0005_0000;
pub(crate) const RET_ALLOW: u32 = 0x7fff_0000;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
/// `__X32_SYSCALL_BIT`, compared as `nr >= this` (unsigned): a negative number is killed too.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Steps 1 and 2 of the module comment. Verdicts: KILL_PROCESS and TRAP only.
pub(crate) fn gate_check(gate_ip: u64) -> [SockFilter; 12] {
    let i = |code, jt, jf, k| SockFilter { code, jt, jf, k };
    [
        i(LD_W_ABS, 0, 0, 4), // arch
        i(JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        i(RET_K, 0, 0, RET_KILL_PROCESS),
        i(LD_W_ABS, 0, 0, 0), // nr
        i(JGE_K, 0, 1, X32_SYSCALL_BIT),
        i(RET_K, 0, 0, RET_KILL_PROCESS),
        i(LD_W_ABS, 0, 0, 8), // instruction_pointer, low half
        i(JEQ_K, 1, 0, gate_ip as u32),
        i(RET_K, 0, 0, RET_TRAP),
        i(LD_W_ABS, 0, 0, 12), // high half
        i(JEQ_K, 1, 0, (gate_ip >> 32) as u32),
        i(RET_K, 0, 0, RET_TRAP),
    ]
}

/// The filter for `mode`: the gate check, then the allowlist compiled by seccompiler. Classic
/// BPF jumps are relative and forward, so the two concatenate as they are.
pub(crate) fn filter(mode: Mode, deny: Deny, pins: &Pins, gate_ip: u64) -> Result<Vec<SockFilter>, seccompiler::Error> {
    let deny = match deny {
        Deny::Kill => SeccompAction::KillProcess,
        Deny::Errno => SeccompAction::Errno(libc::EPERM as u32),
    };
    let filter = SeccompFilter::new(rules(mode, pins), deny, SeccompAction::Allow, TargetArch::x86_64)?;
    let body: BpfProgram = filter.try_into()?;
    let mut p = gate_check(gate_ip).to_vec();
    p.extend(body.iter().map(|f| SockFilter { code: f.code, jt: f.jt, jf: f.jf, k: f.k }));
    Ok(p)
}

/// A caller's restriction as installed: its program after a prologue that lets the one
/// `seccomp` lockdown makes after it through (the filter, installed after the restrictions). The
/// prologue's ALLOW can't widen anything: ALLOW is the weakest verdict, and the filter, stacked
/// on top, judges every call after it (and refuses `seccomp` from the gate, traps it elsewhere).
pub(crate) fn restriction(insns: &[SockFilter]) -> Vec<SockFilter> {
    let i = |code, jt, jf, k| SockFilter { code, jt, jf, k };
    let mut p = vec![
        i(LD_W_ABS, 0, 0, 0),                     // nr
        i(JEQ_K, 0, 1, libc::SYS_seccomp as u32), // else -> the caller's
        i(RET_K, 0, 0, RET_ALLOW),
    ];
    p.extend_from_slice(insns);
    p
}

#[cfg(test)]
#[allow(dead_code)]
mod old;
#[cfg(test)]
mod tests;
