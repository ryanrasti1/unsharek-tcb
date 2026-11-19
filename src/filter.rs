//! The filter: which host syscalls the process may make after lockdown, each argument pinned.
//! [`filter`] makes it from the [`Config`]'s three fields (mode, fds, `ppoll_max`), the
//! process's pid and the gate's address, with seccompiler (Firecracker's); [`crate::lockdown`]
//! installs it.
//!
//! **Shape.** A short hand-written gate check, then seccompiler's allowlist:
//! 1. arch is not x86-64, or the x32 bit is set: KILL_PROCESS (the allowlist knows only x86-64
//!    numbers, and must not judge another ABI's);
//! 2. the instruction pointer is not the gate's ([`crate::Confined::gate_ip`]): TRAP, the
//!    program's call, served in-process by the runtime's SIGSYS handler. Every thread and process
//!    made after lockdown inherits the filter, so this is how all of them are served;
//! 3. seccompiler's program over [`rules`]: a call that matches a rule is ALLOW, anything else
//!    KILL_PROCESS.
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

use crate::{Access, Config, Mode};

/// One classic-BPF instruction (`struct sock_filter`, include/uapi/linux/filter.h).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
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
/// [`Config::ppoll_max`]'s default.
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

/// When a row allows its syscall: always (any arguments), or when one of its rules holds (none:
/// never). The two differ on purpose: to seccompiler an empty rule list is "any arguments".
enum Allow {
    Always,
    When(Vec<SeccompRule>),
}

/// The modes a row is in.
const ALL: &[Mode] = &[Mode::Coroutine, Mode::Threaded, Mode::Fork];
const THREADS: &[Mode] = &[Mode::Threaded, Mode::Fork];
const FORK: &[Mode] = &[Mode::Fork];

/// `read` or `write` on the fds the grants allow it on: one rule per run of consecutive fds.
fn on_fds(config: &Config, write: bool) -> Allow {
    let conds = |(lo, hi)| if lo == hi { vec![eq(0, lo)] } else { within(0, lo, hi) };
    Allow::When(runs(&config.fds, write).into_iter().map(|r| rule(conds(r))).collect())
}

/// The allowlist, README.md's table row by row: everything a mode's runtime makes and nothing
/// else. Each row widens what a compromised program can do through the gate, so each says why.
fn table(config: &Config, pid: u32) -> Vec<(i64, Allow, &'static [Mode])> {
    let sigchld = libc::SIGCHLD as u64;
    let mut kill = vec![eq(0, pid as u64)];
    kill.extend(within(1, 1, 64));
    let mut ppoll = within(1, 0, config.ppoll_max);
    ppoll.push(eq(3, 0));
    vec![
        // The granted fds and the guest's own, with the access each was granted (stdio among them,
        // as the caller granted it; the CPU tokens' eventfds, blocked on and handed over).
        (READ, on_fds(config, false), ALL),
        (WRITE, on_fds(config, true), ALL),
        // The one wait: idle to the next timer, a thread's timed sleep on its eventfd, the fds it
        // waits for. Up to `ppoll_max` pollfds and no signal mask (a mask would let the gate change
        // the host's blocked signals, SIGSYS among them). Which fds can't be pinned (they are in
        // memory the filter doesn't see), and needn't be: ppoll only reports readiness.
        (libc::SYS_ppoll, Allow::When(vec![rule(ppoll)]), ALL),
        // Ending it by a signal, as the program would natively: only this process (in fork mode
        // init's, the sandbox's), only a signal number. The program can end the sandbox anyway.
        (libc::SYS_kill, Allow::When(vec![rule(kill)]), ALL),
        // Ending the process.
        (libc::SYS_exit_group, Allow::Always, ALL),
        // The SIGSYS handler's return (the runtime's restorer jumps to the gate's `syscall`), and
        // a new host thread's start (its frame, built from a trapped `clone`'s).
        (libc::SYS_rt_sigreturn, Allow::Always, ALL),
        // A host thread per program thread: exactly one flag set, all 64 bits (no namespaces, no
        // CLONE_SETTLS, no vfork, no unknown high bits).
        (libc::SYS_clone, Allow::When(vec![rule(vec![eq(0, CLONE_THREAD_FLAGS)])]), THREADS),
        // A host thread's end, after its program thread's: status 0 only.
        (libc::SYS_exit, Allow::When(vec![rule(vec![eq(0, 0)])]), THREADS),
        // The host fork behind a program's fork: flags exactly SIGCHLD and no new stack; from a
        // forked process CLONE_PARENT too, so every process is a host child of init's, whose
        // SIGCHLD sees any of them die (a sibling, not a new authority).
        (
            libc::SYS_clone,
            Allow::When(vec![
                rule(vec![eq(0, sigchld), eq(1, 0)]),
                rule(vec![eq(0, libc::CLONE_PARENT as u64 | sigchld), eq(1, 0)]),
            ]),
            FORK,
        ),
        // No memory call in any mode (no mmap, no madvise): the program's memory is the arena,
        // reserved before.
    ]
}

/// [`table`]'s rows for `config.mode`, as seccompiler takes them: a syscall's rows merged (any one
/// rule allows it), and a row that allows nothing left out.
fn rules(config: &Config, pid: u32) -> BTreeMap<i64, Vec<SeccompRule>> {
    let mut r: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for (nr, allow, modes) in table(config, pid) {
        if !modes.contains(&config.mode) {
            continue;
        }
        match allow {
            Allow::Always => {
                r.insert(nr, vec![]);
            }
            Allow::When(rules) if !rules.is_empty() => r.entry(nr).or_default().extend(rules),
            Allow::When(_) => {}
        }
    }
    r
}

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JGE_K: u16 = 0x35;
const RET_K: u16 = 0x06;
/// The filter's verdicts (include/uapi/linux/seccomp.h).
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_TRAP: u32 = 0x0003_0000;
pub const RET_ALLOW: u32 = 0x7fff_0000;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
/// `__X32_SYSCALL_BIT`, compared as `nr >= this` (unsigned): a negative number is killed too.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Steps 1 and 2 of the module comment. Verdicts: KILL_PROCESS and TRAP only.
fn gate_check(gate_ip: u64) -> [SockFilter; 12] {
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

/// The filter: `config` (its mode, fds and `ppoll_max`) as the gate check, then the allowlist
/// compiled by seccompiler. `pid` is the process's own (the one `kill` may signal), `gate_ip`
/// the gate's ([`crate::Confined::gate_ip`]). Classic BPF jumps are relative and forward, so the
/// two concatenate as they are. Public, so the exact program can be inspected and tested.
pub fn filter(config: &Config, pid: u32, gate_ip: u64) -> Result<Vec<SockFilter>, seccompiler::Error> {
    let f = SeccompFilter::new(rules(config, pid), SeccompAction::KillProcess, SeccompAction::Allow, TargetArch::x86_64)?;
    let body: BpfProgram = f.try_into()?;
    let mut p = gate_check(gate_ip).to_vec();
    p.extend(body.iter().map(|f| SockFilter { code: f.code, jt: f.jt, jf: f.jf, k: f.k }));
    Ok(p)
}
