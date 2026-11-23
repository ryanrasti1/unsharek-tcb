//! The core filter: which host syscalls the process may make after lockdown, each argument
//! pinned, without any plugin. [`core`] is the whole of it, a plain Rust function of a call (`d`,
//! through its typed view, `d.call()`: each argument as the kernel reads it) and the
//! [`crate::Config`]'s mode. The installed filter is seccomp-fn-verify's combinator
//! ([`seccomp_fn_verify::expr::gated`]) of it and the enabled plugins' rows ([`filter`]), compiled
//! by its compiler, proven once for every tree (its `proof.rs`): no proof here.
//! [`crate::lockdown`] installs it.
//!
//! **Shape** (the combinator's). 1. Another arch, or the x32 bit: KILL_PROCESS (the rows know only
//! x86-64 numbers, and must not judge another ABI's). 2. Not from the gate
//! ([`crate::Config::gate`]): TRAP, the program's call, served in-process by the runtime's SIGSYS
//! handler; every thread and process made after lockdown inherits the filter, so this is how
//! all of them are served. The gate's address is the guest's value, which a reviewer needn't
//! trust: this check returns only TRAP and KILL. 3. ALLOW if README.md's core table's rows
//! ([`core`]) or an enabled plugin's allow the call, else KILL_PROCESS: a plugin's rows can only
//! allow, never change the checks before them. There is one filter; no `prctl`, `seccomp` or
//! syscall-user-dispatch rule is in it.
#![allow(non_upper_case_globals)]

use libc::seccomp_data;
use seccomp_fn_verify::calls::{Call, CallExt};
use seccomp_fn_verify::tree::Tree;

use crate::Mode;
use crate::plugin::{Fs, fs, net};

pub use libc::{SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_TRAP};
// Not in libc for x86_64:
/// include/uapi/linux/audit.h: `AUDIT_ARCH_X86_64 = EM_X86_64 | __AUDIT_ARCH_64BIT |
/// __AUDIT_ARCH_LE` (the last two `0x80000000` and `0x40000000`), EM_X86_64 libc's.
pub const AUDIT_ARCH_X86_64: u32 = libc::EM_X86_64 as u32 | 0x8000_0000 | 0x4000_0000;
/// `__X32_SYSCALL_BIT`, arch/x86/include/uapi/asm/unistd.h (libc has it for the x32 target
/// only). Compared as `nr >= this` (unsigned): a negative number is killed too.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The flags of a host thread's `clone`: a thread of this process, its tid cleared at its end.
pub const CLONE_THREAD_FLAGS: u64 = (libc::CLONE_VM
    | libc::CLONE_FS
    | libc::CLONE_FILES
    | libc::CLONE_SIGHAND
    | libc::CLONE_THREAD
    | libc::CLONE_SYSVSEM
    | libc::CLONE_CHILD_CLEARTID) as u64;
/// A host fork's `clone` flags: exactly SIGCHLD, or `CLONE_PARENT | SIGCHLD` (from a forked
/// process: every process a child of init's).
const FORK: u64 = libc::SIGCHLD as u64;
const FORK_PARENT: u64 = (libc::CLONE_PARENT | libc::SIGCHLD) as u64;
/// The most pollfds the core's `ppoll` may pass (the guest's kept fds' waits; the network
/// plugin's own row allows more).
pub const PPOLL_FDS: u32 = 8;

/// The core's rows: README.md's core table, a row per row, in its order. Each row widens what a
/// compromised program can do through the gate, so each says why. The core's rows take no fd
/// floor: without a plugin no row makes an fd, so every open fd is a kept one (lockdown leaves
/// exactly those, at `0..n`). Nothing else of the core's: no memory call (the arena is reserved
/// before), no signal (a death by one is the runtime's `exit_group(128 + n)`), nothing that
/// makes an fd.
pub fn core(d: &seccomp_data, threads: bool, fork: bool) -> bool {
    match d.call() {
        // Any fd: only kept ones are open (and, with a plugin, the ones its rows make), each as
        // its own mode allows.
        Call::Read { .. } | Call::Write { .. } => true,
        // Readiness only, at most `PPOLL_FDS` fds; no signal mask (it could unblock SIGSYS).
        Call::Ppoll { nfds, sigmask, .. } => nfds <= PPOLL_FDS && sigmask.is_null(),
        // The end of the process; the SIGSYS handler's return, and a new host thread's start.
        Call::ExitGroup { .. } | Call::RtSigreturn => true,
        // A host thread: exactly its flags, all 64 bits (no namespaces, no SETTLS, no vfork).
        Call::Clone { clone_flags, .. } if threads && clone_flags == CLONE_THREAD_FLAGS => true,
        // A host thread's end: status 0 only.
        Call::Exit { error_code } => threads && error_code == 0,
        // A host fork: exactly SIGCHLD (CLONE_PARENT too), no new stack.
        Call::Clone { clone_flags, newsp, .. } => fork && (clone_flags == FORK || clone_flags == FORK_PARENT) && newsp == 0,
        _ => false,
    }
}

/// The whole filter's verdict on `d`: the core's rows, then the enabled plugins' (fs's at
/// `fs`, net's if `net`), behind the arch and gate checks, the floor `n`. [`TREE`] is this
/// function's tree (the combinator's), checked equal to it by the `tree_is_policy` harnesses
/// below; [`filter`] compiles it.
pub fn policy(mode: Mode, n: u64, gate: u64, fs: Fs, net: bool) -> impl Fn(&seccomp_data) -> u32 {
    let (threads, fork) = (mode != Mode::Coroutine, mode == Mode::Fork);
    let n = n as u32;
    move |d| {
        if d.arch != AUDIT_ARCH_X86_64 || d.nr as u32 >= X32_SYSCALL_BIT {
            return SECCOMP_RET_KILL_PROCESS;
        }
        if d.instruction_pointer != gate {
            return SECCOMP_RET_TRAP;
        }
        if core(d, threads, fork) || fs::enabled(d, n, fs) || net::enabled(d, n, net) { SECCOMP_RET_ALLOW } else { SECCOMP_RET_KILL_PROCESS }
    }
}

/// The filter's tree, as `const` data: seccomp-fn-verify's combinator (`gated!`) of the core's
/// rows and each plugin's sub-filter ([`fs::ROWS`], [`net::ROWS`]), over [`filter`]'s params
/// by position (`mode, n, gate, fs, net`: each `rows!`'s `in (…)`). Each sub-filter can only allow, never change the checks before it; a plugin not
/// enabled (`fs` off, `net` false) prunes to nothing at build.
pub const TREE: Tree = seccomp_fn_verify::gated!(
    arch = S::Const(AUDIT_ARCH_X86_64 as u64),
    gate = S::Param(2),
    core = seccomp_fn::rows!(core(d, mode != Mode::Coroutine, mode == Mode::Fork) in (mode, n, gate, fs, net)),
    subs = [fs::ROWS, net::ROWS],
);
seccomp_fn_verify::filter!(
    /// [`TREE`]'s program for the params: [`policy`]'s (the harnesses below), compiled by
    /// seccomp-fn-verify's compiler, proven once for every tree.
    pub fn filter(mode: Mode, n: u64, gate: u64, fs: Fs, net: bool) = TREE, policy;
    check tree_is_policy
);

// The check, per mode and plugin choice; the floor and gate symbolic; every call.
#[cfg(kani)]
mod proof {
    use super::*;
    use ::kani::any;
    seccomp_fn_verify::harnesses!(tree_is_policy, unwind = 64;
        coroutine_off => (None, Mode::Coroutine, any(), any(), Fs::Off, false);
        coroutine_off_net => (None, Mode::Coroutine, any(), any(), Fs::Off, true);
        coroutine_ro => (None, Mode::Coroutine, any(), any(), Fs::ReadOnly, false);
        coroutine_ro_net => (None, Mode::Coroutine, any(), any(), Fs::ReadOnly, true);
        coroutine_rw => (None, Mode::Coroutine, any(), any(), Fs::ReadWrite, false);
        coroutine_rw_net => (None, Mode::Coroutine, any(), any(), Fs::ReadWrite, true);
        threaded_off => (None, Mode::Threaded, any(), any(), Fs::Off, false);
        threaded_off_net => (None, Mode::Threaded, any(), any(), Fs::Off, true);
        threaded_ro => (None, Mode::Threaded, any(), any(), Fs::ReadOnly, false);
        threaded_ro_net => (None, Mode::Threaded, any(), any(), Fs::ReadOnly, true);
        threaded_rw => (None, Mode::Threaded, any(), any(), Fs::ReadWrite, false);
        threaded_rw_net => (None, Mode::Threaded, any(), any(), Fs::ReadWrite, true);
        fork_off => (None, Mode::Fork, any(), any(), Fs::Off, false);
        fork_off_net => (None, Mode::Fork, any(), any(), Fs::Off, true);
        fork_ro => (None, Mode::Fork, any(), any(), Fs::ReadOnly, false);
        fork_ro_net => (None, Mode::Fork, any(), any(), Fs::ReadOnly, true);
        fork_rw => (None, Mode::Fork, any(), any(), Fs::ReadWrite, false);
        fork_rw_net => (None, Mode::Fork, any(), any(), Fs::ReadWrite, true);
    );
}
