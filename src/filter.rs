//! The core filter: which host syscalls the process may make after lockdown, each argument
//! pinned, without any plugin. [`core_policy`] is the whole of it, as a plain Rust function of a call
//! (`d`) and the [`crate::Config`]'s mode and the gate's address;
//! `seccomp_fn::bpf!` compiles it to classic BPF. The installed filter is this one composed with
//! the enabled plugins' rows ([`policy`], [`filter`], below), and Kani proves
//! that program gives the composed function's verdict on every call, for every mode, plugin
//! choice, floor and gate (`cargo kani`: `filter::proof::*`). The compiler isn't trusted:
//! the proof checks its output. [`crate::lockdown`] installs it.
//!
//! **Shape.** 1. Another arch, or the x32 bit: KILL_PROCESS (the rows know only x86-64 numbers,
//! and must not judge another ABI's). 2. Not from the gate ([`crate::Config::gate`]): TRAP,
//! the program's call, served in-process by the runtime's SIGSYS handler; every thread and
//! process made after lockdown inherits the filter, so this is how all of them are served. The
//! gate's address is the guest's value, which a reviewer needn't trust: this check returns only
//! TRAP and KILL. 3. README.md's core table, row by row: ALLOW, or [`NO_MATCH`] (the plugins'
//! turn, and then KILL_PROCESS). There is one filter; no `prctl`, `seccomp` or
//! syscall-user-dispatch rule is in it.
#![allow(non_upper_case_globals)] // libc's syscall names, as patterns

use libc::{seccomp_data, sock_filter};

use crate::Mode;
use crate::plugin::{Fs, fs, net};
use libc::SECCOMP_RET_KILL_THREAD;

// The policy's syscalls, libc's.
use libc::{SYS_clone, SYS_exit, SYS_exit_group, SYS_ppoll, SYS_read, SYS_rt_sigreturn, SYS_write};
pub use libc::{SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_TRAP};
/// The core's "none of my rows": never installed (the composition, [`filter`],
/// turns each into the plugins' turn, then KILL_PROCESS). `SECCOMP_RET_KILL_THREAD`'s value, so
/// a program that still had one would fail closed.
pub(crate) const NO_MATCH: u32 = SECCOMP_RET_KILL_THREAD;
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
/// The most pollfds the core's `ppoll` may pass (the guest's kept fds' waits; the network
/// plugin's own row allows more).
pub const PPOLL_FDS: u64 = 8;

/// The core's verdict on a call `d`: README.md's core table, a row per row, in its order. Each
/// row widens what a compromised program can do through the gate, so each says why. The core's
/// rows take no fd floor: without a plugin no row makes an fd, so every open fd is a kept one
/// (lockdown leaves exactly those, at `0..n`). The core knows no plugin: a call its rows don't allow is [`NO_MATCH`], which
/// the composition ([`policy`]) gives to the enabled plugins' rows, and else kills.
/// The arch and gate checks come first and are final: no plugin row sees another ABI's call or
/// the program's.
pub(crate) fn core_policy(mode: Mode, gate: u64) -> impl Fn(&seccomp_data) -> u32 {
    move |d| {
        // Another ABI: the rows know only x86-64's numbers, and must not judge another's.
        if d.arch != AUDIT_ARCH_X86_64 || d.nr as u32 >= X32_SYSCALL_BIT {
            return SECCOMP_RET_KILL_PROCESS;
        }
        // Not from the gate: the program's call, served in-process (SIGSYS). TRAP or KILL only.
        if d.instruction_pointer != gate {
            return SECCOMP_RET_TRAP;
        }
        let threads = mode != Mode::Coroutine;
        let fork = mode == Mode::Fork;
        match d.nr as i64 {
            // Any fd: only kept ones are open (and, with a plugin, the ones its rows make), each as
            // its own mode allows.
            SYS_read | SYS_write => SECCOMP_RET_ALLOW,
            // Readiness only, at most `PPOLL_FDS` fds; no signal mask (it could unblock SIGSYS).
            SYS_ppoll if d.args[1] <= PPOLL_FDS && d.args[3] == 0 => SECCOMP_RET_ALLOW,
            // The end of the process; the SIGSYS handler's return, and a new host thread's start.
            SYS_exit_group | SYS_rt_sigreturn => SECCOMP_RET_ALLOW,
            // A host thread: exactly its flags, all 64 bits (no namespaces, no SETTLS, no vfork).
            SYS_clone if threads && d.args[0] == CLONE_THREAD_FLAGS => SECCOMP_RET_ALLOW,
            // A host thread's end: status 0 only.
            SYS_exit if threads && d.args[0] == 0 => SECCOMP_RET_ALLOW,
            // A host fork: exactly SIGCHLD (CLONE_PARENT too, from a forked process: every process
            // a child of init's), no new stack.
            SYS_clone
                if fork
                    && (d.args[0] == libc::SIGCHLD as u64 || d.args[0] == (libc::CLONE_PARENT | libc::SIGCHLD) as u64)
                    && d.args[1] == 0 =>
            {
                SECCOMP_RET_ALLOW
            }
            // Plugin: fs, net. The close of an fd a plugin opened (at or above `n`), never a kept
            // one (the guest answers that).
            // Nothing else of the core's: no memory call (the arena is reserved before), no signal
            // (a death by one is the runtime's `exit_group(128 + n)`), nothing that makes an fd.
            _ => NO_MATCH,
        }
    }
}

/// The core's program ([`core_policy`]'s, `NO_MATCH` included: [`filter`] turns it into the
/// plugins' turn).
fn core_filter(mode: Mode, gate: u64) -> Vec<sock_filter> {
    seccomp_fn::bpf!(core_policy(mode, gate))
}

/// The whole filter's verdict on `d`: the core's ([`core_policy`]: arch, gate, its rows), and if
/// its rows found none, ALLOW where an enabled plugin's rows allow, else KILL_PROCESS. A plugin's
/// rows answer ALLOW or nothing: any other verdict of theirs is no match.
pub fn policy(mode: Mode, n: u64, gate: u64, fs: Fs, net: bool) -> impl Fn(&seccomp_data) -> u32 {
    let core = core_policy(mode, gate);
    let files = fs::policy(n, fs == Fs::ReadWrite);
    let sockets = net::policy(n);
    move |d| {
        let v = core(d);
        if v != NO_MATCH {
            return v;
        }
        if fs != Fs::Off && files(d) == SECCOMP_RET_ALLOW {
            return SECCOMP_RET_ALLOW;
        }
        if net && sockets(d) == SECCOMP_RET_ALLOW {
            return SECCOMP_RET_ALLOW;
        }
        SECCOMP_RET_KILL_PROCESS
    }
}

/// [`policy`]'s program: the core's, then each enabled plugin's, then KILL_PROCESS. Each part is
/// its own compiled program, joined by turning its "no match" returns into a jump past its end
/// (the core's `NO_MATCH`; a plugin's every return but ALLOW): every jump in a part is forward
/// and inside it, so the parts concatenate. Not trusted: the proof checks the joined program.
pub fn filter(mode: Mode, n: u64, gate: u64, fs: Fs, net: bool) -> Vec<sock_filter> {
    let mut prog = vec![];
    append(&mut prog, core_filter(mode, gate), |i| ret_k(i) == Some(NO_MATCH));
    if fs != Fs::Off {
        append(&mut prog, fs::filter(n, fs == Fs::ReadWrite), |i| is_ret(i) && ret_k(i) != Some(SECCOMP_RET_ALLOW));
    }
    if net {
        append(&mut prog, net::filter(n), |i| is_ret(i) && ret_k(i) != Some(SECCOMP_RET_ALLOW));
    }
    prog.push(sock_filter { code: (libc::BPF_RET | libc::BPF_K) as u16, jt: 0, jf: 0, k: SECCOMP_RET_KILL_PROCESS });
    prog
}

fn is_ret(i: &sock_filter) -> bool {
    i.code & 0x07 == libc::BPF_RET as u16
}

fn ret_k(i: &sock_filter) -> Option<u32> {
    (i.code == (libc::BPF_RET | libc::BPF_K) as u16).then_some(i.k)
}

/// `part` onto `prog`, each instruction `falls` picks made a jump to just past the part.
fn append(prog: &mut Vec<sock_filter>, part: Vec<sock_filter>, falls: impl Fn(&sock_filter) -> bool) {
    let len = part.len();
    for (at, i) in part.into_iter().enumerate() {
        prog.push(if falls(&i) { sock_filter { code: (libc::BPF_JMP | libc::BPF_JA) as u16, jt: 0, jf: 0, k: (len - at - 1) as u32 } } else { i });
    }
}

// The proof: a harness per mode and plugin choice (a mode symbolic took 5x as long as one
// fixed: 663 s against 131 s), the floor and gate symbolic (`filter::proof::*`).
#[cfg(kani)]
mod proof {
    use super::*;
    seccomp_fn_verify::prove!(policy, filter, unwind = 1024, (
        Mode = [coroutine: Coroutine, threaded: Threaded, fork: Fork], _, _,
        Fs = [no_fs: Off, fs_ro: ReadOnly, fs_rw: ReadWrite],
        bool = [no_net: false, net: true]
    ));
}

