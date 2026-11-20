//! The filter: which host syscalls the process may make after lockdown, each argument pinned.
//! [`policy`] is the whole of it, as a plain Rust function of a call (`d`) and the [`Config`]'s
//! mode and `ppoll_max`, the process's pid and the gate's address; `seccomp_fn::compile!`
//! compiles it to classic BPF ([`filter`]), and Kani proves the program gives the function's
//! verdict on every call, for every mode, pid, bound and gate (`cargo kani`:
//! seccomp-fn-validate's harness, `filter::policy_proof::policy_is_filter`). The compiler isn't
//! trusted: the proof checks its output.
//! [`crate::lockdown`] installs it.
//!
//! **Shape.** 1. Another arch, or the x32 bit: KILL_PROCESS (the rows know only x86-64 numbers,
//! and must not judge another ABI's). 2. Not from the gate ([`crate::Confined::gate_ip`]): TRAP,
//! the program's call, served in-process by the runtime's SIGSYS handler; every thread and
//! process made after lockdown inherits the filter, so this is how all of them are served. The
//! gate's address is the guest's value, which a reviewer needn't trust: this check returns only
//! TRAP and KILL. 3. README.md's table, row by row: ALLOW, or KILL_PROCESS.
//! There is one filter; no `prctl`, `seccomp` or syscall-user-dispatch rule is in it.
#![allow(non_upper_case_globals)] // libc's syscall names, as patterns

use libc::{seccomp_data, sock_filter};

use crate::Mode;

// The policy's syscalls, libc's.
use libc::{SYS_clone, SYS_exit, SYS_exit_group, SYS_kill, SYS_ppoll, SYS_read, SYS_rt_sigreturn, SYS_write};
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
/// [`crate::Config::ppoll_max`]'s default.
pub const PPOLL_FDS: u64 = 8;

/// The filter's verdict on a call `d`: README.md's table, a row per row, in its order. Each row
/// widens what a compromised program can do through the gate, so each says why.
pub fn policy(mode: Mode, pid: u64, ppoll_max: u64, gate: u64) -> impl Fn(&seccomp_data) -> u32 {
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
            // Any fd: lockdown closed all but the kept ones, and no row makes another.
            SYS_read | SYS_write => SECCOMP_RET_ALLOW,
            // Readiness only, at most `ppoll_max` fds; no signal mask (it could unblock SIGSYS).
            SYS_ppoll if d.args[1] <= ppoll_max && d.args[3] == 0 => SECCOMP_RET_ALLOW,
            // Only this process (init's in fork mode), only a signal number.
            SYS_kill if d.args[0] == pid && d.args[1] >= 1 && d.args[1] <= 64 => SECCOMP_RET_ALLOW,
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
            // Nothing else: no memory call (the arena is reserved before), nothing that makes an fd.
            _ => SECCOMP_RET_KILL_PROCESS,
        }
    }
}

// The proof: a harness per mode (one with the mode symbolic took 5x as long: 663 s against
// 131 s), every other param symbolic.
seccomp_fn_validate::policy!(policy, filter, unwind = 100, (
    Mode = [coroutine: Coroutine, threaded: Threaded, fork: Fork], _, _, _
));

/// The filter for `mode` and `ppoll_max` ([`crate::Config`]'s): [`policy`]'s program. `pid` is
/// the process's own (the one `kill` may signal), `gate` the gate's
/// ([`crate::Confined::gate_ip`]). Public, so the exact program can be inspected and tested.
pub fn filter(mode: Mode, pid: u64, ppoll_max: u64, gate: u64) -> Vec<sock_filter> {
    seccomp_fn::compile!(policy(mode, pid, ppoll_max, gate))
}
