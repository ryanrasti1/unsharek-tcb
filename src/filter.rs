//! The filter: which host syscalls the process may make after lockdown, each argument pinned.
//! [`policy`] is the whole of it, as a plain Rust function of a call (`d`) and the [`Config`]'s
//! mode, fd floor and `ppoll_max`, and the gate's address; `seccomp_fn::compile!`
//! compiles it to classic BPF ([`filter`]), and Kani proves the program gives the function's
//! verdict on every call, for every mode, floor, bound and gate (`cargo kani`:
//! seccomp-fn-verify's harness, `filter::policy_proof::policy_is_filter`). The compiler isn't
//! trusted: the proof checks its output.
//! [`crate::lockdown`] installs it.
//!
//! **Shape.** 1. Another arch, or the x32 bit: KILL_PROCESS (the rows know only x86-64 numbers,
//! and must not judge another ABI's). 2. Not from the gate ([`crate::Config::gate`]): TRAP,
//! the program's call, served in-process by the runtime's SIGSYS handler; every thread and
//! process made after lockdown inherits the filter, so this is how all of them are served. The
//! gate's address is the guest's value, which a reviewer needn't trust: this check returns only
//! TRAP and KILL. 3. README.md's table, row by row: ALLOW, or KILL_PROCESS.
//! There is one filter; no `prctl`, `seccomp` or syscall-user-dispatch rule is in it.
#![allow(non_upper_case_globals)] // libc's syscall names, as patterns

use libc::{seccomp_data, sock_filter};

use crate::Mode;

// The policy's syscalls, libc's.
use libc::{SYS_clone, SYS_close, SYS_exit, SYS_exit_group, SYS_ppoll, SYS_read, SYS_recvmsg, SYS_rt_sigreturn, SYS_write};
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
/// The largest fd (the kernel's `int`): an fd condition's upper bound, so that no high bit of the
/// 64-bit register turns a refused number into another (the kernel reads 32 bits).
const INT_MAX: u64 = i32::MAX as u64;
/// [`crate::Config::ppoll_max`]'s default.
pub const PPOLL_FDS: u64 = 8;

/// The filter's verdict on a call `d`: README.md's table, a row per row, in its order. Each row
/// widens what a compromised program can do through the gate, so each says why. `n` is the fd
/// floor ([`crate::Fds::n`]): lockdown leaves the kept fds, and only them, at `0..n`; an fd at
/// or above `n` can only be one a row made after lockdown (the kernel gives the lowest free
/// number). `ctl` is the control socket's number (below `n`), with the capnweb plugin.
pub fn policy(mode: Mode, n: u64, ppoll_max: u64, gate: u64, ctl: Option<u64>) -> impl Fn(&seccomp_data) -> u32 {
    move |d| {
        // Plugin: capnweb. Its rows only with a control socket.
        let plugin = ctl.is_some();
        let ctl_fd = ctl.unwrap_or(0);
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
            // A kept fd (below `n`), as its own mode allows; with the plugin also a received one
            // (every fd at or above `n` is).
            SYS_read | SYS_write if d.args[0] < n || (plugin && d.args[0] <= INT_MAX) => SECCOMP_RET_ALLOW,
            // Readiness only, at most `ppoll_max` fds; no signal mask (it could unblock SIGSYS).
            SYS_ppoll if d.args[1] <= ppoll_max && d.args[3] == 0 => SECCOMP_RET_ALLOW,
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
            // Plugin: capnweb (experimental). Fds from the provider's process, on the control
            // socket only (`ctl`, a unix seqpacket socket, lockdown checks), close-on-exec; none
            // sent out (no `sendmsg`). A received fd gets what every kept fd gets: `read`, `write`.
            SYS_recvmsg if plugin && d.args[0] == ctl_fd && d.args[2] == libc::MSG_CMSG_CLOEXEC as u64 => {
                SECCOMP_RET_ALLOW
            }
            // Plugin: capnweb. The close of a received fd: at or above `n`, where only `recvmsg`
            // makes one; an int (no higher bits set).
            SYS_close if plugin && d.args[0] >= n && d.args[0] <= INT_MAX => SECCOMP_RET_ALLOW,
            // Nothing else: no memory call (the arena is reserved before), no signal (a death by
            // one is the runtime's `exit_group(128 + n)`), nothing that makes an fd.
            _ => SECCOMP_RET_KILL_PROCESS,
        }
    }
}

// The proof: a harness per mode (one with the mode symbolic took 5x as long: 663 s against
// 131 s), every other param symbolic.
seccomp_fn_verify::policy!(policy, filter, unwind = 128, (
    Mode = [coroutine: Coroutine, threaded: Threaded, fork: Fork], _, _, _,
    Option<u64> = [none: None, some: Some(_)]
));

/// The filter for `mode`, the fd floor `n` ([`crate::Fds::n`]), `ppoll_max`, the gate
/// ([`crate::Config::gate`]) and the control socket's number, if any: [`policy`]'s program.
/// Public, so the exact program can be inspected and tested.
pub fn filter(mode: Mode, n: u64, ppoll_max: u64, gate: u64, ctl: Option<u64>) -> Vec<sock_filter> {
    seccomp_fn::compile!(policy(mode, n, ppoll_max, gate, ctl))
}
