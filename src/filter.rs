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

use crate::{Fs, Mode};

// The policy's syscalls, libc's.
use libc::{
    SYS_accept4, SYS_bind, SYS_clone, SYS_close, SYS_connect, SYS_exit, SYS_exit_group, SYS_fallocate, SYS_fchmodat,
    SYS_fchownat, SYS_fcntl, SYS_fdatasync, SYS_fstat, SYS_fstatfs, SYS_fsync, SYS_ftruncate, SYS_getdents64,
    SYS_getpeername, SYS_getsockname, SYS_getsockopt, SYS_linkat, SYS_listen, SYS_lseek, SYS_mkdirat, SYS_newfstatat,
    SYS_openat, SYS_ppoll, SYS_pread64, SYS_pwrite64, SYS_read, SYS_readlinkat, SYS_recvfrom, SYS_renameat2,
    SYS_rt_sigreturn, SYS_sendto, SYS_setsockopt, SYS_shutdown, SYS_socket, SYS_statx, SYS_symlinkat, SYS_unlinkat,
    SYS_utimensat, SYS_write,
};
pub use libc::{SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_TRAP};
// Flags the rows compare with, libc's, as u64 (the registers' width).
const O_RDONLY: u64 = libc::O_RDONLY as u64;
const O_WRONLY: u64 = libc::O_WRONLY as u64;
const O_RDWR: u64 = libc::O_RDWR as u64;
const O_CREAT: u64 = libc::O_CREAT as u64;
const O_EXCL: u64 = libc::O_EXCL as u64;
const O_TRUNC: u64 = libc::O_TRUNC as u64;
const O_APPEND: u64 = libc::O_APPEND as u64;
const O_NONBLOCK: u64 = libc::O_NONBLOCK as u64;
const O_DIRECTORY: u64 = libc::O_DIRECTORY as u64;
const O_NOFOLLOW: u64 = libc::O_NOFOLLOW as u64;
const O_CLOEXEC: u64 = libc::O_CLOEXEC as u64;
/// Every `openat`'s: nonblocking (a FIFO or a device must not block the open), close-on-exec.
const O_NB: u64 = O_NONBLOCK | O_CLOEXEC;
const AT_SYMLINK_NOFOLLOW: u64 = libc::AT_SYMLINK_NOFOLLOW as u64;
const AT_SYMLINK_FOLLOW: u64 = libc::AT_SYMLINK_FOLLOW as u64;
const AT_REMOVEDIR: u64 = libc::AT_REMOVEDIR as u64;
const SEEK_HOLE: u64 = libc::SEEK_HOLE as u64;
const F_GETFL: u64 = libc::F_GETFL as u64;
const F_SETFL: u64 = libc::F_SETFL as u64;
const AF_INET: u64 = libc::AF_INET as u64;
const AF_INET6: u64 = libc::AF_INET6 as u64;
const SOCK_STREAM: u64 = libc::SOCK_STREAM as u64;
const SOCK_DGRAM: u64 = libc::SOCK_DGRAM as u64;
const SOCK_NONBLOCK: u64 = libc::SOCK_NONBLOCK as u64;
const SOCK_CLOEXEC: u64 = libc::SOCK_CLOEXEC as u64;
const MSG_DONTWAIT: u64 = libc::MSG_DONTWAIT as u64;
const MSG_NOSIGNAL: u64 = libc::MSG_NOSIGNAL as u64;
const SOL_SOCKET: u64 = libc::SOL_SOCKET as u64;
const SO_REUSEADDR: u64 = libc::SO_REUSEADDR as u64;
const SO_KEEPALIVE: u64 = libc::SO_KEEPALIVE as u64;
const SO_SNDBUF: u64 = libc::SO_SNDBUF as u64;
const SO_RCVBUF: u64 = libc::SO_RCVBUF as u64;
const SO_ERROR: u64 = libc::SO_ERROR as u64;
const IPPROTO_TCP: u64 = libc::IPPROTO_TCP as u64;
const TCP_NODELAY: u64 = libc::TCP_NODELAY as u64;
const TCP_KEEPIDLE: u64 = libc::TCP_KEEPIDLE as u64;
const TCP_KEEPINTVL: u64 = libc::TCP_KEEPINTVL as u64;
const TCP_KEEPCNT: u64 = libc::TCP_KEEPCNT as u64;
const IPPROTO_IPV6: u64 = libc::IPPROTO_IPV6 as u64;
const IPV6_V6ONLY: u64 = libc::IPV6_V6ONLY as u64;
/// A created file's or directory's mode, or a new one: below `S_ISGID` (0o2000), so neither it
/// nor `S_ISUID` (the sticky bit may be).
const MODE_MAX: u64 = 0o1777;
/// include/uapi/linux/fs.h's `RENAME_EXCHANGE` (libc has it for glibc only): with 0 and
/// `RENAME_NOREPLACE` (1) the flags `renameat2` may have; `RENAME_WHITEOUT` is 4.
const RENAME_EXCHANGE: u64 = 2;
/// With the net plugin, the most pollfds one `ppoll` may pass (the guest's sockets).
pub const PPOLL_NET_FDS: u64 = 4096;
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
/// number). `fs` and `net` are the plugins' ([`crate::Config::fs_root`], [`crate::Config::net`]).
///
/// Every plugin row's fd, directory fd among them, is at or above `n` (one the plugin opened,
/// never a kept one, never `AT_FDCWD`); an absolute path ignores its directory fd, so the
/// runtime opens a root by its path with any such number. `AT_EMPTY_PATH` (a call on the
/// directory fd itself) is in no row. Paths and addresses are pointers seccomp can't read: a
/// path is confined by lockdown's Landlock ruleset (the roots), an address by the network
/// namespace the caller runs the process in.
pub fn policy(mode: Mode, n: u64, ppoll_max: u64, gate: u64, fs: Fs, net: bool) -> impl Fn(&seccomp_data) -> u32 {
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
        let files = fs != Fs::Off;
        let writes = fs == Fs::ReadWrite;
        // Fds at or above `n` exist: a plugin's rows make them.
        let opened = files || net;
        match d.nr as i64 {
            // A kept fd (below `n`), as its own mode allows; with a plugin also one it opened
            // (every fd at or above `n` is).
            SYS_read | SYS_write if d.args[0] < n || (opened && d.args[0] <= INT_MAX) => SECCOMP_RET_ALLOW,
            // Readiness only, at most `ppoll_max` fds (with the net plugin `PPOLL_NET_FDS`); no
            // signal mask (it could unblock SIGSYS).
            SYS_ppoll if (d.args[1] <= ppoll_max || (net && d.args[1] <= PPOLL_NET_FDS)) && d.args[3] == 0 => {
                SECCOMP_RET_ALLOW
            }
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
            // one.
            SYS_close if opened && d.args[0] >= n && d.args[0] <= INT_MAX => SECCOMP_RET_ALLOW,
            // Plugin: fs. A file by its path (absolute, or relative to a directory the plugin
            // opened), within the roots (Landlock). Always `O_NONBLOCK` and `O_CLOEXEC`: an open
            // never waits (a FIFO's, a device's); the runtime clears `O_NONBLOCK` after its
            // `fstat` finds a regular file or a directory (the runtime's, not a guarantee: it
            // avoids a hang). Read-only: `O_RDONLY`, with any of `O_DIRECTORY`, `O_NOFOLLOW`.
            // Read-write also: `O_WRONLY` or `O_RDWR` with `O_TRUNC` or `O_APPEND`, and
            // `O_CREAT` (`O_EXCL` with it) for each access mode, the mode without `S_ISUID` or
            // `S_ISGID` (the kernel ignores it without `O_CREAT`: pinned anyway). Never
            // `O_PATH`, `O_TMPFILE`, `O_DIRECT`.
            SYS_openat
                if files
                    && d.args[0] >= n
                    && d.args[0] <= INT_MAX
                    && d.args[3] <= MODE_MAX
                    && (d.args[2] == O_RDONLY | O_NB
                        || d.args[2] == O_RDONLY | O_NOFOLLOW | O_NB
                        || d.args[2] == O_RDONLY | O_DIRECTORY | O_NB
                        || d.args[2] == O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NB
                        || (writes
                            && (d.args[2] == O_RDONLY | O_CREAT | O_NB
                                || d.args[2] == O_RDONLY | O_CREAT | O_EXCL | O_NB
                                || d.args[2] == O_WRONLY | O_NB
                                || d.args[2] == O_WRONLY | O_TRUNC | O_NB
                                || d.args[2] == O_WRONLY | O_APPEND | O_NB
                                || d.args[2] == O_WRONLY | O_CREAT | O_NB
                                || d.args[2] == O_WRONLY | O_CREAT | O_TRUNC | O_NB
                                || d.args[2] == O_WRONLY | O_CREAT | O_APPEND | O_NB
                                || d.args[2] == O_WRONLY | O_CREAT | O_EXCL | O_NB
                                || d.args[2] == O_RDWR | O_NB
                                || d.args[2] == O_RDWR | O_TRUNC | O_NB
                                || d.args[2] == O_RDWR | O_APPEND | O_NB
                                || d.args[2] == O_RDWR | O_CREAT | O_NB
                                || d.args[2] == O_RDWR | O_CREAT | O_TRUNC | O_NB
                                || d.args[2] == O_RDWR | O_CREAT | O_APPEND | O_NB
                                || d.args[2] == O_RDWR | O_CREAT | O_EXCL | O_NB))) =>
            {
                SECCOMP_RET_ALLOW
            }
            // Plugin: fs. An opened file's offset, whence `SEEK_SET` to `SEEK_HOLE`.
            SYS_lseek if files && d.args[0] >= n && d.args[0] <= INT_MAX && d.args[2] <= SEEK_HOLE => SECCOMP_RET_ALLOW,
            // Plugin: fs. An opened file's metadata, entries and bytes at an offset.
            SYS_fstat | SYS_getdents64 | SYS_fstatfs | SYS_pread64 if files && d.args[0] >= n && d.args[0] <= INT_MAX => {
                SECCOMP_RET_ALLOW
            }
            // Plugin: fs. A path's metadata, flags 0 or `AT_SYMLINK_NOFOLLOW`.
            SYS_newfstatat
                if files && d.args[0] >= n && d.args[0] <= INT_MAX && (d.args[3] == 0 || d.args[3] == AT_SYMLINK_NOFOLLOW) =>
            {
                SECCOMP_RET_ALLOW
            }
            SYS_statx
                if files && d.args[0] >= n && d.args[0] <= INT_MAX && (d.args[2] == 0 || d.args[2] == AT_SYMLINK_NOFOLLOW) =>
            {
                SECCOMP_RET_ALLOW
            }
            // Plugin: fs. A symlink's target.
            SYS_readlinkat if files && d.args[0] >= n && d.args[0] <= INT_MAX => SECCOMP_RET_ALLOW,
            // Plugin: fs. An opened file's status flags: read, or set to `O_NONBLOCK` or none
            // (read-write: `O_APPEND` too). No other command (no locks, no owner, no dup).
            SYS_fcntl
                if files
                    && d.args[0] >= n
                    && d.args[0] <= INT_MAX
                    && (d.args[1] == F_GETFL
                        || (d.args[1] == F_SETFL
                            && (d.args[2] == 0
                                || d.args[2] == O_NONBLOCK
                                || (writes && (d.args[2] == O_APPEND || d.args[2] == O_APPEND | O_NONBLOCK))))) =>
            {
                SECCOMP_RET_ALLOW
            }
            // Plugin: fs, read-write. A directory made, or a mode changed: no `S_ISUID`, `S_ISGID`.
            SYS_mkdirat | SYS_fchmodat if writes && d.args[0] >= n && d.args[0] <= INT_MAX && d.args[2] <= MODE_MAX => {
                SECCOMP_RET_ALLOW
            }
            // Plugin: fs, read-write. A name removed (a file's; with `AT_REMOVEDIR` a directory's).
            SYS_unlinkat if writes && d.args[0] >= n && d.args[0] <= INT_MAX && (d.args[2] == 0 || d.args[2] == AT_REMOVEDIR) => {
                SECCOMP_RET_ALLOW
            }
            // Plugin: fs, read-write. A rename, flags 0, `RENAME_NOREPLACE` or `RENAME_EXCHANGE`
            // (no `RENAME_WHITEOUT`).
            SYS_renameat2
                if writes
                    && d.args[0] >= n
                    && d.args[0] <= INT_MAX
                    && d.args[2] >= n
                    && d.args[2] <= INT_MAX
                    && d.args[4] <= RENAME_EXCHANGE =>
            {
                SECCOMP_RET_ALLOW
            }
            // Plugin: fs, read-write. A hard link, flags 0 or `AT_SYMLINK_FOLLOW`.
            SYS_linkat
                if writes
                    && d.args[0] >= n
                    && d.args[0] <= INT_MAX
                    && d.args[2] >= n
                    && d.args[2] <= INT_MAX
                    && (d.args[4] == 0 || d.args[4] == AT_SYMLINK_FOLLOW) =>
            {
                SECCOMP_RET_ALLOW
            }
            // Plugin: fs, read-write. A symlink made.
            SYS_symlinkat if writes && d.args[1] >= n && d.args[1] <= INT_MAX => SECCOMP_RET_ALLOW,
            // Plugin: fs, read-write. A path's owner (no capability: only what the host lets the
            // process itself do) and times (a path given: a null one is the directory fd's own),
            // flags 0 or `AT_SYMLINK_NOFOLLOW`.
            SYS_fchownat
                if writes
                    && d.args[0] >= n
                    && d.args[0] <= INT_MAX
                    && (d.args[4] == 0 || d.args[4] == AT_SYMLINK_NOFOLLOW) =>
            {
                SECCOMP_RET_ALLOW
            }
            SYS_utimensat
                if writes
                    && d.args[0] >= n
                    && d.args[0] <= INT_MAX
                    && d.args[1] != 0
                    && (d.args[3] == 0 || d.args[3] == AT_SYMLINK_NOFOLLOW) =>
            {
                SECCOMP_RET_ALLOW
            }
            // Plugin: fs, read-write. An opened file's size, sync, and bytes at an offset.
            SYS_ftruncate | SYS_fsync | SYS_fdatasync | SYS_pwrite64 if writes && d.args[0] >= n && d.args[0] <= INT_MAX => {
                SECCOMP_RET_ALLOW
            }
            // Plugin: fs, read-write. Space for an opened file: mode 0 (no hole punched, no range
            // collapsed or inserted).
            SYS_fallocate if writes && d.args[0] >= n && d.args[0] <= INT_MAX && d.args[1] == 0 => SECCOMP_RET_ALLOW,
            // Plugin: net. An IPv4 or IPv6 TCP or UDP socket, optionally nonblocking and
            // close-on-exec, protocol 0 (no raw, packet, netlink or unix socket). Any address:
            // the network namespace is the caller's.
            SYS_socket
                if net
                    && (d.args[0] == AF_INET || d.args[0] == AF_INET6)
                    && (d.args[1] == SOCK_STREAM
                        || d.args[1] == SOCK_STREAM | SOCK_NONBLOCK
                        || d.args[1] == SOCK_STREAM | SOCK_CLOEXEC
                        || d.args[1] == SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC
                        || d.args[1] == SOCK_DGRAM
                        || d.args[1] == SOCK_DGRAM | SOCK_NONBLOCK
                        || d.args[1] == SOCK_DGRAM | SOCK_CLOEXEC
                        || d.args[1] == SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC)
                    && d.args[2] == 0 =>
            {
                SECCOMP_RET_ALLOW
            }
            // Plugin: net. A socket the plugin made: its address, connection and names.
            SYS_connect | SYS_bind | SYS_listen | SYS_getsockname | SYS_getpeername
                if net && d.args[0] >= n && d.args[0] <= INT_MAX =>
            {
                SECCOMP_RET_ALLOW
            }
            // Plugin: net. A connection taken, flags of `SOCK_CLOEXEC | SOCK_NONBLOCK` only.
            SYS_accept4
                if net
                    && d.args[0] >= n
                    && d.args[0] <= INT_MAX
                    && (d.args[3] == 0
                        || d.args[3] == SOCK_NONBLOCK
                        || d.args[3] == SOCK_CLOEXEC
                        || d.args[3] == SOCK_NONBLOCK | SOCK_CLOEXEC) =>
            {
                SECCOMP_RET_ALLOW
            }
            // Plugin: net. A half or whole close of a connection (`SHUT_RD` to `SHUT_RDWR`).
            SYS_shutdown if net && d.args[0] >= n && d.args[0] <= INT_MAX && d.args[1] <= libc::SHUT_RDWR as u64 => {
                SECCOMP_RET_ALLOW
            }
            // Plugin: net. Bytes or a datagram sent or received, flags of `MSG_DONTWAIT |
            // MSG_NOSIGNAL` only (no `MSG_OOB`, `MSG_ERRQUEUE`, `MSG_ZEROCOPY`).
            SYS_sendto | SYS_recvfrom
                if net
                    && d.args[0] >= n
                    && d.args[0] <= INT_MAX
                    && (d.args[3] == 0
                        || d.args[3] == MSG_DONTWAIT
                        || d.args[3] == MSG_NOSIGNAL
                        || d.args[3] == MSG_DONTWAIT | MSG_NOSIGNAL) =>
            {
                SECCOMP_RET_ALLOW
            }
            // Plugin: net. A socket option of these (level, option) pairs, each the socket's own
            // behaviour, none reaching another socket or the host:
            // - `SO_REUSEADDR`: a listener's port rebound while old connections are in TIME_WAIT
            //   (Linux's doesn't take a port another socket listens on; `SO_REUSEPORT`, which
            //   shares one, isn't here);
            // - `SO_KEEPALIVE`, `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`: probes of an idle
            //   connection, on it alone;
            // - `SO_SNDBUF`, `SO_RCVBUF`: its buffers, capped by the host's `wmem_max`/`rmem_max`
            //   (the uncapped `…FORCE` options aren't here);
            // - `TCP_NODELAY`: Nagle's algorithm off;
            // - `IPV6_V6ONLY`: whether an IPv6 socket takes IPv4 too.
            // `getsockopt` reads the same, and `SO_ERROR` (a nonblocking connect's result).
            SYS_setsockopt | SYS_getsockopt
                if net
                    && d.args[0] >= n
                    && d.args[0] <= INT_MAX
                    && ((d.args[1] == SOL_SOCKET
                        && (d.args[2] == SO_REUSEADDR
                            || d.args[2] == SO_KEEPALIVE
                            || d.args[2] == SO_SNDBUF
                            || d.args[2] == SO_RCVBUF
                            || (d.nr == SYS_getsockopt as i32 && d.args[2] == SO_ERROR)))
                        || (d.args[1] == IPPROTO_TCP
                            && (d.args[2] == TCP_NODELAY
                                || d.args[2] == TCP_KEEPIDLE
                                || d.args[2] == TCP_KEEPINTVL
                                || d.args[2] == TCP_KEEPCNT))
                        || (d.args[1] == IPPROTO_IPV6 && d.args[2] == IPV6_V6ONLY)) =>
            {
                SECCOMP_RET_ALLOW
            }
            // Nothing else: no memory call (the arena is reserved before), no signal (a death by
            // one is the runtime's `exit_group(128 + n)`), nothing that makes an fd but the
            // plugins' rows above.
            _ => SECCOMP_RET_KILL_PROCESS,
        }
    }
}

// The proof: a harness per mode (one with the mode symbolic took 5x as long: 663 s against
// 131 s), every other param symbolic.
seccomp_fn_verify::policy!(policy, filter, unwind = 1024, (
    Mode = [coroutine: Coroutine, threaded: Threaded, fork: Fork], _, _, _,
    Fs = [no_fs: Off, fs_ro: ReadOnly, fs_rw: ReadWrite],
    bool = [no_net: false, net: true]
));

/// The filter for `mode`, the fd floor `n` ([`crate::Fds::n`]), `ppoll_max`, the gate
/// ([`crate::Config::gate`]) and the plugins ([`crate::Config::fs_root`], [`crate::Config::net`]):
/// [`policy`]'s program.
/// Public, so the exact program can be inspected and tested.
pub fn filter(mode: Mode, n: u64, ppoll_max: u64, gate: u64, fs: Fs, net: bool) -> Vec<sock_filter> {
    seccomp_fn::compile!(policy(mode, n, ppoll_max, gate, fs, net))
}
