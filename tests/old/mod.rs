//! The filter's policy as it was before the typed view (unsharek-tcb's tcb-rework, da22c82):
//! kept to check the new one's verdicts against (tests/filter.rs, `same_as_before`). Verbatim
//! but for paths.
#![allow(non_upper_case_globals, dead_code, clippy::all)]

use libc::*;
use unsharek_tcb::plugin::Fs;
use unsharek_tcb::{CLONE_THREAD_FLAGS, Mode, X32_SYSCALL_BIT, AUDIT_ARCH_X86_64};
const PPOLL_FDS: u64 = 8;
const NO_MATCH: u32 = SECCOMP_RET_KILL_THREAD;

pub fn core_policy(mode: Mode, gate: u64) -> impl Fn(&seccomp_data) -> u32 {
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

pub fn policy(mode: Mode, n: u64, gate: u64, fs: Fs, net: bool) -> impl Fn(&seccomp_data) -> u32 {
    let core = core_policy(mode, gate);
    let files = self::fs::policy(n, fs == Fs::ReadWrite);
    let sockets = self::net::policy(n);
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


pub mod fs {
    use libc::*;
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
const AT_REMOVEDIR: u64 = libc::AT_REMOVEDIR as u64;
/// A created file's or directory's mode, or a new one: below `S_ISGID` (0o2000), so neither it
/// nor `S_ISUID` (the sticky bit may be).
const MODE_MAX: u64 = 0o1777;
/// include/uapi/linux/fs.h's `RENAME_EXCHANGE` (libc has it for glibc only): with 0 and
/// `RENAME_NOREPLACE` (1) the flags `renameat2` may have; `RENAME_WHITEOUT` is 4.
const RENAME_EXCHANGE: u64 = 2;
/// The largest fd (the kernel's `int`): an fd condition's upper bound, so that no high bit of the
/// 64-bit register turns a refused number into another (the kernel reads 32 bits).
const INT_MAX: u64 = i32::MAX as u64;

pub fn policy(n: u64, writes: bool) -> impl Fn(&seccomp_data) -> u32 {
    move |d| {
        match d.nr as i64 {
            // The close of an fd this plugin opened, never a kept one (the guest answers that).
            SYS_close if d.args[0] >= n && d.args[0] <= INT_MAX => SECCOMP_RET_ALLOW,
            // A file by its path (absolute, or relative to a directory the plugin
            // opened), within the roots (Landlock). Always `O_NONBLOCK` and `O_CLOEXEC`: an open
            // never waits (a FIFO's, a device's); the runtime clears `O_NONBLOCK` after its
            // `fstat` finds a regular file or a directory (the runtime's, not a guarantee: it
            // avoids a hang). A path's metadata is this open, then `fstat` (no `statx`,
            // `newfstatat`, `fstatfs`: the guest fakes statfs). Read-only: `O_RDONLY`, with any of `O_DIRECTORY`, `O_NOFOLLOW`.
            // Read-write also: `O_WRONLY` or `O_RDWR` with `O_TRUNC` or `O_APPEND`, and
            // `O_CREAT` (`O_EXCL` with it) for each access mode, the mode without `S_ISUID` or
            // `S_ISGID` (the kernel ignores it without `O_CREAT`: pinned anyway). Never
            // `O_PATH`, `O_TMPFILE`, `O_DIRECT`.
            SYS_openat
                if d.args[0] >= n
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
            // An opened file's metadata, entries and bytes at an offset (no `lseek`:
            // files are read and written only with `pread64`/`pwrite64`, at offsets the guest
            // kernel keeps, so the host's shared offset is never used and no host thread's seek
            // races another's read; `read`/`write` are for sockets and stdio).
            SYS_fstat | SYS_getdents64 | SYS_pread64 if d.args[0] >= n && d.args[0] <= INT_MAX => SECCOMP_RET_ALLOW,
            // A symlink's target.
            SYS_readlinkat if d.args[0] >= n && d.args[0] <= INT_MAX => SECCOMP_RET_ALLOW,
            // Read-write: A directory made, or a mode changed: no `S_ISUID`, `S_ISGID`.
            SYS_mkdirat | SYS_fchmodat if writes && d.args[0] >= n && d.args[0] <= INT_MAX && d.args[2] <= MODE_MAX => {
                SECCOMP_RET_ALLOW
            }
            // Read-write: A name removed (a file's; with `AT_REMOVEDIR` a directory's).
            SYS_unlinkat if writes && d.args[0] >= n && d.args[0] <= INT_MAX && (d.args[2] == 0 || d.args[2] == AT_REMOVEDIR) => {
                SECCOMP_RET_ALLOW
            }
            // Read-write: A rename, flags 0, `RENAME_NOREPLACE` or `RENAME_EXCHANGE`
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
            // Read-write: A symlink made.
            SYS_symlinkat if writes && d.args[1] >= n && d.args[1] <= INT_MAX => SECCOMP_RET_ALLOW,
            // Read-write: A path's times (a path given: a null one is the directory
            // fd's own), flags 0 or `AT_SYMLINK_NOFOLLOW`.
            SYS_utimensat
                if writes
                    && d.args[0] >= n
                    && d.args[0] <= INT_MAX
                    && d.args[1] != 0
                    && (d.args[3] == 0 || d.args[3] == AT_SYMLINK_NOFOLLOW) =>
            {
                SECCOMP_RET_ALLOW
            }
            // Read-write: An opened file's size, sync, and bytes at an offset.
            SYS_ftruncate | SYS_fsync | SYS_pwrite64 if writes && d.args[0] >= n && d.args[0] <= INT_MAX => SECCOMP_RET_ALLOW,
            _ => SECCOMP_RET_KILL_PROCESS,
        }
    }
}

}

pub mod net {
    use libc::*;
    pub struct Net;
    impl Net { pub const PPOLL_FDS: u64 = 4096; }
const AF_INET: u64 = libc::AF_INET as u64;
const AF_INET6: u64 = libc::AF_INET6 as u64;
const SOCK_STREAM: u64 = libc::SOCK_STREAM as u64;
const SOCK_DGRAM: u64 = libc::SOCK_DGRAM as u64;
const SOCK_NONBLOCK: u64 = libc::SOCK_NONBLOCK as u64;
const SOCK_CLOEXEC: u64 = libc::SOCK_CLOEXEC as u64;
const SOL_SOCKET: u64 = libc::SOL_SOCKET as u64;
const SO_REUSEADDR: u64 = libc::SO_REUSEADDR as u64;
const SO_KEEPALIVE: u64 = libc::SO_KEEPALIVE as u64;
const SO_ERROR: u64 = libc::SO_ERROR as u64;
const IPPROTO_TCP: u64 = libc::IPPROTO_TCP as u64;
const TCP_NODELAY: u64 = libc::TCP_NODELAY as u64;
const IPPROTO_IPV6: u64 = libc::IPPROTO_IPV6 as u64;
const IPV6_V6ONLY: u64 = libc::IPV6_V6ONLY as u64;
/// The largest fd (the kernel's `int`): an fd condition's upper bound, so that no high bit of the
/// 64-bit register turns a refused number into another (the kernel reads 32 bits).
const INT_MAX: u64 = i32::MAX as u64;

pub fn policy(n: u64) -> impl Fn(&seccomp_data) -> u32 {
    move |d| {
        match d.nr as i64 {
            // Readiness of up to `Net::PPOLL_FDS` fds (the guest's sockets); no signal mask (it
            // could unblock SIGSYS).
            SYS_ppoll if d.args[1] <= Net::PPOLL_FDS && d.args[3] == 0 => SECCOMP_RET_ALLOW,
            // The close of a socket this plugin made, never a kept fd (the guest answers that).
            SYS_close if d.args[0] >= n && d.args[0] <= INT_MAX => SECCOMP_RET_ALLOW,
            // An IPv4 or IPv6 TCP or UDP socket, optionally nonblocking and
            // close-on-exec, protocol 0 (no raw, packet, netlink or unix socket). Any address:
            // the network namespace is the caller's.
            SYS_socket
                if (d.args[0] == AF_INET || d.args[0] == AF_INET6)
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
            // A socket the plugin made: its address, connection and names. Its data goes
            // over `read` and `write` (UDP always connected: no `sendto`, `recvfrom`).
            SYS_connect | SYS_bind | SYS_listen | SYS_getsockname | SYS_getpeername
                if d.args[0] >= n && d.args[0] <= INT_MAX =>
            {
                SECCOMP_RET_ALLOW
            }
            // A connection taken, flags of `SOCK_CLOEXEC | SOCK_NONBLOCK` only.
            SYS_accept4
                if d.args[0] >= n
                    && d.args[0] <= INT_MAX
                    && (d.args[3] == 0
                        || d.args[3] == SOCK_NONBLOCK
                        || d.args[3] == SOCK_CLOEXEC
                        || d.args[3] == SOCK_NONBLOCK | SOCK_CLOEXEC) =>
            {
                SECCOMP_RET_ALLOW
            }
            // A half or whole close of a connection (`SHUT_RD` to `SHUT_RDWR`).
            SYS_shutdown if d.args[0] >= n && d.args[0] <= INT_MAX && d.args[1] <= libc::SHUT_RDWR as u64 => {
                SECCOMP_RET_ALLOW
            }
            // A socket option of these (level, option) pairs, each the socket's own
            // behaviour, none reaching another socket or the host:
            // - `SO_REUSEADDR`: a listener's port rebound while old connections are in TIME_WAIT
            //   (Linux's doesn't take a port another socket listens on; `SO_REUSEPORT`, which
            //   shares one, isn't here);
            // - `SO_KEEPALIVE`: probes of an idle connection, on it alone;
            // - `TCP_NODELAY`: Nagle's algorithm off;
            // - `IPV6_V6ONLY`: whether an IPv6 socket takes IPv4 too.
            SYS_setsockopt
                if d.args[0] >= n
                    && d.args[0] <= INT_MAX
                    && ((d.args[1] == SOL_SOCKET && (d.args[2] == SO_REUSEADDR || d.args[2] == SO_KEEPALIVE))
                        || (d.args[1] == IPPROTO_TCP && d.args[2] == TCP_NODELAY)
                        || (d.args[1] == IPPROTO_IPV6 && d.args[2] == IPV6_V6ONLY)) =>
            {
                SECCOMP_RET_ALLOW
            }
            // A nonblocking connect's result (`SO_ERROR`), and nothing else read.
            SYS_getsockopt
                if d.args[0] >= n && d.args[0] <= INT_MAX && d.args[1] == SOL_SOCKET && d.args[2] == SO_ERROR =>
            {
                SECCOMP_RET_ALLOW
            }
            _ => SECCOMP_RET_KILL_PROCESS,
        }
    }
}

}
