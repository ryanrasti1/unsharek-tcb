//! Plugin (experimental): the network. IPv4 and IPv6 TCP and UDP sockets, to any address: the
//! network namespace the caller runs the process in is what confines them (an address is a
//! pointer seccomp can't read). Every socket fd is at or above the floor `n`.
#![allow(non_upper_case_globals)] // libc's syscall names, as patterns

use libc::{seccomp_data, sock_filter};
use libc::{
    SYS_accept4, SYS_bind, SYS_close, SYS_connect, SYS_getpeername, SYS_getsockname, SYS_getsockopt, SYS_listen, SYS_ppoll,
    SYS_setsockopt, SYS_shutdown, SYS_socket,
};
use libc::{SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS};

use super::{Plugin, Rows};

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

/// The network plugin: no setup, no kept fds, its rows.
#[derive(Clone, Copy, Debug, Default)]
pub struct Net;

impl Net {
    /// The most pollfds one `ppoll` may pass with this plugin (the guest's sockets; the core's
    /// own is `crate::PPOLL_FDS`).
    pub const PPOLL_FDS: u64 = 4096;
}

impl Plugin for Net {
    fn rows(&self) -> Rows {
        Rows::Net
    }
}

/// The rows: ALLOW, or KILL_PROCESS for no match (the composition, `super::policy`, reads any
/// verdict but ALLOW as none). `n` is the floor.
pub(crate) fn policy(n: u64) -> impl Fn(&seccomp_data) -> u32 {
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

/// [`policy`]'s program.
pub(crate) fn filter(n: u64) -> Vec<sock_filter> {
    seccomp_fn::bpf!(policy(n))
}
