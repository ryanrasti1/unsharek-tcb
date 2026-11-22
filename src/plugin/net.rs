//! Plugin (experimental): the network. IPv4 and IPv6 TCP and UDP sockets, to any address: the
//! network namespace the caller runs the process in is what confines them (an address is a
//! pointer seccomp can't read). Every socket fd is at or above the floor `n`.

use libc::seccomp_data;
use seccomp_fn_verify::calls::{Call, CallExt};
use seccomp_fn_verify::expr::Cond;

use super::Plugin;

// The rows' constants, libc's, as the typed view's fields have them (each an `int`).
const AF_INET: i32 = libc::AF_INET;
const AF_INET6: i32 = libc::AF_INET6;
const SOCK_STREAM: i32 = libc::SOCK_STREAM;
const SOCK_DGRAM: i32 = libc::SOCK_DGRAM;
const SOCK_NONBLOCK: i32 = libc::SOCK_NONBLOCK;
const SOCK_CLOEXEC: i32 = libc::SOCK_CLOEXEC;
const SOL_SOCKET: i32 = libc::SOL_SOCKET;
const SO_REUSEADDR: i32 = libc::SO_REUSEADDR;
const SO_KEEPALIVE: i32 = libc::SO_KEEPALIVE;
const SO_ERROR: i32 = libc::SO_ERROR;
const IPPROTO_TCP: i32 = libc::IPPROTO_TCP;
const TCP_NODELAY: i32 = libc::TCP_NODELAY;
const IPPROTO_IPV6: i32 = libc::IPPROTO_IPV6;
const IPV6_V6ONLY: i32 = libc::IPV6_V6ONLY;
const SHUT_RDWR: i32 = libc::SHUT_RDWR;

/// The network plugin: no setup, no kept fds, its rows.
#[derive(Clone, Copy, Debug, Default)]
pub struct Net;

impl Net {
    /// The most pollfds one `ppoll` may pass with this plugin (the guest's sockets; the core's
    /// own is `crate::PPOLL_FDS`).
    pub const PPOLL_FDS: u32 = 4096;
}

impl Plugin for Net {
    fn rows(&self, n: u32) -> Option<Cond> {
        Some(rows(n))
    }
}

/// The rows: whether they allow `d`. `n` is the floor (each socket fd at or above it, as the
/// kernel reads it: an `int`).
pub(crate) fn sockets(d: &seccomp_data, n: u32) -> bool {
    let ours = |fd: i32| fd >= n as i32;
    match d.call() {
        // Readiness of up to `Net::PPOLL_FDS` fds (the guest's sockets); no signal mask (it could
        // unblock SIGSYS).
        Call::Ppoll { nfds, sigmask, .. } => nfds <= Net::PPOLL_FDS && sigmask.is_null(),
        // The close of a socket this plugin made, never a kept fd (the guest answers that).
        Call::Close { fd } => fd >= n,
        // An IPv4 or IPv6 TCP or UDP socket, optionally nonblocking and close-on-exec, protocol
        // 0 (no raw, packet, netlink or unix socket). Any address: the network namespace is the
        // caller's.
        Call::Socket { family, r#type, protocol } => {
            (family == AF_INET || family == AF_INET6)
                && (r#type == SOCK_STREAM
                    || r#type == SOCK_STREAM | SOCK_NONBLOCK
                    || r#type == SOCK_STREAM | SOCK_CLOEXEC
                    || r#type == SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC
                    || r#type == SOCK_DGRAM
                    || r#type == SOCK_DGRAM | SOCK_NONBLOCK
                    || r#type == SOCK_DGRAM | SOCK_CLOEXEC
                    || r#type == SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC)
                && protocol == 0
        }
        // A socket the plugin made: its address, connection and names. Its data goes over
        // `read` and `write` (UDP always connected: no `sendto`, `recvfrom`).
        Call::Connect { fd, .. } | Call::Bind { fd, .. } | Call::Listen { fd, .. } | Call::Getsockname { fd, .. } | Call::Getpeername { fd, .. } => {
            ours(fd)
        }
        // A connection taken, flags of `SOCK_CLOEXEC | SOCK_NONBLOCK` only.
        Call::Accept4 { fd, flags, .. } => {
            ours(fd) && (flags == 0 || flags == SOCK_NONBLOCK || flags == SOCK_CLOEXEC || flags == SOCK_NONBLOCK | SOCK_CLOEXEC)
        }
        // A half or whole close of a connection (`SHUT_RD` to `SHUT_RDWR`).
        Call::Shutdown { fd, how } => ours(fd) && how >= 0 && how <= SHUT_RDWR,
        // A socket option of these (level, option) pairs, each the socket's own behaviour, none
        // reaching another socket or the host:
        // - `SO_REUSEADDR`: a listener's port rebound while old connections are in TIME_WAIT
        //   (Linux's doesn't take a port another socket listens on; `SO_REUSEPORT`, which
        //   shares one, isn't here);
        // - `SO_KEEPALIVE`: probes of an idle connection, on it alone;
        // - `TCP_NODELAY`: Nagle's algorithm off;
        // - `IPV6_V6ONLY`: whether an IPv6 socket takes IPv4 too.
        Call::Setsockopt { fd, level, optname, .. } => {
            ours(fd)
                && (level == SOL_SOCKET && (optname == SO_REUSEADDR || optname == SO_KEEPALIVE)
                    || level == IPPROTO_TCP && optname == TCP_NODELAY
                    || level == IPPROTO_IPV6 && optname == IPV6_V6ONLY)
        }
        // A nonblocking connect's result (`SO_ERROR`), and nothing else read.
        Call::Getsockopt { fd, level, optname, .. } => ours(fd) && level == SOL_SOCKET && optname == SO_ERROR,
        _ => false,
    }
}

/// [`sockets`]'s rows, as the combinator's sub-filter (`crate::filter`).
pub(crate) fn rows(n: u32) -> Cond {
    seccomp_fn::rows!(sockets(d, n))
}
