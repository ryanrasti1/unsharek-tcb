//! Plugin: capnweb (experimental). The control socket ([`Config::recv_fds`]): after lockdown, an fd
//! arrives on it (`recvmsg`, `MSG_CMSG_CLOEXEC`) and is written; `recvmsg` anywhere else, without
//! the flag, and `sendmsg` kill; a control socket that isn't unix seqpacket is refused at lockdown.
//! Each case in a forked child, as tests/lockdown.rs does.

use std::os::fd::RawFd;

use unsharek_tcb::{Config, Confined, Error, Mode, Sandbox};

/// The test's gate: `nr(a0, a1, a2)`, raw result.
#[unsafe(naked)]
unsafe extern "C" fn gate(nr: usize, a0: usize, a1: usize, a2: usize) -> isize {
    core::arch::naked_asm!(
        "mov rax, rdi",
        "mov rdi, rsi",
        "mov rsi, rdx",
        "mov rdx, rcx",
        ".globl unsharek_tcb_ctl_gate_syscall",
        "unsharek_tcb_ctl_gate_syscall:",
        "syscall",
        ".globl unsharek_tcb_ctl_gate_ret",
        "unsharek_tcb_ctl_gate_ret:",
        "ret",
    )
}

unsafe extern "C" {
    static unsharek_tcb_ctl_gate_ret: u8;
}

fn g(nr: i64, a: [usize; 3]) -> isize {
    // SAFETY: each call is a plain syscall on its own arguments.
    unsafe { gate(nr as usize, a[0], a[1], a[2]) }
}

struct Guest {
    fds: Vec<RawFd>,
    mode: Mode,
}

impl Confined for Guest {
    fn host_fds(&self) -> &[RawFd] {
        &self.fds
    }
    fn gate_ip(&self) -> u64 {
        &raw const unsharek_tcb_ctl_gate_ret as u64
    }
}

fn lockdown(guest: &Guest, grants: impl FnOnce(&mut Config)) -> unsharek_tcb::Result<()> {
    Sandbox::configure_and_lockdown(
        |s| {
            s.mode = guest.mode;
            grants(s);
            Ok(())
        },
        guest,
    )
}

fn eventfd() -> RawFd {
    // SAFETY: a plain eventfd.
    let fd = unsafe { libc::eventfd(0, 0) };
    assert!(fd >= 0);
    fd
}

fn socketpair(kind: i32) -> [RawFd; 2] {
    let mut sv = [0; 2];
    // SAFETY: socketpair into a local.
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, kind, 0, sv.as_mut_ptr()) }, 0);
    sv
}

/// `f` in a forked child, its result the child's status (exit through the gate); the wait status.
fn in_child(f: impl FnOnce() -> i32) -> i32 {
    // SAFETY: the child runs `f` and exits; the parent waits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(100);
        g(libc::SYS_exit_group, [code as usize, 0, 0]);
        unreachable!();
    }
    let mut status = 0;
    // SAFETY: waitpid into a local.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    status
}

fn exit_code(status: i32) -> i32 {
    assert!(libc::WIFEXITED(status), "the child died: status {status:#x}");
    libc::WEXITSTATUS(status)
}

/// `fd` sent on `sock` with SCM_RIGHTS (the provider's side: ordinary host code).
fn send_fd(sock: RawFd, fd: RawFd) {
    let byte = [7u8];
    let mut iov = libc::iovec { iov_base: byte.as_ptr() as *mut _, iov_len: 1 };
    let mut cbuf = [0u64; 4];
    // SAFETY: a msghdr over locals; CMSG_* lay out one fd in `cbuf`.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut _;
        msg.msg_controllen = libc::CMSG_SPACE(4) as usize;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(4) as usize;
        *(libc::CMSG_DATA(c) as *mut i32) = fd;
        assert_eq!(libc::sendmsg(sock, &msg, 0), 1);
    }
}

/// `recvmsg(sock, …, flags)` from the gate: the fd received, or the raw result if none came.
fn gate_recv_fd(sock: RawFd, flags: i32) -> isize {
    let mut byte = [0u8];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut _, iov_len: 1 };
    let mut cbuf = [0u64; 4];
    // SAFETY: a msghdr over locals, filled by the kernel.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut _;
        msg.msg_controllen = libc::CMSG_SPACE(4) as usize;
        let r = g(libc::SYS_recvmsg, [sock as usize, &mut msg as *mut _ as usize, flags as usize]);
        if r != 1 {
            return r;
        }
        let c = libc::CMSG_FIRSTHDR(&msg);
        if c.is_null() || (*c).cmsg_type != libc::SCM_RIGHTS {
            return -1000;
        }
        *(libc::CMSG_DATA(c) as *const i32) as isize
    }
}

/// After lockdown a pipe's write end arrives on the control socket and is written, in every mode;
/// the bytes reach the (granted) read end.
#[test]
fn control_socket_receives_fds() {
    for mode in [Mode::Coroutine, Mode::Threaded, Mode::Fork] {
        let code = exit_code(in_child(|| {
            let [ctl, provider] = socketpair(libc::SOCK_SEQPACKET);
            let mut pipe = [0; 2];
            // SAFETY: pipe into a local.
            assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
            send_fd(provider, pipe[1]);
            let guest = Guest { fds: vec![eventfd()], mode };
            if lockdown(&guest, |s| {
                s.recv_fds = Some(ctl);
                s.grant(pipe[0]);
            })
            .is_err()
            {
                return 1;
            }
            let fd = gate_recv_fd(ctl, libc::MSG_CMSG_CLOEXEC);
            if fd < 0 {
                return 2;
            }
            let msg = *b"hi";
            if g(libc::SYS_write, [fd as usize, msg.as_ptr() as usize, 2]) != 2 {
                return 3;
            }
            let mut got = [0u8; 2];
            if g(libc::SYS_read, [pipe[0] as usize, got.as_mut_ptr() as usize, 2]) != 2 || got != msg {
                return 4;
            }
            0
        }));
        assert_eq!(code, 0, "{mode:?}");
    }
}

/// With a control socket: `recvmsg` on another fd, or without `MSG_CMSG_CLOEXEC`, and `sendmsg`
/// on it, kill the process.
#[test]
fn control_socket_refusals_kill() {
    for (name, case) in [("other fd", 0), ("no cloexec", 1), ("sendmsg", 2)] {
        let status = in_child(|| {
            let [ctl, _provider] = socketpair(libc::SOCK_SEQPACKET);
            let [other, _o] = socketpair(libc::SOCK_SEQPACKET);
            let guest = Guest { fds: vec![eventfd()], mode: Mode::Coroutine };
            if lockdown(&guest, |s| {
                s.recv_fds = Some(ctl);
                s.grant(other);
            })
            .is_err()
            {
                return 1;
            }
            match case {
                0 => gate_recv_fd(other, libc::MSG_CMSG_CLOEXEC),
                1 => gate_recv_fd(ctl, 0),
                _ => g(libc::SYS_sendmsg, [ctl as usize, 0, 0]),
            };
            2
        });
        assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS, "{name}: status {status:#x}");
    }
}

/// A control socket that isn't a unix seqpacket socket (a stream socket, a pipe) is refused.
#[test]
fn refuses_a_control_socket_of_the_wrong_kind() {
    for kind in ["stream", "pipe"] {
        let code = exit_code(in_child(|| {
            let fd = if kind == "stream" {
                socketpair(libc::SOCK_STREAM)[0]
            } else {
                let mut p = [0; 2];
                // SAFETY: pipe into a local.
                assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
                p[0]
            };
            let guest = Guest { fds: vec![eventfd()], mode: Mode::Coroutine };
            match lockdown(&guest, |s| s.recv_fds = Some(fd)) {
                Err(Error::FdKind { .. }) => 0,
                Err(_) => 1,
                Ok(()) => 2,
            }
        }));
        assert_eq!(code, 0, "{kind}");
    }
}
