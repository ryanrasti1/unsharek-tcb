//! The filter is its policy: [`policy`] is the filter, as a Rust function, and Kani proves
//! [`filter`]'s program gives its verdict on every call (`cargo kani`, `cargo xtask prove`). Here,
//! in seconds: the same assertion sampled (seccomp-fn-verify's `check_sampled`), for each mode
//! and some params; README.md's table against the policy's rows.

use unsharek_tcb::{AUDIT_ARCH_X86_64, Fs, Mode, PPOLL_FDS, PPOLL_NET_FDS, RET_ALLOW, filter, policy, seccomp_data, sock_filter};

const GATE: u64 = 0x0000_7f12_3456_7890;
/// The fd floor the tests use: kept fds 0..N.
const N: u64 = 9;
const MODES: [Mode; 3] = [Mode::Coroutine, Mode::Threaded, Mode::Fork];
const FSES: [Fs; 3] = [Fs::Off, Fs::ReadOnly, Fs::ReadWrite];


#[test]
fn filter_is_the_policy() {
    for mode in MODES {
        for fs in FSES {
            for net in [false, true] {
                for (n, ppoll_max, gate) in [(N, PPOLL_FDS, GATE), (0, 0, 0), (u64::MAX, 3, u64::MAX), (3, u64::MAX, 1 << 32)] {
                    seccomp_fn_verify::check_sampled(policy, filter, (mode, n, ppoll_max, gate, fs, net), 2_000);
                }
            }
        }
    }
}

/// A call from the gate.
fn call(nr: i64, args: [u64; 6]) -> seccomp_data {
    seccomp_data { nr: nr as i32, arch: AUDIT_ARCH_X86_64, instruction_pointer: GATE, args }
}

/// Whether `d` is allowed with these plugins (threaded mode, floor N).
fn allowed(fs: Fs, net: bool, d: &seccomp_data) -> bool {
    policy(Mode::Threaded, N, PPOLL_FDS, GATE, fs, net)(d) == RET_ALLOW
}

/// The numbers [`policy`] allows in `mode` without plugins, for some arguments: every x86-64
/// number, each tried with the arguments the program compares with (its jumps' constants).
fn ruled(mode: Mode) -> std::collections::BTreeSet<u32> {
    let prog = filter(mode, N, PPOLL_FDS, GATE, Fs::Off, false);
    let k: Vec<u64> = prog.iter().filter(|i| i.code & 0x07 == 0x05).map(|i| i.k as u64).chain([0, 1]).collect();
    let mut out = std::collections::BTreeSet::new();
    for nr in 0..1024u32 {
        for &a0 in &k {
            for &a1 in &k {
                if policy(mode, N, PPOLL_FDS, GATE, Fs::Off, false)(&call(nr as i64, [a0, a1, 0, 0, 0, 0])) == RET_ALLOW {
                    out.insert(nr);
                }
            }
        }
    }
    out
}

/// The policy's rows, in order, as its program tests them: each row is a load of `nr` and a
/// JEQ per number (the gate check's load of `nr` tests none; a JEQ of `nr` inside a row, as
/// getsockopt's, follows other loads). Rows a build-time guard rules out aren't in the program.
fn program_rows(mode: Mode, fs: Fs, net: bool) -> Vec<Vec<u32>> {
    let ld_nr = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let off_nr = std::mem::offset_of!(libc::seccomp_data, nr) as u32;
    let prog: Vec<sock_filter> = filter(mode, N, PPOLL_FDS, GATE, fs, net);
    let mut out: Vec<Vec<u32>> = vec![];
    let mut in_row = false;
    let mut row_start = true;
    for i in &prog {
        if i.code == ld_nr {
            in_row = i.k == off_nr && row_start;
            if in_row {
                out.push(vec![]);
            }
        } else if in_row && i.code == jeq {
            out.last_mut().unwrap().push(i.k);
        } else {
            in_row = false;
        }
        // A row starts after a return (the previous row's verdicts) or at the program's start.
        row_start = i.code == (libc::BPF_RET | libc::BPF_K) as u16 || (i.code == ld_nr && i.k == off_nr && out.last().is_some_and(|r| r.is_empty()));
    }
    out.retain(|r| !r.is_empty());
    out
}

/// A syscall's number by README.md's name.
fn nr(name: &str) -> u32 {
    (match name {
        "read" => libc::SYS_read,
        "write" => libc::SYS_write,
        "ppoll" => libc::SYS_ppoll,
        "exit_group" => libc::SYS_exit_group,
        "rt_sigreturn" => libc::SYS_rt_sigreturn,
        "clone" => libc::SYS_clone,
        "exit" => libc::SYS_exit,
        "close" => libc::SYS_close,
        "openat" => libc::SYS_openat,
        "fstat" => libc::SYS_fstat,
        "getdents64" => libc::SYS_getdents64,
        "fstatfs" => libc::SYS_fstatfs,
        "pread64" => libc::SYS_pread64,
        "newfstatat" => libc::SYS_newfstatat,
        "statx" => libc::SYS_statx,
        "readlinkat" => libc::SYS_readlinkat,
        "fcntl" => libc::SYS_fcntl,
        "mkdirat" => libc::SYS_mkdirat,
        "fchmodat" => libc::SYS_fchmodat,
        "unlinkat" => libc::SYS_unlinkat,
        "renameat2" => libc::SYS_renameat2,
        "linkat" => libc::SYS_linkat,
        "symlinkat" => libc::SYS_symlinkat,
        "fchownat" => libc::SYS_fchownat,
        "utimensat" => libc::SYS_utimensat,
        "ftruncate" => libc::SYS_ftruncate,
        "fsync" => libc::SYS_fsync,
        "fdatasync" => libc::SYS_fdatasync,
        "pwrite64" => libc::SYS_pwrite64,
        "fallocate" => libc::SYS_fallocate,
        "socket" => libc::SYS_socket,
        "connect" => libc::SYS_connect,
        "bind" => libc::SYS_bind,
        "listen" => libc::SYS_listen,
        "getsockname" => libc::SYS_getsockname,
        "getpeername" => libc::SYS_getpeername,
        "accept4" => libc::SYS_accept4,
        "shutdown" => libc::SYS_shutdown,
        "sendto" => libc::SYS_sendto,
        "recvfrom" => libc::SYS_recvfrom,
        "setsockopt" => libc::SYS_setsockopt,
        "getsockopt" => libc::SYS_getsockopt,
        n => panic!("README.md names a syscall the policy doesn't: {n}"),
    }) as u32
}

/// README.md's allowlist tables are the policy's: for each mode and plugin choice, the rows
/// whose last cell names it (`all`, a mode; a plugin's `fs`, `fs-rw`, `net`) are the
/// program's rows, in order; without plugins the syscalls they name are exactly the ones
/// [`ruled`] finds allowed; the `ppoll` row's bound is [`PPOLL_FDS`].
#[test]
fn readme_table_is_the_policy() {
    let readme = include_str!("../README.md");
    let lines: Vec<&str> = readme.lines().filter(|l| l.starts_with("| `")).collect();
    for mode in MODES {
        let name = match mode {
            Mode::Coroutine => "coroutine",
            Mode::Threaded => "threaded",
            Mode::Fork => "fork",
        };
        for fs in FSES {
            for net in [false, true] {
                let mut table = std::collections::BTreeSet::new();
                let mut ordered: Vec<Vec<u32>> = vec![];
                for line in &lines {
                    let cells: Vec<&str> = line.split(" | ").collect();
                    let tags = cells.last().unwrap().trim_end_matches(" |").trim();
                    let on = tags.split(", ").any(|t| match t {
                        "all" => true,
                        "fs" => fs != Fs::Off,
                        "fs-rw" => fs == Fs::ReadWrite,
                        "net" => net,
                        m => m == name,
                    });
                    if on {
                        let row: Vec<u32> = cells[0].trim_start_matches("| ").split(", ").map(|n| nr(n.trim_matches('`'))).collect();
                        table.extend(row.iter().copied());
                        ordered.push(row);
                    }
                    if cells[0].contains("`ppoll`") {
                        assert!(cells[1].contains(&format!("at most {PPOLL_FDS} fds")), "{line}");
                    }
                }
                if fs == Fs::Off && !net {
                    assert_eq!(table, ruled(mode), "{mode:?}: README.md's table against the policy");
                }
                assert_eq!(ordered, program_rows(mode, fs, net), "{mode:?} {fs:?} net {net}: README.md's rows against the policy's, in order");
            }
        }
    }
    assert_eq!(lines.len(), 28, "README.md's allowlist tables: their rows (6 core, 22 plugin)");
}

/// The program's length in each mode and plugin choice (the kernel takes 4096).
#[test]
fn filter_length() {
    for mode in MODES {
        for fs in FSES {
            for net in [false, true] {
                let n = filter(mode, N, PPOLL_FDS, GATE, fs, net).len();
                eprintln!("{mode:?} {fs:?} net {net}: {n} instructions");
                assert!(n <= 1000, "{mode:?}: {n} instructions");
            }
        }
    }
}

/// `read` and `write` on a kept fd (below the floor) only, as an int; with a plugin on one it
/// opened too (at or above it), never with a high bit set. `kill` never: a death by a signal is
/// the runtime's exit_group(128 + n).
#[test]
fn read_write_below_the_floor() {
    for mode in MODES {
        let without = |d: &seccomp_data| policy(mode, N, PPOLL_FDS, GATE, Fs::Off, false)(d);
        for nr in [libc::SYS_read, libc::SYS_write] {
            for fd in [0, 1, 2, N - 1] {
                assert_eq!(without(&call(nr, [fd, 0, 0, 0, 0, 0])), RET_ALLOW, "{mode:?} {nr} {fd}");
            }
            for fd in [N, N + 1, 1000, (1 << 32) | 1, u64::MAX] {
                assert_ne!(without(&call(nr, [fd, 0, 0, 0, 0, 0])), RET_ALLOW, "{mode:?} {nr} {fd:#x}");
            }
            for (fs, net) in [(Fs::ReadOnly, false), (Fs::Off, true)] {
                let with = |d: &seccomp_data| policy(mode, N, PPOLL_FDS, GATE, fs, net)(d);
                assert_eq!(with(&call(nr, [1000, 0, 0, 0, 0, 0])), RET_ALLOW, "{mode:?}: an opened fd");
                for fd in [1u64 << 31, (1 << 32) | 1, u64::MAX] {
                    assert_ne!(with(&call(nr, [fd, 0, 0, 0, 0, 0])), RET_ALLOW, "{mode:?} {nr} {fd:#x}");
                }
            }
        }
        assert_ne!(policy(mode, 0, PPOLL_FDS, GATE, Fs::Off, false)(&call(libc::SYS_read, [0; 6])), RET_ALLOW);
        for (fs, net) in [(Fs::Off, false), (Fs::ReadWrite, true)] {
            assert!(!allowed(fs, net, &call(libc::SYS_kill, [4242, 9, 0, 0, 0, 0])), "kill");
            assert!(!allowed(fs, net, &call(libc::SYS_recvmsg, [N, 0, libc::MSG_CMSG_CLOEXEC as u64, 0, 0, 0])), "recvmsg");
        }
    }
}

/// `ppoll`: `ppoll_max` fds, or with the net plugin `PPOLL_NET_FDS`; never a signal mask.
#[test]
fn ppoll_bound() {
    let pp = |nfds: u64, mask: u64| call(libc::SYS_ppoll, [0, nfds, 0, mask, 8, 0]);
    assert!(allowed(Fs::Off, false, &pp(PPOLL_FDS, 0)));
    assert!(!allowed(Fs::Off, false, &pp(PPOLL_FDS + 1, 0)));
    assert!(!allowed(Fs::ReadWrite, false, &pp(PPOLL_FDS + 1, 0)));
    assert!(allowed(Fs::Off, true, &pp(PPOLL_NET_FDS, 0)));
    assert!(!allowed(Fs::Off, true, &pp(PPOLL_NET_FDS + 1, 0)));
    assert!(!allowed(Fs::Off, true, &pp(1, 0x1000)));
}

// The plugin rows: each allowed with its args, refused with each pinned arg changed, and
// without its plugin.

/// fd args: an opened fd (N) and a refused one each: a kept fd, AT_FDCWD (both widths), high bits.
const BAD_FDS: [u64; 5] = [0, N - 1, (-100i64) as u64, 0xffff_ff9c, (1 << 32) | N];

/// `ok` allowed with `on` and not with each of `offs`; and each fd arg position in `fds` refused
/// with every bad fd.
fn row(on: (Fs, bool), offs: &[(Fs, bool)], ok: seccomp_data, fds: &[usize]) {
    assert!(allowed(on.0, on.1, &ok), "{} {:?}", ok.nr, ok.args);
    for off in offs {
        assert!(!allowed(off.0, off.1, &ok), "{} without its plugin {off:?}", ok.nr);
    }
    for &i in fds {
        for bad in BAD_FDS {
            let mut d = ok;
            d.args[i] = bad;
            assert!(!allowed(on.0, on.1, &d), "{} arg {i} = {bad:#x}", ok.nr);
        }
    }
}

/// `d` with arg `i` set to each of `vals`: each refused.
fn refused(on: (Fs, bool), ok: seccomp_data, i: usize, vals: &[u64]) {
    for &v in vals {
        let mut d = ok;
        d.args[i] = v;
        assert!(!allowed(on.0, on.1, &d), "{} arg {i} = {v:#x}", ok.nr);
    }
}

const RO: (Fs, bool) = (Fs::ReadOnly, false);
const RW: (Fs, bool) = (Fs::ReadWrite, false);
const NET: (Fs, bool) = (Fs::Off, true);
const NONE: (Fs, bool) = (Fs::Off, false);

#[test]
fn close_row() {
    for on in [RO, NET] {
        row(on, &[NONE], call(libc::SYS_close, [N, 0, 0, 0, 0, 0]), &[0]);
        assert!(allowed(on.0, on.1, &call(libc::SYS_close, [i32::MAX as u64, 0, 0, 0, 0, 0])));
    }
}

#[test]
fn openat_row() {
    let o = |flags: i32, mode: u64| call(libc::SYS_openat, [N, 0x1000, (flags | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64, mode, 0, 0]);
    // Read-only: RDONLY with DIRECTORY, NOFOLLOW; in both fs modes.
    for f in [0, libc::O_DIRECTORY, libc::O_NOFOLLOW, libc::O_DIRECTORY | libc::O_NOFOLLOW] {
        row(RO, &[NONE, NET], o(f, 0), &[0]);
        assert!(allowed(Fs::ReadWrite, false, &o(f, 0)));
    }
    // Read-write only.
    for f in [
        libc::O_WRONLY,
        libc::O_RDWR | libc::O_TRUNC,
        libc::O_WRONLY | libc::O_APPEND,
        libc::O_RDWR | libc::O_CREAT,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        libc::O_CREAT,
        libc::O_RDWR | libc::O_CREAT | libc::O_APPEND,
    ] {
        row(RW, &[NONE, RO, NET], o(f, 0o644), &[0]);
    }
    // Never: without O_NONBLOCK or O_CLOEXEC, O_PATH, O_TMPFILE, O_DIRECT, an unknown bit; a mode
    // with S_ISUID or S_ISGID.
    for on in [RO, RW] {
        for flags in [
            0,
            libc::O_NONBLOCK as u64,
            libc::O_CLOEXEC as u64,
            (libc::O_PATH | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64,
            (libc::O_TMPFILE | libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64,
            (libc::O_DIRECT | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64,
            (libc::O_NOATIME | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64,
            (1u64 << 32) | (libc::O_NONBLOCK | libc::O_CLOEXEC) as u64,
        ] {
            refused(on, o(0, 0), 2, &[flags]);
        }
        refused(on, o(0, 0), 3, &[0o4644, 0o2755, u64::MAX]);
    }
    assert!(allowed(Fs::ReadWrite, false, &o(libc::O_CREAT | libc::O_WRONLY, 0o1777)));
}

#[test]
fn fs_fd_rows() {
    // No lseek: files are read at offsets (pread64), never through the host's shared offset.
    for on in [RO, RW] {
        assert!(!allowed(on.0, on.1, &call(libc::SYS_lseek, [N, 0, 0, 0, 0, 0])), "lseek");
    }
    for nr in [libc::SYS_fstat, libc::SYS_getdents64, libc::SYS_fstatfs, libc::SYS_pread64] {
        row(RO, &[NONE, NET], call(nr, [N, 0x1000, 0, 0, 0, 0]), &[0]);
    }
    for (nr, flags_at) in [(libc::SYS_newfstatat, 3), (libc::SYS_statx, 2)] {
        let mut d = call(nr, [N, 0x1000, 0, 0, 0, 0]);
        row(RO, &[NONE, NET], d, &[0]);
        d.args[flags_at] = libc::AT_SYMLINK_NOFOLLOW as u64;
        assert!(allowed(RO.0, RO.1, &d));
        refused(RO, d, flags_at, &[libc::AT_EMPTY_PATH as u64, (libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW) as u64, 0x800]);
    }
    row(RO, &[NONE, NET], call(libc::SYS_readlinkat, [N, 0x1000, 0x2000, 64, 0, 0]), &[0]);
    // fcntl: F_GETFL; F_SETFL to O_NONBLOCK or 0 (read-write: O_APPEND too); nothing else.
    let fc = |cmd: i32, arg: i32| call(libc::SYS_fcntl, [N, cmd as u64, arg as u64, 0, 0, 0]);
    row(RO, &[NONE, NET], fc(libc::F_GETFL, 0), &[0]);
    row(RO, &[NONE, NET], fc(libc::F_SETFL, 0), &[0]);
    row(RO, &[NONE, NET], fc(libc::F_SETFL, libc::O_NONBLOCK), &[0]);
    row(RW, &[NONE, RO, NET], fc(libc::F_SETFL, libc::O_APPEND | libc::O_NONBLOCK), &[0]);
    for on in [RO, RW] {
        for (cmd, arg) in [(libc::F_SETFL, libc::O_ASYNC), (libc::F_SETFL, libc::O_DIRECT), (libc::F_SETLK, 0), (libc::F_DUPFD, 0), (libc::F_SETOWN, 1)] {
            assert!(!allowed(on.0, on.1, &fc(cmd, arg)), "fcntl {cmd} {arg:#x}");
        }
    }
}

#[test]
fn fs_rw_rows() {
    let rw = |d: seccomp_data, fds: &[usize]| row(RW, &[NONE, RO, NET], d, fds);
    for nr in [libc::SYS_mkdirat, libc::SYS_fchmodat] {
        rw(call(nr, [N, 0x1000, 0o1777, 0, 0, 0]), &[0]);
        refused(RW, call(nr, [N, 0x1000, 0o755, 0, 0, 0]), 2, &[0o4755, 0o2755, 1 << 32]);
    }
    rw(call(libc::SYS_unlinkat, [N, 0x1000, libc::AT_REMOVEDIR as u64, 0, 0, 0]), &[0]);
    refused(RW, call(libc::SYS_unlinkat, [N, 0x1000, 0, 0, 0, 0]), 2, &[1, libc::AT_EMPTY_PATH as u64]);
    rw(call(libc::SYS_renameat2, [N, 0x1000, N + 1, 0x2000, 2, 0]), &[0, 2]);
    refused(RW, call(libc::SYS_renameat2, [N, 0x1000, N, 0x2000, 0, 0]), 4, &[3, 4, 1 << 32]);
    rw(call(libc::SYS_linkat, [N, 0x1000, N, 0x2000, libc::AT_SYMLINK_FOLLOW as u64, 0]), &[0, 2]);
    refused(RW, call(libc::SYS_linkat, [N, 0x1000, N, 0x2000, 0, 0]), 4, &[libc::AT_EMPTY_PATH as u64]);
    rw(call(libc::SYS_symlinkat, [0x1000, N, 0x2000, 0, 0, 0]), &[1]);
    rw(call(libc::SYS_fchownat, [N, 0x1000, 1000, 1000, libc::AT_SYMLINK_NOFOLLOW as u64, 0]), &[0]);
    refused(RW, call(libc::SYS_fchownat, [N, 0x1000, 1000, 1000, 0, 0]), 4, &[libc::AT_EMPTY_PATH as u64]);
    rw(call(libc::SYS_utimensat, [N, 0x1000, 0, 0, 0, 0]), &[0]);
    refused(RW, call(libc::SYS_utimensat, [N, 0x1000, 0, 0, 0, 0]), 1, &[0]);
    refused(RW, call(libc::SYS_utimensat, [N, 0x1000, 0, 0, 0, 0]), 3, &[libc::AT_EMPTY_PATH as u64]);
    for nr in [libc::SYS_ftruncate, libc::SYS_fsync, libc::SYS_fdatasync, libc::SYS_pwrite64] {
        rw(call(nr, [N, 0, 0, 0, 0, 0]), &[0]);
    }
    rw(call(libc::SYS_fallocate, [N, 0, 0, 4096, 0, 0]), &[0]);
    refused(RW, call(libc::SYS_fallocate, [N, 0, 0, 4096, 0, 0]), 1, &[libc::FALLOC_FL_PUNCH_HOLE as u64 | 1, 1]);
}

#[test]
fn net_rows() {
    let net = |d: seccomp_data, fds: &[usize]| row(NET, &[NONE, RW], d, fds);
    for dom in [libc::AF_INET, libc::AF_INET6] {
        for ty in [libc::SOCK_STREAM, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC] {
            net(call(libc::SYS_socket, [dom as u64, ty as u64, 0, 0, 0, 0]), &[]);
        }
    }
    let s = call(libc::SYS_socket, [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]);
    refused(NET, s, 0, &[libc::AF_UNIX as u64, libc::AF_NETLINK as u64, libc::AF_PACKET as u64]);
    refused(NET, s, 1, &[libc::SOCK_RAW as u64, libc::SOCK_SEQPACKET as u64]);
    refused(NET, s, 2, &[libc::IPPROTO_TCP as u64, libc::IPPROTO_RAW as u64]);
    for nr in [libc::SYS_connect, libc::SYS_bind, libc::SYS_listen, libc::SYS_getsockname, libc::SYS_getpeername] {
        net(call(nr, [N, 0x1000, 16, 0, 0, 0]), &[0]);
    }
    let fl = (libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u64;
    net(call(libc::SYS_accept4, [N, 0, 0, fl, 0, 0]), &[0]);
    refused(NET, call(libc::SYS_accept4, [N, 0, 0, 0, 0, 0]), 3, &[1, 1 << 32]);
    net(call(libc::SYS_shutdown, [N, libc::SHUT_RDWR as u64, 0, 0, 0, 0]), &[0]);
    refused(NET, call(libc::SYS_shutdown, [N, 0, 0, 0, 0, 0]), 1, &[3]);
    for nr in [libc::SYS_sendto, libc::SYS_recvfrom] {
        let d = call(nr, [N, 0x1000, 10, (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64, 0, 0]);
        net(d, &[0]);
        refused(NET, d, 3, &[libc::MSG_OOB as u64, libc::MSG_ERRQUEUE as u64, libc::MSG_ZEROCOPY as u64, libc::MSG_PEEK as u64]);
    }
    let so = |nr: i64, level: i32, opt: i32| call(nr, [N, level as u64, opt as u64, 0x1000, 4, 0]);
    for nr in [libc::SYS_setsockopt, libc::SYS_getsockopt] {
        for (level, opt) in [
            (libc::SOL_SOCKET, libc::SO_REUSEADDR),
            (libc::SOL_SOCKET, libc::SO_KEEPALIVE),
            (libc::SOL_SOCKET, libc::SO_SNDBUF),
            (libc::SOL_SOCKET, libc::SO_RCVBUF),
            (libc::IPPROTO_TCP, libc::TCP_NODELAY),
            (libc::IPPROTO_TCP, libc::TCP_KEEPIDLE),
            (libc::IPPROTO_TCP, libc::TCP_KEEPINTVL),
            (libc::IPPROTO_TCP, libc::TCP_KEEPCNT),
            (libc::IPPROTO_IPV6, libc::IPV6_V6ONLY),
        ] {
            net(so(nr, level, opt), &[0]);
        }
        for (level, opt) in [
            (libc::SOL_SOCKET, libc::SO_REUSEPORT),
            (libc::SOL_SOCKET, libc::SO_RCVBUFFORCE),
            (libc::SOL_SOCKET, libc::SO_ATTACH_FILTER),
            (libc::SOL_SOCKET, libc::SO_BINDTODEVICE),
            (libc::IPPROTO_IP, libc::IP_TRANSPARENT),
            (libc::IPPROTO_TCP, libc::SO_REUSEADDR + 100),
        ] {
            assert!(!allowed(NET.0, NET.1, &so(nr, level, opt)), "{nr} {level} {opt}");
        }
    }
    assert!(allowed(NET.0, NET.1, &so(libc::SYS_getsockopt, libc::SOL_SOCKET, libc::SO_ERROR)));
    assert!(!allowed(NET.0, NET.1, &so(libc::SYS_setsockopt, libc::SOL_SOCKET, libc::SO_ERROR)));
}
