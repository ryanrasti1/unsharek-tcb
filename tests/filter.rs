//! The filter is its policy: [`policy`] is the filter, as a Rust function, and [`filter`]'s
//! program is seccomp-fn-verify's compile of its tree, proven once for every tree. Here, in
//! seconds: the same assertion sampled (seccomp-fn-verify's `check_sampled`), for each mode and
//! some params; the verdicts the same as before the typed view (`same_as_before`); README.md's
//! table against the policy's rows.

#[path = "old/mod.rs"]
mod old;

use unsharek_tcb::plugin::{Fs, Net};
use unsharek_tcb::{AUDIT_ARCH_X86_64, Mode, RET_ALLOW, filter, policy, seccomp_data, sock_filter};

const PPOLL_FDS: u64 = unsharek_tcb::PPOLL_FDS as u64;
const PPOLL_NET_FDS: u64 = Net::PPOLL_FDS as u64;

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
                for (n, gate) in [(N, GATE), (0, 0), (u64::MAX, u64::MAX), (3, 1 << 32)] {
                    seccomp_fn_verify::check_sampled(policy, filter, (mode, n, gate, fs, net), 2_000);
                }
            }
        }
    }
}

/// The verdicts are the policy's before the typed view (`old`, the same rows over raw
/// arguments) on every call whose arguments the kernel reads as they are: each a 32-bit one's
/// below 2^31, no high half (each call's every number, its args drawn from the constants the
/// rows compare with, each either side, and extremes). Past that the two differ on purpose: a
/// 32-bit argument's high half is ignored, as the kernel ignores it (`typed_high_halves`).
#[test]
fn same_as_before() {
    let mut s = 0x9e37_79b9_7f4a_7c15u64;
    let mut rand = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let ks: Vec<u64> = vec![0, 1, 2, 3, 4, 7, 8, 9, 10, 0o1777, 0o2000, 128, 4096, 4097, 0x7fff_ffff];
    let mut flags: Vec<u64> = vec![];
    for a in [libc::O_RDONLY, libc::O_WRONLY, libc::O_RDWR] {
        for b in [0, libc::O_CREAT, libc::O_CREAT | libc::O_EXCL, libc::O_TRUNC, libc::O_APPEND, libc::O_DIRECTORY, libc::O_NOFOLLOW, libc::O_PATH] {
            flags.push((a | b | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64);
            flags.push((a | b) as u64);
        }
    }
    for f in [libc::AF_INET, libc::AF_INET6, libc::AF_UNIX, libc::SOCK_STREAM, libc::SOCK_DGRAM, libc::SOCK_RAW, libc::SOCK_NONBLOCK, libc::SOCK_CLOEXEC] {
        flags.push(f as u64);
        flags.push((f | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u64);
    }
    for f in [libc::SOL_SOCKET, libc::SO_REUSEADDR, libc::SO_KEEPALIVE, libc::SO_ERROR, libc::IPPROTO_TCP, libc::TCP_NODELAY, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, libc::SO_REUSEPORT] {
        flags.push(f as u64);
    }
    let pool: Vec<u64> = ks.iter().chain(&flags).copied().collect();
    let clones = [unsharek_tcb::CLONE_THREAD_FLAGS, libc::SIGCHLD as u64, (libc::CLONE_PARENT | libc::SIGCHLD) as u64, 0];
    for mode in MODES {
        for fs in FSES {
            for net in [false, true] {
                let (new, before) = (policy(mode, N, GATE, fs, net), old::policy(mode, N, GATE, fs, net));
                for nr in 0..340i64 {
                    for _ in 0..40 {
                        let mut args = [0u64; 6];
                        for a in args.iter_mut() {
                            *a = pool[rand() as usize % pool.len()];
                        }
                        if nr == libc::SYS_clone {
                            args[0] = clones[rand() as usize % 4];
                        }
                        let d = call(nr, args);
                        if !as_read(&d) {
                            continue;
                        }
                        assert_eq!(new(&d), before(&d), "{mode:?} {fs:?} net {net}: nr {nr} args {args:x?}");
                    }
                }
            }
        }
    }
}

/// Every arg of `d` is as the kernel reads it (by the call table): a 32-bit one below 2^31, a
/// u16 below 2^16.
fn as_read(d: &seccomp_data) -> bool {
    use seccomp_fn_verify::calls::{CALLS, Ty};
    let Some(r) = CALLS.iter().find(|r| r.1 == d.nr as i64) else { return true };
    r.2.iter().enumerate().all(|(i, a)| match a.1 {
        Ty::U16 => d.args[i] < 1 << 16,
        Ty::U32 | Ty::I32 => d.args[i] < 1 << 31,
        _ => true,
    })
}

/// A 32-bit argument's high half: ignored, as the kernel reads only the low half (before the
/// typed view, a refusal); a 64-bit one's isn't.
#[test]
fn typed_high_halves() {
    let g = 0xdead_beef_0000_0000;
    // close(fd) of a plugin's fd: its high half garbage
    assert!(allowed(Fs::ReadOnly, false, &call(libc::SYS_close, [N | g, 0, 0, 0, 0, 0])));
    // a kept fd's number, with high bits: still a kept fd's, refused
    assert!(!allowed(Fs::ReadOnly, false, &call(libc::SYS_close, [1 | g, 0, 0, 0, 0, 0])));
    // an int: AT_FDCWD (-100) read as the kernel reads it, refused whatever its high half
    assert!(!allowed(Fs::ReadOnly, false, &call(libc::SYS_readlinkat, [(-100i32) as u32 as u64, 0, 0, 0, 0, 0])));
    assert!(!allowed(Fs::ReadOnly, false, &call(libc::SYS_readlinkat, [(-100i64) as u64, 0, 0, 0, 0, 0])));
    // clone's flags are 64 bits: a high bit refuses
    assert!(!allowed(Fs::Off, false, &call(libc::SYS_clone, [unsharek_tcb::CLONE_THREAD_FLAGS | 1 << 40, 0, 0, 0, 0, 0])));
}

/// A call from the gate.
fn call(nr: i64, args: [u64; 6]) -> seccomp_data {
    seccomp_data { nr: nr as i32, arch: AUDIT_ARCH_X86_64, instruction_pointer: GATE, args }
}

/// Whether `d` is allowed with these plugins (threaded mode, floor N).
fn allowed(fs: Fs, net: bool, d: &seccomp_data) -> bool {
    allowed_in(Mode::Threaded, fs, net, d)
}

/// [`allowed`], in `mode`.
fn allowed_in(mode: Mode, fs: Fs, net: bool, d: &seccomp_data) -> bool {
    policy(mode, N, GATE, fs, net)(d) == RET_ALLOW
}

/// The numbers [`policy`] allows in `mode` without plugins, for some arguments: every x86-64
/// number, each tried with the arguments the program compares with (its jumps' constants).
fn ruled(mode: Mode) -> std::collections::BTreeSet<u32> {
    let prog = filter(mode, N, GATE, Fs::Off, false);
    let k: Vec<u64> = prog.iter().filter(|i| i.code & 0x07 == 0x05).map(|i| i.k as u64).chain([0, 1]).collect();
    let mut out = std::collections::BTreeSet::new();
    for nr in 0..1024u32 {
        for &a0 in &k {
            for &a1 in &k {
                if policy(mode, N, GATE, Fs::Off, false)(&call(nr as i64, [a0, a1, 0, 0, 0, 0])) == RET_ALLOW {
                    out.insert(nr);
                }
            }
        }
    }
    out
}

/// The policy's rows, in order, as its program tests them: each arm of a `match d.call()` is a
/// load of `nr` and a JEQ per number (the arch check's load of `nr` is followed by a JGE, not a
/// JEQ). Rows a build-time guard rules out aren't in the program (their arms are dead).
fn program_rows(mode: Mode, fs: Fs, net: bool) -> Vec<Vec<u32>> {
    let ld_nr = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let ja = (libc::BPF_JMP | libc::BPF_JA) as u16;
    let off_nr = std::mem::offset_of!(libc::seccomp_data, nr) as u32;
    let prog: Vec<sock_filter> = filter(mode, N, GATE, fs, net);
    let mut out: Vec<Vec<u32>> = vec![];
    let mut in_row = false;
    for (at, i) in prog.iter().enumerate() {
        if i.code == ld_nr && i.k == off_nr {
            in_row = prog.get(at + 1).is_some_and(|n| n.code == jeq);
            if in_row {
                out.push(vec![]);
            }
        } else if in_row && i.code == jeq {
            out.last_mut().unwrap().push(i.k);
        } else if !(in_row && i.code == ja) {
            // (a JA between a row's JEQs: a trampoline to a far arm)
            in_row = false;
        }
    }
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
                    // The core's (a plugin's own `ppoll` row has its own bound).
                    if cells[0].contains("`ppoll`") && tags == "all" {
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
    assert_eq!(lines.len(), 24, "README.md's allowlist tables: their rows (6 core, 9 fs, 9 net)");
}

/// The program's length in each mode and plugin choice (the kernel takes 4096).
#[test]
fn filter_length() {
    for mode in MODES {
        for fs in FSES {
            for net in [false, true] {
                let n = filter(mode, N, GATE, fs, net).len();
                eprintln!("{mode:?} {fs:?} net {net}: {n} instructions");
                assert!(n <= 1000, "{mode:?}: {n} instructions");
            }
        }
    }
}

/// `read` and `write` on any fd: only kept ones are open (lockdown leaves exactly `0..n`), and
/// with a plugin the ones its rows make. `kill` never: a death by a signal is the runtime's
/// exit_group(128 + n).
#[test]
fn read_write_any_fd() {
    for mode in MODES {
        for (fs, net) in [(Fs::Off, false), (Fs::ReadOnly, false), (Fs::Off, true)] {
            for nr in [libc::SYS_read, libc::SYS_write] {
                for fd in [0, 1, 2, N - 1, N, 1000, u64::MAX] {
                    assert!(allowed_in(mode, fs, net, &call(nr, [fd, 0, 0, 0, 0, 0])), "{mode:?} {nr} {fd:#x}");
                }
            }
        }
        for (fs, net) in [(Fs::Off, false), (Fs::ReadWrite, true)] {
            assert!(!allowed(fs, net, &call(libc::SYS_kill, [4242, 9, 0, 0, 0, 0])), "kill");
            assert!(!allowed(fs, net, &call(libc::SYS_recvmsg, [N, 0, libc::MSG_CMSG_CLOEXEC as u64, 0, 0, 0])), "recvmsg");
        }
    }
}

/// `ppoll`: `PPOLL_FDS` fds, or with the net plugin `PPOLL_NET_FDS`; never a signal mask.
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

/// fd args: an opened fd (N) and a refused one each, as the kernel reads the arg (its C type,
/// seccomp-fn-verify's call table): a kept fd, with or without a high half (ignored); an `int`
/// directory fd's AT_FDCWD, both widths (an `unsigned int` fd's 0xffffff9c is a number no fd
/// has: EBADF, not a refusal).
const BAD_FDS: [u64; 4] = [0, N - 1, (1 << 32) | (N - 1), 0xffff_ffff_0000_0000];
const BAD_DFDS: [u64; 2] = [(-100i64) as u64, 0xffff_ff9c];

/// Arg `i` of call `nr` is an `int` (by the call table).
fn int_arg(nr: i32, i: usize) -> bool {
    use seccomp_fn_verify::calls::{CALLS, Ty};
    CALLS.iter().find(|r| r.1 == nr as i64).is_some_and(|r| r.2.get(i).is_some_and(|a| a.1 == Ty::I32))
}

/// `ok` allowed with `on` and not with each of `offs`; and each fd arg position in `fds` refused
/// with every bad fd.
fn row(on: (Fs, bool), offs: &[(Fs, bool)], ok: seccomp_data, fds: &[usize]) {
    assert!(allowed(on.0, on.1, &ok), "{} {:?}", ok.nr, ok.args);
    for off in offs {
        assert!(!allowed(off.0, off.1, &ok), "{} without its plugin {off:?}", ok.nr);
    }
    for &i in fds {
        let dfds: &[u64] = if int_arg(ok.nr, i) { &BAD_DFDS } else { &[] };
        for &bad in BAD_FDS.iter().chain(dfds) {
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
        ] {
            refused(on, o(0, 0), 2, &[flags]);
        }
        refused(on, o(0, 0), 3, &[0o4644, 0o2755, u64::MAX]);
    }
    assert!(allowed(Fs::ReadWrite, false, &o(libc::O_CREAT | libc::O_WRONLY, 0o1777)));
}

#[test]
fn fs_fd_rows() {
    for nr in [libc::SYS_fstat, libc::SYS_getdents64, libc::SYS_pread64] {
        row(RO, &[NONE, NET], call(nr, [N, 0x1000, 0, 0, 0, 0]), &[0]);
    }
    row(RO, &[NONE, NET], call(libc::SYS_readlinkat, [N, 0x1000, 0x2000, 64, 0, 0]), &[0]);
    // Not rows: stat is openat then fstat, the guest fakes statfs, offsets are pread64's, and a
    // file's flags are fixed at open.
    for on in [RO, RW] {
        for nr in [libc::SYS_lseek, libc::SYS_statx, libc::SYS_newfstatat, libc::SYS_fstatfs, libc::SYS_fcntl, libc::SYS_faccessat2, libc::SYS_flock] {
            assert!(!allowed(on.0, on.1, &call(nr, [N, 0x1000, 0, 0, 0, 0])), "{nr}");
        }
    }
}

#[test]
fn fs_rw_rows() {
    let rw = |d: seccomp_data, fds: &[usize]| row(RW, &[NONE, RO, NET], d, fds);
    for nr in [libc::SYS_mkdirat, libc::SYS_fchmodat] {
        rw(call(nr, [N, 0x1000, 0o1777, 0, 0, 0]), &[0]);
        refused(RW, call(nr, [N, 0x1000, 0o755, 0, 0, 0]), 2, &[0o4755, 0o2755, 0o2000 | 1 << 32]);
    }
    rw(call(libc::SYS_unlinkat, [N, 0x1000, libc::AT_REMOVEDIR as u64, 0, 0, 0]), &[0]);
    refused(RW, call(libc::SYS_unlinkat, [N, 0x1000, 0, 0, 0, 0]), 2, &[1, libc::AT_EMPTY_PATH as u64]);
    rw(call(libc::SYS_renameat2, [N, 0x1000, N + 1, 0x2000, 2, 0]), &[0, 2]);
    refused(RW, call(libc::SYS_renameat2, [N, 0x1000, N, 0x2000, 0, 0]), 4, &[3, 4, 4 | 1 << 32]);
    rw(call(libc::SYS_symlinkat, [0x1000, N, 0x2000, 0, 0, 0]), &[1]);
    rw(call(libc::SYS_utimensat, [N, 0x1000, 0, libc::AT_SYMLINK_NOFOLLOW as u64, 0, 0]), &[0]);
    refused(RW, call(libc::SYS_utimensat, [N, 0x1000, 0, 0, 0, 0]), 1, &[0]);
    refused(RW, call(libc::SYS_utimensat, [N, 0x1000, 0, 0, 0, 0]), 3, &[libc::AT_EMPTY_PATH as u64]);
    for nr in [libc::SYS_ftruncate, libc::SYS_fsync, libc::SYS_pwrite64] {
        rw(call(nr, [N, 0, 0, 0, 0, 0]), &[0]);
    }
    for nr in [libc::SYS_fchownat, libc::SYS_linkat, libc::SYS_fallocate, libc::SYS_fdatasync, libc::SYS_lseek, libc::SYS_fcntl] {
        assert!(!allowed(RW.0, RW.1, &call(nr, [N, 0x1000, N, 0x2000, 0, 0])), "{nr}");
    }
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
    refused(NET, call(libc::SYS_accept4, [N, 0, 0, 0, 0, 0]), 3, &[1, 1 | 1 << 32]);
    net(call(libc::SYS_shutdown, [N, libc::SHUT_RDWR as u64, 0, 0, 0, 0]), &[0]);
    refused(NET, call(libc::SYS_shutdown, [N, 0, 0, 0, 0, 0]), 1, &[3, (-1i64) as u64, 0xffff_ffff]);
    // Data over read and write only: UDP is always connected.
    for nr in [libc::SYS_sendto, libc::SYS_recvfrom, libc::SYS_sendmsg, libc::SYS_recvmsg] {
        assert!(!allowed(NET.0, NET.1, &call(nr, [N, 0x1000, 10, 0, 0, 0])), "{nr}");
    }
    let so = |nr: i64, level: i32, opt: i32| call(nr, [N, level as u64, opt as u64, 0x1000, 4, 0]);
    for (level, opt) in [
        (libc::SOL_SOCKET, libc::SO_REUSEADDR),
        (libc::SOL_SOCKET, libc::SO_KEEPALIVE),
        (libc::IPPROTO_TCP, libc::TCP_NODELAY),
        (libc::IPPROTO_IPV6, libc::IPV6_V6ONLY),
    ] {
        net(so(libc::SYS_setsockopt, level, opt), &[0]);
        assert!(!allowed(NET.0, NET.1, &so(libc::SYS_getsockopt, level, opt)), "get {level} {opt}");
    }
    for (level, opt) in [
        (libc::SOL_SOCKET, libc::SO_REUSEPORT),
        (libc::SOL_SOCKET, libc::SO_RCVBUFFORCE),
        (libc::SOL_SOCKET, libc::SO_SNDBUF),
        (libc::SOL_SOCKET, libc::SO_ATTACH_FILTER),
        (libc::SOL_SOCKET, libc::SO_BINDTODEVICE),
        (libc::IPPROTO_IP, libc::IP_TRANSPARENT),
        (libc::SOL_SOCKET, libc::SO_ERROR),
    ] {
        assert!(!allowed(NET.0, NET.1, &so(libc::SYS_setsockopt, level, opt)), "{level} {opt}");
    }
    net(so(libc::SYS_getsockopt, libc::SOL_SOCKET, libc::SO_ERROR), &[0]);
}
