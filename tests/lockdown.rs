//! Lockdown in the real kernel: each test forks a child (single-threaded, as lockdown needs) that
//! locks itself down and reports through its exit status (after lockdown only gate calls reach
//! the host). The refusals are the seccomp-heavy side: each refusal path is taken for real, and
//! the child gets an error, not a filter.

use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use unsharek_tcb::{Config, Error, Fds, Mode};

// ------------------------------------------------------------------------------------------------
// A gate, and a SIGSYS handler that returns through it.

/// The test's gate: `nr(a0, …, a5)`, raw result.
#[unsafe(naked)]
unsafe extern "C" fn gate(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    core::arch::naked_asm!(
        "mov rax, rdi",
        "mov rdi, rsi",
        "mov rsi, rdx",
        "mov rdx, rcx",
        "mov r10, r8",
        "mov r8, r9",
        "mov r9, [rsp + 8]",
        ".globl unsharek_tcb_test_gate_syscall",
        "unsharek_tcb_test_gate_syscall:",
        "syscall",
        ".globl unsharek_tcb_test_gate_ret",
        "unsharek_tcb_test_gate_ret:",
        "ret",
    )
}

unsafe extern "C" {
    static unsharek_tcb_test_gate_ret: u8;
}

fn gate_ip() -> u64 {
    &raw const unsharek_tcb_test_gate_ret as u64
}

fn g(nr: i64, a: [usize; 3]) -> isize {
    // SAFETY: each test's call is a plain syscall on its own arguments.
    unsafe { gate(nr as usize, a[0], a[1], a[2], 0, 0, 0) }
}

/// `rt_sigreturn` from the gate: the handler's return (libc's restorer would trap).
#[unsafe(naked)]
unsafe extern "C" fn restorer() -> ! {
    core::arch::naked_asm!("mov eax, 15", "jmp unsharek_tcb_test_gate_syscall", "ud2")
}

/// Traps seen, and the last one's si_code and syscall number.
static TRAPS: AtomicU32 = AtomicU32::new(0);
static TRAP_CODE: AtomicI32 = AtomicI32::new(0);
static TRAP_NR: AtomicI32 = AtomicI32::new(-1);
const TRAPPED: i64 = -12345;

extern "C" fn on_sigsys(_sig: i32, info: *mut libc::siginfo_t, uc: *mut libc::c_void) {
    // SAFETY: the kernel's siginfo and ucontext for this signal. `si_syscall` is at offset 24
    // (`_sigsys`: call_addr, syscall, arch).
    unsafe {
        TRAP_CODE.store((*info).si_code, Ordering::Relaxed);
        TRAP_NR.store(*((info as *const u8).add(24) as *const i32), Ordering::Relaxed);
        let uc = uc as *mut libc::ucontext_t;
        (*uc).uc_mcontext.gregs[libc::REG_RAX as usize] = TRAPPED;
    }
    TRAPS.fetch_add(1, Ordering::Relaxed);
}

/// The SIGSYS handler, its return through the gate (`SA_RESTORER`).
fn install_handler() {
    #[repr(C)]
    struct KSigaction {
        handler: usize,
        flags: u64,
        restorer: usize,
        mask: u64,
    }
    const SA_RESTORER: u64 = 0x0400_0000;
    let act = KSigaction {
        handler: on_sigsys as *const () as usize,
        flags: (libc::SA_SIGINFO | libc::SA_NODEFER) as u64 | SA_RESTORER,
        restorer: restorer as *const () as usize,
        mask: 0,
    };
    // SAFETY: the kernel reads `act` (its own layout, sigsetsize 8).
    let r = unsafe { libc::syscall(libc::SYS_rt_sigaction, libc::SIGSYS, &act, 0usize, 8usize) };
    assert_eq!(r, 0);
}

// ------------------------------------------------------------------------------------------------
// The guest, and the child.

struct Guest {
    fds: Vec<RawFd>,
    mode: Mode,
}


/// Lockdown for `guest`, in its mode, with the grants `grants` makes.
fn lockdown(guest: &Guest, grants: impl FnOnce(&mut Config)) -> unsharek_tcb::Result<Fds> {
    let mut c = Config::new().mode(guest.mode).guest_fds(guest.fds.iter().copied()).gate(gate_ip());
    grants(&mut c);
    unsharek_tcb::lockdown(c)
}

fn eventfd() -> RawFd {
    // SAFETY: a plain eventfd.
    let fd = unsafe { libc::eventfd(0, 0) };
    assert!(fd >= 0);
    fd
}

/// `f` in a forked child, which ends with `f`'s result as its status, through the gate (after
/// lockdown nothing else can). Returns the child's wait status.
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

/// Locked down: granted calls from the gate go through with the access granted; a call not from
/// the gate traps (SYS_SECCOMP); the fds neither granted nor the guest's are closed (ppoll,
/// allowed from the gate, sees POLLNVAL). Refused calls are [`each_refused_call_kills`]'.
#[test]
fn locks_down_and_probes() {
    for mode in [Mode::Coroutine, Mode::Threaded, Mode::Fork] {
        let code = exit_code(in_child(|| {
            let efd = eventfd();
            let extra = std::fs::File::open("/proc/self/stat").unwrap();
            let extra_fd = extra.as_raw_fd();
            let ro = std::fs::File::open("/proc/self/stat").unwrap();
            let ro_fd = ro.as_raw_fd();
            install_handler();
            let guest = Guest { fds: vec![efd], mode };
            let r = lockdown(&guest, |s| {
                s.fds.extend([1, 2, ro_fd]);
            });
            let Ok(f) = r else {
                return 1;
            };
            // The kept fds' new numbers (the extra one, closed, keeps its old: it must be shut).
            let (efd, ro_fd) = (f.get(efd).unwrap(), f.get(ro_fd).unwrap());
            if f.get(1) != Some(1) || f.get(2) != Some(2) {
                return 2;
            }
            let buf = [0u8; 8];
            let one = 1u64.to_ne_bytes();
            let ptr = buf.as_ptr() as usize;
            let checks: [(i64, [usize; 3], isize); 4] = [
                (libc::SYS_write, [1, ptr, 0], 0),
                (libc::SYS_write, [efd as usize, one.as_ptr() as usize, 8], 8),
                (libc::SYS_read, [efd as usize, ptr, 8], 8),
                (libc::SYS_read, [ro_fd as usize, ptr, 0], 0),
            ];
            for (i, (nr, a, want)) in checks.into_iter().enumerate() {
                if g(nr, a) != want {
                    return 10 + i as i32;
                }
            }
            // Not from the gate: trapped, served by the handler.
            // SAFETY: getppid; the handler answers it.
            let r = unsafe { libc::syscall(libc::SYS_getppid) };
            if r != TRAPPED || TRAPS.load(Ordering::Relaxed) != 1 {
                return 30;
            }
            if TRAP_CODE.load(Ordering::Relaxed) != 1 /* SYS_SECCOMP */ || TRAP_NR.load(Ordering::Relaxed) != libc::SYS_getppid as i32 {
                return 31;
            }
            // The extra fd is closed; the granted one isn't.
            let mut pfd = [libc::pollfd { fd: extra_fd, events: libc::POLLIN, revents: 0 }, libc::pollfd { fd: ro_fd, events: libc::POLLIN, revents: 0 }];
            let ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            // SAFETY: ppoll from the gate on two pollfds, no mask.
            let r = unsafe { gate(libc::SYS_ppoll as usize, pfd.as_mut_ptr() as usize, 2, &ts as *const _ as usize, 0, 8, 0) };
            if r < 0 || pfd[0].revents & libc::POLLNVAL == 0 || pfd[1].revents & libc::POLLNVAL != 0 {
                return 40;
            }
            std::mem::forget((extra, ro));
            0
        }));
        assert_eq!(code, 0, "{mode:?}");
    }
}

/// Each refused call from the gate kills the process with SIGSYS: getppid, openat, socket.
#[test]
fn each_refused_call_kills() {
    type Probe = fn(RawFd) -> (i64, [usize; 3]);
    let probes: [Probe; 3] = [
        |_| (libc::SYS_getppid, [0, 0, 0]),
        |_| (libc::SYS_openat, [libc::AT_FDCWD as usize, c"/".as_ptr() as usize, 0]),
        |_| (libc::SYS_socket, [libc::AF_INET as usize, libc::SOCK_STREAM as usize, 0]),
    ];
    for (i, probe) in probes.into_iter().enumerate() {
        let status = in_child(|| {
            let ro = std::fs::File::open("/proc/self/stat").unwrap();
            let ro_fd = ro.as_raw_fd();
            let guest = Guest { fds: vec![], mode: Mode::Coroutine };
            let Ok(f) = lockdown(&guest, |s| {
                s.fds.extend([ro_fd]);
            }) else {
                return 1;
            };
            let (nr, a) = probe(f.get(ro_fd).unwrap());
            g(nr, a);
            std::mem::forget(ro);
            2
        });
        assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS, "probe {i}: status {status:#x}");
    }
}

/// After lockdown the process is not dumpable and dumps no core: the parent sees its /proc files
/// owned by root, and its core limit 0. The child waits on a granted pipe for the parent's word.
#[test]
fn no_core_dumps() {
    let mut p = [0; 2];
    // SAFETY: a pipe into a local array.
    assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
    let mut q = [0; 2];
    // SAFETY: as above.
    assert_eq!(unsafe { libc::pipe(q.as_mut_ptr()) }, 0);
    // SAFETY: the child locks down and waits; the parent inspects it.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let guest = Guest { fds: vec![], mode: Mode::Coroutine };
        let Ok(f) = lockdown(&guest, |s| {
            s.fds.extend([p[0], q[1]]);
        }) else {
            g(libc::SYS_exit_group, [9, 0, 0]);
            unreachable!();
        };
        let (p0, q1) = (f.get(p[0]).unwrap(), f.get(q[1]).unwrap());
        let b = [1u8];
        g(libc::SYS_write, [q1 as usize, b.as_ptr() as usize, 1]);
        let mut b = [0u8];
        g(libc::SYS_read, [p0 as usize, b.as_mut_ptr() as usize, 1]);
        g(libc::SYS_exit_group, [0, 0, 0]);
        unreachable!();
    }
    let mut b = [0u8];
    // SAFETY: reads the child's word.
    assert_eq!(unsafe { libc::read(q[0], b.as_mut_ptr().cast(), 1) }, 1);
    assert_eq!(b[0], 1, "lockdown failed");
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let core = limits.lines().find(|l| l.starts_with("Max core file size")).unwrap();
    assert_eq!(core.split_whitespace().nth(4), Some("0"), "{core}");
    assert_eq!(core.split_whitespace().nth(5), Some("0"), "{core}");
    // SAFETY: getuid.
    let me = unsafe { libc::getuid() };
    if me != 0 {
        // Root's (the namespace's root: in a user namespace, as nix's build sandbox, it shows as
        // the overflow uid), not ours.
        use std::os::unix::fs::MetadataExt;
        let owner = std::fs::metadata(format!("/proc/{pid}/limits")).unwrap().uid();
        assert_ne!(owner, me, "dumpable: /proc/{pid} is still its owner's");
    }
    // SAFETY: writes the parent's word, then waits.
    assert_eq!(unsafe { libc::write(p[1], b"x".as_ptr().cast(), 1) }, 1);
    let mut status = 0;
    // SAFETY: waitpid into a local.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(exit_code(status), 0);
}

// ------------------------------------------------------------------------------------------------
// Each refusal.

/// The child's lockdown result: 0 locked down, 1 a mapping refused, 2 a guest fd refused, 3 other
/// threads, 4 anything else.
fn verdict(r: unsharek_tcb::Result<Fds>) -> i32 {
    match r {
        Ok(_) => 0,
        Err(Error::Mapping(_)) => 1,
        Err(Error::FdKind { .. }) => 2,
        Err(Error::Threads(t)) if !t.is_empty() => 3,
        Err(_) => 4,
    }
}

fn temp_file() -> (std::fs::File, std::path::PathBuf) {
    // SAFETY: getpid.
    let path = std::env::temp_dir().join(format!("unsharek-tcb-{}-{:?}", unsafe { libc::getpid() }, std::thread::current().id()));
    let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
    f.set_len(4096).unwrap();
    (f, path)
}

fn map(fd: RawFd, prot: i32, flags: i32) {
    // SAFETY: a fresh mapping, never unmapped (the child ends).
    let p = unsafe { libc::mmap(std::ptr::null_mut(), 4096, prot, flags, fd, 0) };
    assert_ne!(p, libc::MAP_FAILED);
}

/// A writable `MAP_SHARED` mapping of a host file: refused, in every mode, even when the file's
/// fd is closed (the mapping outlives it). Read-only shared, or private, it is fine.
#[test]
fn refuses_a_writable_shared_file_mapping() {
    let (f, path) = temp_file();
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    for mode in [Mode::Coroutine, Mode::Threaded, Mode::Fork] {
        for (prot, flags, want) in [
            (rw, libc::MAP_SHARED, 1),
            (libc::PROT_WRITE, libc::MAP_SHARED, 1),
            (libc::PROT_READ, libc::MAP_SHARED, 0),
            (rw, libc::MAP_PRIVATE, 0),
        ] {
            let fd = f.as_raw_fd();
            let got = exit_code(in_child(|| {
                map(fd, prot, flags);
                let guest = Guest { fds: vec![], mode };
                verdict(lockdown(&guest, |_| ()))
            }));
            assert_eq!(got, want, "{mode:?} prot {prot} flags {flags:#x}");
        }
    }
    let _ = std::fs::remove_file(path);
}

/// Shared anonymous memory: the guest's processes' own in fork mode, refused in the others. A
/// memfd's writable shared mapping is a host file's: refused in every mode.
#[test]
fn shared_anonymous_memory_in_fork_mode_only() {
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    for (mode, want) in [(Mode::Coroutine, 1), (Mode::Threaded, 1), (Mode::Fork, 0)] {
        let got = exit_code(in_child(|| {
            map(-1, rw, libc::MAP_SHARED | libc::MAP_ANONYMOUS);
            verdict(lockdown(&Guest { fds: vec![], mode }, |_| ()))
        }));
        assert_eq!(got, want, "{mode:?}");
        let got = exit_code(in_child(|| {
            // SAFETY: a memfd.
            let fd = unsafe { libc::memfd_create(c"x".as_ptr(), 0) };
            // SAFETY: sizes it.
            assert_eq!(unsafe { libc::ftruncate(fd, 4096) }, 0);
            map(fd, rw, libc::MAP_SHARED);
            verdict(lockdown(&Guest { fds: vec![], mode }, |_| ()))
        }));
        assert_eq!(got, 1, "{mode:?} memfd");
    }
}

/// A guest fd that is not an eventfd or a pidfd (a file, a socket, a pipe posing as one, which
/// would get read and write without a grant): refused. An eventfd and a pidfd pass.
#[test]
fn refuses_a_guest_fd_of_the_wrong_kind() {
    let got = exit_code(in_child(|| {
        let (f, _) = temp_file();
        let fd = f.as_raw_fd();
        std::mem::forget(f);
        verdict(lockdown(&Guest { fds: vec![eventfd(), fd], mode: Mode::Threaded }, |_| ()))
    }));
    assert_eq!(got, 2);
    let got = exit_code(in_child(|| {
        let mut p = [0; 2];
        // SAFETY: a pipe.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        verdict(lockdown(&Guest { fds: vec![p[1]], mode: Mode::Threaded }, |_| ()))
    }));
    assert_eq!(got, 2);
    let got = exit_code(in_child(|| {
        // SAFETY: a pidfd of this process.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as RawFd;
        verdict(lockdown(&Guest { fds: vec![eventfd(), pidfd], mode: Mode::Fork }, |_| ()))
    }));
    assert_eq!(got, 0);
    // A pidfd outside fork mode: refused (only fork mode's processes poll init's).
    let got = exit_code(in_child(|| {
        // SAFETY: a pidfd of this process.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as RawFd;
        verdict(lockdown(&Guest { fds: vec![pidfd], mode: Mode::Threaded }, |_| ()))
    }));
    assert_eq!(got, 2);
}

/// A second thread: refused, its tid named. Lockdown is then no further than step 1.
#[test]
fn refuses_a_second_thread() {
    let got = exit_code(in_child(|| {
        std::thread::spawn(|| {
            loop {
                std::thread::park();
            }
        });
        verdict(lockdown(&Guest { fds: vec![], mode: Mode::Coroutine }, |_| ()))
    }));
    assert_eq!(got, 3);
    // A thread joined just before is gone in time.
    let got = exit_code(in_child(|| {
        std::thread::spawn(|| ()).join().unwrap();
        verdict(lockdown(&Guest { fds: vec![], mode: Mode::Coroutine }, |_| ()))
    }));
    assert_eq!(got, 0);
}

/// A granted fd that isn't open is an error, not a grant of whatever opens there later.
#[test]
fn refuses_a_closed_grant() {
    let got = exit_code(in_child(|| {
        match lockdown(&Guest { fds: vec![], mode: Mode::Coroutine }, |s| {
            s.fds.extend([900]);
        }) {
            Err(Error::NotOpen(900)) => 0,
            _ => 1,
        }
    }));
    assert_eq!(got, 0);
}

// ------------------------------------------------------------------------------------------------
// Renumbering (compaction): the kept fds at 0..n.

/// `fd` duplicated to `at` (closed first if open), close-on-exec if `cloexec`.
fn dup_to(fd: RawFd, at: RawFd, cloexec: bool) -> RawFd {
    // SAFETY: dup3 of our own fd.
    let r = unsafe { libc::dup3(fd, at, if cloexec { libc::O_CLOEXEC } else { 0 }) };
    assert_eq!(r, at);
    at
}

/// Kept fds scattered above stray ones land at 0..n: 0-2 in place, the rest lowest-first in
/// order of the old numbers, close-on-exec as they were; each still the same file (a write on
/// the new number reaches the pipe's other end); n and everything above it closed.
#[test]
fn renumbers_the_kept_fds() {
    for mode in [Mode::Coroutine, Mode::Threaded, Mode::Fork] {
        let code = exit_code(in_child(|| {
            let mut p = [0; 2];
            // SAFETY: a pipe into a local.
            assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
            // Strays at 20 and 30, kept ones at 500 (cloexec), 700, 800 (the read end, so the
            // writes don't break the pipe) and an eventfd at 600.
            let _stray = (dup_to(p[0], 20, false), dup_to(p[0], 30, false));
            let w = dup_to(p[1], 500, true);
            let w2 = dup_to(p[1], 700, false);
            let r = dup_to(p[0], 800, false);
            let efd = dup_to(eventfd(), 600, false);
            let Ok(f) = lockdown(&Guest { fds: vec![efd], mode }, |s| s.fds.extend([0, 1, 2, w, w2, r])) else {
                return 1;
            };
            // n = 7: 0, 1, 2 stay; 500 -> 3, 600 -> 4, 700 -> 5, 800 -> 6.
            let want = Fds { n: 7, map: vec![(0, 0), (1, 1), (2, 2), (w, 3), (efd, 4), (w2, 5), (r, 6)] };
            if f != want {
                return 2;
            }
            let msg = *b"hi";
            if g(libc::SYS_write, [3, msg.as_ptr() as usize, 1]) != 1 || g(libc::SYS_write, [5, msg[1..].as_ptr() as usize, 1]) != 1 {
                return 3;
            }
            let one = 1u64.to_ne_bytes();
            if g(libc::SYS_write, [4, one.as_ptr() as usize, 8]) != 8 {
                return 4;
            }
            let mut got = [0u8; 2];
            if g(libc::SYS_read, [6, got.as_mut_ptr() as usize, 2]) != 2 || got != msg {
                return 6;
            }
            // 7 and the old numbers are closed: POLLNVAL.
            let mut pfd: Vec<libc::pollfd> = [7, 20, 500, 600, 700].iter().map(|&fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 }).collect();
            let ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            // SAFETY: ppoll from the gate on five pollfds, no mask.
            let r = unsafe { gate(libc::SYS_ppoll as usize, pfd.as_mut_ptr() as usize, 5, &ts as *const _ as usize, 0, 8, 0) };
            if r != 5 || pfd.iter().any(|p| p.revents & libc::POLLNVAL == 0) {
                return 5;
            }
            0
        }));
        assert_eq!(code, 0, "{mode:?}");
    }
    // Kept fds below the floor stay where they are, those above fill the gaps.
    let code = exit_code(in_child(|| {
        let mut p = [0; 2];
        // SAFETY: a pipe into a local.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        let (a, b) = (dup_to(p[1], 400, true), dup_to(p[1], 401, false));
        let Ok(f) = lockdown(&Guest { fds: vec![], mode: Mode::Coroutine }, |s| s.fds.extend([p[0], a, b])) else {
            return 1;
        };
        let (r, a, b) = (f.get(p[0]).unwrap(), f.get(a).unwrap(), f.get(b).unwrap());
        if f.n != 3 || ![r, a, b].iter().all(|&fd| fd < 3) {
            return 2;
        }
        let x = *b"x";
        if g(libc::SYS_write, [a as usize, x.as_ptr() as usize, 1]) != 1 {
            return 3;
        }
        let mut got = [0u8];
        if g(libc::SYS_read, [r as usize, got.as_mut_ptr() as usize, 1]) != 1 || got != x {
            return 4;
        }
        0
    }));
    assert_eq!(code, 0);
}

/// Granted fds already at 0..n: nothing moves (0-2 in place, duplicates counted once).
#[test]
fn renumbering_leaves_low_fds_in_place() {
    let code = exit_code(in_child(|| {
        // Every fd but 0-2 closed first: the kept ones are already 0..n.
        // SAFETY: closing our own fds.
        unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
        let Ok(f) = lockdown(&Guest { fds: vec![], mode: Mode::Coroutine }, |s| s.fds.extend([2, 0, 1, 1])) else {
            return 1;
        };
        if f != (Fds { n: 3, map: vec![(0, 0), (1, 1), (2, 2)] }) {
            return 2;
        }
        0
    }));
    assert_eq!(code, 0);
}

/// A huge fd number costs nothing (before, the plugin's floor filled every number below it with
/// /dev/null): it moves to 0.
#[test]
fn renumbers_a_huge_fd() {
    let code = exit_code(in_child(|| {
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: get and set our own fd limit.
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
        lim.rlim_cur = lim.rlim_max.min(1 << 20);
        // SAFETY: as above.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) };
        let huge = (lim.rlim_cur - 1) as RawFd;
        let efd = dup_to(eventfd(), huge, false);
        let t = std::time::Instant::now();
        let Ok(f) = lockdown(&Guest { fds: vec![efd], mode: Mode::Coroutine }, |_| ()) else {
            return 1;
        };
        if f != (Fds { n: 1, map: vec![(huge, 0)] }) || t.elapsed() > std::time::Duration::from_millis(500) {
            return 2;
        }
        let one = 1u64.to_ne_bytes();
        if g(libc::SYS_write, [0, one.as_ptr() as usize, 8]) != 8 {
            return 3;
        }
        0
    }));
    assert_eq!(code, 0);
}

// ------------------------------------------------------------------------------------------------
// Threads that never attach, and processes sharing the memory.

/// A host thread's entry after the gate's clone: the gate's `ret` pops this address off the new
/// stack. Its one call, from the gate, is refused: the whole process dies of SIGSYS. A thread
/// made after lockdown is under the filter whatever it runs (it never "attaches" to anything:
/// seccomp's filter is inherited by clone), so no thread escapes it.
extern "C" fn thread_escape() -> ! {
    g(libc::SYS_getppid, [0, 0, 0]);
    // Not reached; if it were, end the process with a code the test refuses.
    g(libc::SYS_exit_group, [77, 0, 0]);
    unreachable!()
}

#[test]
fn a_new_thread_is_under_the_filter() {
    for mode in [Mode::Threaded, Mode::Fork] {
        let status = in_child(|| {
            let stack = Box::leak(vec![0u64; 8192].into_boxed_slice());
            let top = stack.len() - 2; // 16-aligned (the Vec's alignment is 8; fixed below)
            let mut sp = &raw mut stack[top] as usize;
            sp &= !15;
            // SAFETY: the new stack's top: the address the gate's `ret` jumps to.
            unsafe { *(sp as *mut usize) = thread_escape as *const () as usize };
            if lockdown(&Guest { fds: vec![], mode }, |_| ()).is_err() {
                return 1;
            }
            // SAFETY: clone from the gate with the thread flags and the new stack.
            let tid = unsafe { gate(libc::SYS_clone as usize, unsharek_tcb::CLONE_THREAD_FLAGS as usize, sp, 0, 0, 0, 0) };
            if tid <= 0 {
                return 2;
            }
            // Wait for the thread's death to take the process (a second at most).
            let ts = libc::timespec { tv_sec: 1, tv_nsec: 0 };
            // SAFETY: ppoll from the gate on no fds.
            unsafe { gate(libc::SYS_ppoll as usize, 0, 0, &ts as *const _ as usize, 0, 8, 0) };
            3
        });
        assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS, "{mode:?}: status {status:#x}");
    }
}

extern "C" fn sharer(_: *mut libc::c_void) -> i32 {
    loop {
        // SAFETY: sleeps; the test kills it.
        unsafe { libc::pause() };
    }
}

/// A process sharing the memory (`CLONE_VM` without `CLONE_THREAD`): not in /proc/self/task,
/// not reached by TSYNC, it would run unfiltered on memory the program writes. The paranoia
/// check refuses it (kcmp); without paranoia it isn't looked for (the crate's assumption).
#[test]
fn refuses_a_process_sharing_the_memory() {
    {
        let paranoia = true;
        let code = exit_code(in_child(|| {
            let stack = Box::leak(vec![0u128; 1 << 12].into_boxed_slice()); // 16-aligned
            // SAFETY: a CLONE_VM child on its own stack, which only sleeps.
            let pid = unsafe {
                libc::clone(sharer, stack.as_mut_ptr().add(stack.len()) as *mut _, libc::CLONE_VM | libc::SIGCHLD, std::ptr::null_mut())
            };
            assert!(pid > 0);
            let c = Config::new().mode(Mode::Coroutine).gate(gate_ip()).paranoia(paranoia);
            let r = unsharek_tcb::lockdown(c);
            let out = match r {
                Err(Error::Paranoia(m)) if m.contains(&pid.to_string()) => 0,
                Ok(_) => 1,
                Err(_) => 2,
            };
            if out == 1 {
                // Locked down: the kill goes through nothing; the sharer dies with the parent's
                // wait (it's our child: the test's parent reaps us, the sharer is reparented and
                // killed below by its pid).
            } else {
                // SAFETY: our child.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            let _ = std::fs::write(std::env::temp_dir().join(format!("unsharek-tcb-sharer-{}", unsafe { libc::getpid() })), pid.to_string());
            out
        }));
        assert_eq!(code, 0);
    }
    // The sharer, if the child didn't kill it: killed.
    for e in std::fs::read_dir(std::env::temp_dir()).unwrap().flatten() {
        if e.file_name().to_string_lossy().starts_with("unsharek-tcb-sharer-") {
            if let Ok(pid) = std::fs::read_to_string(e.path()).unwrap_or_default().parse::<i32>() {
                // SAFETY: a sharer this test made (or stale: ESRCH).
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Paranoia refuses a kept fd no caller can mean: another process's memory (/proc/<pid>/mem),
/// a writable /proc file. A read-only /proc file passes.
#[test]
fn paranoia_refuses_kernel_fds() {
    for (path, write, want) in [("/proc/self/mem", false, 0), ("/proc/self/attr/current", true, 0), ("/proc/self/stat", false, 1)] {
        let code = exit_code(in_child(|| {
            let Ok(f) = std::fs::OpenOptions::new().read(!write).write(write).open(path) else {
                return 1; // can't open it here: as good as refused
            };
            let fd = f.as_raw_fd();
            std::mem::forget(f);
            match lockdown(&Guest { fds: vec![], mode: Mode::Coroutine }, |s| s.fds.extend([fd])) {
                Err(Error::Paranoia(_)) => 0,
                Ok(_) => 1,
                Err(_) => 2,
            }
        }));
        assert_eq!(code, want, "{path}");
    }
}

/// How long lockdown's checks take (`--nocapture` prints them): the paranoia check, and the
/// rest (threads, fds, mappings).
#[test]
fn check_times() {
    for mode in [Mode::Coroutine, Mode::Fork] {
        let code = exit_code(in_child(|| {
            if mode == Mode::Fork {
                map(-1, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_ANONYMOUS);
            }
            // Allocated before: after lockdown no memory call goes through.
            let mut m = String::with_capacity(256);
            let Ok(f) = lockdown(&Guest { fds: vec![], mode }, |s| s.fds.extend([0, 1, 2])) else {
                return 1;
            };
            use std::fmt::Write;
            let _ = writeln!(m, "{mode:?}: paranoia {} us, checks {} us", unsharek_tcb::paranoia_ns() / 1000, unsharek_tcb::check_ns() / 1000);
            g(libc::SYS_write, [f.get(2).unwrap() as usize, m.as_ptr() as usize, m.len()]);
            0
        }));
        assert_eq!(code, 0);
    }
}
