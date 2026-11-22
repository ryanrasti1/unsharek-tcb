//! Lockdown in the real kernel: each test forks a child (single-threaded, as lockdown needs) that
//! locks itself down and reports through its exit status (after lockdown only gate calls reach
//! the host). The refusals are the seccomp-heavy side: each refusal path is taken for real, and
//! the child gets an error, not a filter.

use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use unsharek_tcb::plugin::{Files, Net};
use unsharek_tcb::plugin::Fs;
use unsharek_tcb::{Config, Error, Kind, Mode};

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
fn lockdown(guest: &Guest, grants: impl FnOnce(&mut Vec<RawFd>)) -> unsharek_tcb::Result<Fds> {
    with_plugins(guest, grants, &[])
}

/// [`lockdown`], with `plugins`: `guest`'s fds (and the mode's, [`mode_fds`]) and the grants put
/// at `0..n`, as a caller does ([`arrange`]), the guest's declared by their kind.
fn with_plugins(guest: &Guest, grants: impl FnOnce(&mut Vec<RawFd>), plugins: &[&dyn unsharek_tcb::Plugin]) -> unsharek_tcb::Result<Fds> {
    let own = mode_fds(guest.mode, &guest.fds);
    let mut granted = vec![];
    grants(&mut granted);
    let fds = arrange(&own.iter().chain(&granted).copied().collect::<Vec<_>>());
    let mut c = Config::new(gate_ip()).mode(guest.mode).grant(granted.iter().map(|&fd| fds.get(fd).unwrap()));
    for &fd in &own {
        let kind = if link(fd) == "anon_inode:[pidfd]" { Kind::Pidfd } else { Kind::Eventfd };
        c = c.grant_as(kind, [fds.get(fd).unwrap()]);
    }
    unsharek_tcb::lockdown(c, plugins).map(|()| fds)
}

/// The kept fds as the test's caller arranged them: their count `n`, and each one's new number.
struct Fds {
    n: RawFd,
    /// (old, new), sorted by the old number.
    map: Vec<(RawFd, RawFd)>,
}

impl Fds {
    fn get(&self, old: RawFd) -> Option<RawFd> {
        self.map.binary_search_by_key(&old, |&(o, _)| o).ok().map(|i| self.map[i].1)
    }
}

/// What a caller does before lockdown (unsharek's setup, untrusted): each kept fd moved to
/// `0..n`, those already below `n` in place, the others to the free numbers below it, lowest
/// first (a stray fd there is replaced; lockdown closes the old numbers, at or above `n`).
/// A kept fd that isn't open stays where it is, for lockdown to refuse.
fn arrange(keep: &[RawFd]) -> Fds {
    let mut keep = keep.to_vec();
    keep.sort_unstable();
    keep.dedup();
    let n = keep.len() as RawFd;
    let mut free = (0..n).filter(|fd| keep.binary_search(fd).is_err());
    let mut map = vec![];
    for &fd in &keep {
        // SAFETY: fcntl on this process's fd.
        let open = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
        let new = if fd < n || !open { fd } else { free.next().unwrap() };
        if new != fd {
            // SAFETY: dup3 of this process's own fd onto a number not kept.
            assert_eq!(unsafe { libc::dup3(fd, new, 0) }, new);
        }
        map.push((fd, new));
    }
    Fds { n, map }
}

/// `fd`'s `/proc/self/fd` link.
fn link(fd: RawFd) -> String {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).map(|l| l.to_string_lossy().into_owned()).unwrap_or_default()
}

/// `fds` and what the mode keeps besides: threaded and fork mode's CPU tokens (eventfds: a few,
/// unless `fds` has one), fork mode's pidfd (unless `fds` has one).
fn mode_fds(mode: Mode, fds: &[RawFd]) -> Vec<RawFd> {
    let mut out = fds.to_vec();
    if mode != Mode::Coroutine && !fds.iter().any(|&fd| link(fd) == "anon_inode:[eventfd]") {
        out.extend((0..3).map(|_| eventfd()));
    }
    if mode == Mode::Fork && !fds.iter().any(|&fd| link(fd) == "anon_inode:[pidfd]") {
        out.push(pidfd());
    }
    out
}

/// A pidfd of this process.
fn pidfd() -> RawFd {
    // SAFETY: pidfd_open of our own pid.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as RawFd;
    assert!(fd >= 0);
    fd
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
            // Above every kept number once renumbered (threaded mode keeps 129 tokens).
            let extra = std::fs::File::open("/proc/self/stat").unwrap();
            // SAFETY: dup2 of our own fd onto a free number.
            let extra_fd = unsafe { libc::dup2(extra.as_raw_fd(), 900) };
            let ro = std::fs::File::open("/proc/self/stat").unwrap();
            let ro_fd = ro.as_raw_fd();
            install_handler();
            // The eventfd: the guest's in threaded and fork mode, a grant in coroutine mode (which
            // keeps no guest fd).
            let guest = Guest { fds: if mode == Mode::Coroutine { vec![] } else { vec![efd] }, mode };
            let r = lockdown(&guest, |s| {
                s.extend([1, 2, ro_fd]);
                if mode == Mode::Coroutine {
                    s.push(efd);
                }
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
                s.extend([ro_fd]);
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
            s.extend([p[0], q[1]]);
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

/// A fd declared an eventfd (a CPU token) that isn't one (a file, a pipe posing as one, which
/// would get read and write as the guest's own): refused. An eventfd and a pidfd pass.
#[test]
fn refuses_a_guest_fd_of_the_wrong_kind() {
    let declared = |mode: Mode, kind: Kind, make: fn() -> RawFd| {
        exit_code(in_child(move || {
            let fd = make();
            let f = arrange(&[fd]);
            verdict(unsharek_tcb::lockdown(Config::new(gate_ip()).mode(mode).grant_as(kind, [f.get(fd).unwrap()]), &[]).map(|()| f))
        }))
    };
    let file = || {
        let (f, _) = temp_file();
        let fd = f.as_raw_fd();
        std::mem::forget(f);
        fd
    };
    let pipe = || {
        let mut p = [0; 2];
        // SAFETY: a pipe.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        p[1]
    };
    assert_eq!(declared(Mode::Threaded, Kind::Eventfd, file), 2, "a file");
    assert_eq!(declared(Mode::Threaded, Kind::Eventfd, pipe), 2, "a pipe");
    assert_eq!(declared(Mode::Threaded, Kind::Eventfd, eventfd), 0, "an eventfd");
    assert_eq!(declared(Mode::Fork, Kind::Pidfd, pidfd), 0, "a pidfd");
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

/// A granted fd that isn't open (in `0..n`: no gap) is an error, not a grant of whatever opens
/// there later.
#[test]
fn refuses_a_closed_grant() {
    let got = exit_code(in_child(|| {
        // SAFETY: closes fd 3, this process's.
        unsafe { libc::close(3) };
        match unsharek_tcb::lockdown(Config::new(gate_ip()).grant([0, 1, 2, 3]), &[]) {
            Err(Error::NotOpen(3)) => 0,
            _ => 1,
        }
    }));
    assert_eq!(got, 0);
}

// ------------------------------------------------------------------------------------------------
// The kept fds: exactly 0..n, the caller's to arrange.

/// A gap in the kept fds (fd 3 not kept, 4 is): refused, naming it. Lockdown renumbers nothing.
#[test]
fn refuses_a_gap() {
    let got = exit_code(in_child(|| {
        let mut p = [0; 2];
        // SAFETY: a pipe, its write end moved to 4, 3 closed.
        unsafe {
            assert_eq!(libc::pipe(p.as_mut_ptr()), 0);
            assert_eq!(libc::dup2(p[1], 4), 4);
            libc::close(3);
        }
        match unsharek_tcb::lockdown(Config::new(gate_ip()).grant([0, 1, 2, 4]), &[]) {
            Err(Error::Gap { gap: 3, n: 4 }) => 0,
            _ => 1,
        }
    }));
    assert_eq!(got, 0);
}

/// An fd at or above `n` is closed, not an error (a CLI inherits stray fds): after lockdown the
/// gate's ppoll sees it gone (POLLNVAL), and the kept pipe still works.
#[test]
fn closes_fds_at_or_above_n() {
    let got = exit_code(in_child(|| {
        let mut p = [0; 2];
        // SAFETY: a pipe.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        // SAFETY: dup of this process's fd far above.
        let stray = unsafe { libc::dup2(p[0], 700) };
        let Ok(f) = lockdown(&Guest { fds: vec![], mode: Mode::Coroutine }, |s| s.extend([p[0], p[1]])) else {
            return 1;
        };
        let (r, w) = (f.get(p[0]).unwrap(), f.get(p[1]).unwrap());
        let mut pfd = [libc::pollfd { fd: stray, events: libc::POLLIN, revents: 0 }];
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        if g(libc::SYS_ppoll, [pfd.as_mut_ptr() as usize, 1, &ts as *const _ as usize]) != 1 || pfd[0].revents != libc::POLLNVAL {
            return 2;
        }
        let mut b = [0u8; 1];
        if r >= f.n || w >= f.n || g(libc::SYS_write, [w as usize, b"x".as_ptr() as usize, 1]) != 1 || g(libc::SYS_read, [r as usize, b.as_mut_ptr() as usize, 1]) != 1 {
            return 3;
        }
        0
    }));
    assert_eq!(got, 0);
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
            let c = Config::new(gate_ip()).mode(Mode::Coroutine).paranoia(paranoia);
            let r = unsharek_tcb::lockdown(c, &[]);
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

/// A kept fd no caller can mean is refused, always (not paranoia): another process's memory
/// (/proc/<pid>/mem), a writable /proc file. A read-only /proc file passes.
#[test]
fn refuses_kernel_fds() {
    for (path, write, want) in [("/proc/self/mem", false, 0), ("/proc/self/attr/current", true, 0), ("/proc/self/stat", false, 1)] {
        let code = exit_code(in_child(|| {
            let Ok(f) = std::fs::OpenOptions::new().read(!write).write(write).open(path) else {
                return 1; // can't open it here: as good as refused
            };
            let fd = f.as_raw_fd();
            std::mem::forget(f);
            match lockdown(&Guest { fds: vec![], mode: Mode::Coroutine }, |s| s.extend([fd])) {
                Err(Error::FdKind { .. }) => 0,
                Ok(_) => 1,
                Err(_) => 2,
            }
        }));
        assert_eq!(code, want, "{path}");
    }
}

/// How long lockdown's checks take (`--nocapture` prints them, with `--features testing`): the
/// paranoia check, the fd checks (for about 140 kept fds: stdio and threaded mode's CPU tokens
/// and more), and all of steps 1-3 (threads, fds, mappings).
#[cfg(feature = "testing")]
#[test]
fn check_times() {
    for (mode, extra) in [(Mode::Coroutine, 0), (Mode::Threaded, 136), (Mode::Fork, 0)] {
        let code = exit_code(in_child(|| {
            if mode == Mode::Fork {
                map(-1, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_ANONYMOUS);
            }
            let tokens: Vec<RawFd> = (0..extra).map(|_| eventfd()).collect();
            // Allocated before: after lockdown no memory call goes through.
            let mut m = String::with_capacity(256);
            let Ok(f) = lockdown(&Guest { fds: tokens, mode }, |s| s.extend([0, 1, 2])) else {
                return 1;
            };
            let (checks, fds, paranoia) = unsharek_tcb::times_ns();
            use std::fmt::Write;
            let _ = writeln!(m, "{mode:?}, {} fds: paranoia {} us, threads and fds {} us ({} ns a fd), checks {} us", f.n, paranoia / 1000, fds / 1000, fds / f.n as u64, checks / 1000);
            g(libc::SYS_write, [f.get(2).unwrap() as usize, m.as_ptr() as usize, m.len()]);
            0
        }));
        assert_eq!(code, 0);
    }
}

// ------------------------------------------------------------------------------------------------
// Plugins: fs (Landlock-confined roots) and net.

/// A read-only root: a file in it opens (by absolute path, any dirfd >= n) and reads; one
/// outside it is EACCES (Landlock; a write open is no row: the next test). Read-write: a file made
/// and written under the root, and still EACCES outside it.
#[test]
fn fs_roots_are_confined() {
    let base = std::env::temp_dir().join(format!("unsharek-tcb-fs-{}", std::process::id()));
    let (root, out) = (base.join("root"), base.join("out"));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(root.join("in"), b"in").unwrap();
    std::fs::write(out.join("x"), b"x").unwrap();
    let c = |p: &std::path::Path| std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    let (inside, outside, new) = (c(&root.join("in")), c(&out.join("x")), c(&root.join("new")));
    let nb = (libc::O_NONBLOCK | libc::O_CLOEXEC) as usize;
    for access in [Fs::ReadOnly, Fs::ReadWrite] {
        let code = exit_code(in_child(|| {
            let Ok(f) = with_plugins(&Guest { fds: vec![], mode: Mode::Coroutine }, |_| (), &[&Files::new().root(&root, access)]) else {
                return 1;
            };
            let n = f.n as usize;
            let fd = g(libc::SYS_openat, [n, inside.as_ptr() as usize, nb]);
            let mut b = [0u8; 2];
            if fd < n as isize || g(libc::SYS_read, [fd as usize, b.as_mut_ptr() as usize, 2]) != 2 || &b != b"in" {
                return 2;
            }
            if g(libc::SYS_openat, [n, outside.as_ptr() as usize, nb]) != -(libc::EACCES as isize) {
                return 3;
            }
            if access == Fs::ReadWrite {
                // SAFETY: openat from the gate, with a mode.
                let w = unsafe { gate(libc::SYS_openat as usize, n, new.as_ptr() as usize, nb | (libc::O_CREAT | libc::O_WRONLY) as usize, 0o644, 0, 0) };
                if w < n as isize || g(libc::SYS_write, [w as usize, b.as_ptr() as usize, 2]) != 2 {
                    return 4;
                }
                // SAFETY: as above.
                let o = unsafe { gate(libc::SYS_openat as usize, n, outside.as_ptr() as usize, nb | libc::O_WRONLY as usize, 0, 0, 0) };
                if o != -(libc::EACCES as isize) {
                    return 5;
                }
                return 0;
            }
            0
        }));
        assert_eq!(code, 0, "{access:?}");
        if access == Fs::ReadWrite {
            assert_eq!(std::fs::read(root.join("new")).unwrap(), b"in");
        }
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// A read-only lockdown's write open: the filter kills it.
#[test]
fn fs_read_only_refuses_a_write_open() {
    let status = in_child(|| {
        let Ok(f) = with_plugins(&Guest { fds: vec![], mode: Mode::Coroutine }, |_| (), &[&Files::new().root("/", Fs::ReadOnly)]) else {
            return 1;
        };
        g(libc::SYS_openat, [f.n as usize, c"/tmp/x".as_ptr() as usize, (libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) as usize]);
        2
    });
    assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS, "status {status:#x}");
}

/// Net: a TCP listener and a connection to it on loopback, all through the gate, after lockdown.
#[test]
fn net_sockets_work() {
    let code = exit_code(in_child(|| {
        let Ok(_) = with_plugins(&Guest { fds: vec![], mode: Mode::Coroutine }, |_| (), &[&Net]) else {
            return 1;
        };
        let st = (libc::SOCK_STREAM | libc::SOCK_CLOEXEC) as usize;
        let l = g(libc::SYS_socket, [libc::AF_INET as usize, st, 0]);
        let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        a.sin_family = libc::AF_INET as u16;
        a.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
        let len = std::mem::size_of::<libc::sockaddr_in>();
        if l < 0 || g(libc::SYS_bind, [l as usize, &a as *const _ as usize, len]) != 0 || g(libc::SYS_listen, [l as usize, 1, 0]) != 0 {
            return 2;
        }
        let mut alen = len as u32;
        if g(libc::SYS_getsockname, [l as usize, &mut a as *mut _ as usize, &mut alen as *mut _ as usize]) != 0 {
            return 3;
        }
        let c = g(libc::SYS_socket, [libc::AF_INET as usize, st, 0]);
        if g(libc::SYS_connect, [c as usize, &a as *const _ as usize, len]) != 0 {
            return 4;
        }
        // SAFETY: accept4 from the gate.
        let s = unsafe { gate(libc::SYS_accept4 as usize, l as usize, 0, 0, libc::SOCK_CLOEXEC as usize, 0, 0) };
        let msg = *b"hi";
        // Data over write and read (no sendto, recvfrom).
        let sent = g(libc::SYS_write, [c as usize, msg.as_ptr() as usize, 2]);
        let mut b = [0u8; 2];
        let got = g(libc::SYS_read, [s as usize, b.as_mut_ptr() as usize, 2]);
        if s < 0 || sent != 2 || got != 2 || b != msg {
            return 5;
        }
        if g(libc::SYS_close, [s as usize, 0, 0]) != 0 {
            return 6;
        }
        0
    }));
    assert_eq!(code, 0);
}

/// The opt-out: with `no_landlock` the fs rows go in without a ruleset (a file outside the root
/// opens: the roots confine nothing).
#[test]
fn fs_without_landlock() {
    let code = exit_code(in_child(|| {
        let Ok(f) = with_plugins(&Guest { fds: vec![], mode: Mode::Coroutine }, |_| (), &[&Files::new().root("/nonexistent-root", Fs::ReadOnly).no_landlock(true)]) else {
            return 1;
        };
        let fd = g(libc::SYS_openat, [f.n as usize, c"/proc/version".as_ptr() as usize, (libc::O_NONBLOCK | libc::O_CLOEXEC) as usize]);
        if fd < f.n as isize { 2 } else { 0 }
    }));
    assert_eq!(code, 0);
}

/// Fork mode's shared anonymous memory inherited from the parent, which still maps it: the
/// paranoia check refuses it.
#[test]
fn paranoia_refuses_inherited_shared_memory() {
    // In a child of its own (the mapping, in the test process, would be every other test's
    // child's too): it maps, its child locks down.
    let code = exit_code(in_child(|| {
        let rw = libc::PROT_READ | libc::PROT_WRITE;
        // SAFETY: a fresh shared mapping, inherited by the child below.
        let p = unsafe { libc::mmap(std::ptr::null_mut(), 4096, rw, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1, 0) };
        assert_ne!(p, libc::MAP_FAILED);
        let st = in_child(|| match lockdown(&Guest { fds: vec![], mode: Mode::Fork }, |_| ()) {
            Err(Error::Paranoia(m)) if m.contains("ancestor") => 0,
            Ok(_) => 1,
            Err(_) => 2,
        });
        if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 3 }
    }));
    assert_eq!(code, 0);
}

/// The mode's own kinds: an eventfd only in threaded and fork mode, a pidfd only in fork mode
/// (declared so: a kind rule, not a count); a fd declared one that isn't is refused too.
#[test]
fn kinds_are_the_modes() {
    let run = |mode: Mode, kind: Kind, make: fn() -> RawFd| {
        exit_code(in_child(move || {
            let fd = make();
            let f = arrange(&[0, 1, 2, fd]);
            match unsharek_tcb::lockdown(Config::new(gate_ip()).mode(mode).grant([0, 1, 2]).grant_as(kind, [f.get(fd).unwrap()]), &[]) {
                Ok(_) => 0,
                Err(Error::ModeKind { .. }) => 1,
                Err(Error::FdKind { .. }) => 2,
                Err(_) => 3,
            }
        }))
    };
    assert_eq!(run(Mode::Coroutine, Kind::Eventfd, eventfd), 1, "coroutine: an eventfd");
    assert_eq!(run(Mode::Coroutine, Kind::Pidfd, pidfd), 1, "coroutine: a pidfd");
    assert_eq!(run(Mode::Threaded, Kind::Pidfd, pidfd), 1, "threaded: a pidfd");
    assert_eq!(run(Mode::Threaded, Kind::Eventfd, eventfd), 0, "threaded: an eventfd");
    assert_eq!(run(Mode::Fork, Kind::Pidfd, pidfd), 0, "fork: a pidfd");
    assert_eq!(run(Mode::Threaded, Kind::Eventfd, pidfd), 2, "threaded: a pidfd declared an eventfd");
    assert_eq!(run(Mode::Fork, Kind::Pidfd, eventfd), 2, "fork: an eventfd declared a pidfd");
}
