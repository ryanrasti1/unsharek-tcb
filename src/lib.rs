//! unsharek-tcb: the lockdown of an in-process sandbox, and nothing else. The only code that
//! protects the host from the current process after lockdown (README.md: the guarantee, what
//! isn't guaranteed, the design and a review checklist).
//!
//! A process that runs an untrusted program in its own address space (unsharek: a Linux kernel as a
//! library, serving the program's syscalls from a SIGSYS handler) calls [`lockdown`] once, before
//! anything untrusted runs. From then on the process can reach on the host exactly what lockdown
//! left it: the fds granted (and the guest's own, checked), its memory (every mapping checked), and
//! the syscalls one seccomp filter allows from one instruction, the guest's gate, each argument
//! pinned. Every other syscall traps (SIGSYS, served by the guest).
//!
//! ```no_run
//! use unsharek_tcb::{Config, Mode, lockdown};
//! # let (gate, token_fd) = (0u64, 3);
//! let c = Config::new()
//!     .mode(Mode::Threaded)
//!     .grant([0, 1, 2])      // kept, read and write only
//!     .guest_fds([token_fd]) // the guest's own: kind-checked
//!     .gate(gate);           // the one instruction host calls may come from
//! let fds = lockdown(c)?;    // the kept fds, renumbered 0..n
//! let token_fd = fds.get(token_fd).unwrap();
//! // Locked down: run the program.
//! # Ok::<(), unsharek_tcb::Error>(())
//! ```
//!
//! Lockdown uses the config and nothing else: it calls no code of the caller's. Whatever the guest
//! must do first (making its fds, say) is the caller's, before it.
//!
//! **Templates.** A template process forks before lockdown, once per instance; each child makes
//! its own config (its own connection's fd, its own guest fds) and calls [`lockdown`].
//!
//! **Not here.** Process limits (`RLIMIT_NPROC`, cgroups) are the caller's to set, before
//! lockdown or from outside: the runtime's own limits (unsharek's `max_procs`) run in the program's
//! address space and a compromised program can bypass them.
//!
//! **Assumptions.** Lockdown checks what it can of the process it leaves behind; these it takes
//! as given, from the caller (code before lockdown is trusted):
//! - **one thread**, the caller's, at lockdown (checked: `/proc/self/task`), and no other process
//!   sharing the address space (a `CLONE_VM` child that isn't a thread, or a `vfork` parent:
//!   seccomp's TSYNC doesn't reach it; the paranoia check looks, below);
//! - **mappings persist** as checked: no allowed call makes, changes or removes one, and nothing
//!   outside changes them (no tracer: the paranoia check looks; after lockdown the process isn't
//!   dumpable, so the host's same user can't attach);
//! - **no shared anonymous memory from elsewhere**: fork mode's `MAP_SHARED | MAP_ANONYMOUS`
//!   memory is the sandbox's own, not inherited from a host process (the paranoia check looks
//!   for an ancestor mapping the same memory);
//! - **no unknown fds**: each granted fd is what the caller means to give (read and write on it
//!   are the program's); lockdown checks only that it is open (the paranoia check refuses some
//!   kinds that can't be meant: another process's memory, io_uring, userfaultfd, …).
//!
//! **Paranoia** ([`Config::paranoia`], on by default) is a best-effort check of those
//! assumptions, before the rest: it reads every process's `/proc` entries it may, so it costs
//! time in proportion to the host's processes ([`paranoia_ns`]).
//!
//! **Disclosure.** Lockdown leaves the address space as it is: everything in memory at lockdown
//! (the caller's heap, its stack, its static data) is readable by the program. Hold no secret in
//! memory when locking down.

use std::fmt;
use std::os::fd::RawFd;

mod filter;
mod lockdown;

pub use filter::{
    AUDIT_ARCH_X86_64, CLONE_THREAD_FLAGS, PPOLL_FDS, PPOLL_NET_FDS, SECCOMP_RET_ALLOW as RET_ALLOW, SECCOMP_RET_KILL_PROCESS as RET_KILL_PROCESS,
    SECCOMP_RET_TRAP as RET_TRAP, X32_SYSCALL_BIT, filter, policy,
};
pub use libc::{seccomp_data, sock_filter};
#[doc(hidden)]
pub use lockdown::{check_ns, map_ok, paranoia_ns};

/// How the guest runs the program's threads and processes. Each mode's allowlist is a superset of
/// the one before.
// (not `kani::Arbitrary`: the proof lists its values, `policy!(…, Mode = [coroutine: …])`)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// One host thread.
    #[default]
    Coroutine,
    /// A host thread per program thread, made through the filter by one exact `clone`.
    Threaded,
    /// Threaded, and a guest `fork` is a host fork. The guest's processes share memory
    /// (`MAP_SHARED | MAP_ANONYMOUS`, made before lockdown), which lockdown accepts in this mode
    /// only.
    Fork,
}

/// A file plugin's access ([`Config::fs_root`]): which rows the filter has, and which rights
/// Landlock gives a root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fs {
    /// No file plugin: no row opens a file.
    #[default]
    Off,
    /// Reading files and directories under the roots: no call that changes one.
    ReadOnly,
    /// Reading, writing, making and removing them.
    ReadWrite,
}

/// The guest's CPU-token eventfds in threaded and fork mode: one per host-thread slot (128 for
/// the program's threads, one for the kernel's).
pub const TOKEN_FDS: usize = 129;

/// The process locked down ([`lockdown`] succeeded).
static LOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether [`lockdown`] has succeeded in this process.
pub fn locked_down() -> bool {
    LOCKED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Everything lockdown checks and enforces, and nothing else: [`lockdown`]'s only input. Built with
/// [`Config::new`] and the methods below; each says what lockdown does with it.
#[derive(Clone, Debug)]
pub struct Config {
    /// Which allowlist the filter has ([`Config::mode`]).
    pub mode: Mode,
    /// The fds kept open past lockdown, read and write ([`Config::grant`]).
    pub fds: Vec<RawFd>,
    /// The guest's own host fds, kept, kind-checked ([`Config::guest_fds`]).
    pub guest_fds: Vec<RawFd>,
    /// The address just past the gate's `syscall` ([`Config::gate`]). Required.
    pub gate: Option<u64>,
    /// The most pollfds one `ppoll` may pass: at least what the guest waits on at once.
    pub ppoll_max: u64,
    /// Plugin: fs. The roots the program may reach by path, each with its access
    /// ([`Config::fs_root`]).
    pub fs_roots: Vec<(std::path::PathBuf, Fs)>,
    /// Plugin: fs. Install the fs rows without Landlock ([`Config::no_landlock`]): only where the
    /// process's file access is already scoped by something else (a container's own
    /// filesystem), since then the rows reach every file the process can.
    pub no_landlock: bool,
    /// Plugin: net. IPv4 and IPv6 TCP and UDP sockets ([`Config::net`]).
    pub net: bool,
    /// The best-effort check of lockdown's assumptions ([`Config::paranoia`]). On by default.
    pub paranoia: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { mode: Mode::default(), fds: vec![], guest_fds: vec![], gate: None, ppoll_max: PPOLL_FDS, fs_roots: vec![], no_landlock: false, net: false, paranoia: true }
    }
}

impl Config {
    /// Nothing granted, coroutine mode, no gate yet.
    pub fn new() -> Self {
        Config::default()
    }

    /// The filter's allowlist: each mode's is a superset of the one before.
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Keep `fds` open past lockdown; every other fd is closed. Fds 0-2 are granted like any other
    /// (none is by default). Lockdown checks each is open, and renumbers the kept fds `0..n`
    /// ([`Fds`]: a kept fd already below `n`, as 0-2 when granted, keeps its number). What may be done on one is `read` and
    /// `write`, as its own mode allows (an `O_RDONLY` file can't be written; a pipe end is one-way),
    /// and nothing else (no `ioctl`, no `sendmsg`, no `close`). A two-way fd the program should only
    /// write (a terminal as stdout) is the caller's to reopen one-way first.
    pub fn grant(mut self, fds: impl IntoIterator<Item = RawFd>) -> Self {
        self.fds.extend(fds);
        self
    }

    /// The guest's own host fds, kept past lockdown, read and write: exactly the mode's. None in
    /// coroutine mode; [`TOKEN_FDS`] eventfds (`anon_inode:[eventfd]`, the CPU tokens: one per
    /// host-thread slot) in threaded and fork mode; and in fork mode init's pidfd
    /// (`anon_inode:[pidfd]`). Lockdown refuses any other kind, or count.
    pub fn guest_fds(mut self, fds: impl IntoIterator<Item = RawFd>) -> Self {
        self.guest_fds.extend(fds);
        self
    }

    /// The address just past the gate's `syscall` instruction: the one place host calls are allowed
    /// from. Needn't be trusted: the gate check's verdicts are TRAP and KILL only. Required: without
    /// it every call would trap, the process's own exit too.
    pub fn gate(mut self, ip: u64) -> Self {
        self.gate = Some(ip);
        self
    }

    /// Plugin: fs. The program may reach `root` and what is under it, by path, with `access`
    /// (not [`Fs::Off`]): the filter gets the fs rows (read-only ones if every root is
    /// read-only), and lockdown applies a Landlock ruleset, just before the filter, that allows
    /// exactly the roots (read-only: reading files and directories; read-write: also writing,
    /// truncating, making and removing files, directories and symlinks, and renaming between
    /// roots; never a device, FIFO or socket node made, and no device ioctl where the kernel's
    /// Landlock has the right). Lockdown refuses if the kernel has no Landlock, or not the
    /// rights the access needs ([`Config::no_landlock`]).
    pub fn fs_root(mut self, root: impl Into<std::path::PathBuf>, access: Fs) -> Self {
        if access != Fs::Off {
            self.fs_roots.push((root.into(), access));
        }
        self
    }

    /// Plugin: fs. The opt-out of Landlock: the fs rows go in without a ruleset, and the roots
    /// confine nothing. Only for a process whose file access is already scoped (a container's
    /// own filesystem); without it lockdown refuses the fs rows on a kernel without Landlock
    /// (or where a seccomp profile hides it: ENOSYS, EPERM), or whose Landlock lacks a right
    /// the access needs (read-write: `REFER`, ABI 2, and `TRUNCATE`, ABI 3).
    pub fn no_landlock(mut self, on: bool) -> Self {
        self.no_landlock = on;
        self
    }

    /// The file plugin's rows: the widest access of the roots.
    pub fn fs(&self) -> Fs {
        self.fs_roots.iter().map(|r| r.1).max().unwrap_or(Fs::Off)
    }

    /// Plugin: net. The filter gets the socket rows: IPv4 and IPv6 TCP and UDP, to any address
    /// (the network namespace the caller runs the process in is what confines it), and `ppoll`
    /// on up to [`PPOLL_NET_FDS`] fds.
    pub fn net(mut self, on: bool) -> Self {
        self.net = on;
        self
    }

    /// Whether lockdown first checks its assumptions, best-effort (the crate's "Assumptions":
    /// another process sharing the memory, a tracer, shared memory another process maps, a
    /// grant of a kind that can't be meant). On by default; off saves its time
    /// ([`paranoia_ns`]), not a guarantee.
    pub fn paranoia(mut self, on: bool) -> Self {
        self.paranoia = on;
        self
    }

    /// `f(self)`: a step of the caller's in the chain (`.pipe(|c| guest.configure_sandbox(c))?`).
    pub fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

/// Why lockdown refused. Nothing untrusted has run; the process is as it was but for what the
/// failed step had done (fds closed, the dump flag cleared, capabilities dropped).
#[derive(Debug)]
pub enum Error {
    /// The config has no gate ([`Config::gate`]).
    NoGate,
    /// Other host threads exist (their tids): they would run code nobody checked, under the filter.
    Threads(Vec<i32>),
    /// A granted fd isn't open.
    NotOpen(RawFd),
    /// A guest fd of a kind it can't be (its `/proc/self/fd` link).
    FdKind { fd: RawFd, kind: String },
    /// The guest's fds aren't the mode's: their eventfds and pidfds counted ([`Config::guest_fds`]).
    GuestFds { mode: Mode, eventfds: usize, pidfds: usize },
    /// A mapping lockdown refuses (its `/proc/self/maps` line): writable and shared with something
    /// outside the sandbox.
    Mapping(String),
    /// The paranoia check ([`Config::paranoia`]) found an assumption broken.
    Paranoia(String),
    /// Landlock (for [`Config::fs_root`]): unavailable, or a root it couldn't take.
    Landlock(String),
    /// A capability lockdown couldn't drop.
    Capabilities(String),
    /// The filter is longer than the kernel takes.
    Filter(String),
    /// A syscall of lockdown's failed.
    Os { what: &'static str, source: std::io::Error },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoGate => write!(f, "no gate: lockdown needs the address host calls may come from"),
            Error::Threads(tids) => write!(
                f,
                "{} other host thread(s) at lockdown (tids {tids:?}): only the calling thread may exist, \
                 the others would run unchecked code in the sandbox",
                tids.len()
            ),
            Error::NotOpen(fd) => write!(f, "granted fd {fd} is not open"),
            Error::FdKind { fd, kind } => {
                write!(f, "the guest's fd {fd} is {kind:?}, not an eventfd or a pidfd")
            }
            Error::GuestFds { mode, eventfds, pidfds } => write!(
                f,
                "the guest's fds in {mode:?} mode: {eventfds} eventfds and {pidfds} pidfds, not the mode's (coroutine none; \
                 threaded {TOKEN_FDS} eventfds; fork {TOKEN_FDS} eventfds and one pidfd)"
            ),
            Error::Mapping(line) => write!(f, "a mapping shared with the host, writable: {line}"),
            Error::Paranoia(what) => write!(f, "paranoia: {what}"),
            Error::Landlock(what) => write!(f, "landlock: {what}"),
            Error::Capabilities(what) => write!(f, "capabilities: {what}"),
            Error::Filter(e) => write!(f, "the filter: {e}"),
            Error::Os { what, source } => write!(f, "{what}: {source}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The kept fds after lockdown: the grants and the guest's own, renumbered `0..n` in place. A
/// kept fd below `n` keeps its number (0-2, when granted); each one at or above it moves to a
/// free number below (lowest first, in order of the old numbers), close-on-exec as it was. So
/// the filter's `fd < n` is exactly the kept fds, whatever numbers they had (no placeholder
/// fills a gap, and a huge fd costs nothing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fds {
    /// The floor: the number of kept fds.
    pub n: RawFd,
    /// (old, new) for every kept fd, sorted by the old number.
    pub map: Vec<(RawFd, RawFd)>,
}

impl Fds {
    /// The new number of kept fd `old`; `None` if it wasn't kept.
    pub fn get(&self, old: RawFd) -> Option<RawFd> {
        self.map.binary_search_by_key(&old, |&(o, _)| o).ok().map(|i| self.map[i].1)
    }
}

/// Lock the process down with `config`, and nothing else. In this order:
///
/// 0. with [`Config::paranoia`], its assumptions checked (the crate's "Assumptions");
/// 1. exactly one thread, the caller's (`/proc/self/task`, read through one fd of `/proc/self`,
///    checked to be procfs; a thread just joined gets a few ms to vanish). Every check after
///    this one can't be raced;
/// 2. the guest's own fds ([`Config::guest_fds`]) kind-checked: eventfds, and pidfds in fork
///    mode only; every granted fd open;
/// 3. every mapping kind-checked (`/proc/self/maps`): private, or shared and read-only, or (in
///    fork mode) shared anonymous memory (the kernel's shmem); above all no writable shared
///    mapping of a host file;
/// 4. every fd neither granted nor the guest's closed (not refused: a CLI inherits stray fds),
///    and the kept ones renumbered `0..n` ([`Fds`]);
/// 5. no core dump (`RLIMIT_CORE` 0) and not dumpable (`PR_SET_DUMPABLE` 0): a crash makes the
///    host write none of the process's memory, nor start `core_pattern`'s helper;
/// 6. every capability dropped (bounding where permitted, ambient, effective, permitted,
///    inheritable);
/// 7. `no_new_privs`, and with [`Config::fs_root`] the Landlock ruleset of the roots;
/// 8. the filter ([`filter`], its floor `n`), with TSYNC (redundant after step 1, kept).
///
/// A caller that wants more restrictions installs its own seccomp filter before this: filters
/// stack, the strictest answer wins (it must let lockdown's own calls through).
///
/// On success the process is locked down ([`locked_down`]); the caller uses the kept fds' new
/// numbers ([`Fds::get`]) and hands over to the program. On failure nothing untrusted has run
/// (the fds may have been renumbered already: the caller reports the error and ends).
pub fn lockdown(config: Config) -> Result<Fds> {
    let fds = lockdown::lockdown(config)?;
    LOCKED.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(fds)
}
