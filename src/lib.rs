//! unsharek-tcb: the lockdown of an in-process sandbox, and nothing else. The only code that
//! protects the host from the current process after lockdown (README.md: the guarantee, what
//! isn't guaranteed, the design and a review checklist).
//!
//! A process that runs an untrusted program in its own address space (unsharek: a Linux kernel as a
//! library, serving the program's syscalls from a SIGSYS handler) calls [`lockdown`] once, before
//! anything untrusted runs. From then on the process can reach on the host exactly what lockdown
//! left it: the fds granted (exactly `0..n`, each checked), its memory (every mapping checked), and
//! the syscalls one seccomp filter allows from one instruction, the guest's gate, each argument
//! pinned. Every other syscall traps (SIGSYS, served by the guest).
//!
//! ```no_run
//! use unsharek_tcb::{Config, Kind, Mode, lockdown};
//! # let gate = 0u64;
//! // The caller has put the kept fds at 0..n: stdio, then the guest's CPU tokens.
//! let c = Config::new(gate)              // the one instruction host calls may come from
//!     .mode(Mode::Threaded)
//!     .grant([0, 1, 2])                  // kept, read and write only
//!     .grant_as(Kind::Eventfd, 3..132);  // the guest's own: checked eventfds
//! lockdown(c, &[])?;                     // no plugins
//! // Locked down: run the program.
//! # Ok::<(), unsharek_tcb::Error>(())
//! ```
//!
//! Lockdown uses the config and nothing else: it calls no code of the caller's. Whatever the guest
//! must do first (making its fds, say) is the caller's, before it.
//!
//! **Templates.** A template process forks before lockdown, once per instance; each child makes
//! its own config (its own connection's fd, its own CPU tokens) and calls [`lockdown`].
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
//!   are the program's); lockdown checks it is open, of its declared kind, and of no kind that
//!   can't be meant (another process's memory, io_uring, userfaultfd, …: [`Kind::Any`]).
//!
//! **Paranoia** ([`Config::paranoia`], on by default; paranoia.rs) is a best-effort check of
//! those it can't check exactly, before the rest: it reads every process's `/proc` entries it
//! may, so it costs time in proportion to the host's processes.
//!
//! **Disclosure.** Lockdown leaves the address space as it is: everything in memory at lockdown
//! (the caller's heap, its stack, its static data) is readable by the program. Hold no secret in
//! memory when locking down.

use std::fmt;
use std::os::fd::RawFd;

mod filter;
mod lockdown;
mod paranoia;
pub mod plugin;

pub use filter::{AUDIT_ARCH_X86_64, CLONE_THREAD_FLAGS, PPOLL_FDS, X32_SYSCALL_BIT, filter, policy};
pub use libc::{SECCOMP_RET_ALLOW as RET_ALLOW, SECCOMP_RET_KILL_PROCESS as RET_KILL_PROCESS, SECCOMP_RET_TRAP as RET_TRAP};
pub use libc::{seccomp_data, sock_filter};
pub use plugin::Plugin;
#[cfg(feature = "testing")]
pub use lockdown::times_ns;
#[cfg(feature = "testing")]
/// `/proc/self/maps` line `line`'s verdict in `mode` (`shm` the shmem device): for the tests.
pub fn map_ok(line: &str, mode: Mode, shm: &str) -> bool {
    lockdown::map_ok(line, mode, shm)
}

/// How the guest runs the program's threads and processes. Each mode's allowlist is a superset of
/// the one before.
// (not `kani::Arbitrary`: the proof lists its values, `prove!(…, Mode = [coroutine: …])`)
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

/// A kept fd's declared kind ([`Config::grant_as`]): lockdown checks the fd is one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// Any kind but those no caller means to give (another process's memory, io_uring,
    /// userfaultfd, a writable /proc or /sys file, …): a plain grant ([`Config::grant`]).
    Any,
    /// An eventfd: the guest's CPU token, in threaded and fork mode only.
    Eventfd,
    /// A pidfd: init's, which each forked process polls to end with it, in fork mode only.
    Pidfd,
}

/// Everything lockdown checks and enforces, and nothing else: [`lockdown`]'s only input. Built with
/// [`Config::new`] and the methods below; each says what lockdown does with it.
#[derive(Clone, Debug)]
pub struct Config {
    /// Which allowlist the filter has ([`Config::mode`]).
    pub mode: Mode,
    /// The fds kept open past lockdown, read and write, each with its declared kind
    /// ([`Config::grant`], [`Config::grant_as`]).
    pub fds: Vec<(RawFd, Kind)>,
    /// The address just past the gate's `syscall` ([`Config::new`]).
    pub gate: u64,
    /// The best-effort check of lockdown's assumptions ([`Config::paranoia`]). On by default.
    pub paranoia: bool,
}

impl Config {
    /// Nothing granted, coroutine mode. `gate` is the address just past the gate's `syscall`
    /// instruction: the one place host calls are allowed from. It needn't be trusted: the gate
    /// check's verdicts are TRAP and KILL only.
    pub fn new(gate: u64) -> Self {
        Config { mode: Mode::default(), fds: vec![], gate, paranoia: true }
    }

    /// The filter's allowlist: each mode's is a superset of the one before.
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Keep `fds` open past lockdown ([`Kind::Any`]); every other fd is closed. Fds 0-2 are
    /// granted like any other (none is by default). The kept fds must be exactly `0..n`,
    /// contiguous: putting them there is the caller's (its `dup2`s, untrusted; lockdown
    /// renumbers nothing and refuses a gap), and lockdown checks each is open and of no kind
    /// refused. What may be done on one is `read` and `write`, as its own mode allows (an
    /// `O_RDONLY` file can't be written; a pipe end is one-way), and nothing else (no `ioctl`, no
    /// `sendmsg`, no `close`). A two-way fd the program should only write (a terminal as stdout)
    /// is the caller's to reopen one-way first.
    pub fn grant(self, fds: impl IntoIterator<Item = RawFd>) -> Self {
        self.grant_as(Kind::Any, fds)
    }

    /// [`Config::grant`], each fd declared `kind`, which lockdown checks: the guest's CPU tokens
    /// ([`Kind::Eventfd`], threaded and fork mode only) and init's pidfd ([`Kind::Pidfd`], fork
    /// mode only).
    pub fn grant_as(mut self, kind: Kind, fds: impl IntoIterator<Item = RawFd>) -> Self {
        self.fds.extend(fds.into_iter().map(|fd| (fd, kind)));
        self
    }

    /// Whether lockdown first checks its assumptions, best-effort (the crate's "Assumptions":
    /// another process sharing the memory, a tracer, shared memory an ancestor maps). On by
    /// default; off saves its time, not a guarantee.
    pub fn paranoia(mut self, on: bool) -> Self {
        self.paranoia = on;
        self
    }
}

/// Why lockdown refused. Nothing untrusted has run; the process is as it was but for what the
/// failed step had done (fds closed, the dump flag cleared, capabilities dropped).
#[derive(Debug)]
pub enum Error {
    /// Other host threads exist (their tids): they would run code nobody checked, under the filter.
    Threads(Vec<i32>),
    /// A granted fd isn't open.
    NotOpen(RawFd),
    /// The kept fds aren't `0..n`: `gap` is below their count `n` and not one of them.
    Gap { gap: RawFd, n: RawFd },
    /// A kept fd not of its declared kind, or of a kind refused (its `/proc/self/fd` link).
    FdKind { fd: RawFd, kind: Kind, link: String },
    /// A kept fd declared a kind its mode doesn't keep ([`Config::grant_as`]).
    ModeKind { fd: RawFd, kind: Kind, mode: Mode },
    /// A mapping lockdown refuses (its `/proc/self/maps` line): writable and shared with something
    /// outside the sandbox.
    Mapping(String),
    /// The paranoia check ([`Config::paranoia`]) found an assumption broken.
    Paranoia(String),
    /// Landlock (for [`plugin::Files`]): unavailable, or a root it couldn't take.
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
            Error::Threads(tids) => write!(
                f,
                "{} other host thread(s) at lockdown (tids {tids:?}): only the calling thread may exist, \
                 the others would run unchecked code in the sandbox",
                tids.len()
            ),
            Error::NotOpen(fd) => write!(f, "granted fd {fd} is not open"),
            Error::Gap { gap, n } => write!(f, "the kept fds aren't 0..{n}: {gap} isn't one (the caller puts them there, contiguous)"),
            Error::FdKind { fd, kind, link } => write!(f, "kept fd {fd} is {link:?}: not {kind:?}, or a kind refused"),
            Error::ModeKind { fd, kind, mode } => write!(f, "kept fd {fd} is declared {kind:?}, which {mode:?} mode doesn't keep"),
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

/// Lock the process down with `config`, and nothing else. In this order:
///
/// 0. with [`Config::paranoia`], its assumptions checked, best-effort (the crate's
///    "Assumptions");
/// 1. exactly one thread, the caller's (`/proc/self/task`, read through one fd of `/proc/self`,
///    checked to be procfs; a thread just joined gets a few ms to vanish). Every check after
///    this one can't be raced;
/// 2. the kept fds exactly `0..n` (a gap refused, and a kind its mode doesn't keep, before
///    anything: renumbering is the caller's); each open, of its declared kind, and of no kind
///    refused ([`Kind::Any`]);
/// 3. every mapping kind-checked (`/proc/self/maps`): private, or shared and read-only, or (in
///    fork mode) shared anonymous memory (the kernel's shmem); above all no writable shared
///    mapping of a host file;
/// 4. every fd at or above `n` closed (not refused: a CLI inherits stray fds);
/// 5. no core dump (`RLIMIT_CORE` 0) and not dumpable (`PR_SET_DUMPABLE` 0): a crash makes the
///    host write none of the process's memory, nor start `core_pattern`'s helper;
/// 6. every capability dropped (bounding where permitted, ambient, effective, permitted,
///    inheritable);
/// 7. `no_new_privs`, then each plugin's [`Plugin::setup`] (the file plugin's Landlock ruleset of
///    its roots);
/// 8. the filter ([`filter`]: the core's rows, then the plugins', its floor `n`), with TSYNC
///    (redundant after step 1, kept).
///
/// `plugins` (experimental) widen the sandbox, each only when passed ([`plugin`]): their
/// [`Plugin::check`]s run first, before anything changes; their kept fds are kept as grants are.
///
/// A caller that wants more restrictions installs its own seccomp filter before this: filters
/// stack, the strictest answer wins (it must let lockdown's own calls through).
///
/// On success the process is locked down; the caller hands over to the program. On failure nothing untrusted has run (the fds at or above `n` may be closed already:
/// the caller reports the error and ends).
pub fn lockdown(config: Config, plugins: &[&dyn Plugin]) -> Result<()> {
    lockdown::lockdown(config, plugins)
}
