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
//! lockdown(c)?;
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
//! **Disclosure.** Lockdown leaves the address space as it is: everything in memory at lockdown
//! (the caller's heap, its stack, its static data) is readable by the program. Hold no secret in
//! memory when locking down.

use std::fmt;
use std::os::fd::RawFd;

mod filter;
mod lockdown;

pub use filter::{
    AUDIT_ARCH_X86_64, CLONE_THREAD_FLAGS, PPOLL_FDS, SECCOMP_RET_ALLOW as RET_ALLOW, SECCOMP_RET_KILL_PROCESS as RET_KILL_PROCESS,
    SECCOMP_RET_TRAP as RET_TRAP, X32_SYSCALL_BIT, filter, policy,
};
pub use libc::{seccomp_data, sock_filter};
#[doc(hidden)]
pub use lockdown::{check_ns, map_ok};

/// How the guest runs the program's threads and processes. Each mode's allowlist is a superset of
/// the one before.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
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
    /// Plugin: capnweb (experimental). The control socket ([`Config::recv_fds`]).
    pub recv_fds: Option<RawFd>,
}

impl Default for Config {
    fn default() -> Self {
        Config { mode: Mode::default(), fds: vec![], guest_fds: vec![], gate: None, ppoll_max: PPOLL_FDS, recv_fds: None }
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
    /// (none is by default). Lockdown checks each is open. What may be done on one is `read` and
    /// `write`, as its own mode allows (an `O_RDONLY` file can't be written; a pipe end is one-way),
    /// and nothing else (no `ioctl`, no `sendmsg`, no `close`). A two-way fd the program should only
    /// write (a terminal as stdout) is the caller's to reopen one-way first.
    pub fn grant(mut self, fds: impl IntoIterator<Item = RawFd>) -> Self {
        self.fds.extend(fds);
        self
    }

    /// The guest's own host fds, kept past lockdown, read and write: its CPU tokens' eventfds
    /// (`anon_inode:[eventfd]`) and, in fork mode, init's pidfd (`anon_inode:[pidfd]`). Lockdown
    /// refuses any other kind (a pidfd in another mode too).
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

    /// Plugin: capnweb (experimental). A control socket, kept like a grant, on which the process
    /// may `recvmsg` (`MSG_CMSG_CLOEXEC`) the fds the provider's process sends, and `close` those
    /// fds: lockdown checks it is a unix `SOCK_SEQPACKET` socket.
    pub fn recv_fds(mut self, ctl: RawFd) -> Self {
        self.recv_fds = Some(ctl);
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
    /// A mapping lockdown refuses (its `/proc/self/maps` line): writable and shared with something
    /// outside the sandbox.
    Mapping(String),
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
            Error::Mapping(line) => write!(f, "a mapping shared with the host, writable: {line}"),
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
/// 1. exactly one thread, the caller's (`/proc/self/task`; a thread just joined gets a few ms
///    to vanish). Every check after this one can't be raced;
/// 2. the guest's own fds ([`Config::guest_fds`]) kind-checked: eventfds, and pidfds in fork
///    mode only; every granted fd open;
/// 3. every mapping kind-checked (`/proc/self/maps`): private, or shared and read-only, or (in
///    fork mode) shared anonymous memory; above all no writable shared mapping of a host file;
/// 4. every fd neither granted nor the guest's closed (not refused: a CLI inherits stray fds);
/// 5. no core dump (`RLIMIT_CORE` 0) and not dumpable (`PR_SET_DUMPABLE` 0): a crash makes the
///    host write none of the process's memory, nor start `core_pattern`'s helper;
/// 6. every capability dropped (bounding where permitted, ambient, effective, permitted,
///    inheritable);
/// 7. `no_new_privs`;
/// 8. the filter ([`filter`]), with TSYNC (redundant after step 1, kept).
///
/// A caller that wants more restrictions installs its own seccomp filter before this: filters
/// stack, the strictest answer wins (it must let lockdown's own calls through).
///
/// On success the process is locked down ([`locked_down`]) and the caller hands over to the
/// program. On failure nothing untrusted has run.
pub fn lockdown(config: Config) -> Result<()> {
    lockdown::lockdown(config)?;
    LOCKED.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}
