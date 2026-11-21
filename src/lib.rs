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
//! use unsharek_tcb::{Config, Confined, Mode};
//! # struct Guest;
//! # impl Confined for Guest {
//! #     fn host_fds(&self) -> Vec<std::os::fd::RawFd> { vec![] }
//! #     fn gate_ip(&self) -> u64 { 0 }
//! #     fn mode(&self) -> Mode { Mode::Coroutine }
//! # }
//! # static GUEST: Guest = Guest;
//! unsharek_tcb::register(&GUEST); // the guest, once (unsharek's Guest::boot does it)
//! let mut c = Config::default();
//! c.grant(0).grant(1).grant(2);
//! unsharek_tcb::lockdown(c)?;
//! // Locked down: run the program.
//! # Ok::<(), unsharek_tcb::Error>(())
//! ```
//!
//! **Templates.** A template process forks before lockdown, once per instance; each child makes
//! its own grants (its own connection's fd, say) and calls [`lockdown`]. The child is a copy of
//! the template, the guest's fds included: a guest whose fds must be its own per instance
//! (unsharek's CPU tokens) makes them in [`Confined::before_lockdown`], in the child.
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

/// The guest whose program runs after lockdown: what lockdown asks of it ([`register`]). Nothing it
/// says is trusted to widen the filter: its fds are checked for kind, the gate's address only sends
/// other calls back as TRAP, and its grants are read and write only, as the caller's are.
pub trait Confined {
    /// The guest's own host fds, kept past lockdown, read and write: its CPU tokens' eventfds
    /// (`anon_inode:[eventfd]`) and, in fork mode, init's pidfd (`anon_inode:[pidfd]`). Lockdown
    /// refuses any other kind (a pidfd in another mode too). Asked after
    /// [`Confined::before_lockdown`].
    fn host_fds(&self) -> Vec<RawFd>;
    /// The address just past the gate's `syscall` instruction: the one place host calls are
    /// allowed from. Needn't be trusted: the gate check's verdicts are TRAP and KILL only.
    fn gate_ip(&self) -> u64;
    /// The guest's mode: the filter's allowlist ([`Config::mode`] is used without a guest).
    fn mode(&self) -> Mode;
    /// Fds the guest itself needs kept (unsharek's passed and held fds): granted as
    /// [`Config::grant`] grants, read and write, nothing more.
    fn grants(&self) -> Vec<RawFd> {
        vec![]
    }
    /// The guest's own preparation, which [`lockdown`] runs first (making its host fds, say). Code
    /// before lockdown, and the guest's, not this crate's: like everything before lockdown it runs
    /// with the host's authority, and lockdown checks only what it leaves behind.
    fn before_lockdown(&self) -> Result<()> {
        Ok(())
    }
}

thread_local! {
    /// The registered guest ([`register`]): one per process, on the thread that locks down.
    static GUEST: std::cell::Cell<Option<&'static dyn Confined>> = const { std::cell::Cell::new(None) };
}

/// The process locked down ([`lockdown`] succeeded).
static LOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Register the guest that [`lockdown`] confines, on the thread that will call it (unsharek's
/// `Guest::boot` does). Replaces an earlier one.
pub fn register(guest: &'static dyn Confined) {
    GUEST.with(|g| g.set(Some(guest)));
}

/// Whether [`lockdown`] has succeeded in this process.
pub fn locked_down() -> bool {
    LOCKED.load(std::sync::atomic::Ordering::SeqCst)
}

/// No guest registered: no fds of its own, no gate (every call traps), the config's mode.
struct NoGuest(Mode);

impl Confined for NoGuest {
    fn host_fds(&self) -> Vec<RawFd> {
        vec![]
    }
    fn gate_ip(&self) -> u64 {
        0
    }
    fn mode(&self) -> Mode {
        self.0
    }
}

/// The sandbox: everything the filter is made from ([`filter`]), and the grants: [`lockdown`]'s
/// argument.
#[derive(Clone, Debug)]
pub struct Config {
    /// Which allowlist, without a registered guest (with one: [`Confined::mode`]).
    pub mode: Mode,
    /// The fds kept open past lockdown; every other one is closed. Fds 0-2 are granted like any
    /// other (none is by default). What may be done on one is `read` and `write`, as its own mode
    /// allows (an `O_RDONLY` file can't be written; a pipe end is one-way), and nothing else (no
    /// `ioctl`, no `sendmsg`, no `close`). A two-way fd the program should only write (a terminal
    /// as stdout) is the caller's to reopen one-way first.
    pub fds: Vec<RawFd>,
    /// The most pollfds one `ppoll` may pass: at least what the guest waits on at once.
    pub ppoll_max: u64,
    /// Plugin: capnweb (experimental). A control socket, kept like a grant, on which the process
    /// may `recvmsg` (`MSG_CMSG_CLOEXEC`) the fds the provider's process sends: lockdown checks it
    /// is a unix `SOCK_SEQPACKET` socket. None: no `recvmsg`.
    pub recv_fds: Option<RawFd>,
}

impl Default for Config {
    fn default() -> Self {
        Config { mode: Mode::default(), fds: vec![], ppoll_max: PPOLL_FDS, recv_fds: None }
    }
}

impl Config {
    /// Keep host fd `fd` open past lockdown ([`Config::fds`]).
    pub fn grant(&mut self, fd: RawFd) -> &mut Self {
        self.fds.push(fd);
        self
    }
}

/// Why lockdown refused. Nothing untrusted has run; the process is as it was but for what the
/// failed step had done (fds closed, the dump flag cleared, capabilities dropped).
#[derive(Debug)]
pub enum Error {
    /// The guest's own preparation failed ([`Confined::before_lockdown`]).
    Guest(Box<dyn std::error::Error + Send + Sync>),
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
            Error::Guest(e) => write!(f, "{e}"),
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

impl Error {
    /// The guest's error, boxed: `Err(Error::guest(e))`, or `?` on an `io::Error`.
    pub fn guest(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Error {
        Error::Guest(e.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Guest(Box::new(e))
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Lock the process down with `config` (the caller's grants: [`Config::grant`]). The registered
/// guest's ([`register`]) preparation runs first ([`Confined::before_lockdown`]); its grants are
/// added and its mode is the filter's. Then, in this order:
///
/// 1. exactly one thread, the caller's (`/proc/self/task`; a thread just joined gets a few ms
///    to vanish). Every check after this one can't be raced;
/// 2. the guest's own fds ([`Confined::host_fds`]) kind-checked: eventfds, and pidfds in fork
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
pub fn lockdown(mut config: Config) -> Result<()> {
    let none = NoGuest(config.mode);
    let guest: &dyn Confined = GUEST.with(|g| g.get()).unwrap_or(&none);
    guest.before_lockdown()?;
    config.mode = guest.mode();
    config.fds.extend(guest.grants());
    lockdown::lockdown(config, guest)?;
    LOCKED.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}
