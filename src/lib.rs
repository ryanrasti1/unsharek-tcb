//! exobox-tcb: the lockdown of an in-process sandbox, and nothing else. The only code that
//! protects the host from the program (`TCB.md`: the model, what is in it and what isn't, and a
//! review checklist).
//!
//! A process that runs an untrusted program in its own address space (exobox: a Linux kernel as a
//! library, serving the program's syscalls from a SIGSYS handler) calls
//! [`Sandbox::configure_and_lockdown`] once, before anything untrusted runs. From then on the
//! process can reach on the host exactly what lockdown left it: the fds granted (and the guest's
//! own, checked), its memory (every mapping checked), and the syscalls one seccomp filter allows
//! from one instruction, the guest's gate, each argument pinned. Every other syscall traps
//! (SIGSYS, served by the guest).
//!
//! ```no_run
//! use exobox_tcb::{Access, Confined, Mode, Sandbox};
//! # struct Guest;
//! # impl Confined for Guest {
//! #     fn host_fds(&self) -> &[std::os::fd::RawFd] { &[] }
//! #     fn mode(&self) -> Mode { Mode::Coroutine }
//! #     fn gate_ip(&self) -> u64 { 0 }
//! # }
//! # let guest = Guest;
//! Sandbox::configure_and_lockdown(
//!     |s| {
//!         s.grant(0, Access::Read).grant(1, Access::Write).grant(2, Access::Write);
//!         Ok(())
//!     },
//!     &guest,
//! )?;
//! // Locked down: run the program.
//! # Ok::<(), exobox_tcb::Error>(())
//! ```
//!
//! **Templates.** The callback runs first, before any check: a template process forks there, once
//! per instance. The parent never returns from the callback (it loops, forking); each child makes
//! its own grants (its own connection's fd, say) and returns, and lockdown goes on in the child
//! alone:
//!
//! ```ignore
//! Sandbox::configure_and_lockdown(|s| {
//!     loop {
//!         let conn = accept()?;                     // the template's work
//!         if unsafe { libc::fork() } == 0 {         // the instance
//!             s.grant(conn, Access::ReadWrite);
//!             return Ok(());
//!         }
//!         // the template: close its copy of `conn`, reap children, loop
//!     }
//! }, &guest)?;
//! ```
//!
//! The child is a copy of the template, the guest's fds included: a guest whose fds must be its
//! own per instance (exobox's CPU tokens) makes them in the child, before lockdown reads
//! [`Confined::host_fds`].
//!
//! **Not here.** Process limits (`RLIMIT_NPROC`, cgroups) are the caller's to set, before
//! lockdown or from outside: the runtime's own limits (exobox's `max_procs`) run in the program's
//! address space and a compromised program can bypass them.
//!
//! **Disclosure.** Lockdown leaves the address space as it is: everything in memory at lockdown
//! (the caller's heap, its stack, its static data) is readable by the program. Hold no secret in
//! memory when locking down.

use std::fmt;
use std::os::fd::RawFd;

mod filter;
mod lockdown;

pub use filter::{CLONE_THREAD_FLAGS, PPOLL_FDS, SockFilter};
#[doc(hidden)]
pub use lockdown::check_ns;

/// How the guest runs the program's threads and processes. Each mode's allowlist is a superset of
/// the one before.
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

/// What the filter does to a call from the gate it doesn't allow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Deny {
    /// Kill the process (SIGSYS).
    #[default]
    Kill,
    /// Fail the call with EPERM: for probing the filter (exobox's escape tests), never for a
    /// sandbox.
    Errno,
}

/// What may be done on a granted fd: `read`, `write`, or both. Nothing else ever is (no `ioctl`,
/// no `sendmsg`, no `close`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    ReadWrite,
}

impl Access {
    fn reads(self) -> bool {
        self != Access::Write
    }
    fn writes(self) -> bool {
        self != Access::Read
    }
}

/// The guest whose program runs after lockdown: what lockdown asks of it. Nothing it says is
/// trusted to widen the filter: its fds are checked for kind, and the gate's address only sends
/// other calls back as TRAP.
pub trait Confined {
    /// The guest's own host fds, kept past lockdown, read and write: its CPU tokens' eventfds
    /// (`anon_inode:[eventfd]`) and, in fork mode, init's pidfd (`anon_inode:[pidfd]`). Lockdown
    /// refuses any other kind.
    fn host_fds(&self) -> &[RawFd];
    /// The mode, which decides the allowlist.
    fn mode(&self) -> Mode;
    /// The address just past the gate's `syscall` instruction: the one place host calls are
    /// allowed from. Needn't be trusted: the gate check's verdicts are TRAP and KILL only.
    fn gate_ip(&self) -> u64;
}

/// The caller's side of lockdown, made in [`Sandbox::configure_and_lockdown`]'s callback.
#[derive(Debug, Default)]
pub struct Config {
    grants: Vec<(RawFd, Access)>,
    deny: Deny,
    restrictions: Vec<Vec<SockFilter>>,
}

impl Config {
    /// Keep host fd `fd` open past lockdown, with `access` on it. Fds 0-2 are granted like any
    /// other (none is by default). Granting one fd twice grants the union.
    pub fn grant(&mut self, fd: RawFd, access: Access) -> &mut Self {
        self.grants.push((fd, access));
        self
    }

    /// What a refused call from the gate gets (default: kill).
    pub fn deny(&mut self, deny: Deny) -> &mut Self {
        self.deny = deny;
        self
    }

    /// One more seccomp program, stacked under the filter: the kernel runs every filter and takes
    /// the strictest answer, so a restriction can only take away (a call the mode allows fails as
    /// the restriction says; one it refuses stays refused), never add. A classic-BPF program over
    /// `struct seccomp_data`, as seccompiler and libseccomp make them. It sees the guest's calls
    /// from the gate and the program's (which the filter traps: of the kernel's precedence,
    /// KILL > TRAP > ERRNO > ALLOW, only a kill outranks a trap, so an ERRNO leaves the
    /// program's call to the guest). Repeatable.
    pub fn restrict(&mut self, prog: impl IntoIterator<Item = SockFilter>) -> &mut Self {
        self.restrictions.push(prog.into_iter().collect());
        self
    }
}

/// Why lockdown refused. Nothing untrusted has run; the process is as it was but for what the
/// failed step had done (fds closed, the dump flag cleared, capabilities dropped).
#[derive(Debug)]
pub enum Error {
    /// The caller's callback failed.
    Callback(Box<dyn std::error::Error + Send + Sync>),
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
    /// The filter didn't compile (a bad grant: a negative fd).
    Filter(String),
    /// A syscall of lockdown's failed.
    Os { what: &'static str, source: std::io::Error },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Callback(e) => write!(f, "{e}"),
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
    /// The callback's error, boxed: `Err(Error::callback(e))`, or `?` on an `io::Error`.
    pub fn callback(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Error {
        Error::Callback(e.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Callback(Box::new(e))
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Lockdown's entry point.
pub struct Sandbox;

impl Sandbox {
    /// Run `configure` (the caller's grants: [`Config::grant`]; a template forks here: the crate
    /// comment), then lock the process down, in this order:
    ///
    /// 1. exactly one thread, the caller's (`/proc/self/task`; a thread just joined gets a few ms
    ///    to vanish). Every check after this one can't be raced;
    /// 2. the guest's own fds ([`Confined::host_fds`]) kind-checked: eventfds and pidfds only;
    /// 3. every fd neither granted nor the guest's closed;
    /// 4. every mapping kind-checked (`/proc/self/maps`): private, or shared and read-only, or (in
    ///    fork mode) shared anonymous memory; above all no writable shared mapping of a host file;
    /// 5. no core dump (`RLIMIT_CORE` 0) and not dumpable (`PR_SET_DUMPABLE` 0): a crash makes the
    ///    host write none of the process's memory, nor start `core_pattern`'s helper;
    /// 6. every capability dropped (bounding where permitted, ambient, effective, permitted,
    ///    inheritable);
    /// 7. `no_new_privs`;
    /// 8. the caller's restrictions, then the filter, with TSYNC (redundant after step 1, kept).
    ///
    /// On success the process is locked down and the caller hands over to the program. On failure
    /// nothing untrusted has run.
    pub fn configure_and_lockdown<C: Confined + ?Sized>(
        configure: impl FnOnce(&mut Config) -> Result<()>,
        guest: &C,
    ) -> Result<()> {
        let mut config = Config::default();
        configure(&mut config)?;
        lockdown::lockdown(config, guest)
    }
}
