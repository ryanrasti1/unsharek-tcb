//! Plugins (experimental): what widens the sandbox past the core, and only when the caller passes
//! one to [`crate::lockdown`]. A plugin is three things, all of it in the TCB while enabled:
//!
//! 1. its **setup**, which lockdown runs at its own point (after `no_new_privs`, before the
//!    filter): fs's Landlock ruleset;
//! 2. the **fds it keeps** past lockdown ([`Plugin::kept`]), kept as grants are;
//! 3. its **rows** ([`Plugin::rows`]): calls the filter allows after the core's rows found none,
//!    and after the core's arch and gate checks, so a plugin widens only what the gate itself
//!    may call: it never decides a program's call (TRAP) or another ABI's (KILL).
//!
//! Each plugin file ([`fs`], [`net`]) exports only its [`Plugin`] impl; the core (lockdown.rs,
//! filter.rs) imports neither. Every fd a plugin's calls make is at or above the floor `n`
//! (lockdown leaves only the kept fds below it), and each of its fd rows says `fd >= n`.
//!
//! **Composition.** A plugin's rows are a condition of the tree (seccomp-fn's `rows!` of a
//! function of its file), which seccomp-fn-verify's combinator (`expr::gated`) puts after the
//! core's, behind the arch and gate checks: a sub-filter can only allow, never change the checks
//! before it. The compiler is proven once for every tree, the combinator's among them.

use crate::Result;
use seccomp_fn_verify::expr::Cond;

pub(crate) mod fs;
pub(crate) mod net;

pub use fs::{Files, Fs};
pub use net::Net;

/// An fd a plugin keeps past lockdown, as a grant is kept (one of `0..n`, the caller's to place).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeptFd(pub std::os::fd::RawFd);

/// A plugin: setup, kept fds, rows. Lockdown calls [`Plugin::check`] before it changes anything,
/// [`Plugin::setup`] at its step 7b, and reads the others once.
pub trait Plugin {
    /// What the plugin needs of the kernel, checked before anything changes (fs: Landlock's
    /// ABI), so a refusal leaves the process as it was.
    fn check(&self) -> Result<()> {
        Ok(())
    }
    /// Runs inside lockdown, after `no_new_privs`, before the filter (fs: the roots' Landlock
    /// ruleset).
    fn setup(&self) -> Result<()> {
        Ok(())
    }
    /// The fds it keeps past lockdown.
    fn kept(&self) -> &[KeptFd] {
        &[]
    }
    /// Its rows, for the floor `n`: allowed after the core's rows found none, or none.
    fn rows(&self, n: u32) -> Option<Cond>;
}
