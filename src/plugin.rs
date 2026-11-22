//! Plugins (experimental): what widens the sandbox past the core, and only when the caller passes
//! one to [`crate::lockdown`]. A plugin is three things, all of it in the TCB while enabled:
//!
//! 1. its **setup**, which lockdown runs at its own point (after `no_new_privs`, before the
//!    filter): fs's Landlock ruleset;
//! 2. the **fds it keeps** past lockdown ([`Plugin::kept`]), renumbered with the grants;
//! 3. its **rows** ([`Plugin::rows`]): calls the filter allows after the core's rows found none,
//!    and after the core's arch and gate checks, so a plugin widens only what the gate itself
//!    may call: it never decides a program's call (TRAP) or another ABI's (KILL).
//!
//! Each plugin file ([`fs`], [`net`]) exports only its [`Plugin`] impl; the core (lockdown.rs,
//! filter.rs) imports neither. Every fd a plugin's calls make is at or above the floor `n`
//! (lockdown leaves only the kept fds below it), and each of its fd rows says `fd >= n`.
//!
//! **Composition, for now.** Today's compiler compiles one function of one file, so the rows
//! are a fixed set per plugin, named by [`Rows`], and [`policy`]/[`filter`] here compose the
//! core's and each enabled plugin's, as one function and one program, for the proof (Kani:
//! `proof::*`, over every mode and plugin choice). The structural compiler's combinator
//! replaces this: a plugin then hands its own compiled rows (allow or fall through, proven
//! once), and [`Rows`] goes.

use libc::{seccomp_data, sock_filter};

use crate::filter::{self, NO_MATCH};
use crate::{Fs, Mode, Result};

mod fs;
mod net;

pub use fs::Files;
pub use net::Net;

use libc::{SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS};

/// An fd a plugin keeps past lockdown, as a grant is kept (and renumbered: [`crate::Fds`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeptFd(pub std::os::fd::RawFd);

/// Which rows a plugin adds (see the module's "Composition, for now").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rows {
    /// None: a plugin of setup only.
    None,
    /// The file rows, read-only or read-write ([`Files`]).
    Files(Fs),
    /// The socket rows ([`Net`]).
    Net,
}

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
    /// Its rows: allowed after the core's rows found none, or nothing.
    fn rows(&self) -> Rows;
}

/// What a set of plugins adds to the filter: the widest file access, and whether any is the net's.
pub(crate) fn rows(plugins: &[&dyn Plugin]) -> (Fs, bool) {
    plugins.iter().fold((Fs::Off, false), |(fs, net), p| match p.rows() {
        Rows::None => (fs, net),
        Rows::Files(a) => (fs.max(a), net),
        Rows::Net => (fs, true),
    })
}

/// The whole filter's verdict on `d`: the core's ([`filter::policy`]: arch, gate, its rows), and if
/// its rows found none, ALLOW where an enabled plugin's rows allow, else KILL_PROCESS. A plugin's
/// rows answer ALLOW or nothing: any other verdict of theirs is no match.
pub fn policy(mode: Mode, n: u64, ppoll_max: u64, gate: u64, fs: Fs, net: bool) -> impl Fn(&seccomp_data) -> u32 {
    let core = filter::policy(mode, n, ppoll_max, gate);
    let files = fs::policy(n, fs == Fs::ReadWrite);
    let sockets = net::policy(n);
    move |d| {
        let v = core(d);
        if v != NO_MATCH {
            return v;
        }
        if fs != Fs::Off && files(d) == SECCOMP_RET_ALLOW {
            return SECCOMP_RET_ALLOW;
        }
        if net && sockets(d) == SECCOMP_RET_ALLOW {
            return SECCOMP_RET_ALLOW;
        }
        SECCOMP_RET_KILL_PROCESS
    }
}

/// [`policy`]'s program: the core's, then each enabled plugin's, then KILL_PROCESS. Each part is
/// its own compiled program, joined by turning its "no match" returns into a jump past its end
/// (the core's `NO_MATCH`; a plugin's every return but ALLOW): every jump in a part is forward
/// and inside it, so the parts concatenate. Not trusted: the proof checks the joined program.
pub fn filter(mode: Mode, n: u64, ppoll_max: u64, gate: u64, fs: Fs, net: bool) -> Vec<sock_filter> {
    let mut prog = vec![];
    append(&mut prog, filter::filter(mode, n, ppoll_max, gate), |i| ret_k(i) == Some(NO_MATCH));
    if fs != Fs::Off {
        append(&mut prog, fs::filter(n, fs == Fs::ReadWrite), |i| is_ret(i) && ret_k(i) != Some(SECCOMP_RET_ALLOW));
    }
    if net {
        append(&mut prog, net::filter(n), |i| is_ret(i) && ret_k(i) != Some(SECCOMP_RET_ALLOW));
    }
    prog.push(sock_filter { code: (libc::BPF_RET | libc::BPF_K) as u16, jt: 0, jf: 0, k: SECCOMP_RET_KILL_PROCESS });
    prog
}

fn is_ret(i: &sock_filter) -> bool {
    i.code & 0x07 == libc::BPF_RET as u16
}

fn ret_k(i: &sock_filter) -> Option<u32> {
    (i.code == (libc::BPF_RET | libc::BPF_K) as u16).then_some(i.k)
}

/// `part` onto `prog`, each instruction `falls` picks made a jump to just past the part.
fn append(prog: &mut Vec<sock_filter>, part: Vec<sock_filter>, falls: impl Fn(&sock_filter) -> bool) {
    let len = part.len();
    for (at, i) in part.into_iter().enumerate() {
        prog.push(if falls(&i) { sock_filter { code: (libc::BPF_JMP | libc::BPF_JA) as u16, jt: 0, jf: 0, k: (len - at - 1) as u32 } } else { i });
    }
}

// The proof: a harness per mode and plugin choice (a mode symbolic took 5x as long as one
// fixed: 663 s against 131 s), the floor, bound and gate symbolic (`plugin::proof::*`).
#[cfg(kani)]
mod proof {
    use super::*;
    seccomp_fn_verify::prove!(policy, filter, unwind = 1024, (
        Mode = [coroutine: Coroutine, threaded: Threaded, fork: Fork], _, _, _,
        Fs = [no_fs: Off, fs_ro: ReadOnly, fs_rw: ReadWrite],
        bool = [no_net: false, net: true]
    ));
}
