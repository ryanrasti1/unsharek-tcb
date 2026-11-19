//! The filter as it was before seccompiler (exobox-rt's `filter.rs`, unchanged but for
//! this line and the tests' module): kept as the oracle the new filter is checked against
//! (`tests.rs`'s `same_as_the_old_filter`), test-only.
//!
//! The seccomp-BPF filter: compiled from plain parameters into a classic-BPF program, then
//! installed.
//!
//! The runtime issues its own host syscalls from one `syscall` instruction, the gate; the filter
//! routes by the instruction pointer the kernel reports (the address just past that instruction).
//! That check is routing, not security: a compromised program can jump to the gate. So what the
//! filter permits from the gate is the attack surface, and it is exactly the mode's list
//! ([`HOST`]) plus the user's rules, each with its arguments pinned as tightly as the runtime's
//! use allows.
//!
//! The program, in order:
//! 1. arch is not x86-64, or the x32 bit is set: kill (a filter that only knows x86-64 numbers
//!    must not judge another ABI's).
//! 2. not from the gate: `SECCOMP_RET_TRAP` (the program's syscall, served in-process). The
//!    program's `rt_sigreturn` too: it returns from a handler the runtime ran (`guest`'s signal
//!    delivery), so it is the runtime's to serve. (It was allowed from anywhere, for the SIGSYS
//!    handler's return; that return now goes through the gate, `trap`'s restorer.)
//! 3. from the gate: the first rule whose number matches and whose conditions all hold allows;
//!    nothing matching is `deny`. Or, for [`Policy::RouteOnly`], allow everything.
//!
//! **Two filters, stacked.** The sandbox's routing and its security are separate layers, each a
//! filter of this shape: first the routing-only one ([`Policy::RouteOnly`]: steps 1-3, then allow
//! all from the gate), installed when the guest starts running (`exobox::Guest::run`), then,
//! before the program's exec, the mode's ([`Policy::Mode`]), stacked on it. The kernel runs every
//! installed filter and takes the highest-precedence action (KILL > TRAP > ERRNO > ALLOW): a
//! non-gate call is TRAP in both, a gate call ALLOW in the first and the mode list's verdict in the
//! second. That is why the mode filter keeps its own instruction-pointer check (step 3) instead of
//! judging every call by its list: a KILL or ERRNO for a non-gate call would outrank the routing
//! filter's TRAP, and the program's own syscalls would be refused instead of served.
//!
//! Compilation is a pure function into caller-provided fixed storage ([`Program`]); installing is
//! separate ([`install`]) so the program can be built and checked without touching the process.

use core::fmt;

/// One classic-BPF instruction (`struct sock_filter`, include/uapi/linux/filter.h).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// The kernel's limit on a program's length (`BPF_MAXINSNS`, include/uapi/linux/bpf_common.h).
pub const MAX_INSNS: usize = 4096;

// Syscall numbers (arch/x86/entry/syscalls/syscall_64.tbl). Only the ones the mode lists name.
pub const NR_READ: u32 = 0;
pub const NR_WRITE: u32 = 1;
pub const NR_RT_SIGRETURN: u32 = 15;
pub const NR_MADVISE: u32 = 28;
pub const NR_KILL: u32 = 62;
pub const NR_CLONE: u32 = 56;
pub const NR_EXIT: u32 = 60;
pub const NR_EXIT_GROUP: u32 = 231;
pub const NR_PPOLL: u32 = 271;
/// `seccomp(2)` itself and `prctl(2)`, for [`install`].
const NR_SECCOMP: usize = 317;
const NR_PRCTL: usize = 157;

/// The one flag set a host thread is made with (include/uapi/linux/sched.h): `CLONE_VM |
/// CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_CHILD_CLEARTID`.
/// The child-cleared tid word is how the runtime learns a thread's slot is free.
pub const CLONE_HOST_THREAD: u64 = 0x100 | 0x200 | 0x400 | 0x800 | 0x1_0000 | 0x4_0000 | 0x20_0000;
/// The most pollfds one `ppoll` from the gate may pass (the idle wait: see `HOST`).
pub const PPOLL_FDS: u64 = 8;
/// `SIGCHLD` (arch/x86/include/uapi/asm/signal.h): clone's flags for a plain fork.
pub const SIGCHLD: u64 = 17;
/// `CLONE_PARENT`: the new process is a sibling of the caller's (a child of its parent).
pub const CLONE_PARENT: u64 = 0x8000;

// Return values (include/uapi/linux/seccomp.h).
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// `EPERM` (include/uapi/asm-generic/errno-base.h), the errno [`Deny::Errno`] returns.
pub const EPERM: u32 = 1;

/// `AUDIT_ARCH_X86_64` (include/uapi/linux/audit.h).
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
/// `__X32_SYSCALL_BIT` (arch/x86/include/uapi/asm/unistd.h). Compared as `nr >= this`, unsigned,
/// so a negative number (e.g. -1) is killed too: it is no x86-64 syscall either.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// struct seccomp_data (include/uapi/linux/seccomp.h): nr (int), arch (u32), instruction_pointer
// (u64), args[6] (u64). x86-64 is little-endian: a u64's low half is at its offset, its high half
// 4 bytes on.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_IP: u32 = 8;
const fn off_arg(i: u8) -> u32 {
    16 + 8 * i as u32
}

// Opcodes (include/uapi/linux/bpf_common.h). Only these are emitted; the tests' interpreter
// knows exactly these.
const LD_W_ABS: u16 = 0x20; // BPF_LD (0) | BPF_W (0) | BPF_ABS
const JEQ_K: u16 = 0x05 | 0x10; // BPF_JMP | BPF_JEQ | BPF_K
const JGT_K: u16 = 0x05 | 0x20; // BPF_JMP | BPF_JGT | BPF_K
const JGE_K: u16 = 0x05 | 0x30; // BPF_JMP | BPF_JGE | BPF_K
const RET_K: u16 = 0x06; // BPF_RET | BPF_K

/// Which of the runtime's modes the filter is for: each permits a different host set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// One host thread; program threads are coroutines.
    Coroutine,
    /// A host thread per program thread, CPU tokens passed through eventfds.
    Threaded,
    /// Threaded, plus host processes per program process.
    Fork,
}

/// What the filter decides for a call from the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Routing only: everything from the gate is allowed (the first of the stacked filters; see the
    /// module comment). `deny`, the arena, the token fds and the extra rules are unused.
    RouteOnly,
    /// The mode's list, then the extra rules, then `deny`.
    Mode(Mode),
}

/// What a refused syscall from the gate gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deny {
    /// `SECCOMP_RET_KILL_PROCESS`: the default; a refused gate call is an escape attempt or a bug.
    Kill,
    /// `SECCOMP_RET_ERRNO | EPERM`: for probing the filter (the escape tests).
    Errno,
}

impl Deny {
    pub const fn ret(self) -> u32 {
        match self {
            Deny::Kill => SECCOMP_RET_KILL_PROCESS,
            Deny::Errno => SECCOMP_RET_ERRNO | EPERM,
        }
    }
}

/// Argument `arg` (0-5) within `lo..=hi`, compared as 64 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cond {
    pub arg: u8,
    pub lo: u64,
    pub hi: u64,
}

/// Syscall `nr` is allowed (from the gate) when every condition holds. At most [`MAX_CONDS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule<'a> {
    pub nr: u32,
    pub conds: &'a [Cond],
}

/// One condition per argument is all a rule needs (a second on the same argument is an
/// intersection, which the user can write as one range).
pub const MAX_CONDS: usize = 6;

/// Everything the filter depends on. Plain data: the caller fills it in at lockdown.
#[derive(Clone, Copy, Debug)]
pub struct Params<'a> {
    pub policy: Policy,
    pub deny: Deny,
    /// The address just past the gate's `syscall` instruction (what the kernel reports):
    /// `trap::gate_ip()`.
    pub gate_ip: u64,
    /// The CPU-token eventfds, an inclusive range (threaded and fork mode; ignored otherwise).
    pub token_fds: (u32, u32),
    /// The sandbox's own host pid: the one process `kill` from the gate may signal (coroutine and
    /// threaded mode: a guest death by a signal is the sandbox's, `guest`'s `die`).
    pub pid: u32,
    /// The user's rules, after the mode's.
    pub extra: &'a [Rule<'a>],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The program doesn't fit in [`MAX_INSNS`].
    TooLong,
    /// A condition (or the token fds) with `lo > hi`.
    EmptyRange,
    /// A condition on an argument past 5.
    NoSuchArg,
    /// A rule with more than [`MAX_CONDS`] conditions.
    TooManyConds,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::TooLong => "the seccomp filter is longer than the kernel allows",
            Error::EmptyRange => "a filter range with lo > hi",
            Error::NoSuchArg => "a filter condition on an argument past arg5",
            Error::TooManyConds => "a filter rule with more than 6 conditions",
        })
    }
}

/// A compiled program: fixed storage, no allocation. 32 KiB; the caller decides where it lives.
pub struct Program {
    insns: [SockFilter; MAX_INSNS],
    len: usize,
}

impl Program {
    pub const fn new() -> Self {
        Program { insns: [SockFilter { code: 0, jt: 0, jf: 0, k: 0 }; MAX_INSNS], len: 0 }
    }

    pub fn as_slice(&self) -> &[SockFilter] {
        &self.insns[..self.len]
    }
}

impl Default for Program {
    fn default() -> Self {
        Self::new()
    }
}

// ------------------------------------------------------------------------------------------------
// The mode lists: what the gate may do, per mode, and why.

const COROUTINE: u8 = 1;
const THREADED: u8 = 2;
const FORK: u8 = 4;
const ALL: u8 = COROUTINE | THREADED | FORK;

/// A condition's range in the table: a constant, or one of the bounds only known at lockdown.
#[derive(Clone, Copy)]
enum Is {
    /// `lo..=hi`.
    In(u64, u64),
    /// Exactly this value (all 64 bits).
    Eq(u64),
    /// Within `Params::token_fds`.
    TokenFd,
    /// Exactly `Params::pid`.
    Pid,
}

struct Entry {
    modes: u8,
    nr: u32,
    conds: &'static [(u8, Is)],
}

/// The host allowlist from the gate. Everything a mode uses and nothing else; adding an entry
/// widens what a compromised program can do through the gate, so each says why it is needed.
const HOST: &[Entry] = &[
    // The SIGSYS handler's return (`trap`'s restorer jumps to the gate's `syscall`), and a new
    // host thread's start (`trap::clone_thread`'s frame).
    Entry { modes: ALL, nr: NR_RT_SIGRETURN, conds: &[] },
    // The program's stdout and stderr, written by the runtime on its behalf.
    Entry { modes: ALL, nr: NR_WRITE, conds: &[(0, Is::In(1, 2))] },
    // stdin: the guest's file for it is read from the host's fd 0.
    Entry { modes: ALL, nr: NR_READ, conds: &[(0, Is::Eq(0))] },
    // Ending the process.
    Entry { modes: ALL, nr: NR_EXIT_GROUP, conds: &[] },
    // Ending it by a signal: the guest's process died of one (its default action), and the
    // sandbox dies of the same, as the program would natively (abort's SIGABRT). Only this
    // process, only a signal number: the program can end the sandbox anyway. In fork mode the
    // pinned pid is init's process's, the sandbox's: only its death by a signal is the
    // sandbox's (a forked process's is the guest's, seen by its parent in wait), and so is the
    // death of any process on the host (init's SIGCHLD, `guest`'s fork mode).
    Entry { modes: ALL, nr: NR_KILL, conds: &[(0, Is::Pid), (1, Is::In(1, 64))] },
    // The one wait: idle to the next timer (coroutine), a thread's timed sleep on its eventfd
    // (threaded), the program's nanosleep; and the fds it waits for: stdin, the fds the hooks
    // hold and passed fds the guest polls (`executor`). Up to PPOLL_FDS pollfds and no signal
    // mask (a mask would let the gate change the host's blocked signals, SIGSYS among them).
    // Which fds can't be pinned (they are in memory the filter doesn't see), and needn't be:
    // ppoll only waits and reports readiness, it reads or writes no fd's data, so polling any of
    // the process's fds tells a compromised program nothing it couldn't learn by timing the
    // reads the filter does allow, and changes nothing.
    Entry { modes: ALL, nr: NR_PPOLL, conds: &[(1, Is::In(0, PPOLL_FDS)), (3, Is::Eq(0))] },
    // No madvise in any mode: memory stays at its peak, freed pages cleared on reuse (arena.rs).
    // Where there are host threads, madvise concurrent with page faults on other threads is the
    // Dirty-COW race class; exec needs none (the image zone is read-only); and one memory model
    // for every mode is simpler than two. (Coroutine mode had MADV_DONTNEED on the arena, one
    // MiB at a time.)
    // Block on (read) and hand over (write) the CPU token: the eventfds, made before lockdown.
    Entry { modes: THREADED | FORK, nr: NR_READ, conds: &[(0, Is::TokenFd)] },
    Entry { modes: THREADED | FORK, nr: NR_WRITE, conds: &[(0, Is::TokenFd)] },
    // A host thread per program thread, made lazily after lockdown: exactly one flag set, all 64
    // bits (no namespaces, no CLONE_SETTLS, no vfork, no unknown high bits).
    Entry { modes: THREADED | FORK, nr: NR_CLONE, conds: &[(0, Is::Eq(CLONE_HOST_THREAD))] },
    // A host thread's end, after its program thread's: status 0 only.
    Entry { modes: THREADED | FORK, nr: NR_EXIT, conds: &[(0, Is::Eq(0))] },
    // The host fork behind a program's fork: flags exactly SIGCHLD and no new stack; from a
    // forked process, CLONE_PARENT too, so that every process is a host child of init's, whose
    // SIGCHLD sees any of them die on the host (a sibling, not a new authority).
    Entry { modes: FORK, nr: NR_CLONE, conds: &[(0, Is::Eq(SIGCHLD)), (1, Is::Eq(0))] },
    Entry { modes: FORK, nr: NR_CLONE, conds: &[(0, Is::Eq(CLONE_PARENT | SIGCHLD)), (1, Is::Eq(0))] },
];

// ------------------------------------------------------------------------------------------------
// Compilation.

// Jump targets not yet known, written into jt/jf and patched once they are. Real offsets inside
// one rule stay far below these: a rule is at most 2 + 6 * 9 + 1 instructions.
const TO_FAIL: u8 = 0xff; // past this rule's ALLOW: the next rule
const TO_END: u8 = 0xfe; // past this condition: it holds
const TO_L1: u8 = 0xfd; // inside a condition: the high half is above lo's

struct Emit<'p> {
    p: &'p mut Program,
    /// Whether the accumulator holds `nr` on every path into the next instruction.
    a_is_nr: bool,
}

impl Emit<'_> {
    fn push(&mut self, code: u16, jt: u8, jf: u8, k: u32) -> Result<(), Error> {
        let slot = self.p.insns.get_mut(self.p.len).ok_or(Error::TooLong)?;
        *slot = SockFilter { code, jt, jf, k };
        self.p.len += 1;
        Ok(())
    }

    fn ld(&mut self, off: u32) -> Result<(), Error> {
        self.a_is_nr = off == OFF_NR;
        self.push(LD_W_ABS, 0, 0, off)
    }

    fn ret(&mut self, k: u32) -> Result<(), Error> {
        self.push(RET_K, 0, 0, k)
    }

    /// Point every jump in `from..` that names `label` at the next instruction.
    fn patch(&mut self, from: usize, label: u8) {
        let here = self.p.len;
        for (i, ins) in self.p.insns[from..here].iter_mut().enumerate() {
            let off = here - (from + i + 1);
            for j in [&mut ins.jt, &mut ins.jf] {
                if *j == label && ins.code != LD_W_ABS && ins.code != RET_K {
                    // A rule is far shorter than 255 instructions (see TO_FAIL).
                    *j = u8::try_from(off).expect("a jump within one rule");
                }
            }
        }
    }

    /// `lo <= arg <= hi` as 64-bit unsigned, from 32-bit loads and compares: falls through when
    /// it holds, jumps to TO_FAIL when not. The classic bug is comparing the halves
    /// independently; here the low half is only compared when the high half is equal to the
    /// bound's.
    fn cond(&mut self, c: &Cond) -> Result<(), Error> {
        let start = self.p.len;
        let (lo_w, hi_w) = (off_arg(c.arg), off_arg(c.arg) + 4);
        let (lh, ll) = ((c.lo >> 32) as u32, c.lo as u32);
        let (hh, hl) = ((c.hi >> 32) as u32, c.hi as u32);
        if c.lo == c.hi {
            self.ld(hi_w)?;
            self.push(JEQ_K, 0, TO_FAIL, lh)?;
            self.ld(lo_w)?;
            self.push(JEQ_K, 0, TO_FAIL, ll)?;
        } else if lh == hh {
            // Same high half: it must equal that, and the low half is a 32-bit range.
            self.ld(hi_w)?;
            self.push(JEQ_K, 0, TO_FAIL, lh)?;
            if ll != 0 || hl != u32::MAX {
                self.ld(lo_w)?;
                if ll != 0 {
                    self.push(JGE_K, 0, TO_FAIL, ll)?;
                }
                if hl != u32::MAX {
                    self.push(JGT_K, TO_FAIL, 0, hl)?;
                }
            }
        } else {
            // lh < hh. A high half strictly between them passes outright; equal to lh, the low
            // half must be >= ll (and then <= hi holds, as lh < hh); equal to hh, <= hl.
            self.ld(hi_w)?;
            if c.lo != 0 {
                self.push(JGT_K, TO_L1, 0, lh)?;
                if ll == 0 {
                    self.push(JEQ_K, TO_END, TO_FAIL, lh)?;
                } else {
                    self.push(JEQ_K, 0, TO_FAIL, lh)?;
                    self.ld(lo_w)?;
                    self.push(JGE_K, TO_END, TO_FAIL, ll)?;
                }
            }
            self.patch(start, TO_L1);
            // Here the accumulator is the high half, and arg >= lo.
            if c.hi != u64::MAX {
                self.push(JGT_K, TO_FAIL, 0, hh)?;
                if hl != u32::MAX {
                    self.push(JEQ_K, 0, TO_END, hh)?;
                    self.ld(lo_w)?;
                    self.push(JGT_K, TO_FAIL, 0, hl)?;
                }
            }
        }
        self.patch(start, TO_END);
        Ok(())
    }

    fn rule(&mut self, nr: u32, conds: &[Cond]) -> Result<(), Error> {
        if conds.len() > MAX_CONDS {
            return Err(Error::TooManyConds);
        }
        for c in conds {
            if c.arg > 5 {
                return Err(Error::NoSuchArg);
            }
            if c.lo > c.hi {
                return Err(Error::EmptyRange);
            }
        }
        let start = self.p.len;
        // Every path into a rule comes from the previous rule's checks; reload nr only if those
        // loaded an argument.
        if !self.a_is_nr {
            self.ld(OFF_NR)?;
        }
        self.push(JEQ_K, 0, TO_FAIL, nr)?;
        for c in conds {
            self.cond(c)?;
        }
        self.ret(SECCOMP_RET_ALLOW)?;
        self.patch(start, TO_FAIL);
        Ok(())
    }

    /// A table entry with its lockdown-time bounds filled in.
    fn entry(&mut self, e: &Entry, params: &Params) -> Result<(), Error> {
        let mut conds = [Cond { arg: 0, lo: 0, hi: 0 }; MAX_CONDS];
        for (i, &(arg, is)) in e.conds.iter().enumerate() {
            let (lo, hi) = match is {
                Is::In(lo, hi) => (lo, hi),
                Is::Eq(v) => (v, v),
                Is::TokenFd => (params.token_fds.0 as u64, params.token_fds.1 as u64),
                Is::Pid => (params.pid as u64, params.pid as u64),
            };
            conds[i] = Cond { arg, lo, hi };
        }
        self.rule(e.nr, &conds[..e.conds.len()])
    }
}

/// Compile `params` into `out` (overwritten). Pure: no syscalls, no allocation.
pub fn compile(params: &Params, out: &mut Program) -> Result<(), Error> {
    out.len = 0;
    if params.token_fds.0 > params.token_fds.1 {
        return Err(Error::EmptyRange);
    }
    let mut e = Emit { p: out, a_is_nr: false };
    let ip = params.gate_ip;

    // 1. Only x86-64 numbers are judged.
    e.ld(OFF_ARCH)?;
    e.push(JEQ_K, 1, 0, AUDIT_ARCH_X86_64)?;
    e.ret(SECCOMP_RET_KILL_PROCESS)?;
    e.ld(OFF_NR)?;
    e.push(JGE_K, 0, 1, X32_SYSCALL_BIT)?;
    e.ret(SECCOMP_RET_KILL_PROCESS)?;
    // 2. Not the gate (either half of the address differs): the program's syscall, trapped.
    e.ld(OFF_IP)?;
    e.push(JEQ_K, 1, 0, ip as u32)?;
    e.ret(SECCOMP_RET_TRAP)?;
    e.ld(OFF_IP + 4)?;
    e.push(JEQ_K, 1, 0, (ip >> 32) as u32)?;
    e.ret(SECCOMP_RET_TRAP)?;
    // 3. The gate: the mode's list, then the user's rules, then deny; or all of it.
    let bit = match params.policy {
        Policy::RouteOnly => return e.ret(SECCOMP_RET_ALLOW),
        Policy::Mode(Mode::Coroutine) => COROUTINE,
        Policy::Mode(Mode::Threaded) => THREADED,
        Policy::Mode(Mode::Fork) => FORK,
    };
    for entry in HOST.iter().filter(|en| en.modes & bit != 0) {
        e.entry(entry, params)?;
    }
    for r in params.extra {
        e.rule(r.nr, r.conds)?;
    }
    e.ret(params.deny.ret())?;
    Ok(())
}
