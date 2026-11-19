//! The filter against a model: [`model`] is README.md's allowlist table written as a plain
//! predicate, and [`filter`]'s program, run by a classic-BPF interpreter, must give its verdict for
//! every syscall number, from the gate and not, under every arch, with each argument at every
//! edge of every constant (and the pairs of arguments the multi-condition rules test). The
//! table itself is checked against the model's rules, so README.md, the model and the filter
//! agree.

use std::os::fd::RawFd;

use exobox_tcb::{Access, CLONE_THREAD_FLAGS, Config, Mode, PPOLL_FDS, RET_ALLOW, RET_KILL_PROCESS, RET_TRAP, SockFilter, filter};

const GATE: u64 = 0x0000_7f12_3456_7890;
const PID: u32 = 4242;
const MODES: [Mode; 3] = [Mode::Coroutine, Mode::Threaded, Mode::Fork];
const X86_64: u32 = 0xc000_003e;
const X32_BIT: u32 = 0x4000_0000;
const SIGCHLD: u64 = 17;
const SIBLING: u64 = 0x8000 | SIGCHLD;

const READ: u32 = 0;
const WRITE: u32 = 1;
const RT_SIGRETURN: u32 = 15;
const CLONE: u32 = 56;
const EXIT: u32 = 60;
const KILL: u32 = 62;
const EXIT_GROUP: u32 = 231;
const PPOLL: u32 = 271;

#[derive(Clone, Copy, Debug)]
struct Data {
    nr: u32,
    arch: u32,
    ip: u64,
    args: [u64; 6],
}

fn gate(nr: u32, args: [u64; 6]) -> Data {
    Data { nr, arch: X86_64, ip: GATE, args }
}

// ------------------------------------------------------------------------------------------------
// The model.

/// What may be done on `fd`, from `config.fds` (a fd granted twice: the union).
fn access(config: &Config, fd: u64) -> (bool, bool) {
    config.fds.iter().filter(|&&(f, _)| f >= 0 && f as u64 == fd).fold((false, false), |(r, w), &(_, a)| {
        (r || a != Access::Write, w || a != Access::Read)
    })
}

/// README.md's table, row by row.
fn allowed(config: &Config, pid: u32, nr: u32, a: [u64; 6]) -> bool {
    let threads = config.mode != Mode::Coroutine;
    let fork = config.mode == Mode::Fork;
    match nr {
        READ => access(config, a[0]).0,
        WRITE => access(config, a[0]).1,
        PPOLL => a[1] <= config.ppoll_max && a[3] == 0,
        KILL => a[0] == pid as u64 && (1..=64).contains(&a[1]),
        EXIT_GROUP | RT_SIGRETURN => true,
        CLONE => (threads && a[0] == CLONE_THREAD_FLAGS) || (fork && (a[0] == SIGCHLD || a[0] == SIBLING) && a[1] == 0),
        EXIT => threads && a[0] == 0,
        _ => false,
    }
}

/// The numbers [`allowed`] has a row for, in `mode`.
fn ruled(mode: Mode) -> Vec<u32> {
    let mut v = vec![READ, WRITE, PPOLL, KILL, EXIT_GROUP, RT_SIGRETURN];
    if mode != Mode::Coroutine {
        v.extend([CLONE, EXIT]);
    }
    v
}

/// The whole filter, modelled: another ABI is killed, a call not from the gate traps, a call from
/// the gate is allowed by a row or killed.
fn model(config: &Config, pid: u32, d: &Data) -> u32 {
    if d.arch != X86_64 || d.nr >= X32_BIT {
        RET_KILL_PROCESS
    } else if d.ip != GATE {
        RET_TRAP
    } else if allowed(config, pid, d.nr, d.args) {
        RET_ALLOW
    } else {
        RET_KILL_PROCESS
    }
}

// ------------------------------------------------------------------------------------------------
// Classic BPF.

/// Classic BPF over `struct seccomp_data`: the opcodes the gate check and seccompiler emit
/// (loads, jumps, returns, and AND for seccompiler's masks); anything else panics, as does a
/// jump out of the program.
fn run(prog: &[SockFilter], d: &Data) -> u32 {
    let word = |off: u32| -> u32 {
        match off {
            0 => d.nr,
            4 => d.arch,
            8 => d.ip as u32,
            12 => (d.ip >> 32) as u32,
            16..=63 if off.is_multiple_of(4) => {
                let a = d.args[(off as usize - 16) / 8];
                if off.is_multiple_of(8) { a as u32 } else { (a >> 32) as u32 }
            }
            _ => panic!("load from {off}"),
        }
    };
    let (mut pc, mut a) = (0usize, 0u32);
    loop {
        let ins = prog[pc];
        let jump = |taken: bool| pc + 1 + if taken { ins.jt } else { ins.jf } as usize;
        pc = match ins.code {
            0x20 => {
                a = word(ins.k);
                pc + 1
            }
            0x54 => {
                a &= ins.k;
                pc + 1
            }
            0x05 => pc + 1 + ins.k as usize,
            0x15 => jump(a == ins.k),
            0x25 => jump(a > ins.k),
            0x35 => jump(a >= ins.k),
            0x45 => jump(a & ins.k != 0),
            0x06 => return ins.k,
            c => panic!("opcode {c:#x}"),
        };
        assert!(pc < prog.len(), "jump past the end");
    }
}

/// Values around each range's edges, in both halves, plus the extremes.
fn probes(ranges: &[(u64, u64)]) -> Vec<u64> {
    let mut v = vec![0, 1, u64::MAX, u64::MAX - 1, 1 << 32, (1 << 32) - 1, 1 << 63, u32::MAX as u64];
    for &(lo, hi) in ranges {
        for x in [lo, hi] {
            for d in [0, 1, 2, 1 << 32] {
                v.push(x.wrapping_add(d));
                v.push(x.wrapping_sub(d));
            }
            v.push(x ^ (1 << 32));
            v.push(x ^ (1 << 63));
            v.push(x | 0xffff_ffff_0000_0000);
            v.push(x & 0xffff_ffff);
            v.push(x.rotate_left(32));
        }
    }
    v
}

/// `fds`' numbers as runs of consecutive fds: their edges are what a rule can get wrong.
fn runs(fds: &[(RawFd, Access)]) -> Vec<(u64, u64)> {
    let mut v: Vec<u64> = fds.iter().map(|&(f, _)| f as u64).collect();
    v.sort_unstable();
    v.dedup();
    let mut out: Vec<(u64, u64)> = vec![];
    for fd in v {
        match out.last_mut() {
            Some((_, hi)) if *hi + 1 == fd => *hi = fd,
            _ => out.push((fd, fd)),
        }
    }
    out
}

/// The configurations checked: stdio as exobox grants it, a run of guest token fds, passed fds
/// (one read-only, one write-only), and three `ppoll_max`es.
fn configs(mode: Mode) -> Vec<Config> {
    let stdio = vec![(0, Access::Read), (1, Access::Write), (2, Access::Write)];
    let tokens: Vec<(RawFd, Access)> =
        if mode == Mode::Coroutine { vec![] } else { (3..=131).map(|fd| (fd, Access::ReadWrite)).collect() };
    let mut a = Config { mode, fds: stdio.clone(), ppoll_max: PPOLL_FDS };
    a.fds.extend(tokens.iter().copied());
    let mut b = a.clone();
    b.fds.extend([(1000, Access::ReadWrite), (1001, Access::Read), (1003, Access::Write), (0x7fff_ffff, Access::ReadWrite)]);
    b.ppoll_max = 3;
    let c = Config { mode, fds: vec![], ppoll_max: 0 };
    vec![a, b, c]
}

#[test]
fn filter_is_the_model() {
    let mut checked = 0u64;
    for mode in MODES {
        for c in configs(mode) {
            let prog = filter(&c, PID, GATE).unwrap();
            let mut same = |d: Data| {
                checked += 1;
                assert_eq!(run(&prog, &d), model(&c, PID, &d), "{mode:?} fds {} ppoll_max {}: {d:x?}", c.fds.len(), c.ppoll_max);
            };
            let mut ranges = vec![(1, 64), (0, c.ppoll_max), (PID as u64, PID as u64), (CLONE_THREAD_FLAGS, CLONE_THREAD_FLAGS), (SIGCHLD, SIBLING)];
            ranges.extend(runs(&c.fds));
            let vals = probes(&ranges);
            let small: Vec<u64> = ranges
                .iter()
                .flat_map(|&(lo, hi)| [lo, hi])
                .flat_map(|x| [x.wrapping_sub(1), x, x.wrapping_add(1), x ^ (1 << 32)])
                .chain([u64::MAX])
                .collect();
            // Every number, a few argument patterns, every arch and a few instruction pointers.
            let mut nrs: Vec<u32> = (0..=460).collect();
            nrs.extend([X32_BIT - 1, X32_BIT, X32_BIT | 1, u32::MAX, 0x8000_0000]);
            for &nr in &nrs {
                for arch in [X86_64, 0x4000_0003, X86_64 ^ 1] {
                    for ip in [GATE, GATE + 2, GATE - 2, GATE ^ (1 << 40), GATE ^ 1, 0, u64::MAX] {
                        for args in [[0; 6], [u64::MAX; 6], [1, 2, 3, 4, 5, 6], [3; 6], [PID as u64; 6]] {
                            same(Data { nr, arch, ip, args });
                        }
                    }
                }
            }
            // The ruled numbers and their neighbours: each argument at every edge, the others
            // zero, then at an allowed value; and the pairs the multi-condition rows test.
            let neighbours: Vec<u32> = ruled(Mode::Fork).iter().flat_map(|&n| [n.saturating_sub(1), n, n + 1]).collect();
            for &nr in &neighbours {
                for arg in 0..6 {
                    for &v in &vals {
                        let mut args = [0; 6];
                        args[arg] = v;
                        same(gate(nr, args));
                    }
                }
            }
            let bases: &[(u32, [u64; 6])] = &[
                (KILL, [PID as u64, 9, 0, 0, 0, 0]),
                (PPOLL, [0, 1, 0, 0, 8, 0]),
                (CLONE, [SIGCHLD, 0, 0, 0, 0, 0]),
                (CLONE, [SIBLING, 0, 0, 0, 0, 0]),
                (CLONE, [CLONE_THREAD_FLAGS, 0, 0, 0, 0, 0]),
                (WRITE, [1, 0, 0, 0, 0, 0]),
                (READ, [3, 0, 0, 0, 0, 0]),
            ];
            for &(nr, base) in bases {
                for arg in 0..6 {
                    for &v in &vals {
                        let mut args = base;
                        args[arg] = v;
                        same(gate(nr, args));
                    }
                }
                for &a in &small {
                    for &b in &small {
                        for (i, j) in [(0, 1), (1, 3)] {
                            let mut args = base;
                            args[i] = a;
                            args[j] = b;
                            same(gate(nr, args));
                        }
                    }
                }
            }
        }
    }
    eprintln!("{checked} cases, the model's verdict each");
}

/// The gate check (the program's first twelve instructions, the only hand-written BPF) returns
/// TRAP or KILL, never ALLOW: whatever it decides, only the allowlist after it allows.
#[test]
fn gate_check_never_allows() {
    for mode in MODES {
        let prog = filter(&Config { mode, ..Config::default() }, PID, GATE).unwrap();
        for ins in &prog[..12] {
            if ins.code == 0x06 {
                assert!(ins.k == RET_KILL_PROCESS || ins.k == RET_TRAP, "{ins:?}");
            }
        }
    }
}

/// README.md's allowlist table is the model's: for each mode, the syscalls its rows name are
/// exactly [`ruled`], and the `ppoll` row's bound is [`PPOLL_FDS`].
#[test]
fn readme_table_is_the_model() {
    let readme = include_str!("../README.md");
    let nr = |name: &str| -> u32 {
        match name {
            "read" => READ,
            "write" => WRITE,
            "ppoll" => PPOLL,
            "kill" => KILL,
            "exit_group" => EXIT_GROUP,
            "rt_sigreturn" => RT_SIGRETURN,
            "clone" => CLONE,
            "exit" => EXIT,
            n => panic!("README.md names a syscall the model doesn't know: {n}"),
        }
    };
    let mut rows = 0;
    for mode in MODES {
        let name = match mode {
            Mode::Coroutine => "coroutine",
            Mode::Threaded => "threaded",
            Mode::Fork => "fork",
        };
        let mut table = std::collections::BTreeSet::new();
        for line in readme.lines().filter(|l| l.starts_with("| `")) {
            let cells: Vec<&str> = line.split(" | ").collect();
            let modes = cells.last().unwrap().trim_end_matches(" |").trim();
            if modes == "all" || modes.split(", ").any(|m| m == name) {
                for n in cells[0].trim_start_matches("| ").split(", ") {
                    table.insert(nr(n.trim_matches('`')));
                }
            }
            if mode == Mode::Coroutine {
                rows += 1;
                if cells[0].contains("`ppoll`") {
                    assert!(cells[1].contains(&format!("at most {PPOLL_FDS} fds")), "{line}");
                }
            }
        }
        let model: std::collections::BTreeSet<u32> = ruled(mode).into_iter().collect();
        assert_eq!(table, model, "{mode:?}: README.md's table against the model");
    }
    assert_eq!(rows, 7, "README.md's allowlist table: its rows");
}
