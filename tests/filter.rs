//! The filter is its policy: [`policy`] is the filter, as a Rust function, and Kani proves
//! [`filter`]'s program gives its verdict on every call (`cargo kani`, `./test --prove`). Here,
//! in seconds: the macro's sampled test (`policy_matches_its_bpf_sampled`, the lib's), and here
//! the same through [`filter`], for each mode; README.md's table against the policy's rows.

use unsharek_tcb::{AUDIT_ARCH_X86_64, Config, Mode, PPOLL_FDS, RET_ALLOW, SeccompData, SockFilter, filter, policy, policy_constants};
use seccomp_fn::{Field, check_sampled};

const GATE: u64 = 0x0000_7f12_3456_7890;
const PID: u32 = 4242;
const MODES: [Mode; 3] = [Mode::Coroutine, Mode::Threaded, Mode::Fork];

const READ: u32 = libc::SYS_read as u32;
const WRITE: u32 = libc::SYS_write as u32;
const RT_SIGRETURN: u32 = libc::SYS_rt_sigreturn as u32;
const CLONE: u32 = libc::SYS_clone as u32;
const EXIT: u32 = libc::SYS_exit as u32;
const KILL: u32 = libc::SYS_kill as u32;
const EXIT_GROUP: u32 = libc::SYS_exit_group as u32;
const PPOLL: u32 = libc::SYS_ppoll as u32;

#[test]
fn filter_is_the_policy() {
    for mode in MODES {
        for (pid, ppoll_max, gate) in [(PID, PPOLL_FDS, GATE), (1, 0, 0), (u32::MAX, 3, u64::MAX), (7, u64::MAX, 1 << 32)] {
            let c = Config { mode, fds: vec![], ppoll_max };
            let prog = filter(&c, pid, gate);
            let constants = policy_constants(mode, pid as u64, ppoll_max, gate);
            check_sampled(&prog, &constants, 5_000, |d| policy(d, mode, pid as u64, ppoll_max, gate));
        }
    }
}

/// The numbers [`policy`] allows in `mode`, for some arguments: its numbers, each tried with
/// the arguments it compares with.
fn ruled(mode: Mode) -> std::collections::BTreeSet<u32> {
    let k = policy_constants(mode, PID as u64, PPOLL_FDS, GATE);
    let of = |f: Field| -> Vec<u64> { k.iter().filter(|c| c.0 == f).map(|c| c.1).chain([0, 1]).collect() };
    let mut out = std::collections::BTreeSet::new();
    for nr in of(Field::Nr) {
        for &a0 in &of(Field::Arg(0)) {
            for &a1 in &of(Field::Arg(1)) {
                let d = SeccompData { nr: nr as u32, arch: AUDIT_ARCH_X86_64, instruction_pointer: GATE, args: [a0, a1, 0, 0, 0, 0] };
                if policy(&d, mode, PID as u64, PPOLL_FDS, GATE) == RET_ALLOW {
                    out.insert(nr as u32);
                }
            }
        }
    }
    out
}

/// The policy's rows in `mode`, in order, as its program tests them: each row is a load of `nr`
/// and a JEQ per number (the gate check's load of `nr` tests none). Rows a mode's build-time
/// guard rules out aren't in its program.
fn program_rows(mode: Mode) -> Vec<Vec<u32>> {
    let ld_nr = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let off_nr = std::mem::offset_of!(libc::seccomp_data, nr) as u32;
    let prog: Vec<SockFilter> = filter(&Config { mode, ..Config::default() }, PID, GATE);
    let mut out: Vec<Vec<u32>> = vec![];
    let mut in_row = false;
    for i in &prog {
        if i.code == ld_nr {
            in_row = i.k == off_nr;
            if in_row {
                out.push(vec![]);
            }
        } else if in_row && i.code == jeq {
            out.last_mut().unwrap().push(i.k);
        } else {
            in_row = false;
        }
    }
    out.retain(|r| !r.is_empty());
    out
}

/// README.md's allowlist table is the policy's: for each mode, its rows are the program's rows,
/// in order; the syscalls they name are exactly the ones [`ruled`] finds allowed; the `ppoll`
/// row's bound is [`PPOLL_FDS`].
#[test]
fn readme_table_is_the_policy() {
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
            n => panic!("README.md names a syscall the policy doesn't: {n}"),
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
        let mut ordered: Vec<Vec<u32>> = vec![];
        for line in readme.lines().filter(|l| l.starts_with("| `")) {
            let cells: Vec<&str> = line.split(" | ").collect();
            let modes = cells.last().unwrap().trim_end_matches(" |").trim();
            if modes == "all" || modes.split(", ").any(|m| m == name) {
                let row: Vec<u32> = cells[0].trim_start_matches("| ").split(", ").map(|n| nr(n.trim_matches('`'))).collect();
                table.extend(row.iter().copied());
                ordered.push(row);
            }
            if mode == Mode::Coroutine {
                rows += 1;
                if cells[0].contains("`ppoll`") {
                    assert!(cells[1].contains(&format!("at most {PPOLL_FDS} fds")), "{line}");
                }
            }
        }
        assert_eq!(table, ruled(mode), "{mode:?}: README.md's table against the policy");
        assert_eq!(ordered, program_rows(mode), "{mode:?}: README.md's rows against the policy's, in order");
    }
    assert_eq!(rows, 7, "README.md's allowlist table: its rows");
}

/// The program's length in each mode.
#[test]
fn filter_length() {
    for mode in MODES {
        let n = filter(&Config { mode, ..Config::default() }, PID, GATE).len();
        eprintln!("{mode:?}: {n} instructions");
        assert!(n <= 128, "{mode:?}: {n} instructions");
    }
}
