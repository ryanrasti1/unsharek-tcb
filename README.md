# Exobox TCB
This repo contains the trusted computing base for exobox. It is extracted from the main repo to keep a very concise, readable implementation guarantee of the security sandbox: about 620 lines of source including comments (`src/lib.rs`, `src/filter.rs`, `src/lockdown.rs`), with two dependencies, `seccomp-fn` (the filter, a Rust function compiled to classic BPF and proven equal to it) and `libc`.


## TCB & Guarantees
After `Sandbox::configure_and_lockdown()` returns, the current process can use the host kernel only through:
  (a) its configured syscalls (see below for the default modes which pin arguments), on the fds granted to it: every other fd is closed, and no allowed syscall opens one
  (b) its memory mappings, none of which can write outside the sandbox (i.e., each is private, read-only, or (fork mode only) anonymous memory shared among the sandbox's own processes)

Access is enforced by seccomp, with three configurations, one per mode ([`policy()`](src/filter.rs)):
1. `coroutine`: every guest thread runs on one host thread
2. `threaded`: a host thread per guest thread, taking turns on one guest CPU
3. `fork`: as threaded, and a guest fork is a host fork; the processes share one guest kernel

| Syscall | Allowed when | Modes |
|---|---|---|
| `read`, `write` | any fd: only granted ones are open, and nothing can open more (as each fd's own mode allows) | all |
| `ppoll` | at most 8 fds, no signal mask (readiness only: moves no data) | all |
| `kill` | the sandbox's own pid, a signal number (ends it as a native death by that signal would) | all |
| `exit_group`, `rt_sigreturn` | always | all |
| `clone` | exactly a host thread's flags | threaded, fork |
| `exit` | status 0 (a host thread's end) | threaded, fork |
| `clone` | exactly `SIGCHLD`, or `CLONE_PARENT \| SIGCHLD`, and no new stack (a host fork) | fork |

Anything else kills the process.

The complete TCB then includes:
- seccomp being correctly implemented by your Linux kernel
- `/proc/self/{task,fd,maps}` correctly pointing to the current process (part of the lockdown check)
- the Rust toolchain and `libc` (constants, raw syscalls)
- Kani's proof that the filter's program is `policy()` (`cargo kani`), resting on seccomp-fn's `run_bpf` matching the kernel (checked against it: seccomp-fn's `tests/kernel.rs`)
- hardware

## Not guaranteed
- **Memory contents**: everything in the address space at lockdown is readable by the current process. Hold no secrets in memory before lockdown.
- **Denial of service**: CPU, memory, and process counts are the caller's to bound (rlimits, cgroups).
- **Code before lockdown** is trusted: it runs with the host's authority. Lockdown verifies only what it leaves behind.
- **Side channels**: the caller's concern.

# Design
The guarantee is achieved at the end of `Sandbox::configure_and_lockdown()` by, in order:
1. Checking, and returning an error if any of the following do not hold:
   - First, that there is exactly 1 thread running (guards against TOCTOU for the remaining checks)
   - The guest's own fds (`Confined::host_fds`) are of an allowed kind: `eventfd` (the CPU token), or `pidfd` in fork mode (each forked process polls init's to end with it)
   - All mappings are private, read-only, or anonymous shared (fork mode)
2. Closing every fd that is neither granted nor the guest's
3. Disabling core dumps (`RLIMIT_CORE` 0, not dumpable): a crash must not write memory to the host's disk, or start `core_pattern`'s helper
4. Dropping all capabilities, and setting `no_new_privs`
5. Enabling the configured seccomp filter, on every thread (`TSYNC`)

Nothing untrusted has run if lockdown fails: the caller reports the error.

The filter is one Rust function, `policy()`: another ABI is KILL; a call not made from exobox's one syscall instruction (the gate) gets TRAP, and is served inside the process; then the table above, a match arm per row, in its order. The gate check never returns ALLOW, so whatever it decides, only the rows reach the host. `#[seccomp]` compiles it to classic BPF, and Kani proves the program equal to it for every call and every mode, pid, `ppoll_max` and gate (`./test --prove`; the release build requires it).

## Review checklist
| Guarantee | Where | Verify |
|---|---|---|
| the policy | `src/filter.rs` `policy()` | the ABI and gate checks return only KILL or TRAP; each row pins every argument it needs; nothing creates an fd or a mapping |
| the proof | `cargo kani -p exobox-tcb` | `policy_is_its_bpf_*` pass (seccomp-fn's README: what the proof rests on) |
| one thread | `src/lockdown.rs` | counted before any other check |
| fds | `src/lockdown.rs` | the guest's kinds checked; everything else closed |
| mappings | `src/lockdown.rs` | no writable shared mapping of a file |
| core dumps, capabilities, `no_new_privs` | `src/lockdown.rs` | set before the filter |
| filter install | `src/lockdown.rs` | `TSYNC`; a failure is an error |
