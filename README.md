# Unsharek TCB
This repo contains the trusted computing base for unsharek. It is extracted from the main repo to keep a very concise, readable implementation guarantee of the security sandbox: about 650 lines of source including comments (`src/lib.rs`, `src/filter.rs`, `src/lockdown.rs`), with three dependencies: [`seccomp-fn`](https://github.com/ryanrasti1/seccomp-fn) (and its `seccomp-fn-verify`), `libc` and `rustix`.


## TCB & Guarantees
After `unsharek_tcb::lockdown(config)` returns, the current process can use the host kernel only through:
  (a) its configured syscalls (see below for the default modes which pin arguments), on the fds granted to it: every other fd is closed, and no allowed syscall opens one, except the fds a plugin's provider sends on its control socket (below)
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

Plugins (experimental) widen the table only when the caller enables them, and only by these rows:

| Syscall | Allowed when | Modes |
|---|---|---|
| `recvmsg` | plugin: network. Only on the control socket (`Config::recv_fds`, a unix seqpacket socket lockdown checks), only with `MSG_CMSG_CLOEXEC`; received fds get `read`/`write` like every kept fd | plugin |
| `close` | plugin: network. Only fds at or above a floor one above every kept fd (lockdown fills the numbers below it), and below 2^31: received connections, never a kept fd | plugin |

A plugin's own host process (a file server, a network provider) is confined by its own Landlock rules and proven filter; when enabled it is part of the TCB, but this crate's guarantee covers the sandbox only.

The complete TCB then includes:
- This crate: the policy (`src/filter.rs`) being the intended one, and lockdown's checks (`src/lockdown.rs`). TODO: the whole crate as one `src/lib.rs`
- [`seccomp-fn-verify`](https://github.com/ryanrasti1/seccomp-fn): proves the compiled BPF equal to the policy (its README lists what that rests on); `seccomp-fn`, the compiler, needs no trust
- Toolchain correctness:
  - `rustc`
  - `libc` (constants; the raw `close_range` and `seccomp` calls)
  - `rustix` (lockdown's other syscalls, typed)
- Minimal Linux kernel surface:
  - `/proc/self/{task,fd,maps}` correctly pointing to the current process (part of the lockdown check)
  - seccomp implementation
  - each kept fd honouring its own mode, and private mappings staying private
- Hardware

## Not guaranteed
- **Memory contents**: everything in the address space at lockdown is readable by the current process. Hold no secrets in memory before lockdown.
- **Denial of service**: CPU, memory, and process counts are the caller's to bound (rlimits, cgroups).
- **Code before lockdown** is trusted: it runs with the host's authority. Lockdown verifies only what it leaves behind.
- **Side channels**: the caller's concern.

# Design
The guarantee is achieved by `unsharek_tcb::lockdown(config)`, which uses its config and nothing else (it calls no code of the caller's; the guest's preparation, such as making its fds, is the caller's, before it), by, in order:
1. Checking, and returning an error if any of the following do not hold:
   - First, that there is exactly 1 thread running (guards against TOCTOU for the remaining checks)
   - The guest's own fds (`Config::guest_fds`) are of an allowed kind: `eventfd` (the CPU token), or `pidfd` in fork mode (each forked process polls init's to end with it)
   - All mappings are private, read-only, or anonymous shared (fork mode)
   - With the network plugin: its control socket (`Config::recv_fds`) is a unix seqpacket socket
2. Closing every fd that is neither granted nor the guest's
3. Disabling core dumps (`RLIMIT_CORE` 0, not dumpable): a crash must not write memory to the host's disk, or start `core_pattern`'s helper
4. Dropping all capabilities, and setting `no_new_privs`
5. Enabling the configured seccomp filter, on every thread (`TSYNC`)

Nothing untrusted has run if lockdown fails: the caller reports the error.

The filter is `policy()`, one Rust function: the gate check, then the table's rows. A call not made from unsharek's one syscall instruction (the gate) gets TRAP, and is served inside the process; that check never returns ALLOW, so whatever it decides, only the rows reach the host. `seccomp-fn` compiles the function to BPF, and Kani proves the program gives the function's verdict for every call and every configuration.

## Review checklist
| Guarantee | Where | Verify |
|---|---|---|
| policy | `src/filter.rs` `policy()` | is the intended policy: the gate check returns only TRAP or KILL; each row pins every argument it needs; nothing creates an fd or a mapping |
| proof | `src/filter.rs` (`seccomp_fn_verify::policy!`) | `cargo kani -p unsharek-tcb` proves `policy_proof::*`, one harness per mode and plugin on/off; the release build depends on it |
| one thread | `src/lockdown.rs` | counted before any other check |
| fds | `src/lockdown.rs` | the guest's kinds checked; everything else closed |
| control socket (plugin) | `src/lockdown.rs` | AF_UNIX `SOCK_SEQPACKET`, checked before the filter; the `recvmsg` row pins fd and flags; the floor below received fds filled |
| mappings | `src/lockdown.rs` | no writable shared mapping of a file |
| core dumps, capabilities, `no_new_privs` | `src/lockdown.rs` | set before the filter |
| filter install | `src/lockdown.rs` | `TSYNC`; a failure is an error |
