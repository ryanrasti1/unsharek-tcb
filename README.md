# Unsharek TCB
This repo contains the trusted computing base for unsharek. It is extracted from the main repo to keep a very concise, readable implementation guarantee of the security sandbox: about 790 lines of source including comments in the core (`src/lib.rs`, `src/filter.rs`, `src/lockdown.rs`, `src/paranoia.rs`), and the experimental plugins' (`src/plugin.rs`, `src/plugin/fs.rs`, `src/plugin/net.rs`) about 470 more, with three dependencies: [`seccomp-fn`](https://github.com/ryanrasti1/seccomp-fn) (and its `seccomp-fn-verify`), `libc` and `rustix`.


## TCB & Guarantees
After `unsharek_tcb::lockdown(config)` returns, the current process can use the host kernel only through:
  (a) its configured syscalls (see below for the default modes which pin arguments), on the fds granted to it: every other fd is closed, and no allowed syscall opens one, except an enabled plugin's rows (below), whose fds are always at or above every kept one
  (b) its memory mappings, none of which can write outside the sandbox (i.e., each is private, read-only, or (fork mode only) anonymous memory shared among the sandbox's own processes)

Access is enforced by seccomp, with three configurations, one per mode ([`policy()`](src/filter.rs)):
1. `coroutine`: every guest thread runs on one host thread
2. `threaded`: a host thread per guest thread, taking turns on one guest CPU
3. `fork`: as threaded, and a guest fork is a host fork; the processes share one guest kernel

| Syscall | Allowed when | Modes |
|---|---|---|
| `read`, `write` | any fd: only kept ones are open, and a plugin's (as each fd's own mode allows) | all |
| `ppoll` | at most 8 fds, no signal mask (readiness only: moves no data) | all |
| `exit_group`, `rt_sigreturn` | always | all |
| `clone` | exactly a host thread's flags | threaded, fork |
| `exit` | status 0 (a host thread's end) | threaded, fork |
| `clone` | exactly `SIGCHLD`, or `CLONE_PARENT \| SIGCHLD`, and no new stack (a host fork) | fork |

Anything else kills the process.

Plugins (experimental) widen the table only when the caller passes them to lockdown, and only
by their own rows ([`src/plugin/`](src/plugin.rs)), checked after the core's rows find none and
after the arch and gate checks (a plugin allows calls from the gate, never decides the program's).
Each plugin file exports only its `Plugin` impl; the core (`src/lockdown.rs`, `src/filter.rs`)
imports neither. Every fd a plugin's calls make is at or above the floor n.

The file plugin ([`src/plugin/fs.rs`](src/plugin/fs.rs)), its roots confined by Landlock:

| Syscall | Allowed when | Modes |
|---|---|---|
| `close` | fd ≥ n | fs |
| `openat` | dirfd ≥ n; always `O_NONBLOCK \| O_CLOEXEC`; `O_RDONLY` with `O_DIRECTORY`, `O_NOFOLLOW`; read-write also `O_WRONLY`/`O_RDWR` with `O_TRUNC`, `O_APPEND`, `O_CREAT` (`O_EXCL`); mode without `S_ISUID`/`S_ISGID`; never `O_PATH`, `O_TMPFILE`, `O_DIRECT` | fs |
| `fstat`, `getdents64`, `pread64` | fd ≥ n | fs |
| `readlinkat` | dirfd ≥ n | fs |
| `mkdirat`, `fchmodat` | dirfd ≥ n, mode without `S_ISUID`/`S_ISGID` | fs-rw |
| `unlinkat` | dirfd ≥ n, flags 0 or `AT_REMOVEDIR` | fs-rw |
| `renameat2` | both dirfds ≥ n, flags 0, `RENAME_NOREPLACE` or `RENAME_EXCHANGE` | fs-rw |
| `symlinkat` | dirfd ≥ n | fs-rw |
| `utimensat` | dirfd ≥ n, a path, flags 0 or `AT_SYMLINK_NOFOLLOW` | fs-rw |
| `ftruncate`, `fsync`, `pwrite64` | fd ≥ n | fs-rw |

The network plugin ([`src/plugin/net.rs`](src/plugin/net.rs)), any address (the network namespace
the caller runs the process in is what confines it):

| Syscall | Allowed when | Modes |
|---|---|---|
| `ppoll` | at most 4096 fds, no signal mask | net |
| `close` | fd ≥ n | net |
| `socket` | `AF_INET`/`AF_INET6`, `SOCK_STREAM`/`SOCK_DGRAM` (with `SOCK_NONBLOCK`, `SOCK_CLOEXEC`), protocol 0 | net |
| `connect`, `bind`, `listen`, `getsockname`, `getpeername` | fd ≥ n | net |
| `accept4` | fd ≥ n, flags of `SOCK_NONBLOCK \| SOCK_CLOEXEC` | net |
| `shutdown` | fd ≥ n, how up to `SHUT_RDWR` | net |
| `setsockopt` | fd ≥ n; `SO_REUSEADDR`, `SO_KEEPALIVE`, `TCP_NODELAY`, `IPV6_V6ONLY` | net |
| `getsockopt` | fd ≥ n; `SO_ERROR` | net |

A plugin is in the TCB when it is passed: its setup (the file plugin's Landlock ruleset, run by
lockdown after `no_new_privs`), the fds it keeps, and its rows.

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
The guarantee is achieved by `unsharek_tcb::lockdown(config, plugins)`, which uses its config and the plugins passed and nothing else (it calls no code of the caller's; the guest's preparation, such as making its fds, is the caller's, before it), by, in order:
1. Checking, and returning an error if any of the following do not hold:
   - First, that there is exactly 1 thread running (guards against TOCTOU for the remaining checks)
   - The kept fds are exactly `0..n` (`Config::grant`; a gap refused), each open and of its declared kind (`Config::grant_as`: an eventfd, a pidfd); putting them there is the caller's (its `dup2`s, untrusted)
   - The mode's own among them, by declared kind: eventfds (the CPU tokens) only in threaded and fork mode; a pidfd only in fork mode (each forked process polls init's to end with it)
   - No kept fd of a kind no caller means to give (another process's memory, io_uring, userfaultfd, a writable `/proc` or `/sys` file, …), always: not a paranoia check
   - All mappings are private, read-only, or anonymous shared (fork mode)
2. Closing every fd at or above `n`
3. Disabling core dumps (`RLIMIT_CORE` 0, not dumpable): a crash must not write memory to the host's disk, or start `core_pattern`'s helper
4. Dropping all capabilities, and setting `no_new_privs`; then each plugin's setup (the file plugin's Landlock ruleset)
5. Enabling the configured seccomp filter, on every thread (`TSYNC`)

Nothing untrusted has run if lockdown fails: the caller reports the error.

At lockdown the kept fds are exactly 0..n, each open and of its declared kind. After it nothing below n can be freed (no close row for fd < n, no dup2/dup3), so the kernel's lowest-free rule gives every new fd a number >= n: every fd >= n was opened by a plugin row, every fd < n is a kept one. The file and network plugins' fds share the range >= n: a filter is stateless, and a call of one plugin's on the other's fd meets the kernel's own type checks (ENOTSOCK, ESPIPE, EINVAL).

Paranoia (`src/paranoia.rs`, on by default) is best-effort only: a tracer, another process sharing the memory, shared memory an ancestor maps. Every exact check is lockdown's (`src/lockdown.rs`).

The filter is seccomp-fn-verify's combinator (`gated`) of the core's rows (`core()`, one Rust function over the typed call, `d.call()`: each argument as the kernel reads it) and each enabled plugin's rows: the arch check, then the gate check, then ALLOW if any rows allow the call, else KILL. A call not made from unsharek's one syscall instruction (the gate) gets TRAP, and is served inside the process; that check never returns ALLOW, and a plugin's rows can only allow, so only the rows reach the host. seccomp-fn-verify's compiler, proven once for every policy (its `proof.rs`), compiles it to BPF: there is no proof here.

## Review checklist
| Guarantee | Where | Verify |
|---|---|---|
| policy | `src/filter.rs` `core()`, `src/plugin/*.rs` rows | is the intended policy: the gate check returns only TRAP or KILL; each row pins every argument it needs; nothing creates an fd or a mapping |
| proof | seccomp-fn-verify (`src/proof.rs`) | its compiler is proven once for every policy; this crate's `core()` and plugin rows are compiled by it (`seccomp_fn::rows!`) |
| one thread | `src/lockdown.rs` | counted before any other check |
| fds | `src/lockdown.rs` | exactly `0..n`, no gap; each open, of its declared kind, of no kind refused; eventfds and pidfds only in their modes |
| fd floor | `src/lockdown.rs` | everything at or above `n` closed; every plugin row's fd and dirfd `>= n`, no `AT_EMPTY_PATH` |
| plugins | `src/plugin.rs`, `src/plugin/*.rs` | rows only after the core's (after the arch and gate checks), allow or no match; each file exports only its `Plugin` impl |
| roots (plugin: fs) | `src/plugin/fs.rs` | Landlock ruleset of the roots, after `no_new_privs`, before the filter; refused without Landlock or its needed ABI unless `no_landlock` |
| mappings | `src/lockdown.rs` | no writable shared mapping of a file |
| core dumps, capabilities, `no_new_privs` | `src/lockdown.rs` | set before the filter |
| filter install | `src/lockdown.rs` | `TSYNC`; a failure is an error |
