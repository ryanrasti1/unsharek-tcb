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
| `exit_group`, `rt_sigreturn` | always | all |
| `clone` | exactly a host thread's flags | threaded, fork |
| `exit` | status 0 (a host thread's end) | threaded, fork |
| `clone` | exactly `SIGCHLD`, or `CLONE_PARENT \| SIGCHLD`, and no new stack (a host fork) | fork |

Anything else kills the process.

Plugins (experimental) widen the table only when the caller enables them, and only by these rows:

| Syscall | Allowed when | Modes |
|---|---|---|
| `close` | fd ≥ n (one a plugin opened) | fs, net |
| `openat` | dirfd ≥ n; always `O_NONBLOCK \| O_CLOEXEC`; `O_RDONLY` with `O_DIRECTORY`, `O_NOFOLLOW`; read-write also `O_WRONLY`/`O_RDWR` with `O_TRUNC`, `O_APPEND`, `O_CREAT` (`O_EXCL`); mode without `S_ISUID`/`S_ISGID`; never `O_PATH`, `O_TMPFILE`, `O_DIRECT` | fs |
| `lseek` | fd ≥ n, whence up to `SEEK_HOLE` | fs |
| `fstat`, `getdents64`, `fstatfs`, `pread64` | fd ≥ n | fs |
| `newfstatat` | dirfd ≥ n, flags 0 or `AT_SYMLINK_NOFOLLOW` | fs |
| `statx` | dirfd ≥ n, flags 0 or `AT_SYMLINK_NOFOLLOW` | fs |
| `readlinkat` | dirfd ≥ n | fs |
| `fcntl` | fd ≥ n; `F_GETFL`, or `F_SETFL` to 0 or `O_NONBLOCK` (read-write: with `O_APPEND`) | fs |
| `mkdirat`, `fchmodat` | dirfd ≥ n, mode without `S_ISUID`/`S_ISGID` | fs-rw |
| `unlinkat` | dirfd ≥ n, flags 0 or `AT_REMOVEDIR` | fs-rw |
| `renameat2` | both dirfds ≥ n, flags 0, `RENAME_NOREPLACE` or `RENAME_EXCHANGE` | fs-rw |
| `linkat` | both dirfds ≥ n, flags 0 or `AT_SYMLINK_FOLLOW` | fs-rw |
| `symlinkat` | dirfd ≥ n | fs-rw |
| `fchownat` | dirfd ≥ n, flags 0 or `AT_SYMLINK_NOFOLLOW` | fs-rw |
| `utimensat` | dirfd ≥ n, a path, flags 0 or `AT_SYMLINK_NOFOLLOW` | fs-rw |
| `ftruncate`, `fsync`, `fdatasync`, `pwrite64` | fd ≥ n | fs-rw |
| `fallocate` | fd ≥ n, mode 0 | fs-rw |
| `socket` | `AF_INET`/`AF_INET6`, `SOCK_STREAM`/`SOCK_DGRAM` (with `SOCK_NONBLOCK`, `SOCK_CLOEXEC`), protocol 0 | net |
| `connect`, `bind`, `listen`, `getsockname`, `getpeername` | fd ≥ n | net |
| `accept4` | fd ≥ n, flags of `SOCK_NONBLOCK \| SOCK_CLOEXEC` | net |
| `shutdown` | fd ≥ n, how up to `SHUT_RDWR` | net |
| `sendto`, `recvfrom` | fd ≥ n, flags of `MSG_DONTWAIT \| MSG_NOSIGNAL` | net |
| `setsockopt`, `getsockopt` | fd ≥ n; `SO_REUSEADDR`, `SO_KEEPALIVE`, `SO_SNDBUF`, `SO_RCVBUF`, `TCP_NODELAY`, `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`, `IPV6_V6ONLY` (get: `SO_ERROR` too) | net |

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
| proof | `src/filter.rs` (`seccomp_fn_verify::policy!`) | `cargo kani -p unsharek-tcb` proves `policy_proof::*`, one harness per mode, fs access and net on/off; the release build depends on it |
| one thread | `src/lockdown.rs` | counted before any other check |
| fds | `src/lockdown.rs` | the guest's kinds checked; everything else closed |
| fd floor | `src/lockdown.rs` | the kept fds renumbered `0..n`, everything at or above `n` closed; every plugin row's fd and dirfd `>= n`, no `AT_EMPTY_PATH` |
| roots (plugin: fs) | `src/lockdown.rs` | Landlock ruleset of the roots, after `no_new_privs`, before the filter; refused without Landlock or its needed ABI unless `no_landlock` |
| mappings | `src/lockdown.rs` | no writable shared mapping of a file |
| core dumps, capabilities, `no_new_privs` | `src/lockdown.rs` | set before the filter |
| filter install | `src/lockdown.rs` | `TSYNC`; a failure is an error |
