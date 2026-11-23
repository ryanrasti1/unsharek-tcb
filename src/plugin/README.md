# Plugins (experimental)
Plugins (experimental) widen the table only when the caller passes them to lockdown, and only
by their own rows ([`plugin.rs`](../plugin.rs)), checked after the core's rows find none and
after the arch and gate checks (a plugin allows calls from the gate, never decides the program's).
Each plugin file exports only its `Plugin` impl; the core (`src/lockdown.rs`, `src/filter.rs`)
imports neither. Every fd a plugin's calls make is at or above the floor n.

The file plugin ([`fs.rs`](fs.rs)), its roots confined by Landlock:

| Syscall | Allowed when | Modes |
|---|---|---|
| `close` | fd ≥ n | fs |
| `openat` | dirfd ≥ n; always `O_NONBLOCK \| O_CLOEXEC`; `O_RDONLY`; read-write also `O_RDWR`, `O_RDWR \| O_CREAT` (`O_EXCL`); mode without `S_ISUID`/`S_ISGID`; nothing else (no `O_WRONLY`, `O_TRUNC`, `O_APPEND`, `O_DIRECTORY`, `O_NOFOLLOW`, `O_PATH`, `O_TMPFILE`, `O_DIRECT`) | fs |
| `fstat`, `getdents64`, `pread64` | fd ≥ n | fs |
| `readlinkat` | dirfd ≥ n | fs |
| `mkdirat`, `fchmodat` | dirfd ≥ n, mode without `S_ISUID`/`S_ISGID` | fs-rw |
| `unlinkat` | dirfd ≥ n, flags 0 or `AT_REMOVEDIR` | fs-rw |
| `renameat2` | both dirfds ≥ n, flags 0, `RENAME_NOREPLACE` or `RENAME_EXCHANGE` | fs-rw |
| `symlinkat` | dirfd ≥ n | fs-rw |
| `utimensat` | dirfd ≥ n, a path, flags 0 or `AT_SYMLINK_NOFOLLOW` | fs-rw |
| `ftruncate`, `fsync`, `pwrite64` | fd ≥ n | fs-rw |

The network plugin ([`net.rs`](net.rs)), any address (the network namespace
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
