# Exobox TCB
This repo contains the trusted computing base for exobox.

## TCB & Guarantees
After `Sandbox::configure_and_lockdown()` returns, the current process can use the host kernel only through:
  (a) its mode's allowlist of syscalls, each argument pinned; any fd they take must be granted, and is usable only with its granted access (read, write, or both)
  (b) its memory mappings, every one of which is private, read-only, or (fork mode only) anonymous memory shared among the sandbox's own processes: no mapping writes anything outside the sandbox

"Current process" is everything in it after lockdown: the program, the runtime, the guest kernel, the network hooks.

Access is enforced by seccomp, with three configurations, one per mode ([`rules()`](src/filter.rs)):
1. `coroutine`: every guest thread runs on one host thread
2. `threaded`: a host thread per guest thread, taking turns on one guest CPU
3. `fork`: as threaded, and a guest fork is a host fork; the processes share one guest kernel

| Syscall | Allowed when | Modes |
|---|---|---|
| `read`, `write` | the fd is granted, with that access | all |
| `ppoll` | at most 8 fds, no signal mask (readiness only: moves no data) | all |
| `kill` | the sandbox's own pid, a signal number (ends it as a native death by that signal would) | all |
| `exit_group`, `rt_sigreturn` | always | all |
| `clone` | exactly a host thread's flags | threaded, fork |
| `exit` | status 0 (a host thread's end) | threaded, fork |
| `clone` | exactly `SIGCHLD`, or `CLONE_PARENT \| SIGCHLD`, and no new stack (a host fork) | fork |

Anything else kills the process.

The complete TCB then includes seccomp being correctly implemented by your Linux kernel, `/proc` (lockdown reads `/proc/self/{task,fd,maps}`), and hardware.

## Not guaranteed
- **Memory contents**: everything in the address space at lockdown is readable by the current process. Hold no secrets in memory before lockdown.
- **Denial of service**: CPU, memory, and process counts are the caller's to bound (rlimits, cgroups).
- **Code before lockdown** is trusted: it runs with the host's authority. Lockdown verifies only what it leaves behind.
- **Network hooks** are not a policy point: policy belongs at the far end of a granted fd.
- **Side channels.**

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

The filter is seccompiler's allowlist behind one hand-written check: a call not made from exobox's one syscall instruction (the gate) gets TRAP, and is served inside the process. That check never returns ALLOW, so whatever it decides, only the allowlist reaches the host.

## Review checklist
| Guarantee | Where | Verify |
|---|---|---|
| allowlist | `src/filter.rs` `rules()` | each entry pins every argument it needs; nothing creates an fd or a mapping |
| gate check | `src/filter.rs` `gate_check()` | returns only TRAP or KILL |
| one thread | `src/lockdown.rs` | counted before any other check |
| fds | `src/lockdown.rs` | the guest's kinds checked; everything else closed |
| mappings | `src/lockdown.rs` | no writable shared mapping of a file |
| core dumps, capabilities, `no_new_privs` | `src/lockdown.rs` | set before the filter |
| filter install | `src/lockdown.rs` | `TSYNC`; a failure is an error |
