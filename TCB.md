# exobox's trusted computing base

What protects the host from a sandboxed program, where it is, and how to review it.

## The model

After lockdown the program shares one address space with everything else in the process: the
runtime (the SIGSYS handler, the dispatcher, the scheduler, the arena, the loader), the guest
kernel, and the network hooks. It can read and write all of it. So none of that code protects the
host: a bug there, or a program that corrupts it, breaks the guest, never the host. The host is
protected only by:

1. **The security filter**: which host syscalls the process may make, every argument pinned.
2. **The authority inventory at lockdown**: which host fds are open, what is mapped, which host
   threads exist.
3. **The order**: nothing untrusted runs before the filter is in place.

That is the TCB, and it is `native/exobox/src/tcb/`, about 600 lines with their comments:

| File | What |
|---|---|
| `tcb/inventory.rs` | every host resource the sandbox keeps past lockdown, made and recorded there |
| `tcb/filter.rs` | the security filter, per mode, built from the inventory, compiled by seccompiler |
| `tcb/lockdown.rs` | one function: threads checked, fds closed, filters installed, in that order |

Plus their call sites in `lib.rs` (where the API makes inventory resources, and `Sandbox::start`,
which builds the filter and calls `lockdown` from `Guest::launch` before anything else runs).

## What is not in it, and why

- **The routing filter** (`exobox-rt`'s `route.rs`, thirteen hand-written instructions). It traps
  every call not made from the gate and allows every call from it. The kernel takes the strictest
  answer of all stacked filters, so a filter under the security filter can only take away: a bug
  in it misroutes calls, it never lets the host make one the security filter refuses.
- **The runtime** (`native/rt`), **the guest kernel** (`lkl/`, `native/lkl-sys`), the arena, the
  loader, the scheduler: after lockdown they are the program's to corrupt. They are given the
  inventory's resources; nothing they produce is a value the filter trusts. (The gate's address is
  the runtime's: the filter uses it only to send other calls back as TRAP, below.)
- **The network hooks** (`exobox-kit`'s `net.rs`: `on_connect`, `on_listen`, `on_resolve`,
  `on_start`, `Cx`). They run after lockdown in the program's address space: any check inside a
  hook is the program's to skip. A hook is not a policy point. The network's only TCB surface is
  the held fds: which ones the inventory holds, and the filter pinning `read` and `write` to
  exactly those. Policy lives at their far end, in the provider's own process, which exobox leaves
  agnostic.
- **Setup and the store** (`exobox-kit`'s `setup.rs`, `store.rs`, `image.rs`): what the guest is
  given to see. They run before lockdown, as the host, and decide what the guest's files are; what
  the host exposes through them is the images' bytes, mapped privately and read-only.
- **The allocator after lockdown** (`exobox-kit`'s `alloc.rs`): a region reserved before, in the
  program's address space like the rest.
- **The API** (`lib.rs`): it turns calls into inventory entries and calls the TCB; a reviewer
  checks only its calls into `tcb` (below).

## The security filter's shape

A 12-instruction prologue, then seccompiler's program:

1. arch not x86-64, or the x32 bit set: KILL_PROCESS;
2. the instruction pointer not the gate's: TRAP (the program's call, served by the guest kernel);
3. seccompiler's allowlist: a matching rule ALLOWs, anything else is KILL_PROCESS (ERRNO(EPERM)
   with the CLI's hidden `--deny=errno`).

Step 2 is not trusted for isolation. A plain allowlist would need no instruction-pointer test if
its default were weaker than TRAP, but its default is KILL, which outranks the routing filter's
TRAP: every program syscall not on the list would kill the sandbox. So the prologue sends
non-gate calls back as TRAP itself. Its only verdicts are TRAP and KILL, never ALLOW, so whatever
it decides (whatever the gate's address), the host makes only calls the allowlist allows.

## Review checklist

The inventory (`tcb/inventory.rs`):
- [ ] Every fd that survives lockdown is in `Inventory::fds`: stdio, passed (`pass_fd`), held
      (`hold_fd`), the CPU tokens' eventfds (made there, at fds checked free), fork mode's init
      pidfd. `lockdown` closes every other.
- [ ] `read`/`write` reach only stdio, passed, held and token fds (`Inventory::pins`, then
      `filter::rules`); the pidfd is only polled.
- [ ] The arena, the kernel's memory and stacks, the images and fork mode's shared section are
      mapped through the inventory. Only fork mode's are shared (`MAP_SHARED`), and with the
      sandbox's own processes only (host forks that inherit the filters); `Sandbox::fork` (a
      template, which is never locked down) refuses when `has_shared`. The other mappings made
      before lockdown (the runtime's per-thread signal stacks, the allocator's region) are
      private anonymous memory: no authority beyond their bytes (`grep -rn MAP_SHARED native/`
      finds only the inventory's host calls; the arena's are the guest's flags, emulated).
- [ ] Host threads at lockdown: the boot thread, and threaded mode's kernel idler.

The filter (`tcb/filter.rs`):
- [ ] `prologue` returns only KILL_PROCESS and TRAP (`prologue_never_allows`).
- [ ] Each entry of `rules`: needed by the mode, every argument that can be pinned pinned, as
      64-bit comparisons. No memory call, no `open`, no `socket`, no `seccomp` or `prctl`.
- [ ] Pinned values come from the inventory (`Pins`) or are constants: never the runtime's.
- [ ] `restriction`'s prologue only ALLOWs `prctl` and `seccomp` from the gate: ALLOW is the
      weakest verdict, and the security filter (installed after) refuses both.

Lockdown (`tcb/lockdown.rs`) and its call:
- [ ] In `Guest::launch`, `lockdown` runs before the hooks' first task and before the exec or
      `run_fn`'s closure; on failure, the error returns and nothing untrusted has run.
- [ ] Threads: exactly the inventory's. Then `close_range` around the inventory's fds. Then the
      restrictions, then the security filter with TSYNC: every thread gets it, and a failure to
      sync is lockdown's failure.
- [ ] Every syscall lockdown makes goes through the gate (the routing filter traps the others).

The tests that back these: `tcb::filter::tests` (each rule's edges through a BPF interpreter;
`same_as_the_old_filter`, 2.3 million cases against the hand-written compiler this one replaced,
kept as `tcb/filter/old.rs`; installs in the kernel with TSYNC), and the suite's `escape*` and
`sysaudit` cases and `tests/guest.rs`'s `run_fn*` (an fd from before lockdown is closed; gate
calls refused and killed).
