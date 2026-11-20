//! Lockdown's mapping rule, line by line: private anything; shared only read-only, or in fork mode
//! anonymous (the kernel's shmem); never a writable shared mapping of a file, a memfd or SysV shm.

use unsharek_tcb::{Mode, map_ok};

#[test]
fn maps_rules() {
    for m in [Mode::Coroutine, Mode::Threaded, Mode::Fork] {
        assert!(map_ok("55d0-55d1 r-xp 00000000 fd:01 123                        /usr/bin/x", m));
        assert!(map_ok("7f00-7f01 rw-p 00000000 00:00 0 ", m));
        assert!(map_ok("7f00-7f01 rw-p 00000000 00:00 0", m));
        assert!(map_ok("7ffd-7ffe rw-p 00000000 00:00 0                          [stack]", m));
        assert!(map_ok("7f00-7f01 r--s 00000000 fd:01 99                         /nix/store/x.erofs", m));
        assert!(!map_ok("7f00-7f01 rw-s 00000000 fd:01 99                        /tmp/file", m));
        assert!(!map_ok("7f00-7f01 -w-s 00000000 fd:01 99                        /tmp/file", m));
        assert!(!map_ok("7f00-7f01 rw-s 00000000 00:01 9                         /memfd:x (deleted)", m));
        assert!(!map_ok("7f00-7f01 rw-s 00000000 00:01 9                         /SYSV00000000 (deleted)", m));
        assert!(!map_ok("garbage", m));
        assert!(!map_ok("", m));
    }
    let anon = "7f00-7f01 rw-s 00000000 00:01 146407                     /dev/zero (deleted)";
    assert!(map_ok(anon, Mode::Fork));
    assert!(!map_ok(anon, Mode::Coroutine));
    assert!(!map_ok(anon, Mode::Threaded));
    // A host file can't pass for it: not on the kernel's internal mount.
    assert!(!map_ok("7f00-7f01 rw-s 00000000 fd:01 9                         /dev/zero (deleted)", Mode::Fork));
}
