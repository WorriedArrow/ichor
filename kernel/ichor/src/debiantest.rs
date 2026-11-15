//! Milestone 4, Phase D: Debian 12 (bookworm-slim) userland, unmodified,
//! in a cell. Its programs are glibc-linked: every run goes through
//! glibc's `ld-linux-x86-64.so.2` (`PT_INTERP`).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::println;

use crate::kcell::{Cell, System};
use crate::loader;
use crate::process::LinuxProcess;
use crate::runtest::{fail, run_linux};
use crate::vfs::{ROOT, Vfs};

const CELL_PAGES: u64 = 65536;

/// The pty session script (see `RUNS`).
const PTY_SCRIPT: &str = r#"use strict; use warnings; use POSIX ();
sub fail { print "debian: pty FAILED: @_\n"; exit 1 }
# One terminal session: open a pty, type $pre, run $cmd on the slave as the
# controlling terminal of a new session, then for each (pattern, input)
# step wait for the output to match and type the input; read to the
# hangup (EIO) and reap. Returns the master's output and the wait status.
sub session {
    my ($cmd, $pre, @steps) = @_;
    sysopen(my $m, "/dev/ptmx", 2) or fail("open /dev/ptmx: $!");
    my $n = pack("i", 0);
    ioctl($m, 0x80045430, $n) or fail("TIOCGPTN: $!");
    my $name = "/dev/pts/" . unpack("i", $n);
    my @st = stat($name) or fail("stat $name: $!");
    ($st[2] & 0170000) == 0020000 or fail("$name is not a character device");
    sysopen(my $x, $name, 2) and fail("opened a locked slave");
    $!{EIO} or fail("locked slave: $!");
    my $unlock = pack("i", 0);
    ioctl($m, 0x40045431, $unlock) or fail("unlockpt: $!");
    my $ws = pack("S4", 24, 80, 0, 0);
    ioctl($m, 0x5414, $ws) or fail("TIOCSWINSZ: $!");
    syswrite($m, $pre) == length($pre) or fail("write: $!");
    my $pid = fork() // fail("fork: $!");
    if ($pid == 0) {
        POSIX::setsid();
        close $m;
        sysopen(my $s, $name, 2) or POSIX::_exit(90);
        POSIX::dup2(fileno($s), $_) for 0 .. 2;
        exec("/bin/sh", "-c", $cmd) or POSIX::_exit(91);
    }
    my $out = "";
    while (@steps) {
        my ($wait, $send) = splice(@steps, 0, 2);
        while ($out !~ $wait) {
            my $r = sysread($m, my $buf, 4096);
            $r or fail("output ended before $wait: " . ($r // $!) . " [$out]");
            $out .= $buf;
        }
        syswrite($m, $send) == length($send) or fail("write: $!");
    }
    while (1) {
        my $r = sysread($m, my $buf, 4096);
        if (!defined $r) { $!{EIO} or fail("master read: $!"); last }
        $r or fail("master read EOF instead of EIO [$out]");
        $out .= $buf;
    }
    waitpid($pid, 0) == $pid or fail("waitpid: $!");
    my $status = $?;
    close $m;
    -e $name and fail("$name outlived its master");
    return ($out, $status);
}
my ($out, $st) = session(
    'tty; stty size; read line; echo "got:$line"; stty -echo; echo noecho; read s; echo "secret:$s"',
    "ab\x7fc\n",
    qr/noecho\r\n/, "hidden\n");
$st == 0 or fail("shell exited $st [$out]");
$out =~ m{^ab\x08 \x08c\r\n/dev/pts/\d+\r\n24 80\r\ngot:ac\r\nnoecho\r\nsecret:hidden\r\n\z}
    or fail("unexpected output [$out]");
($out, $st) = session(
    'trap "echo caught; exit 3" INT; echo ready; while :; do sleep 1; done',
    "",
    qr/ready\r\n/, "\x03");
($st >> 8) == 3 or fail("^C: status $st [$out]");
$out =~ /\^Ccaught\r\n/ or fail("^C: output [$out]");
print "debian: pty: openpty, line editing, echo, stty, ^C and hangup work\n";
"#;

/// `(argv, expected exit code)`: argv[0] is a path under `/usr/bin`.
const RUNS: &[(&[&str], i32)] = &[
    (
        &[
            "dash",
            "-c",
            "echo debian: dash runs, release $(cat /etc/debian_version)",
        ],
        0,
    ),
    (
        &[
            "dash",
            "-c",
            "ls /usr/bin >/dev/null && [ \"$(id -u)\" = 0 ] && \
             printf 'b\\na\\n' | sort | head -1 | grep -q a && \
             echo debian: coreutils run",
        ],
        0,
    ),
    (
        &[
            "dash",
            "-c",
            "n=$(nproc) && [ \"$n\" -ge 1 ] && [ \"$(getconf _NPROCESSORS_ONLN)\" = \"$n\" ] && \
             [ \"$(stat -c %s /etc/debian_version)\" -gt 0 ] && \
             echo debian: nproc, getconf and stat agree",
        ],
        0,
    ),
    // Pseudo-terminals, driven the way a terminal emulator or sshd would:
    // Debian's perl opens /dev/ptmx and runs dash, tty and stty on the
    // slave (glibc's ttyname, tcgetattr/tcsetattr, ioctls).
    (&["perl", "-e", PTY_SCRIPT], 0),
    (
        &[
            "dash",
            "-c",
            "export DEBIAN_FRONTEND=noninteractive; apt-get update -q &&              apt-get install -y -q --no-install-recommends hello jq && hello &&              [ \"$(echo '{\"a\":[1,2,3]}' | jq '.a|add')\" = 6 ] && dpkg -s libonig5 >/dev/null &&              echo debian: apt-get installed hello and jq from the local repository",
        ],
        0,
    ),
];

fn read(vfs: &Vfs, path: &str) -> Vec<u8> {
    let mut fs = vfs.lock();
    let ino = fs
        .resolve(ROOT, path, true)
        .unwrap_or_else(|_| fail("debian: missing file"));
    let size = fs.stat(ino).map(|s| s.size).unwrap_or(0) as usize;
    let mut v = alloc::vec![0u8; size];
    let n = fs.read(ino, 0, &mut v).unwrap_or(0);
    v.truncate(n);
    v
}

pub(crate) fn run(vfs: &Arc<Vfs>) {
    let release = read(vfs, "/etc/debian_version");
    println!(
        "ichor: debian: root disk holds Debian {}",
        String::from_utf8_lossy(&release).trim()
    );
    let system = System::new(CELL_PAGES * 2).unwrap_or_else(|| fail("no system cell"));
    for (argv, want) in RUNS {
        let exe = read(vfs, &alloc::format!("/usr/bin/{}", argv[0]));
        let interp_path = match loader::interp_path(&crate::file::Bytes(&exe)) {
            Ok(Some(p)) => p,
            _ => fail("debian: program is not dynamically linked"),
        };
        let interp = read(vfs, &interp_path);
        let cell =
            Cell::new(&system.root_account, CELL_PAGES).unwrap_or_else(|| fail("no debian cell"));
        let p = LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("no process"));
        let (code, syscalls) = run_linux(p, &exe, Some(&interp), argv);
        if code != *want {
            println!(
                "ichor: debian: {:?} exited {code}, expected {want}",
                &argv[..argv.len().min(2)]
            );
            fail("debian program");
        }
        println!("ichor: debian: {} ok ({syscalls} syscalls)", argv[0]);
    }
    println!("ichor: debian: all runs passed");
}
