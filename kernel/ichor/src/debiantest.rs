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

/// The TCP socket script (see `RUNS`): loopback inside the cell's stack.
const SOCKET_SCRIPT: &str = r#"use strict; use warnings; use Socket; use Fcntl; use POSIX ();
sub fail { print "debian: sockets FAILED: @_\n"; exit 1 }
sub tcp { socket(my $s, AF_INET, SOCK_STREAM, 0) or fail("socket: $!"); $s }
my $lo = inet_aton("127.0.0.1");
# Nothing listens: the stack answers RST.
my $c = tcp();
connect($c, pack_sockaddr_in(1, $lo)) and fail("connect to a closed port worked");
$!{ECONNREFUSED} or fail("closed port: $!");
close $c;
# A listener on an ephemeral port; a second bind to it is refused.
my $l = tcp();
setsockopt($l, SOL_SOCKET, SO_REUSEADDR, 1) or fail("SO_REUSEADDR: $!");
bind($l, pack_sockaddr_in(0, $lo)) or fail("bind: $!");
listen($l, 16) or fail("listen: $!");
my ($port) = unpack_sockaddr_in(getsockname($l));
$port >= 32768 or fail("ephemeral port $port");
-S $l or fail("fstat: not a socket");
readlink("/proc/self/fd/" . fileno($l)) =~ /^socket:\[\d+\]$/ or fail("/proc/self/fd link");
unpack("i", getsockopt($l, SOL_SOCKET, SO_TYPE)) == SOCK_STREAM or fail("SO_TYPE");
my $d = tcp();
bind($d, pack_sockaddr_in($port, $lo)) and fail("second bind worked");
$!{EADDRINUSE} or fail("second bind: $!");
close $d;
# 1 MiB up, half-close, 1 MiB back: both directions fill their windows.
my $n = 1 << 20;
my $data = substr(join("", map { chr } 0 .. 250) x (int($n / 251) + 1), 0, $n);
my $pid = fork() // fail("fork: $!");
if ($pid == 0) {
    my $s = tcp();
    connect($s, pack_sockaddr_in($port, $lo)) or POSIX::_exit(10);
    my $off = 0;
    while ($off < $n) { my $w = syswrite($s, $data, 65536, $off) or POSIX::_exit(11); $off += $w }
    shutdown($s, 1) or POSIX::_exit(12);
    my $back = "";
    while (1) {
        my $r = sysread($s, my $buf, 65536);
        defined $r or POSIX::_exit(13);
        last if !$r;
        $back .= $buf;
    }
    POSIX::_exit($back eq $data ? 0 : 14);
}
my $peer = accept(my $a, $l) or fail("accept: $!");
my ($pport, $paddr) = unpack_sockaddr_in($peer);
inet_ntoa($paddr) eq "127.0.0.1" or fail("peer address");
my ($gport) = unpack_sockaddr_in(getpeername($a));
$gport == $pport or fail("getpeername $gport != $pport");
my $got = "";
while (1) {
    my $r = sysread($a, my $buf, 65536);
    defined $r or fail("server read: $!");
    last if !$r;
    $got .= $buf;
}
$got eq $data or fail("server got " . length($got) . " bytes");
my $off = 0;
while ($off < $n) { my $w = syswrite($a, $got, 65536, $off) // fail("server write: $!"); $off += $w }
close $a;
waitpid($pid, 0) == $pid or fail("waitpid: $!");
$? == 0 or fail("client exited " . ($? >> 8));
# Non-blocking: accept on an empty backlog, connect, select, SO_ERROR.
fcntl($l, F_SETFL, fcntl($l, F_GETFL, 0) | O_NONBLOCK) or fail("F_SETFL: $!");
accept(my $z, $l) and fail("non-blocking accept worked");
$!{EAGAIN} or fail("non-blocking accept: $!");
my $rin = ""; vec($rin, fileno($l), 1) = 1;
select(my $rout = $rin, undef, undef, 0) == 0 or fail("idle listener is readable");
my $nb = tcp();
fcntl($nb, F_SETFL, O_NONBLOCK) or fail("F_SETFL: $!");
connect($nb, pack_sockaddr_in($port, $lo)) or $!{EINPROGRESS} or fail("connect: $!");
my $win = ""; vec($win, fileno($nb), 1) = 1;
select(undef, my $wout = $win, undef, 5) == 1 or fail("connect never completed");
unpack("i", getsockopt($nb, SOL_SOCKET, SO_ERROR)) == 0 or fail("SO_ERROR");
select($rout = $rin, undef, undef, 5) == 1 or fail("listener never readable");
accept(my $b, $l) or fail("accept after select: $!");
syswrite($nb, "ping") == 4 or fail("write: $!");
my $p4 = "";
sysread($b, $p4, 4) == 4 && $p4 eq "ping" or fail("read back");
close $nb; close $b; close $l;
print "debian: sockets: refused, EADDRINUSE, 1 MiB each way, half-close, non-blocking connect and accept work\n";
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
    // TCP sockets on the cell's own stack (loopback).
    (&["perl", "-e", SOCKET_SCRIPT], 0),
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
