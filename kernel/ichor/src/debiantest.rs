//! Milestone 4, Phase D: Debian 12 (bookworm-slim) userland, unmodified,
//! in a cell. Its programs are glibc-linked: every run goes through
//! glibc's `ld-linux-x86-64.so.2` (`PT_INTERP`).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use frame::println;
use frame::sync::SpinLock;
use frame::task::TaskOptions;

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

/// Interval timers: `alarm` interrupts a sleep with SIGALRM and reports
/// what is left; a periodic `setitimer` (raw syscalls 36/38) keeps firing
/// and `getitimer` reads it back; disarming stops it.
const TIMER_SCRIPT: &str = r#"use strict; use warnings;
sub fail { print "debian: timers FAILED: @_\n"; exit 1 }
my $n = 0;
$SIG{ALRM} = sub { $n++ };
alarm(1) == 0 or fail("alarm was armed");
my $t0 = time;
select(undef, undef, undef, 10);
$n == 1 or fail("SIGALRM count $n");
time - $t0 < 5 or fail("the sleep was not interrupted");
alarm(30);
my $left = alarm(0);
$left >= 29 && $left <= 30 or fail("alarm left $left");
my $it = pack("q4", 0, 200000, 0, 200000);
my $none = pack("q4", 0, 0, 0, 0);
my $zero = 0;
syscall(38, $zero, $it, $zero) == 0 or fail("setitimer: $!");
my $cur = pack("q4", 0, 0, 0, 0);
syscall(36, $zero, $cur) == 0 or fail("getitimer: $!");
my @c = unpack("q4", $cur);
$c[0] == 0 && $c[1] == 200000 && $c[2] == 0 && $c[3] > 0 && $c[3] <= 200000 or fail("getitimer: @c");
$n = 0;
my $end = time + 20;
select(undef, undef, undef, 0.5) while $n < 3 && time < $end;
$n >= 3 or fail("periodic timer fired $n times");
syscall(38, $zero, $none, $zero) == 0 or fail("disarm: $!");
$n = 0;
select(undef, undef, undef, 0.6);
$n == 0 or fail("disarmed timer fired");
syscall(38, 1, $it, $zero) == -1 && $!{EINVAL} or fail("ITIMER_VIRTUAL accepted");
print "debian: alarm and setitimer deliver SIGALRM, getitimer reads back\n";
"#;

/// The server cell of the cross-cell run: `ME PEER PORT`. Accepts one
/// connection on `PORT`, checks both ends' addresses, reads to EOF and
/// answers with the peer's address and the byte count.
const CELL_SERVER: &str = r#"use strict; use warnings; use Socket;
sub fail { print "debian: cells FAILED (server): @_\n"; exit 1 }
my ($me, $peer, $port) = @ARGV;
socket(my $l, AF_INET, SOCK_STREAM, 0) or fail("socket: $!");
setsockopt($l, SOL_SOCKET, SO_REUSEADDR, 1) or fail("SO_REUSEADDR: $!");
bind($l, pack_sockaddr_in($port, INADDR_ANY)) or fail("bind: $!");
listen($l, 8) or fail("listen: $!");
my $from = accept(my $c, $l) or fail("accept: $!");
my (undef, $paddr) = unpack_sockaddr_in($from);
inet_ntoa($paddr) eq $peer or fail("peer is " . inet_ntoa($paddr) . ", not $peer");
my (undef, $laddr) = unpack_sockaddr_in(getsockname($c));
inet_ntoa($laddr) eq $me or fail("accepted on " . inet_ntoa($laddr));
my $n = 0;
while (1) {
    my $r = sysread($c, my $buf, 65536);
    defined $r or fail("read: $!");
    last if !$r;
    $n += $r;
}
syswrite($c, inet_ntoa($paddr) . " $n\n") or fail("write: $!");
close $c;
"#;

/// The client cell of the cross-cell run: `ME SERVER PORT`. Its own
/// loopback has no listener (stacks are per cell); the server's address
/// does, through the switch.
const CELL_CLIENT: &str = r#"use strict; use warnings; use Socket;
sub fail { print "debian: cells FAILED (client): @_\n"; exit 1 }
my ($me, $server, $port) = @ARGV;
socket(my $lo, AF_INET, SOCK_STREAM, 0) or fail("socket: $!");
connect($lo, pack_sockaddr_in($port, inet_aton("127.0.0.1"))) and fail("the other cell's listener is on my loopback");
$!{ECONNREFUSED} or fail("loopback: $!");
my $s;
for my $try (1 .. 400) {
    socket($s, AF_INET, SOCK_STREAM, 0) or fail("socket: $!");
    last if connect($s, pack_sockaddr_in($port, inet_aton($server)));
    $!{ECONNREFUSED} or fail("connect: $!");
    close $s; undef $s;
    select(undef, undef, undef, 0.05);
}
defined $s or fail("the server never listened");
my (undef, $laddr) = unpack_sockaddr_in(getsockname($s));
inet_ntoa($laddr) eq $me or fail("connected from " . inet_ntoa($laddr));
my $n = 1 << 20;
my $data = "x" x $n;
my $off = 0;
while ($off < $n) { my $w = syswrite($s, $data, 65536, $off) or fail("write: $!"); $off += $w }
shutdown($s, 1) or fail("shutdown: $!");
my $reply = "";
while (1) { my $r = sysread($s, my $buf, 4096); defined $r or fail("read: $!"); last if !$r; $reply .= $buf }
$reply eq "$me $n\n" or fail("reply [$reply]");
print "debian: cells: $me sent 1 MiB to $server through the switch; loopback is per cell\n";
"#;

/// A cell reaching the host through the uplink's NAT: `HOST PORT`, an echo
/// server on the test host.
const NAT_CLIENT: &str = r#"use strict; use warnings; use Socket;
sub fail { print "debian: nat FAILED: @_\n"; exit 1 }
my ($host, $port) = @ARGV;
socket(my $s, AF_INET, SOCK_STREAM, 0) or fail("socket: $!");
connect($s, pack_sockaddr_in($port, inet_aton($host))) or fail("connect: $!");
my $n = 256 * 1024;
my $data = substr(join("", map { chr } 0 .. 250) x (int($n / 251) + 1), 0, $n);
my $pid = fork() // fail("fork: $!");
if ($pid == 0) {
    my $off = 0;
    while ($off < $n) { my $w = syswrite($s, $data, 65536, $off) or exit 2; $off += $w }
    shutdown($s, 1) or exit 3;
    exit 0;
}
my $back = "";
while (1) { my $r = sysread($s, my $buf, 65536); defined $r or fail("read: $!"); last if !$r; $back .= $buf }
waitpid($pid, 0) == $pid && $? == 0 or fail("writer exited $?");
$back eq $data or fail("echo returned " . length($back) . " bytes");
print "debian: nat: a cell echoed 256 KiB with $host:$port through the uplink\n";
"#;

/// A published port's server: `PORT`. Serves one HTTP/1.0 request.
const PUBLISHED_SERVER: &str = r#"use strict; use warnings; use Socket;
sub fail { print "debian: published FAILED: @_\n"; exit 1 }
my ($port) = @ARGV;
socket(my $l, AF_INET, SOCK_STREAM, 0) or fail("socket: $!");
setsockopt($l, SOL_SOCKET, SO_REUSEADDR, 1) or fail("SO_REUSEADDR: $!");
bind($l, pack_sockaddr_in($port, INADDR_ANY)) or fail("bind: $!");
listen($l, 8) or fail("listen: $!");
print "debian: published: listening on port $port\n";
my $from = accept(my $c, $l) or fail("accept: $!");
my (undef, $paddr) = unpack_sockaddr_in($from);
my $req = "";
while ($req !~ /\r\n\r\n/) {
    my $r = sysread($c, my $buf, 4096);
    defined $r && $r or fail("request ended early [$req]");
    $req .= $buf;
}
$req =~ m{^GET / HTTP/1\.[01]\r\n} or fail("request [$req]");
my $body = "hello from an Ichor cell\n";
syswrite($c, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " . length($body) . "\r\n\r\n$body");
close $c;
print "debian: published: served a request from " . inet_ntoa($paddr) . "\n";
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
    (&["perl", "-e", TIMER_SCRIPT], 0),
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
    network(vfs, &system);
    println!("ichor: debian: all runs passed");
}

/// Debian's perl with `args` in `cell`, on this task.
fn perl(vfs: &Arc<Vfs>, cell: Arc<Cell>, script: &str, args: &[String]) -> i32 {
    let exe = read(vfs, "/usr/bin/perl");
    let interp = match loader::interp_path(&crate::file::Bytes(&exe)) {
        Ok(Some(p)) => read(vfs, &p),
        _ => fail("debian: perl is not dynamically linked"),
    };
    let p = LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("no process"));
    let mut argv: Vec<&str> = alloc::vec!["perl", "-e", script];
    argv.extend(args.iter().map(String::as_str));
    run_linux(p, &exe, Some(&interp), &argv).0
}

/// [`perl`] on a task of its own; the slot gets the exit code.
fn spawn_perl(
    vfs: &Arc<Vfs>,
    cell: Arc<Cell>,
    script: &'static str,
    args: Vec<String>,
) -> Arc<SpinLock<Option<i32>>> {
    let done = Arc::new(SpinLock::new(None));
    let (vfs, slot) = (vfs.clone(), done.clone());
    TaskOptions::new(move || {
        let code = perl(&vfs, cell, script, &args);
        *slot.lock() = Some(code);
    })
    .spawn()
    .unwrap_or_else(|| fail("debian: no task for a server cell"));
    done
}

fn wait_for(slot: &SpinLock<Option<i32>>, what: &str) -> i32 {
    let deadline = frame::time::now() + Duration::from_secs(120);
    loop {
        if let Some(code) = *slot.lock() {
            return code;
        }
        if frame::time::now() > deadline {
            fail(what);
        }
        frame::task::yield_now();
    }
}

fn cell_addr(cell: &Cell) -> String {
    match crate::netstack::stack_for(cell.id()).addr() {
        Some(a) => alloc::format!("{a}"),
        None => fail("debian: a cell got no address from the switch"),
    }
}

/// Cells on the cell switch: one cell serves another through it; with an
/// uplink, a cell reaches the test host through NAT (`net_echo_port`) and
/// serves the host on a published port (`net_publish`).
fn network(vfs: &Arc<Vfs>, system: &System) {
    let new_cell =
        || Cell::new(&system.root_account, CELL_PAGES).unwrap_or_else(|| fail("no debian cell"));
    let (server, client) = (new_cell(), new_cell());
    let (sa, ca) = (cell_addr(&server), cell_addr(&client));
    let port = String::from("7000");
    let (sid, cid) = (server.id(), client.id());
    let done = spawn_perl(
        vfs,
        server,
        CELL_SERVER,
        alloc::vec![sa.clone(), ca.clone(), port.clone()],
    );
    if perl(vfs, client, CELL_CLIENT, &[ca, sa, port]) != 0 {
        fail("debian: cross-cell client");
    }
    if wait_for(&done, "debian: the server cell never finished") != 0 {
        fail("debian: cross-cell server");
    }
    let (Some(s), Some(c)) = (crate::switch::stats(sid), crate::switch::stats(cid)) else {
        fail("debian: no switch counters");
    };
    println!(
        "ichor: debian: switch: server cell sent {} received {} dropped {}; client cell sent {} received {} dropped {}",
        s.0, s.1, s.2, c.0, c.1, c.2
    );
    if !crate::switch::has_uplink() {
        return;
    }
    let echo = crate::nettest::echo_port();
    if echo != 0 {
        let gw = String::from("10.0.2.2");
        if perl(vfs, new_cell(), NAT_CLIENT, &[gw, alloc::format!("{echo}")]) != 0 {
            fail("debian: NAT client");
        }
    }
    let publish = crate::nettest::publish_port();
    if publish != 0 {
        let cell = new_cell();
        let _ = cell_addr(&cell); // attach it to the switch
        if !crate::switch::publish(net::wire::PROTO_TCP, publish, cell.id(), 80) {
            fail("debian: could not publish the port");
        }
        if perl(vfs, cell, PUBLISHED_SERVER, &[String::from("80")]) != 0 {
            fail("debian: published server");
        }
        crate::switch::unpublish(net::wire::PROTO_TCP, publish);
    }
}
