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
connect($c, pack_sockaddr_in(1, $lo)) and fail("connect to a closed port worked the second time");
$!{ECONNREFUSED} or fail("closed port, again: $!");
# A listener on an ephemeral port; a second bind to it is refused.
my $l = tcp();
setsockopt($l, SOL_SOCKET, SO_REUSEADDR, 1) or fail("SO_REUSEADDR: $!");
bind($l, pack_sockaddr_in(0, $lo)) or fail("bind: $!");
listen($l, 16) or fail("listen: $!");
my ($port) = unpack_sockaddr_in(getsockname($l));
$port >= 32768 or fail("ephemeral port $port");
# The socket that was refused may connect after all.
connect($c, pack_sockaddr_in($port, $lo)) or fail("connect after a refusal: $!");
accept(my $ca, $l) or fail("accept after a refusal: $!");
close $ca; close $c;
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
        defined $r or do { print "debian: sockets: client read: $!\n"; POSIX::_exit(13) };
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
# TCP_INFO (iperf3 reads it every second): established is 1, listening 10.
my $ti = getsockopt($nb, 6, 11) // fail("TCP_INFO: $!");
length($ti) >= 104 && unpack("C", $ti) == 1 or fail("TCP_INFO state " . unpack("C", $ti));
unpack("C", getsockopt($l, 6, 11) // "") == 10 or fail("TCP_INFO of a listener");
select($rout = $rin, undef, undef, 5) == 1 or fail("listener never readable");
accept(my $b, $l) or fail("accept after select: $!");
syswrite($nb, "ping") == 4 or fail("write: $!");
my $p4 = "";
sysread($b, $p4, 4) == 4 && $p4 eq "ping" or fail("read back");
close $nb; close $b; close $l;
print "debian: sockets: refused, EADDRINUSE, 1 MiB each way, half-close, non-blocking connect and accept work\n";
# UDP: datagram boundaries, sources, truncation, connect, port spaces.
sub udp { socket(my $s, AF_INET, SOCK_DGRAM, 0) or fail("udp socket: $!"); $s }
my $u1 = udp();
bind($u1, pack_sockaddr_in(0, $lo)) or fail("udp bind: $!");
my ($up) = unpack_sockaddr_in(getsockname($u1));
my $u2 = udp();
unpack("i", getsockopt($u2, SOL_SOCKET, SO_TYPE)) == SOCK_DGRAM or fail("udp SO_TYPE");
send($u2, "one", 0, pack_sockaddr_in($up, $lo)) == 3 or fail("udp send: $!");
send($u2, "two!", 0, pack_sockaddr_in($up, $lo)) == 4 or fail("udp send 2: $!");
my ($u2p) = unpack_sockaddr_in(getsockname($u2));
$u2p >= 32768 or fail("udp autobind port $u2p");
my $rin2 = ""; vec($rin2, fileno($u1), 1) = 1;
select(my $rout2 = $rin2, undef, undef, 5) == 1 or fail("udp not readable");
my $from = recv($u1, my $m, 100, 0) // fail("udp recv: $!");
$m eq "one" or fail("udp got [$m]");
my ($fp, $fa) = unpack_sockaddr_in($from);
$fp == $u2p && inet_ntoa($fa) eq "127.0.0.1" or fail("udp source $fp");
recv($u1, $m, 2, 0) // fail("udp recv 2: $!");
$m eq "tw" or fail("udp truncation gave [$m]");
connect($u1, $from) or fail("udp connect: $!");
syswrite($u1, "back") == 4 or fail("udp write: $!");
sysread($u2, $m, 100) == 4 && $m eq "back" or fail("udp read back [$m]");
my ($pp) = unpack_sockaddr_in(getpeername($u1));
$pp == $u2p or fail("udp getpeername");
# A connected socket hears only its peer.
my $u3 = udp();
send($u3, "stranger", 0, pack_sockaddr_in($up, $lo)) == 8 or fail("udp send 3: $!");
send($u2, "friend", 0, pack_sockaddr_in($up, $lo)) == 6 or fail("udp send 4: $!");
sysread($u1, $m, 100) == 6 && $m eq "friend" or fail("connected socket got [$m]");
# UDP and TCP have separate port spaces; a second UDP bind is refused.
my $t = tcp();
bind($t, pack_sockaddr_in($up, $lo)) or fail("tcp could not share the udp port number: $!");
my $u4 = udp();
bind($u4, pack_sockaddr_in($up, $lo)) and fail("second udp bind worked");
$!{EADDRINUSE} or fail("second udp bind: $!");
listen($u4, 1) and fail("listen on udp worked");
fcntl($u2, F_SETFL, O_NONBLOCK) or fail("F_SETFL: $!");
defined(sysread($u2, $m, 100)) and fail("empty udp read returned");
$!{EAGAIN} or fail("empty non-blocking udp read: $!");
# A connected socket learns that nobody listens, once; another does not.
my $gone = udp();
bind($gone, pack_sockaddr_in(0, $lo)) or fail("udp bind: $!");
my $dead = getsockname($gone);
close $gone;
my $u5 = udp();
connect($u5, $dead) or fail("udp connect: $!");
syswrite($u5, "anyone?") == 7 or fail("udp write to a closed port: $!");
my $rin5 = ""; vec($rin5, fileno($u5), 1) = 1;
select(my $rout5 = $rin5, undef, undef, 5) == 1 or fail("an error does not make a socket ready");
defined(sysread($u5, $m, 100)) and fail("read from a closed port");
$!{ECONNREFUSED} or fail("a closed udp port: $!");
unpack("i", getsockopt($u5, SOL_SOCKET, SO_ERROR)) == 0 or fail("the error stayed");
send($u3, "anyone?", 0, $dead) == 7 or fail("udp send to a closed port: $!");
unpack("i", getsockopt($u3, SOL_SOCKET, SO_ERROR)) == 0 or fail("an unconnected socket got an error");
# The error queue (IP_RECVERR) can be had, and is empty.
setsockopt($u3, 0, 11, 1) or fail("IP_RECVERR: $!");
defined(recv($u3, $m, 100, 0x2000)) and fail("an error in the error queue");
$!{EAGAIN} or fail("the error queue: $!");
# glibc's resolver, asking a name server here: one that knows one address.
open(my $rc, ">", "/etc/resolv.conf") or fail("resolv.conf: $!");
print $rc "nameserver 127.0.0.1\n";
close $rc;
my $dns = udp();
bind($dns, pack_sockaddr_in(53, $lo)) or fail("bind to port 53: $!");
my $server = fork() // fail("fork: $!");
if ($server == 0) {
    while (defined(my $who = recv($dns, my $q, 512, 0))) {
        my ($name, $type) = unpack("x12 Z* n", $q);
        my $end = 12 + length($name) + 5;
        my $a = $type == 1 ? pack("n n n N n C4", 0xc00c, 1, 1, 60, 4, 192, 0, 2, 7) : "";
        my $r = substr($q, 0, 2) . pack("n5", 0x8180, 1, $a ne "" ? 1 : 0, 0, 0);
        send($dns, $r . substr($q, 12, $end - 12) . $a, 0, $who);
    }
    POSIX::_exit(1);
}
my $named = gethostbyname("ichor.test") or fail("gethostbyname: $?");
inet_ntoa($named) eq "192.0.2.7" or fail("gethostbyname: " . inet_ntoa($named));
my ($gai, @found) = Socket::getaddrinfo("ichor.test", "80", { socktype => SOCK_STREAM });
$gai and fail("getaddrinfo: $gai");
@found == 1 && (unpack_sockaddr_in($found[0]{addr}))[0] == 80 or fail("getaddrinfo: " . @found);
kill(9, $server); waitpid($server, 0);
print "debian: udp: datagrams keep boundaries and sources, truncate, connect filters, ports are per protocol\n";
"#;

/// Signals beyond delivery to a handler: stopping and continuing (what
/// `waitpid` reports, a sleep that goes on over it), who sent one, queued
/// real-time ones, `rt_sigtimedwait`, children nobody waits for, POSIX and
/// CPU-time timers, and process descriptors.
const SIGNAL_SCRIPT: &str = r#"use strict; use warnings; use Errno;
use POSIX qw(:signal_h :sys_wait_h setpgid);
$| = 1;
my $pid;
sub fail { print "debian: signals FAILED: @_\n"; kill KILL => $pid if $pid; POSIX::_exit(1) }
my $WCONTINUED = 8;
sub child { my $f = shift; my $pid = fork() // fail("fork: $!"); if (!$pid) { $f->(); POSIX::_exit(0) } $pid }
# The status as the kernel gave it ($? leaves stops out).
our $status = 0;
sub native { $status }
BEGIN {
    package Wait;
    *main::waitpid = sub { my $s = "\0" x 4; my $r = syscall(61, $_[0] + 0, $s, $_[1] + 0, 0); $main::status = unpack("I", $s); $r };
}
$SIG{ALRM} = sub { my (undef, undef, $l) = caller; fail("timed out at line $l") };
alarm 60;
# Stop and continue, each reported once.
$pid = child(sub { setpgid(0, 0); while (1) { select(undef, undef, undef, 1) } });
setpgid($pid, $pid);
for my $sig (SIGSTOP, SIGTSTP) {
    kill $sig => $pid or fail("kill $sig: $!");
    waitpid($pid, WUNTRACED) == $pid or fail("wait for a stop: $!");
    (native() & 0xff) == 0x7f && native() >> 8 == $sig or fail("stop status " . native());
    waitpid($pid, WUNTRACED | WNOHANG) == 0 or fail("stop reported twice");
    kill CONT => $pid;
    waitpid($pid, $WCONTINUED) == $pid && native() == 0xffff or fail("continue status " . native());
    waitpid($pid, $WCONTINUED | WNOHANG) == 0 or fail("continue reported twice");
}
# A stopped process dies of SIGKILL, not of a pending SIGTERM.
kill STOP => $pid; waitpid($pid, WUNTRACED) == $pid or fail("stop: $!");
kill TERM => $pid;
waitpid($pid, WNOHANG) == 0 or fail("a stopped process took SIGTERM");
kill KILL => $pid;
waitpid($pid, 0) == $pid && native() == SIGKILL or fail("kill status " . native());
# A sleep goes on over a stop, to its own deadline.
sub now { my $ts = "\0" x 16; syscall(228, 1, $ts); my ($s, $n) = unpack("qq", $ts); $s + $n / 1e9 }
$pid = child(sub {
    my $t = now();
    select(undef, undef, undef, 0.4) == 0 or POSIX::_exit(2);
    POSIX::_exit(now() - $t < 0.39 ? 3 : 0);
});
select(undef, undef, undef, 0.05);
kill STOP => $pid; waitpid($pid, WUNTRACED) == $pid or fail("stop a sleeper: $!");
kill CONT => $pid;
waitpid($pid, 0) == $pid && native() == 0 or fail("the sleeper ended with " . native());
# Who sent it. (Perl runs this kind of handler at once, wherever it is, so
# let it be in sigsuspend.)
my ($from, $code);
sigprocmask(SIG_BLOCK, POSIX::SigSet->new(SIGUSR1)) or fail("sigprocmask: $!");
my $act = POSIX::SigAction->new(sub { $from = $_[1]{pid}; $code = $_[1]{code} }, POSIX::SigSet->new, SA_SIGINFO);
sigaction(SIGUSR1, $act) or fail("sigaction: $!");
my $me = $$;
$pid = child(sub { kill USR1 => $me });
waitpid($pid, 0) == $pid or fail("a blocked signal interrupted a wait: $!");
POSIX::sigsuspend(POSIX::SigSet->new);
defined $from or fail("sigsuspend returned without its signal");
$from == $pid && $code == 0 or fail("SIGUSR1 from " . $from . " code " . $code);
# Real-time signals queue, with their values; taken by rt_sigtimedwait.
my $set = POSIX::SigSet->new(40, 41, SIGCHLD);
sigprocmask(SIG_BLOCK, $set) or fail("sigprocmask: $!");
sub info { pack("i i i i i I q x96", $_[0], 0, -1, 0, $$, 0, $_[1]) }
syscall(129, $$, 40, my $one = info(40, 111)) == 0 or fail("sigqueue: $!");
syscall(129, $$, 40, my $two = info(40, 222)) == 0 or fail("sigqueue: $!");
sub timedwait {
    my ($bits, $sec) = @_;
    my ($s, $i, $t) = (pack("Q", $bits), "\0" x 128, pack("qq", $sec, 0));
    my $r = syscall(128, $s, $i, $t, 8);
    ($r, unpack("x8 i x12 q", $i));
}
for my $want (111, 222) {
    my ($r, $c, $v) = timedwait(1 << 39, 5);
    $r == 40 && $c == -1 && $v == $want or fail("sigtimedwait gave $r, code $c, value $v");
}
my ($r) = timedwait(1 << 39, 0);
$r == -1 && $!{EAGAIN} or fail("empty sigtimedwait gave $r: $!");
$pid = child(sub { select(undef, undef, undef, 0.05) });
($r, $code) = timedwait(1 << (SIGCHLD - 1), 5);
$r == SIGCHLD && $code == 1 or fail("waiting for SIGCHLD gave $r, code $code");
waitpid($pid, 0);
# A POSIX timer.
my $ev = pack("Q i i x48", 77, 41, 0);
my $id = pack("i", -1);
syscall(222, 1, $ev, $id) == 0 or fail("timer_create: $!");
$id = unpack("i", $id);
my $spec = pack("q4", 0, 0, 0, 10_000_000);
syscall(223, $id, 0, $spec, 0) == 0 or fail("timer_settime: $!");
($r, $code, my $v) = timedwait(1 << 40, 5);
$r == 41 && $code == -2 && $v == 77 or fail("timer gave $r, code $code, value $v");
syscall(226, $id) == 0 or fail("timer_delete: $!");
syscall(226, $id) == -1 && $!{EINVAL} or fail("a deleted timer is still there");
# CPU time: ITIMER_PROF fires while computing.
my $prof = 0;
$SIG{PROF} = sub { $prof++ };
my $it = pack("q4", 0, 20_000, 0, 20_000);
syscall(38, 2, $it, 0) == 0 or fail("setitimer: $!");
my $x = 0;
while ($prof < 3) { $x += $_ for 1 .. 10000 }
$it = "\0" x 32;
syscall(38, 2, $it, 0) == 0 or fail("setitimer off: $!");
# Process descriptors.
$pid = child(sub { while (1) { select(undef, undef, undef, 1) } });
my $fd = syscall(434, $pid, 0);
$fd >= 0 or fail("pidfd_open: $!");
my $rin = ""; vec($rin, $fd, 1) = 1;
select(my $rout = $rin, undef, undef, 0) == 0 or fail("a running process's pidfd is readable");
syscall(424, $fd, SIGTERM, 0, 0) == 0 or fail("pidfd_send_signal: $!");
select($rout = $rin, undef, undef, 5) == 1 or fail("an exited process's pidfd is not readable");
my $si = "\0" x 128;
syscall(247, 3, $fd, $si, 4, 0) == 0 or fail("waitid(P_PIDFD): $!");
my ($signo, $c2, $spid, $st) = unpack("i x4 i x4 i x4 i", $si);
$signo == SIGCHLD && $c2 == 2 && $spid == $pid && $st == SIGTERM or fail("waitid: $signo $c2 $spid $st");
syscall(434, $pid, 0) == -1 && $!{ESRCH} or fail("a reaped process still opens");
# Timers and signals as descriptors.
my $tfd = syscall(283, 1, 04000);
$tfd >= 0 or fail("timerfd_create: $!");
$spec = pack("q4", 0, 10_000_000, 0, 10_000_000);
syscall(286, $tfd, 0, $spec, 0) == 0 or fail("timerfd_settime: $!");
$rin = ""; vec($rin, $tfd, 1) = 1;
select($rout = $rin, undef, undef, 5) == 1 or fail("the timer never expired");
select(undef, undef, undef, 0.03);
open(my $th, "<&=", $tfd) or fail("fdopen: $!");
my $count = "";
sysread($th, $count, 8) == 8 && unpack("Q", $count) >= 2 or fail("timer read: $!");
sigprocmask(SIG_BLOCK, POSIX::SigSet->new(SIGUSR2)) or fail("sigprocmask: $!");
my $mask = pack("Q", 1 << (SIGUSR2 - 1));
my $sfd = syscall(289, -1, $mask, 8, 04000);
$sfd >= 0 or fail("signalfd: $!");
$rin = ""; vec($rin, $sfd, 1) = 1;
select($rout = $rin, undef, undef, 0) == 0 or fail("an empty signalfd is readable");
$pid = child(sub { kill USR2 => $me });
select($rout = $rin, undef, undef, 5) == 1 or fail("the signal never arrived");
open(my $sh, "<&=", $sfd) or fail("fdopen: $!");
sysread($sh, my $rec, 1024) == 128 or fail("signalfd read: $!");
($signo, my $spid2) = unpack("I x8 I", $rec);
$signo == SIGUSR2 && $spid2 == $pid or fail("signalfd gave $signo from $spid2");
waitpid($pid, 0);
# An epoll instance watching another.
my ($outer, $inner) = (syscall(291, 0), syscall(291, 0));
pipe(my $pr, my $pw) or fail("pipe: $!");
my $eev = pack("I Q", 1, 7);
syscall(233, $inner, 1, fileno $pr, $eev) == 0 && syscall(233, $outer, 1, $inner, $eev) == 0 or fail("epoll_ctl: $!");
syscall(233, $inner, 1, $outer, $eev) == -1 && $!{ELOOP} or fail("epoll instances in a circle: $!");
my $evs = "\0" x 48;
syscall(232, $outer, $evs, 4, 0) == 0 or fail("an idle nested epoll is ready");
$pid = child(sub { select(undef, undef, undef, 0.05); syswrite($pw, "x") });
syscall(232, $outer, $evs, 4, 5000) == 1 or fail("a nested epoll never became ready");
waitpid($pid, 0);
# Children of a process that ignores SIGCHLD are not waited for.
$SIG{CHLD} = "IGNORE";
$pid = child(sub { });
waitpid($pid, 0) == -1 && $!{ECHILD} or fail("an ignored child was waited for");
print "debian: signals: stop and continue, senders, queues, timers and process descriptors work\n";
"#;

/// Moving and looking at bytes inside the kernel: `splice`, `tee`,
/// `copy_file_range`, gathered writes, `MSG_PEEK`, `FIONREAD`, socket
/// timeouts, and what netlink and the interface ioctls say of the cell.
const MOVE_SCRIPT: &str = r#"use strict; use warnings; use Socket; use Errno; use Fcntl;
sub fail { print "debian: moves FAILED: @_\n"; exit 1 }
$SIG{ALRM} = sub { fail("timed out") };
alarm 60;
my $m;
sub full { my ($f, $n) = @_; my $got = ""; while (length $got < $n) { sysread($f, $got, $n - length $got, length $got) or last } $got }
pipe(my $r, my $w) or fail("pipe: $!");
socketpair(my $a, my $b, AF_UNIX, SOCK_STREAM, 0) or fail("socketpair: $!");
my ($rf, $wf, $af) = (fileno $r, fileno $w, fileno $a);
# Pipe to socket, socket to pipe, file to pipe, pipe to file.
syswrite($w, "hello splice") == 12 or fail("write: $!");
syscall(275, $rf, 0, $af, 0, 100, 0) == 12 or fail("splice to a socket: $!");
full($b, 12) eq "hello splice" or fail("spliced bytes");
syswrite($b, "back") == 4 or fail("write: $!");
syscall(275, $af, 0, $wf, 0, 100, 0) == 4 or fail("splice from a socket: $!");
full($r, 4) eq "back" or fail("bytes spliced back");
my $p = "/tmp/ichor-move";
open(my $f, "+>", $p) or fail("open: $!");
syswrite($f, "0123456789" x 100) == 1000 or fail("write: $!");
my $off = pack("q", 10);
syscall(275, fileno $f, $off, $wf, 0, 20, 0) == 20 or fail("splice from a file: $!");
unpack("q", $off) == 30 or fail("the offset did not move");
# tee leaves what it copies; a full copy then goes to a file.
pipe(my $r2, my $w2) or fail("pipe: $!");
syscall(276, $rf, fileno $w2, 100, 0) == 20 or fail("tee: $!");
full($r2, 20) eq "0123456789" x 2 or fail("teed bytes");
open(my $g, "+>", "$p.2") or fail("open: $!");
syscall(275, $rf, 0, fileno $g, 0, 100, 0) == 20 or fail("splice to a file: $!");
sysseek($g, 0, 0); full($g, 20) eq "0123456789" x 2 or fail("bytes spliced to a file");
# Refusals.
syscall(275, fileno $f, 0, fileno $g, 0, 1, 0) == -1 && $!{EINVAL} or fail("splice without a pipe: $!");
$off = pack("q", 0);
syscall(275, $rf, $off, $af, 0, 1, 0) == -1 && $!{ESPIPE} or fail("splice at a pipe's offset: $!");
syscall(275, $rf, 0, $af, 0, 1, 2) == -1 && $!{EAGAIN} or fail("splice of an empty pipe: $!");
# A socket that takes only part leaves the rest in the pipe.
fcntl($a, F_SETFL, O_NONBLOCK) or fail("fcntl: $!");
my $big = join("", map { chr(33 + $_ % 90) } 0 .. 59999);
my ($in, $out) = (0, "");
while (1) {
    syswrite($w, $big) == length $big or fail("write: $!") if $in == 0;
    my $n = syscall(275, $rf, 0, $af, 0, 1 << 20, 0);
    if ($n < 0) { $!{EAGAIN} or fail("splice: $!"); last }
    $in = ($in + $n) % length $big;
}
my $queued = pack("i", 0);
ioctl($r, 0x541b, $queued) or fail("FIONREAD: $!");
unpack("i", $queued) == length($big) - $in or fail("the pipe holds " . unpack("i", $queued) . ", not " . (length($big) - $in));
ioctl($b, 0x541b, $queued) or fail("FIONREAD: $!");
my $sock = unpack("i", $queued);
my $all = full($b, $sock);
$all eq substr($big x 10, 0, $sock) or fail("the socket's bytes are not in order");
full($r, length($big) - $in) eq substr($big, $in) or fail("the pipe's bytes are not in order");
# copy_file_range, and an overlapping one.
my ($o1, $o2) = (pack("q", 5), pack("q", 0));
syscall(326, fileno $f, $o1, fileno $g, $o2, 995, 0) == 995 or fail("copy_file_range: $!");
sysseek($g, 0, 0); full($g, 995) eq substr("0123456789" x 100, 5) or fail("copied bytes");
($o1, $o2) = (pack("q", 0), pack("q", 50));
syscall(326, fileno $f, $o1, fileno $f, $o2, 100, 0) == -1 && $!{EINVAL} or fail("overlapping copy: $!");
# Peeking, on a stream and at a datagram.
for my $fam ([AF_UNIX, SOCK_STREAM], [AF_UNIX, SOCK_DGRAM]) {
    socketpair(my $s, my $t, $fam->[0], $fam->[1], 0) or fail("socketpair: $!");
    syswrite($s, "peekaboo") == 8 or fail("write: $!");
    for (1, 2) { defined recv($t, $m, 4, MSG_PEEK) && $m eq "peek" or fail("MSG_PEEK gave [$m]: $!") }
    sysread($t, $m, 100) == 8 && $m eq "peekaboo" or fail("read after a peek [$m]");
    # A receive timeout.
    setsockopt($t, SOL_SOCKET, SO_RCVTIMEO, pack("qq", 0, 30_000)) or fail("SO_RCVTIMEO: $!");
    join(",", unpack("qq", getsockopt($t, SOL_SOCKET, SO_RCVTIMEO))) eq "0,30000" or fail("SO_RCVTIMEO reads back wrong");
    !defined(sysread($t, $m, 1)) && $!{EAGAIN} or fail("a timed read gave $!");
}
# TCP: 0.0.0.0 is this host; peeking; a reset on close without lingering.
socket(my $l, AF_INET, SOCK_STREAM, 0) or fail("socket: $!");
listen($l, 1) or fail("listen: $!");
my ($port) = unpack_sockaddr_in(getsockname($l));
socket(my $c, AF_INET, SOCK_STREAM, 0) or fail("socket: $!");
connect($c, pack_sockaddr_in($port, INADDR_ANY)) or fail("connect to 0.0.0.0: $!");
accept(my $s, $l) or fail("accept: $!");
syswrite($c, "peek") == 4 or fail("write: $!");
for (1, 2) { defined recv($s, $m, 2, MSG_PEEK) && $m eq "pe" or fail("TCP MSG_PEEK gave [$m]: $!") }
sysread($s, $m, 10) == 4 or fail("read: $!");
setsockopt($c, SOL_SOCKET, SO_LINGER, pack("ii", 1, 0)) or fail("SO_LINGER: $!");
close $c;
!defined(sysread($s, $m, 1)) && $!{ECONNRESET} or fail("no reset from a close without lingering");
# Two listeners share a port, and its connections; a third may not.
my (@shared, @counts, @clients);
for my $n (0, 1) {
    socket($shared[$n], AF_INET, SOCK_STREAM, 0) or fail("socket: $!");
    setsockopt($shared[$n], SOL_SOCKET, 15, 1) or fail("SO_REUSEPORT: $!");
    bind($shared[$n], pack_sockaddr_in(4712, inet_aton("127.0.0.1"))) or fail("shared bind: $!");
    listen($shared[$n], 64) or fail("shared listen: $!");
    fcntl($shared[$n], F_SETFL, O_NONBLOCK);
}
socket(my $alone, AF_INET, SOCK_STREAM, 0) or fail("socket: $!");
bind($alone, pack_sockaddr_in(4712, inet_aton("127.0.0.1"))) and fail("bound a port others share");
for (1 .. 32) {
    socket(my $cc, AF_INET, SOCK_STREAM, 0) or fail("socket: $!");
    connect($cc, pack_sockaddr_in(4712, inet_aton("127.0.0.1"))) or fail("connect: $!");
    push @clients, $cc;
}
for my $n (0, 1) { while (accept(my $ac, $shared[$n])) { $counts[$n]++ } }
($counts[0] // 0) > 0 && ($counts[1] // 0) > 0 && $counts[0] + $counts[1] == 32 or fail("a shared port gave " . join(",", map { $_ // 0 } @counts));
# What the cell's interfaces are.
socket(my $n, 16, 3, 0) or fail("netlink: $!");
send($n, pack("L S S L L C x3", 20, 22, 0x301, 1, 0, 0), 0) == 20 or fail("netlink send: $!");
my $answer = "";
while (1) {
    defined recv($n, $m, 8192, 0) or fail("netlink recv: $!");
    $answer .= $m;
    last if unpack("x4 S", $m) == 3;
}
index($answer, "lo\0") > 0 && index($answer, inet_aton("127.0.0.1")) > 0 or fail("no loopback address");
my $req = pack("a16 x24", "lo");
ioctl($l, 0x8913, $req) or fail("SIOCGIFFLAGS: $!");
(unpack("x16 S", $req) & 0x49) == 0x49 or fail("loopback flags");
open(my $tty, "<", "/dev/tty") and fail("/dev/tty opened without a terminal");
$!{ENXIO} or fail("/dev/tty: $!");
# inotify on a directory.
my $d = "/tmp/ichor-watched";
mkdir $d or fail("mkdir: $!");
my $ifd = syscall(294, 04000);
$ifd >= 0 or fail("inotify_init1: $!");
my $wd = syscall(254, $ifd, $d, 0xfff);
$wd > 0 or fail("inotify_add_watch: $!");
open(my $nf, ">", "$d/f") or fail("open: $!");
syswrite($nf, "x"); syswrite($nf, "y"); close $nf;
rename "$d/f", "$d/g"; chmod 0600, "$d/g"; unlink "$d/g"; rmdir $d or fail("rmdir: $!");
open(my $inh, "<&=", $ifd) or fail("fdopen: $!");
my ($buf, $seen, $cookies) = ("", "", "");
sysread($inh, $buf, 8192) or fail("inotify read: $!");
while (length $buf) {
    my ($w, $mask, $cookie, $len) = unpack("iIII", $buf);
    my $name = unpack("Z*", substr($buf, 16, $len));
    $w == $wd or fail("event for watch $w");
    $cookies .= "$cookie " if $mask & 0xc0;
    $seen .= sprintf("%x%s ", $mask, $name);
    substr($buf, 0, 16 + $len) = "";
}
$seen eq "100f 20f 2f 8f 40f 80g 4g 200g 40000400 8000 " or fail("inotify saw $seen");
$cookies =~ /^([1-9]\d*) \1 $/ or fail("move cookies $cookies");
!defined(sysread($inh, $buf, 8192)) && $!{EAGAIN} or fail("inotify has more to say");
readlink("/proc/self/fd/" . fileno $f) eq $p or fail("/proc/self/fd names " . readlink("/proc/self/fd/" . fileno $f));
system("/usr/bin/perl", "-e", 'system("/proc/self/exe", "-e", "exit 3"); exit($? >> 8)');
$? >> 8 == 3 or fail("/proc/self/exe ran with status $?");
# System V shared memory: shared over fork, attachments counted, removed
# with the last one.
my $id = shmget(4711, 5000, 01600) // fail("shmget: $!");
shmget(4711, 5000, 03600) and fail("an exclusive shmget of a key in use worked");
$!{EEXIST} or fail("exclusive shmget: $!");
shmget(4711, 5000, 0) == $id or fail("the key finds another segment");
my $at = syscall(30, $id, 0, 0);
$at > 0 or fail("shmat: $!");
sub put { my ($a, $s) = @_; pipe(my $pr, my $pw); syswrite($pw, $s); syscall(0, fileno $pr, $a, length $s) == length $s or fail("write to shared memory: $!") }
sub peek { unpack("P$_[1]", pack("Q", $_[0])) }
sub attached { shmctl($id, 2, my $ds) or return -1; unpack("x88 Q", $ds) }
put($at + 4096, "hello");
my $pid = fork() // fail("fork: $!");
if (!$pid) { peek($at + 4096, 5) eq "hello" or exit 2; attached() == 2 or exit 3; put($at, "world"); kill KILL => $$ }
waitpid($pid, 0); $? == 9 or fail("the child ended with $?");
peek($at, 5) eq "world" or fail("the child's write is not shared");
attached() == 1 or fail("a killed child still counts: " . attached());
shmctl($id, 0, 0) or fail("IPC_RMID: $!");
attached() == 1 or fail("a removed segment went with an attachment left");
syscall(67, $at) == 0 or fail("shmdt: $!");
attached() == -1 && $!{EINVAL} or fail("a removed segment outlived its attachments");
# A FIFO opened for both: no peer needed, and it is its own.
require POSIX;
unlink "/tmp/both"; POSIX::mkfifo("/tmp/both", 0600) or fail("mkfifo: $!");
sysopen(my $both, "/tmp/both", O_RDWR) or fail("O_RDWR FIFO: $!");
(fcntl($both, F_GETFL, 0) & 3) == O_RDWR or fail("F_GETFL of an O_RDWR FIFO");
syswrite($both, "round") == 5 && sysread($both, $m, 10) == 5 && $m eq "round" or fail("through an O_RDWR FIFO: $!");
sysopen(my $one, "/tmp/both", O_WRONLY | O_NONBLOCK) or fail("a writer beside it: $!");
(stat $both)[0] == (stat "/tmp/both")[0] && (stat _)[1] == (stat $both)[1] or fail("an open FIFO is not the FIFO");
close $both;
# A descriptor that only names a file, a symlink itself included.
unlink "/tmp/named"; symlink("both", "/tmp/named") or fail("symlink: $!");
sysopen(my $named, "/tmp/named", 010000000 | 0400000) or fail("O_PATH of a symlink: $!");
((stat $named)[2] & 0170000) == 0120000 or fail("O_PATH followed the symlink");
defined(sysread($named, $m, 1)) and fail("read through O_PATH");
$!{EBADF} or fail("read through O_PATH: $!");
sysopen(my $null, "/dev/null", O_RDWR) or fail("/dev/null: $!");
sysseek($null, 100, 0) or fail("seek in /dev/null: $!");
open(my $perl, "<", "/usr/bin/perl") or fail("open: $!");
my $before = pack("q", -1);
syscall(40, $wf, fileno $perl, $before, 10) == -1 && $!{EINVAL} or fail("sendfile from before the start: $!");
sysopen(my $pdir, "/proc/$$", O_RDONLY) or fail("/proc/<pid>: $!");
syscall(424, fileno $pdir, 0, 0, 0) == 0 or fail("a signal by /proc/<pid>: $!");
syscall(424, $wf, 0, 0, 0) == -1 && $!{EBADF} or fail("a signal by a pipe: $!");
# A futex waits until a time of the wall clock, not for ever.
for my $when (time + 1, time - 100) {
    my ($word, $ts) = (pack("L", 5), pack("qq", $when, 0));
    syscall(202, $word, 9 | 256, 5, $ts, 0, 0xffffffff) == -1 && $!{ETIMEDOUT} or fail("a wall-clock futex wait: $!");
    time - $when < 30 or $when < time - 50 or fail("a wall-clock futex wait was late");
}
# A process's files in /proc are its user's; with the machine's boot time
# they say when it began.
my $kid = fork // fail("fork: $!");
if ($kid == 0) { $) = "33 33"; $> = 33; sleep 60; exit 0 }
for (1 .. 3000) { last if (stat "/proc/$kid")[4] == 33; select undef, undef, undef, 0.01 }
(stat "/proc/$kid/status")[4] == 33 && (stat "/proc/$kid")[5] == 33 or fail("/proc/<pid> is not its user's");
open(my $kst, "<", "/proc/$kid/stat") or fail("stat: $!");
(stat $kst)[4] == 33 && (stat $kst)[1] == (stat "/proc/$kid/stat")[1] or fail("fstat in /proc");
my $began = (split / /, (<$kst> =~ /.*\) (.*)/s)[0])[19] / 100;
my ($btime) = `cat /proc/stat` =~ /^btime (\d+)$/m;
abs($btime + $began - time) < 120 or fail("booted at $btime, began $began later");
kill "KILL", $kid; waitpid($kid, 0);
{ local $SIG{PIPE} = "IGNORE"; defined(syswrite($one, "x")) and fail("a write with no reader left"); $!{EPIPE} or fail("no reader: $!") }
# A title written over argv is what /proc shows; many arguments, long ones.
$0 = "a title";
open(my $cf, "<", "/proc/self/cmdline") or fail("cmdline: $!");
my $cmdline = <$cf>;
$cmdline =~ /^a title\0*$/ or fail("cmdline is $cmdline");
seek($cf, 2, 0) && <$cf> =~ /^title/ or fail("seek in /proc: $!");
open(my $maps, "-|", "cat", "/proc/self/maps") or fail("maps: $!");
my @maps = <$maps>;
my $ino = (stat("/usr/bin/cat"))[1];
(grep { m{^[0-9a-f]+-[0-9a-f]+ r-xp [0-9a-f]{8} 00:01 $ino +/usr/bin/cat$} } @maps) == 1 or fail("cat is not mapped: @maps");
(grep { / \[stack\]$/ } @maps) == 1 && (grep { / \[heap\]$/ } @maps) == 1 or fail("no stack or heap: @maps");
system("/bin/sh", "-c", '[ $# = 20000 ] && [ ${#1} = 100000 ]', "sh", "x" x 100000, ("y") x 19999) == 0 or fail("20000 arguments: $?");
system("/bin/true", "x" x 140000) != 0 && $!{E2BIG} or fail("an argument over 128 KiB: $!");
print "debian: moves: splice, tee, copy_file_range, MSG_PEEK, timeouts, netlink, inotify and shared memory work\n";
"#;

/// `AF_UNIX`: a socketpair with credentials and end of file; a stream
/// server on a path in the root (a socket node, EADDRINUSE, a forked client
/// sending 300 KB through a half-close, ECONNREFUSED once it is gone);
/// datagrams between abstract names with sources and truncation.
const UNIX_SCRIPT: &str = r#"use strict; use warnings; use Socket; use POSIX ();
sub fail { print "debian: unix FAILED: @_\n"; exit 1 }
sub sock { socket(my $s, AF_UNIX, $_[0], 0) or fail("socket: $!"); $s }
my $m;
socketpair(my $a, my $b, AF_UNIX, SOCK_STREAM, 0) or fail("socketpair: $!");
syswrite($a, "ping") == 4 or fail("write: $!");
sysread($b, $m, 100) == 4 && $m eq "ping" or fail("read [$m]");
my ($cpid, $cuid) = unpack("iII", getsockopt($b, SOL_SOCKET, SO_PEERCRED));
$cpid == $$ && $cuid == 0 or fail("SO_PEERCRED $cpid $cuid, I am $$");
unpack("i", getsockopt($a, SOL_SOCKET, SO_TYPE)) == SOCK_STREAM or fail("SO_TYPE");
readlink("/proc/self/fd/" . fileno($a)) =~ /^socket:\[\d+\]$/ or fail("/proc/self/fd link");
close $a;
sysread($b, $m, 100) == 0 or fail("no end of file after the peer closed");
my $path = "/tmp/ichor-unix.sock";
unlink $path;
my $l = sock(SOCK_STREAM);
bind($l, pack_sockaddr_un($path)) or fail("bind: $!");
-S $path or fail("no socket node at $path");
listen($l, 4) or fail("listen: $!");
my $d = sock(SOCK_STREAM);
bind($d, pack_sockaddr_un($path)) and fail("a second bind worked");
$!{EADDRINUSE} or fail("second bind: $!");
open(my $fh, "<", $path) and fail("open of a socket node worked");
my $n = 300_000;
my $pid = fork() // fail("fork: $!");
if ($pid == 0) {
    my $c = sock(SOCK_STREAM);
    connect($c, pack_sockaddr_un($path)) or POSIX::_exit(10);
    unpack_sockaddr_un(getpeername($c)) eq $path or POSIX::_exit(11);
    my $data = "y" x $n;
    my $off = 0;
    while ($off < $n) { my $w = syswrite($c, $data, 65536, $off) or POSIX::_exit(12); $off += $w }
    shutdown($c, 1) or POSIX::_exit(13);
    my $r;
    sysread($c, $r, 100) == 2 && $r eq "ok" or POSIX::_exit(14);
    POSIX::_exit(0);
}
accept(my $s, $l) or fail("accept: $!");
my ($ppid) = unpack("iII", getsockopt($s, SOL_SOCKET, SO_PEERCRED));
$ppid == $pid or fail("peer pid $ppid, not $pid");
unpack_sockaddr_un(getsockname($s)) eq $path or fail("accepted socket's name");
my $got = 0;
while (1) { my $r = sysread($s, my $buf, 65536); defined $r or fail("read: $!"); last if !$r; $got += $r }
$got == $n or fail("got $got bytes");
syswrite($s, "ok") == 2 or fail("reply: $!");
waitpid($pid, 0) == $pid && $? == 0 or fail("client exited " . ($? >> 8));
close $s; close $l;
my $e = sock(SOCK_STREAM);
connect($e, pack_sockaddr_un($path)) and fail("connect after the listener closed");
$!{ECONNREFUSED} or fail("connect after close: $!");
unlink $path or fail("unlink: $!");
my $u1 = sock(SOCK_DGRAM);
bind($u1, pack_sockaddr_un("\0ichor-test")) or fail("abstract bind: $!");
my $u2 = sock(SOCK_DGRAM);
bind($u2, pack_sockaddr_un("\0ichor-test-2")) or fail("abstract bind 2: $!");
send($u2, "one", 0, pack_sockaddr_un("\0ichor-test")) == 3 or fail("dgram send: $!");
send($u2, "two!", 0, pack_sockaddr_un("\0ichor-test")) == 4 or fail("dgram send 2: $!");
my $from = recv($u1, $m, 100, 0) // fail("dgram recv: $!");
$m eq "one" or fail("dgram [$m]");
unpack_sockaddr_un($from) =~ /ichor-test-2$/ or fail("dgram source");
recv($u1, $m, 2, 0) // fail("dgram recv 2: $!");
$m eq "tw" or fail("dgram truncation [$m]");
my $u3 = sock(SOCK_STREAM);
connect($u3, pack_sockaddr_un("\0ichor-test")) and fail("stream connect to a datagram name");
print "debian: unix: socketpair, path servers, abstract datagrams, SO_PEERCRED and end of file work\n";
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
syscall(38, 3, $it, $zero) == -1 && $!{EINVAL} or fail("a fourth interval timer accepted");
print "debian: alarm and setitimer deliver SIGALRM, getitimer reads back\n";
"#;

/// The server cell of the cross-cell run: `ME PEER PORT`. Accepts one
/// connection on `PORT`, checks both ends' addresses, reads to EOF and
/// answers with the peer's address and the byte count.
const CELL_SERVER: &str = r#"use strict; use warnings; use Socket;
sub fail { print "debian: cells FAILED (server): @_\n"; exit 1 }
my ($me, $peer, $port) = @ARGV;
socket(my $u, AF_INET, SOCK_DGRAM, 0) or fail("udp socket: $!");
bind($u, pack_sockaddr_in($port, INADDR_ANY)) or fail("udp bind: $!");
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
# One datagram from the client cell, answered to its source.
my $src = recv($u, my $dg, 2048, 0) // fail("udp recv: $!");
my (undef, $saddr) = unpack_sockaddr_in($src);
inet_ntoa($saddr) eq $peer or fail("datagram from " . inet_ntoa($saddr));
send($u, "pong $dg", 0, $src) or fail("udp send: $!");
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
# The other cell says so when nobody has a port there.
socket(my $v, AF_INET, SOCK_DGRAM, 0) or fail("udp socket: $!");
connect($v, pack_sockaddr_in($port + 1, inet_aton($server))) or fail("udp connect: $!");
syswrite($v, "anyone?") == 7 or fail("udp write: $!");
my $vin = ""; vec($vin, fileno($v), 1) = 1;
select(my $vout = $vin, undef, undef, 30) == 1 or fail("no word of a closed port in the other cell");
defined(sysread($v, my $nothing, 10)) and fail("read from a closed port in the other cell");
$!{ECONNREFUSED} or fail("a closed port in the other cell: $!");
socket(my $u, AF_INET, SOCK_DGRAM, 0) or fail("udp socket: $!");
my $to = pack_sockaddr_in($port, inet_aton($server));
send($u, "ping", 0, $to) == 4 or fail("udp send: $!");
my $rin = ""; vec($rin, fileno($u), 1) = 1;
select(my $rout = $rin, undef, undef, 30) == 1 or fail("no datagram came back");
my $f = recv($u, my $back, 2048, 0) // fail("udp recv: $!");
$f eq $to or fail("the answer came from elsewhere");
$back eq "pong ping" or fail("udp answer [$back]");
print "debian: cells: a datagram crossed the switch and came back\n";
"#;

/// A cell reaching the host through the uplink's NAT: `HOST PORT`, an echo
/// server on the test host.
const NAT_CLIENT: &str = r#"use strict; use warnings; use Socket;
sub fail { print "debian: nat FAILED: @_\n"; exit 1 }
my ($host, $port) = @ARGV;
# What a cloud tells the machine is not for its cells.
for my $addr ("169.254.169.254", "168.63.129.16") {
    socket(my $md, AF_INET, SOCK_STREAM, 0) or fail("socket: $!");
    connect($md, pack_sockaddr_in(80, inet_aton($addr))) and fail("connected to the machine's $addr");
    $!{ECONNREFUSED} or fail("$addr: $!");
}
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
# A datagram to the host's UDP echo on the same port number (retried: the
# outside may drop one).
socket(my $u, AF_INET, SOCK_DGRAM, 0) or fail("udp socket: $!");
my $to = pack_sockaddr_in($port, inet_aton($host));
my $got = "";
for my $try (1 .. 20) {
    send($u, "datagram $try", 0, $to) or fail("udp send: $!");
    my $rin = ""; vec($rin, fileno($u), 1) = 1;
    next unless select(my $r = $rin, undef, undef, 1) == 1;
    my $f = recv($u, $got, 2048, 0) // fail("udp recv: $!");
    $f eq $to or fail("the udp answer came from elsewhere");
    last;
}
$got =~ /^datagram \d+$/ or fail("no udp echo [$got]");
print "debian: nat: a datagram went through the uplink and came back\n";
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
    (&["perl", "-e", UNIX_SCRIPT], 0),
    (&["perl", "-e", SIGNAL_SCRIPT], 0),
    (&["perl", "-e", MOVE_SCRIPT], 0),
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
    match crate::netstack::stack_for(cell).addr() {
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
    // Held until the counters are read: they go with the cells.
    let (sid, cid) = (server.id(), client.id());
    let done = spawn_perl(
        vfs,
        server.clone(),
        CELL_SERVER,
        alloc::vec![sa.clone(), ca.clone(), port.clone()],
    );
    if perl(vfs, client.clone(), CELL_CLIENT, &[ca, sa, port]) != 0 {
        fail("debian: cross-cell client");
    }
    if wait_for(&done, "debian: the server cell never finished") != 0 {
        fail("debian: cross-cell server");
    }
    let (Some(s), Some(c)) = (crate::switch::stats(sid), crate::switch::stats(cid)) else {
        fail("debian: no switch counters");
    };
    drop((server, client));
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
