# Section 1: process identity. Every call that names one of B's pids or
# tids from A finds nothing (ESRCH; ECHILD for wait4), and the same call on
# A's own child works. Signals sent to every process (-1), to A's group (0)
# or to B's group never reach B: B's helper reports what arrived.
$RULE = "process_ids_and_signals_are_scoped_to_their_cell";
my %B = kv(@ARGV);
my @BPIDS = ($B{pid}, $B{child}, $B{futex_pid}, $B{futex2_pid});
my ($SIGKILL, $SIGUSR1, $SIGUSR2, $SIGTERM, $SIGCONT) = (9, 10, 12, 15, 18);

# A's own objects: a child in a process group of its own, which reports
# each signal it catches through a pipe.
pipe(my $r, my $w) or die "pipe: $!";
my $kid = fork() // die "fork: $!";
if ($kid == 0) {
    close $r;
    for my $s (qw(USR1 USR2 TERM CONT)) { $SIG{$s} = eval "sub { syswrite(\$w, '$s ') }" }
    syswrite($w, "ready ");
    POSIX::pause() while 1;
    POSIX::_exit(0);
}
close $w;
sub from_kid {
    my ($want) = @_;
    my $got = "";
    while (index($got, $want) < 0) {
        my $rin = "";
        vec($rin, fileno($r), 1) = 1;
        last unless select(my $o = $rin, undef, undef, 10) == 1;
        sysread($r, my $buf, 100) or last;
        $got .= $buf;
    }
    index($got, $want) >= 0 ? "caught" : "not caught [$got]";
}
same("A's child is ready", from_kid("ready"), "caught");
my $SIGNALLED_SELF = 0;
$SIG{USR2} = sub { $SIGNALLED_SELF++ };

# setpgid: B's pid is not A's to move (ESRCH); A's own child is.
want("setpgid(B pid)", "ESRCH", syscall(109, $B{pid}, $B{pid}));
control("setpgid(B pid)", syscall(109, $kid, $kid));

for my $p (@BPIDS) {
    want("kill(B pid $p, 0)", "ESRCH", syscall(62, $p, 0));
    want("kill(B pid $p, SIGUSR1)", "ESRCH", syscall(62, $p, $SIGUSR1));
    want("kill(B pid $p, SIGTERM)", "ESRCH", syscall(62, $p, $SIGTERM));
    want("kill(B pid $p, SIGKILL)", "ESRCH", syscall(62, $p, $SIGKILL));
    want("tkill(B tid $p, SIGUSR1)", "ESRCH", syscall(200, $p, $SIGUSR1));
    want("tgkill(B pid $p, B tid $p, SIGUSR1)", "ESRCH", syscall(234, $p, $p, $SIGUSR1));
    want("getpgid(B pid $p)", "ESRCH", syscall(121, $p));
    want("getsid(B pid $p)", "ESRCH", syscall(124, $p));
    my $old = "\0" x 16;
    want("prlimit64(B pid $p)", "ESRCH", syscall(302, $p, 7, 0, $old));
    my $mask = "\0" x 128;
    want("sched_getaffinity(B pid $p)", "ESRCH", syscall(204, $p, 128, $mask));
    my $st = "\0" x 4;
    want("wait4(B pid $p)", "ECHILD", syscall(61, $p, $st, 1, 0));
}
control("kill(B pid, 0)", syscall(62, $kid, 0));
control("kill(B pid, SIGUSR1)", syscall(62, $kid, $SIGUSR1));
same("A's child got SIGUSR1", from_kid("USR1"), "caught");
control("kill(B pid, SIGTERM)", syscall(62, $kid, $SIGTERM));
same("A's child got SIGTERM", from_kid("TERM"), "caught");
control("tkill(B tid)", syscall(200, $kid, $SIGCONT));
same("A's child got SIGCONT", from_kid("CONT"), "caught");
control("tgkill(B pid, B tid)", syscall(234, $kid, $kid, $SIGCONT));
same("A's child got SIGCONT again", from_kid("CONT"), "caught");
same("getpgid(B pid): control", syscall(121, $kid), $kid);
same("getsid(B pid): control", syscall(124, $kid), syscall(124, 0));
my $old = "\0" x 16;
control("prlimit64(B pid)", syscall(302, $$ + 0, 7, 0, $old));
my $mask = "\0" x 128;
control("sched_getaffinity(B pid)", syscall(204, $kid, 128, $mask));

# Group signals: B's group finds nothing; A's own group, and every process
# (-1), reach only A (B reports what arrived after this section).
want("kill(-B pgid, SIGUSR1)", "ESRCH", syscall(62, -$B{pgid}, $SIGUSR1));
want("kill(-B pgid, 0)", "ESRCH", syscall(62, -$B{pgid}, 0));
control("kill(-B pgid, 0)", syscall(62, -$kid, 0));
control("kill(0, SIGUSR2) (A's own group)", syscall(62, 0, $SIGUSR2));
control("kill(-1, SIGUSR1) (every process A may signal)", syscall(62, -1, $SIGUSR1));
same("A's child got kill(-1, SIGUSR1)", from_kid("USR1"), "caught");
same("A got its own group's SIGUSR2", $SIGNALLED_SELF, 1);

# Queued signals, process descriptors and waitid.
my $si = pack("iii", $SIGUSR1, 0, -1) . ("\0" x 116); # SI_QUEUE
my $info = "\0" x 128;
my $set = pack("Q", 1);
my $param = "\0" x 8;
for my $p (@BPIDS) {
    want("rt_sigqueueinfo(B pid $p)", "ESRCH", syscall(129, $p, $SIGUSR1, $si));
    want("rt_tgsigqueueinfo(B pid $p, B tid $p)", "ESRCH", syscall(297, $p, $p, $SIGUSR1, $si));
    want("pidfd_open(B pid $p)", "ESRCH", syscall(434, $p, 0));
    want("waitid(P_PID, B pid $p)", "ECHILD", syscall(247, 1, $p, $info, 4 | 1, 0));
    want("sched_setaffinity(B pid $p)", "ESRCH", syscall(203, $p, 8, $set));
    want("sched_getscheduler(B pid $p)", "ESRCH", syscall(145, $p));
    want("sched_getparam(B pid $p)", "ESRCH", syscall(143, $p, $param));
    my $hdr = pack("Li", 0x20080522, $p);
    my $caps = "\0" x 24;
    want("capget(B pid $p)", "ESRCH", syscall(125, $hdr, $caps));
    # getpriority/setpriority name only the caller (A's child is ESRCH too).
    want("getpriority(B pid $p)", "ESRCH", syscall(140, 0, $p));
    want("setpriority(B pid $p)", "ESRCH", syscall(141, 0, $p, 5));
    # Any thread but the caller is EPERM, whether it exists or not.
    my ($head, $hlen) = ("\0" x 8, "\0" x 8);
    want("get_robust_list(B tid $p)", "EPERM", syscall(274, $p, $head, $hlen));
}
want("waitid(P_PGID, B pgid)", "ECHILD", syscall(247, 2, $B{pgid}, $info, 4 | 1, 0));
control("rt_sigqueueinfo(B pid)", syscall(129, $kid, $SIGUSR1, $si));
same("A's child got the queued SIGUSR1", from_kid("USR1"), "caught");
control("rt_tgsigqueueinfo(B pid, B tid)", syscall(297, $kid, $kid, $SIGUSR1, $si));
same("A's child got the thread-queued SIGUSR1", from_kid("USR1"), "caught");
my $pfd = syscall(434, $kid, 0);
control("pidfd_open(B pid)", $pfd);
control("pidfd_send_signal (A's own child)", syscall(424, $pfd, $SIGUSR1, 0, 0));
same("A's child got the pidfd's SIGUSR1", from_kid("USR1"), "caught");
control("waitid(P_PID, B pid)", syscall(247, 1, $kid, $info, 4 | 1, 0));
control("waitid(P_PGID, B pgid)", syscall(247, 2, $kid, $info, 4 | 1, 0));
control("sched_setaffinity(B pid) (A itself: only the caller's is settable)", syscall(203, $$ + 0, 8, $set));
control("sched_getscheduler(B pid)", syscall(145, $kid));
control("sched_getparam(B pid)", syscall(143, $kid, $param));
my ($hdr, $caps) = (pack("Li", 0x20080522, $kid), "\0" x 24);
control("capget(B pid)", syscall(125, $hdr, $caps));
control("getpriority(B pid) (A itself)", syscall(140, 0, $$ + 0));
control("setpriority(B pid) (A itself)", syscall(141, 0, $$ + 0, 1));
my ($head, $hlen) = ("\0" x 8, "\0" x 8);
control("get_robust_list(B tid) (A itself)", syscall(274, $$ + 0, $head, $hlen));

# SIGIO through F_SETOWN. Any pid may be set (Linux: ESRCH for one that is
# not there), so B's must do exactly what a pid nobody has does, and the
# signal goes to B from nowhere (B reports it if it arrives).
sub sigio {
    my ($owner) = @_;
    socketpair(my $x, my $y, AF_UNIX, SOCK_STREAM, 0) or die "socketpair: $!";
    my $r = syscall(72, fileno($x), 8, $owner); # F_SETOWN
    my $e = $! + 0;
    syscall(72, fileno($x), 4, 020000); # F_SETFL, O_ASYNC
    syswrite($y, "data");
    $r == -1 ? en($e) : "ok";
}
my $nobody = 4_000_000;
same("F_SETOWN(B pid) is as for a pid nobody has", sigio($B{pid}), sigio($nobody));
my $ios = 0;
$SIG{IO} = sub { $ios++ };
same("F_SETOWN(B pid): control (A itself)", sigio($$ + 0), "ok");
select(undef, undef, undef, 0.1);
same("A got its own SIGIO", $ios > 0 ? "caught" : "not caught", "caught");

# Calls that do not exist yet: ENOSYS, for B's objects and A's own alike.
# Each needs a real check when it is implemented.
my $buf = "\0" x 16;
my $liov = pack("QQ", ptr($buf), 16);
my $riov = pack("QQ", $B{futex_va} + $B{futex_off}, 16);
for ([$B{pid}, "B pid"], [$kid, "A's own child"]) {
    my ($p, $who) = @$_;
    want("pidfd_getfd($who) [ENOSYS today]", "ENOSYS", syscall(438, $pfd, 0, 0));
    want("ptrace(PTRACE_ATTACH, $who) [ENOSYS today]", "ENOSYS", syscall(101, 16, $p, 0, 0));
    want("process_vm_readv($who) [ENOSYS today]", "ENOSYS", syscall(310, $p, $liov, 1, $riov, 1, 0));
    want("process_vm_writev($who) [ENOSYS today]", "ENOSYS", syscall(311, $p, $liov, 1, $riov, 1, 0));
    want("kcmp($who, self) [ENOSYS today]", "ENOSYS", syscall(312, $p, $$ + 0, 0, 0, 0));
}

# kill(p, 0) over every pid handed out so far (the highest is the last
# field of /proc/loadavg) and some beyond: only A's two processes answer.
open(my $la, "<", "/proc/loadavg") or die "loadavg: $!";
my ($last) = (<$la> =~ /(\d+)\s*$/);
close $la;
my $top = $last + 256;
my @found = grep { syscall(62, $_, 0) == 0 } 1 .. $top;
same("kill(p, 0) for p in 1..$top finds only A's processes",
    join(",", @found), join(",", sort { $a <=> $b } ($$, $kid)));
my @bfound = grep { my $p = $_; grep { $_ == $p } @found } @BPIDS;
same("the sweep found none of B's pids", scalar(@bfound), 0);

# The last signal: SIGKILL to every process A may signal. Only A's child
# dies (wait4 reaps it); B's helper must still be there afterwards.
control("kill(-1, SIGKILL)", syscall(62, -1, $SIGKILL));
my $st = "\0" x 4;
same("wait4(B pid): control (A's child, killed by kill(-1, SIGKILL))", syscall(61, $kid, $st, 0, 0), $kid);
same("A's child died of SIGKILL", unpack("i", $st) & 0x7f, $SIGKILL);
done();
