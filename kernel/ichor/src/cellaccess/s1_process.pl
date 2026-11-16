# Section 1: process identity. Every call that names one of B's pids or
# tids from A finds nothing (ESRCH; ECHILD for wait4), and the same call on
# A's own child works. Signals sent to every process (-1), to A's group (0)
# or to B's group never reach B: B's helper reports what arrived.
$RULE = "process_ids_and_signals_are_scoped_to_their_cell";
my %B = kv(@ARGV);
my @BPIDS = ($B{pid}, $B{child}, $B{futex_pid});
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

# Calls that do not exist yet: ENOSYS, for B's objects and A's own alike.
# Each needs a real check when it is implemented.
my $si = pack("iii", $SIGUSR1, 0, -1) . ("\0" x 116); # SI_QUEUE
my $buf = "\0" x 16;
my $liov = pack("QQ", ptr($buf), 16);
my $riov = pack("QQ", $B{futex_va} + $B{futex_off}, 16);
my $info = "\0" x 128;
my $set = pack("Q", 1);
for ([$B{pid}, "B pid"], [$kid, "A's own child"]) {
    my ($p, $who) = @$_;
    my $si2 = $si;
    want("rt_sigqueueinfo($who) [ENOSYS today]", "ENOSYS", syscall(129, $p, $SIGUSR1, $si2));
    want("rt_tgsigqueueinfo($who) [ENOSYS today]", "ENOSYS", syscall(297, $p, $p, $SIGUSR1, $si2));
    want("pidfd_open($who) [ENOSYS today]", "ENOSYS", syscall(434, $p, 0));
    want("waitid(P_PID, $who) [ENOSYS today]", "ENOSYS", syscall(247, 1, $p, $info, 4 | 1, 0));
    want("sched_setaffinity($who) [ENOSYS today]", "ENOSYS", syscall(203, $p, 8, $set));
    want("getpriority($who) [ENOSYS today]", "ENOSYS", syscall(140, 0, $p));
    want("setpriority($who) [ENOSYS today]", "ENOSYS", syscall(141, 0, $p, 5));
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
