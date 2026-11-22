# B's helper: makes the objects A's checks aim at, reports their names to
# the harness (out-ids), then serves the harness's requests until in-exit.
# Arguments: ip=B's address port=TCP port uplink=uplink-facing port.
$RULE = "B";
my %ARG = kv(@ARGV);
# If the helper dies, its children go with it (their memory must return).
my $MAIN = $$;
our @KIDS;
END { kill("KILL", @KIDS) if $$ == $MAIN && @KIDS }
sub record {
    open(my $f, ">>", "/run/ichor/$_[0]") or return;
    print $f "$_[1]\n";
    close $f;
}
sub slurp { open(my $f, "<", $_[0]) or return undef; local $/; my $v = <$f>; close $f; $v }
# Every catchable signal that arrives in B is written down: none may.
my @CAUGHT = qw(HUP INT QUIT USR1 USR2 PIPE ALRM TERM CONT TSTP TTIN TTOU WINCH URG IO);
$SIG{$_} = eval "sub { record('signals', \"\$\$ SIG$_\") }" for @CAUGHT;

# A file and a directory that exist only in this root.
mkdir "/b-only" or die "mkdir /b-only: $!";
open(my $sf, ">", "/b-only/secret") or die "secret: $!";
print $sf "B's secret\n";
close $sf;
symlink("/b-only/secret", "/b-only/link") or die "symlink: $!";
# What section 3's links, renames and removals aim at.
for my $n (1 .. 6) {
    open(my $f, ">", "/b-only/v$n") or die "v$n: $!";
    close $f;
}
mkdir("/b-only/vd1") && mkdir("/b-only/vd2") or die "mkdir: $!";

# A plain child (a second pid in B), pausing forever.
my $child = fork() // die "fork: $!";
if ($child == 0) { POSIX::pause() while 1; POSIX::_exit(0) }
push @KIDS, $child;

# The futex waiters: children that map page 1 of /usr/bin/dash at a fixed
# address and wait on its first word, one through a shared mapping (the
# page cache's own page, so the futex is kept by physical address) and one
# through a private one. Only the harness's SIGUSR1 may end the waits; each
# writes how its wait ended to /run/ichor/futex-KIND.
my ($FVA, $FOFF) = (0x5a00_0000_0000, 4096);
sub waiter {
    my ($kind, $flags) = @_;
    my $pid = fork() // die "fork: $!";
    return $pid if $pid;
    $SIG{USR1} = sub { };
    open(my $d, "<", "/usr/bin/dash") or POSIX::_exit(20);
    my $a = syscall(9, $FVA, 8192, 1, $flags | 0x10, fileno($d), 0); # PROT_READ, MAP_FIXED
    $a == $FVA or POSIX::_exit(21);
    my $word = unpack("L", peek($FVA + $FOFF, 4));
    record("futex-ready", "$kind word=$word");
    my $r = syscall(202, $FVA + $FOFF, 0, $word, 0, 0, 0); # FUTEX_WAIT
    my $e = $! + 0;
    record("futex-$kind", $r == -1 ? en($e) : "woken:$r");
    POSIX::_exit(0);
}
my $fpid = waiter("shared", 0x01);
push @KIDS, $fpid;
my $fpid2 = waiter("private", 0x02);
push @KIDS, $fpid2;

# A System V shared memory segment holding B's words, attached.
my $SHMKEY = 0x1c0b0b0;
my $shmid = syscall(29, $SHMKEY, 4096, 01000 | 02000 | 0600); # IPC_CREAT|IPC_EXCL
$shmid >= 0 or die "shmget: $!";
my $shm = syscall(30, $shmid, 0, 0);
$shm > 0 or die "shmat: $!";
{
    pipe(my $r, my $w) or die "pipe: $!";
    syswrite($w, "B's shared memory");
    syscall(0, fileno($r), $shm, 17) == 17 or die "fill shm: $!";
}

# B's own view of the same file, page 1 (section 4 compares it).
open(my $dash, "<", "/usr/bin/dash") or die "dash: $!";
my $VIEW = syscall(9, 0, 8192, 1, 0x02, fileno($dash), 0);
$VIEW > 0 or die "mmap: $!";

# Sockets: TCP on B's address, the uplink-facing port, a Unix path, an
# abstract stream name and an abstract datagram name.
sub listener {
    my ($port) = @_;
    socket(my $s, AF_INET, SOCK_STREAM, 0) or die "socket: $!";
    setsockopt($s, SOL_SOCKET, SO_REUSEADDR, 1) or die "SO_REUSEADDR: $!";
    bind($s, pack_sockaddr_in($port, INADDR_ANY)) or die "bind $port: $!";
    listen($s, 16) or die "listen: $!";
    $s;
}
my $tcp = listener($ARG{port});
my $up = listener($ARG{uplink});
my $UPATH = "/tmp/ichor-b.sock";
socket(my $us, AF_UNIX, SOCK_STREAM, 0) or die "unix: $!";
bind($us, pack_sockaddr_un($UPATH)) or die "bind $UPATH: $!";
listen($us, 4) or die "listen: $!";
socket(my $ua, AF_UNIX, SOCK_STREAM, 0) or die "unix: $!";
bind($ua, pack_sockaddr_un("\0ichor-b-stream")) or die "bind abstract: $!";
listen($ua, 4) or die "listen: $!";
socket(my $ud, AF_UNIX, SOCK_DGRAM, 0) or die "unix: $!";
bind($ud, pack_sockaddr_un("\0ichor-b-dgram")) or die "bind abstract dgram: $!";

# Two pseudo-terminals: /dev/pts/0 and /dev/pts/1 of B's devpts.
my @pts;
for (1 .. 2) {
    sysopen(my $m, "/dev/ptmx", 2) or die "ptmx: $!";
    my $n = pack("i", 0);
    ioctl($m, 0x80045430, $n) or die "TIOCGPTN: $!";
    my $u = pack("i", 0);
    ioctl($m, 0x40045431, $u) or die "unlockpt: $!";
    push @pts, [$m, unpack("i", $n)];
}

# A descriptor at a fixed number (200): A names the same number in its
# io_uring checks.
open(my $held, "<", "/b-only/secret") or die "secret: $!";
POSIX::dup2(fileno($held), 200) // die "dup2: $!";

# Wait until both futex children are in (or about to enter) their waits.
for (1 .. 500) {
    last if (slurp("/run/ichor/futex-ready") // "") =~ /\n.*\n/;
    select(undef, undef, undef, 0.02);
}
(slurp("/run/ichor/futex-ready") // "") =~ /\n.*\n/ or die "the futex children never got ready";
my $host = (POSIX::uname())[1];
my ($pgid, $sid) = (getpgrp(), syscall(124, 0));
put("ids", join(" ",
    "pid=$$", "tid=$$", "child=$child", "futex_pid=$fpid", "pgid=$pgid", "sid=$sid",
    "hostname=$host", "only=/b-only/secret", "ip=$ARG{ip}", "port=$ARG{port}",
    "uplink=$ARG{uplink}", "upath=$UPATH", "abstract=ichor-b-stream", "dgram=ichor-b-dgram",
    "pts=" . join(",", map { $_->[1] } @pts), "futex_va=$FVA", "futex_off=$FOFF",
    "file=/usr/bin/dash", "fd=200", "futex2_pid=$fpid2", "shmkey=$SHMKEY", "shmid=$shmid"));

# What A's checks may have changed, as B sees it now.
sub status {
    my @s = ("alive=1");
    push @s, "child=" . (kill(0, $child) ? "live" : "gone");
    for my $kind ("shared", "private") {
        my $fx = slurp("/run/ichor/futex-$kind") // "waiting";
        chomp $fx;
        push @s, ($kind eq "shared" ? "futex" : "futex2") . "=$fx";
    }
    # The segment: B's words, one attachment (B's own), still under its key.
    my $ds = "\0" x 112;
    my $st = syscall(31, $shmid, 2, $ds); # IPC_STAT
    my $there = $st == 0 && unpack("Q", substr($ds, 88, 8)) == 1
        && syscall(29, $SHMKEY, 0, 0) == $shmid && peek($shm, 17) eq "B's shared memory";
    push @s, "shm=" . ($there ? "intact" : "changed");
    my $sig = slurp("/run/ichor/signals") // "";
    chomp $sig;
    $sig =~ s/\n/;/g;
    push @s, "signals=" . ($sig eq "" ? "none" : $sig);
    my $acc = slurp("/run/ichor/accepted") // "";
    chomp $acc;
    $acc =~ s/\n/;/g;
    push @s, "accepted=" . ($acc eq "" ? "none" : $acc);
    push @s, "hostname=" . (POSIX::uname())[1];
    push @s, "secret=" . ((slurp("/b-only/secret") // "") eq "B's secret\n" ? "intact" : "changed");
    my $view = unpack("H*", peek($VIEW + 4096, 16));
    my $read = "";
    sysseek($dash, 4096, 0);
    sysread($dash, $read, 16);
    push @s, "view=$view", "file=" . unpack("H*", $read);
    push @s, "pts=" . join(",", map { -e "/dev/pts/$_->[1]" ? $_->[1] : "lost" } @pts);
    join(" ", @s);
}

# Serves accepts and the harness's requests until in-exit.
while (1) {
    my $rin = "";
    vec($rin, fileno($_), 1) = 1 for ($tcp, $up, $us, $ua, $ud);
    if (select(my $rout = $rin, undef, undef, 0.02) > 0) {
        for ([$tcp, "tcp"], [$up, "uplink"], [$us, "unix-path"], [$ua, "unix-abstract"]) {
            my ($l, $what) = @$_;
            next unless vec($rout, fileno($l), 1);
            my $peer = accept(my $c, $l) or next;
            my $from = $what =~ /^unix/ ? "unix" : inet_ntoa((unpack_sockaddr_in($peer))[1]);
            record("accepted", "$what\@$from");
            syswrite($c, $what eq "uplink"
                ? "HTTP/1.0 200 OK\r\nContent-Length: 18\r\n\r\nhello from cell B\n"
                : "B $what\n");
            close $c;
        }
        if (vec($rout, fileno($ud), 1)) {
            recv($ud, my $m, 100, 0);
            record("accepted", "unix-dgram");
        }
    }
    if (defined(my $v = poll_in("status"))) { put("status", status()) }
    if (defined(my $v = poll_in("alloc"))) {
        # Section 8: 8 MiB of fresh memory and a fork, while A is at its limits.
        my $len = 8 << 20;
        my $mem = syscall(9, 0, $len, 3, 0x22, -1, 0);
        my $r = "mmap failed: " . en($! + 0);
        if ($mem > 0) {
            open(my $z, "<", "/dev/zero") or die "zero: $!";
            my $got = 0;
            while ($got < $len) {
                my $n = syscall(0, fileno($z), $mem + $got, $len - $got);
                last if $n <= 0;
                $got += $n;
            }
            my $k = fork();
            if (defined $k && $k == 0) { POSIX::_exit(7) }
            my $st = defined $k ? (waitpid($k, 0) == $k ? $? >> 8 : -1) : "fork failed: $!";
            syscall(11, $mem, $len);
            $r = "filled=$got fork=$st";
        }
        put("alloc", $r);
    }
    if (defined(my $v = poll_in("look"))) {
        # Paths A made in its root: none may exist here.
        put("look", join(" ", map { "$_=" . (-e $_ || -l $_ ? "exists" : "absent") } split ' ', $v));
    }
    if (defined(my $v = poll_in("list"))) {
        # What a directory of B's lists.
        opendir(my $d, $v) or die "cellaccess: opendir $v: $!\n";
        put("list", join(" ", sort grep { !/^\.\.?$/ } readdir($d)));
        closedir $d;
    }
    if (defined(my $v = poll_in("ptys"))) {
        # Each pty's size, and whether anything was written to its slave:
        # nobody has opened either.
        my @s;
        for (@pts) {
            my ($m, $n) = @$_;
            my $size = "\0" x 8;
            ioctl($m, 0x5413, $size) or die "cellaccess: TIOCGWINSZ: $!\n";
            my $rin = "";
            vec($rin, fileno($m), 1) = 1;
            my $heard = select(my $rout = $rin, undef, undef, 0) > 0 ? "something" : "nothing";
            push @s, "$n=" . join("x", (unpack("S4", $size))[0, 1]) . ",$heard";
        }
        put("ptys", join(" ", @s));
    }
    last if defined poll_in("exit");
}
kill("KILL", $child, $fpid, $fpid2);
waitpid($_, 0) for ($child, $fpid, $fpid2);
syscall(67, $shm); # shmdt
syscall(31, $shmid, 0, 0); # IPC_RMID
close $_->[0] for @pts;
unlink $UPATH;
put("bye", "ok");
exit 0;
