# Section 6: other per-cell state. SysV IPC, POSIX message queues and
# sethostname do not exist yet (ENOSYS, recorded; B's hostname is checked
# after the section). io_uring operations from A that name B's path, B's
# abstract socket and B's descriptor number fail the way the plain
# syscalls do, and the same operations on A's own objects work.
$RULE = "other_kernel_state_is_per_cell";
my %B = kv(@ARGV);

for my $key (0, 0x1c0ffee) { # IPC_PRIVATE and a fixed key
    my $k = sprintf("%#x", $key);
    want("shmget($k) [ENOSYS today]", "ENOSYS", syscall(29, $key, 4096, 01000 | 0600));
    want("semget($k) [ENOSYS today]", "ENOSYS", syscall(64, $key, 1, 01000 | 0600));
    want("msgget($k) [ENOSYS today]", "ENOSYS", syscall(68, $key, 01000 | 0600));
}
want("mq_open [ENOSYS today]", "ENOSYS", syscall(240, my $q = "ichor-b", O_CREAT | O_RDWR, 0600, 0));
my $name = "cell-a";
want("sethostname [ENOSYS today]", "ENOSYS", syscall(170, $name, length($name)));
want("setdomainname [ENOSYS today]", "ENOSYS", syscall(171, $name, length($name)));
same("A's uname nodename", (POSIX::uname())[1], $B{hostname});

# io_uring: one ring, one SQE at a time.
my $params = "\0" x 120;
my $ring = syscall(425, 8, $params);
control("io_uring_setup", $ring);
my @p = unpack("L10 L8 Q L8 Q", $params);
my ($sqn, $cqn) = @p[0, 1];
my %sq; @sq{qw(head tail mask entries flags dropped array)} = @p[10 .. 16];
my %cq; @cq{qw(head tail mask entries overflow cqes flags)} = @p[19 .. 25];
my $len = $sq{array} + 4 * $sqn;
$len = $cq{cqes} + 16 * $cqn if $cq{cqes} + 16 * $cqn > $len;
my $rings = syscall(9, 0, $len, 3, 0x01 | 0x8000, $ring, 0); # MAP_SHARED|MAP_POPULATE
my $sqes = syscall(9, 0, 64 * $sqn, 3, 0x01 | 0x8000, $ring, 0x1000_0000);
$rings > 0 && $sqes > 0 or die "ring mmap: $!";
# The offsets name where each ring's mask lives; the masks are in the ring.
my $sqmask = unpack("L", peek($rings + $sq{mask}, 4));
my $cqmask = unpack("L", peek($rings + $cq{mask}, 4));
# Bytes go into the shared ring pages through read() from a pipe (perl
# has no plain stores); the kernel copies them like any read.
pipe(my $pr, my $pw) or die "pipe: $!";
sub poke {
    my ($addr, $bytes) = @_;
    syswrite($pw, $bytes) == length($bytes) or die "poke: $!";
    syscall(0, fileno($pr), $addr, length($bytes)) == length($bytes) or die "poke read: $!";
}
my $seq = 0;
# Submits one SQE (opcode, fd, addr, len, off, op_flags) and returns the
# completion's res.
sub submit {
    my ($op, $fd, $addr, $n, $off, $opf) = @_;
    $seq++;
    poke($sqes, pack("CCSlQQLLQSSlx16", $op, 0, 0, $fd, $off, $addr, $n, $opf, $seq, 0, 0, 0));
    my $tail = unpack("L", peek($rings + $sq{tail}, 4));
    poke($rings + $sq{array} + 4 * ($tail & $sqmask), pack("L", 0));
    poke($rings + $sq{tail}, pack("L", $tail + 1));
    syscall(426, $ring, 1, 1, 1, 0, 0) >= 0 or die "io_uring_enter: $!"; # GETEVENTS
    my $head = unpack("L", peek($rings + $cq{head}, 4));
    my ($ud, $res) = unpack("Ql", peek($rings + $cq{cqes} + 16 * ($head & $cqmask), 12));
    poke($rings + $cq{head}, pack("L", $head + 1));
    $ud == $seq or die "completion $ud for submission $seq";
    $res;
}
sub cqe_want {
    my ($check, $name, $res) = @_;
    if ($res == -ev($name)) { ok("$check ($name)") }
    elsif ($res < 0) { bad($check, "expected $name, got " . en(-$res)) }
    else { bad($check, "expected $name, got success ($res)") }
}
sub cqe_control {
    my ($check, $res) = @_;
    if ($res >= 0) { ok("$check: control") } else { bad("$check: control", "expected success, got " . en(-$res)) }
}
my ($OPENAT, $CONNECT, $READ) = (18, 16, 22);
my $bpath = $B{only};
cqe_want("IORING_OP_OPENAT(B's path)", "ENOENT", submit($OPENAT, -100, ptr($bpath), 0, 0, O_RDONLY));
my $apath = "/etc/debian_version";
my $afd = submit($OPENAT, -100, ptr($apath), 0, 0, O_RDONLY);
cqe_control("IORING_OP_OPENAT(B's path)", $afd);
my $buf = "\0" x 64;
cqe_want("IORING_OP_READ(fd $B{fd}, B's descriptor number)", "EBADF", submit($READ, $B{fd}, ptr($buf), 64, 0, 0));
cqe_control("IORING_OP_READ(fd $B{fd}, B's descriptor number)", submit($READ, $afd, ptr($buf), 64, 0, 0));
my $babs = pack_sockaddr_un("\0$B{abstract}");
socket(my $us, AF_UNIX, SOCK_STREAM, 0) or die "socket: $!";
cqe_want("IORING_OP_CONNECT(B's abstract name)", "ECONNREFUSED", submit($CONNECT, fileno($us), ptr($babs), 0, length($babs), 0));
socket(my $al, AF_UNIX, SOCK_STREAM, 0) or die "socket: $!";
bind($al, $babs) or die "bind: $!"; # the same name, in A's own namespace
listen($al, 1) or die "listen: $!";
socket(my $us2, AF_UNIX, SOCK_STREAM, 0) or die "socket: $!";
cqe_control("IORING_OP_CONNECT(B's abstract name)", submit($CONNECT, fileno($us2), ptr($babs), 0, length($babs), 0));
my $bunix = pack_sockaddr_un($B{upath});
socket(my $us3, AF_UNIX, SOCK_STREAM, 0) or die "socket: $!";
cqe_want("IORING_OP_CONNECT(B's Unix path)", "ENOENT", submit($CONNECT, fileno($us3), ptr($bunix), 0, length($bunix), 0));
done();
