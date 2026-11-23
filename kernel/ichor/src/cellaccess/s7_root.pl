# Section 7: uid 0 in A has no authority outside A (ADR-0009 §3). The
# calls a host superuser would use fail with EPERM, or ENOSYS where they
# do not exist (ADR-0009: "already EPERM or absent"; recorded). Ownership
# and mode changes cannot reach B's files, and uid 0 signals none of B's
# processes.
$RULE = "uid_0_in_a_cell_has_no_authority_outside_it";
my %B = kv(@ARGV);
same("A runs as uid 0", syscall(102) . " " . syscall(107), "0 0"); # getuid, geteuid

my ($src, $dst, $fs) = ("/dev/vda", "/mnt", "ext4");
want("mount", "EPERM", syscall(165, $src, $dst, $fs, 0, 0));
my $root = "/";
want("umount2(/)", "EPERM", syscall(166, $root, 0));
my $node = "/tmp/ichor-node";
# Device nodes (a character and a block device) are refused; a node
# without a device behind it is not.
want("mknod(character device)", "EPERM", syscall(133, $node, 0020000 | 0600, (1 << 8) | 1));
want("mknodat(block device)", "EPERM", syscall(259, -100, $node, 0060000 | 0600, (254 << 8)));
control("mknod (a FIFO)", syscall(133, $node, 0010000 | 0600, 0));
my $node2 = "/tmp/ichor-node2";
control("mknodat (a FIFO)", syscall(259, -100, $node2, 0010000 | 0600, 0));
want("reboot [ENOSYS today]", "ENOSYS", syscall(169, 0xfee1dead, 672274793, 0, 0)); # CAD_OFF
my $ts = pack("qq", 0, 0);
want("clock_settime(CLOCK_REALTIME)", "EPERM", syscall(227, 0, $ts));
my $tv = pack("qq", 0, 0);
want("settimeofday", "EPERM", syscall(164, $tv, 0));
my $now = pack("qq", 0, 0);
control("clock_gettime (A may read the clock it may not set)", syscall(228, 0, $now));
same("the clock did not move", (unpack("qq", $now))[0] > 1_600_000_000 ? "kept" : "set", "kept");
my $tx = "\0" x 208;
want("adjtimex [ENOSYS today]", "ENOSYS", syscall(159, $tx));
want("clock_adjtime [ENOSYS today]", "ENOSYS", syscall(305, 0, $tx));
want("chroot [ENOSYS today]", "ENOSYS", syscall(161, my $c = "/tmp"));
want("unshare(CLONE_NEWNS)", "EPERM", syscall(272, 0x20000));
control("unshare (nothing)", syscall(272, 0));
want("setns", "EPERM", syscall(308, 0, 0));
my $img = "";
want("init_module [ENOSYS today]", "ENOSYS", syscall(175, $img, 0, $img));
want("iopl(3) [ENOSYS today]", "ENOSYS", syscall(172, 3));
want("ioperm [ENOSYS today]", "ENOSYS", syscall(173, 0x70, 2, 1));
want("kexec_load [ENOSYS today]", "ENOSYS", syscall(246, 0, 0, 0, 0));
want("swapon [ENOSYS today]", "ENOSYS", syscall(167, $src, 0));

# Ownership and modes: B's paths are not in A's view.
my $only = $B{only};
for my $p ($only, "/b-only", "/b-only/link", "/proc/$B{pid}/status") {
    want("chown($p) as uid 0", "ENOENT", syscall(92, my $x = $p, 1000, 1000));
    want("lchown($p) as uid 0", "ENOENT", syscall(94, my $y = $p, 1000, 1000));
    want("chmod($p) as uid 0", "ENOENT", syscall(90, my $z = $p, 0777));
    want("fchownat($p) as uid 0", "ENOENT", syscall(260, -100, my $w = $p, 1000, 1000, 0));
}
open(my $mine, ">", "/tmp/a-owned") or die "a-owned: $!";
close $mine;
my $own = "/tmp/a-owned";
control("chown($only) as uid 0", syscall(92, $own, 1000, 1000));
control("lchown($only) as uid 0", syscall(94, $own, 1000, 1000));
control("chmod($only) as uid 0", syscall(90, $own, 0777));
control("fchownat($only) as uid 0", syscall(260, -100, $own, 0, 0, 0));

# Signals: uid 0 (CAP_KILL in A) still finds none of B's processes.
for my $p ($B{pid}, $B{child}, $B{futex_pid}) {
    want("kill(B pid $p, SIGKILL) as uid 0", "ESRCH", syscall(62, $p, 9));
    want("kill(B pid $p, SIGSTOP) as uid 0", "ESRCH", syscall(62, $p, 19));
}
# The control: the same check (kill with signal 0) on A's own process.
control("kill(B pid, 0) as uid 0", syscall(62, $$ + 0, 0));
want("kill(B pid, 0) as uid 0", "ESRCH", syscall(62, $B{pid}, 0));
done();
