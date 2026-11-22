# Section 4 (perl part): A and B map the same image file, whose pages come
# from the shared page cache. A's FUTEX_WAKE at B's futex (same file,
# offset and address) wakes nobody; read() into A's private mapping
# changes only A's copy; read() into a PROT_READ mapping is EFAULT; a
# write to the file copies it up in A's root only. The harness then asks
# B what it sees (its mapping and its file) and ends B's futex wait.
$RULE = "shared_cache_pages_never_carry_writes_between_cells";
my %B = kv(@ARGV);
my ($VA, $OFF) = ($B{futex_va}, $B{futex_off});
open(my $f, "<", $B{file}) or die "$B{file}: $!";
my $orig = "";
sysseek($f, $OFF, 0);
sysread($f, $orig, 16) == 16 or die "read: $!";

# The futexes: B's waiters sit on the first word of page 1 of the file,
# mapped at $VA, one shared and one private. A maps the same page at the
# same address both ways and wakes it. (The harness has checked that both
# roots' page 1 is the same physical page.)
for (["shared", 0x01], ["private", 0x02]) {
    my ($kind, $flags) = @$_;
    my $m = syscall(9, $VA, 8192, 1, $flags | 0x10, fileno($f), 0); # PROT_READ, MAP_FIXED
    same("A maps the file at B's futex address ($kind)", $m, $VA);
    same("A's page holds the same bytes as B's ($kind)", unpack("H*", peek($VA + $OFF, 16)), unpack("H*", $orig));
    same("FUTEX_WAKE at B's futex ($kind mapping) wakes nobody", syscall(202, $VA + $OFF, 1, 0x7fffffff, 0, 0, 0), 0);
    same("FUTEX_WAKE|PRIVATE at B's futex ($kind mapping) wakes nobody", syscall(202, $VA + $OFF, 1 | 128, 0x7fffffff, 0, 0, 0), 0);
    syscall(11, $VA, 8192);
}
# Control: a waiter of A's own, another process of A's waiting on the same
# file page through a shared mapping, is woken.
my $m = syscall(9, $VA, 8192, 1, 0x11, fileno($f), 0);
$m == $VA or die "mmap: $!";
my $word = unpack("L", peek($VA + $OFF, 4));
my $kid = fork() // die "fork: $!";
if ($kid == 0) {
    my $r = syscall(202, $VA + $OFF, 0, $word, 0, 0, 0);
    POSIX::_exit($r == 0 ? 0 : 1);
}
my $woken = 0;
for (1 .. 500) {
    $woken = syscall(202, $VA + $OFF, 1, 0x7fffffff, 0, 0, 0);
    last if $woken == 1;
    select(undef, undef, undef, 0.01);
}
same("FUTEX_WAKE at B's futex: control (wakes A's own waiter on that page, and only it)", $woken, 1);
waitpid($kid, 0);
same("A's waiter returned from its wait", $? >> 8, 0);
syscall(11, $VA, 8192);

# read() into a writable private mapping of the file: A's copy changes.
my $rw = syscall(9, 0, 8192, 3, 0x02, fileno($f), 0); # PROT_RW, MAP_PRIVATE
$rw > 0 or die "mmap rw: $!";
open(my $src, "<", "/etc/debian_version") or die "debian_version: $!";
my $n = syscall(17, fileno($src), $rw + $OFF, 16, 0); # pread64
control("read() into A's private file mapping", $n);
my $mine = peek($rw + $OFF, 16);
same("A's private mapping now holds what A read", $mine eq $orig ? "unchanged" : "changed", "changed");
# read() into a PROT_READ mapping of the file: EFAULT, nothing written.
my $ro = syscall(9, 0, 8192, 1, 0x02, fileno($f), 0);
$ro > 0 or die "mmap ro: $!";
want("read() into a PROT_READ file mapping", "EFAULT", syscall(17, fileno($src), $ro + $OFF, 16, 0));
same("the PROT_READ mapping kept the original bytes", unpack("H*", peek($ro + $OFF, 16)), unpack("H*", $orig));
syscall(11, $rw, 8192);
syscall(11, $ro, 8192);
close $f;

# A write to the file copies it up into A's root.
open(my $w, "+<", $B{file}) or die "open for writing: $!";
sysseek($w, $OFF, 0);
same("A writes to the file (copy-up)", syswrite($w, "written by A....", 16), 16);
close $w;
open(my $again, "<", $B{file}) or die "reopen: $!";
sysseek($again, $OFF, 0);
sysread($again, my $now, 16);
same("A reads its own write back", $now, "written by A....");
close $again;
put("orig", unpack("H*", $orig));
done();
