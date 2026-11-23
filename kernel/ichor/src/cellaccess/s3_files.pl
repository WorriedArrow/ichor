# Section 3: file systems. `..` at A's root is A's root, symlinks resolve
# in A's root only, B's files are absent in A whatever the call, links and
# renames end inside A's root, and B's ptys have no node in A's devpts (nor
# does a stale node of A's own reach one). What A makes here stays, so that
# the harness can have B look for it (cellaccess.rs, `s3`); only what has a
# name of B's is removed again.
$RULE = "file_systems_are_scoped_to_their_root";
my %B = kv(@ARGV);
my ($OPATH, $ODIR, $CWD, $FOLLOW) = (0x200000, 0x10000, -100, 0x400);
my $st = "\0" x 144;

# What is at a path or descriptor: st_dev:st_ino, or the errno.
sub id {
    my ($p, $b) = ($_[0], "\0" x 144);
    syscall(4, $p, $b) == 0 ? join(":", unpack("QQ", $b)) : en($! + 0);
}
sub fid {
    my ($fd, $b) = ($_[0], "\0" x 144);
    syscall(5, $fd, $b) == 0 ? join(":", unpack("QQ", $b)) : en($! + 0);
}
sub cwd {
    my $b = "\0" x 4096;
    my $n = syscall(79, $b, 4096);
    $n > 0 ? substr($b, 0, $n - 1) : en($! + 0);
}
sub ls {
    opendir(my $d, $_[0]) or return "errno " . en($! + 0);
    my @n = sort grep { !/^\.\.?$/ } readdir($d);
    closedir $d;
    join(",", @n);
}
sub slurp { open(my $f, "<", $_[0]) or return en($! + 0); local $/; my $v = <$f>; close $f; $v }
sub spew { open(my $f, ">", $_[0]) or die "$_[0]: $!"; print $f $_[1]; close $f or die "$_[0]: $!" }
sub fd_of { my $p = $_[0]; my $fd = syscall(2, $p, $ODIR, 0); $fd >= 0 or die "open $p: $!"; $fd }

# Ptys first, while A has none of its own: B's numbers (0 and 1) name
# nothing here.
my @PTS = map { $_ + 0 } split /,/, $B{pts};
same("B has ptys 0 and 1", "@PTS", "0 1");
same("A's devpts is empty while B has ptys", ls("/dev/pts"), "");
my $ptsfd = fd_of("/dev/pts");
for my $n (@PTS) {
    want("stat /dev/pts/$n (B's)", "ENOENT", syscall(4, my $p = "/dev/pts/$n", $st));
    want("open /dev/pts/$n (B's)", "ENOENT", syscall(2, my $q = "/dev/pts/$n", O_RDWR | O_NOCTTY, 0));
    want("openat(/dev/pts, $n) (B's)", "ENOENT", syscall(257, $ptsfd, my $r = "$n", O_RDWR | O_NOCTTY, 0));
    want("link(/dev/pts/$n) (B's)", "ENOENT", syscall(86, my $s = "/dev/pts/$n", my $t = "/tmp/a-pts"));
}

# A's own files: what the controls use, and what B looks for.
mkdir("/a-only") or die "mkdir: $!";
spew("/a-only/secret", "A's secret\n");
symlink("/a-only/secret", "/a-only/link") or die "symlink: $!";
socket(my $srv, AF_UNIX, SOCK_STREAM, 0) or die "socket: $!";
bind($srv, pack_sockaddr_un("/a-only/sock")) or die "bind: $!";
listen($srv, 8) or die "listen: $!";
my $ROOT = id("/");

# `..` at the root, by chdir: from several depths, and by chains far longer
# than the path is deep. The root is told by its path, by its inode, by A's
# own directory being in it, and by B's not being there.
my %CHAIN = ("3" => "../" x 3, "64" => "../" x 64, "1300" => "../" x 1300);
sub at_root {
    my ($how) = @_;
    same("$how: getcwd is /", cwd(), "/");
    same("$how: it is A's root", id("."), $ROOT);
    want("$how: B's file from there", "ENOENT", syscall(4, my $p = "b-only/secret", $st));
    control("$how: B's file from there", syscall(4, my $q = "a-only/secret", $st));
}
for my $up ("..", "/..", "/../..", "../.", "./../../") {
    chdir("/") or die "chdir: $!";
    control("chdir($up) at the root", syscall(80, my $p = $up));
    at_root("chdir($up) at the root");
}
for my $from ("/a-only", "/usr/bin", "/var/lib/dpkg") {
    for my $n (sort { $a <=> $b } keys %CHAIN) {
        chdir($from) or die "chdir $from: $!";
        control("chdir of $n x .. from $from", syscall(80, my $p = $CHAIN{$n}));
        at_root("chdir of $n x .. from $from");
    }
}
chdir("/") or die "chdir: $!";
for (1 .. 50) { syscall(80, my $p = "..") == 0 or bad("chdir(..) 50 times", en($! + 0)) }
at_root("chdir(..) 50 times");
same("/.. lists what / lists", ls("/.."), ls("/"));
same("A's root lists A's directory, not B's",
    join(",", grep { /^[ab]-only$/ } split /,/, ls("/")), "a-only");

# The same with directory descriptors, and from the descriptor `..` gave.
for my $from ("/", "/a-only", "/usr/bin", "/var/lib/dpkg") {
    my $fd = fd_of($from);
    for my $n (sort { $a <=> $b } keys %CHAIN) {
        my $what = "openat($from, $n x ..)";
        my $up = syscall(257, $fd, my $p = $CHAIN{$n}, $OPATH | $ODIR, 0);
        control($what, $up);
        same("$what is A's root", fid($up), $ROOT);
        want("$what, then B's file", "ENOENT", syscall(257, $fd, my $q = "$CHAIN{$n}b-only/secret", 0, 0));
        control("$what, then B's file", syscall(257, $fd, my $r = "$CHAIN{$n}a-only/secret", 0, 0));
        want("newfstatat($from, $n x .. and B's file)", "ENOENT", syscall(262, $fd, my $s = "$CHAIN{$n}b-only/secret", $st, 0));
        control("newfstatat($from, $n x .. and B's file)", syscall(262, $fd, my $t = "$CHAIN{$n}a-only/secret", $st, 0));
        my $again = syscall(257, $up, my $v = "..", $OPATH | $ODIR, 0);
        same("openat(.., ..) after $what is A's root", fid($again), $ROOT);
        control("fchdir to what $what gave", syscall(81, $up));
        at_root("fchdir to what $what gave");
        POSIX::close($_) for ($up, $again);
    }
    POSIX::close($fd);
}
# A directory moved while a descriptor holds it, and one removed: their
# `..` still leads to A's root and no further.
mkdir("/a-only/deep") && mkdir("/a-only/deep/moved") && mkdir("/a-only/gone") or die "mkdir: $!";
my ($mfd, $gfd) = (fd_of("/a-only/deep/moved"), fd_of("/a-only/gone"));
rename("/a-only/deep/moved", "/a-moved-dir") or die "rename: $!";
rmdir("/a-only/gone") or die "rmdir: $!";
for (["moved", $mfd], ["removed", $gfd]) {
    my ($what, $fd) = @$_;
    my $up = syscall(257, $fd, my $p = "../../..", $OPATH | $ODIR, 0);
    control("openat(a $what directory, ../../..)", $up);
    same("openat(a $what directory, ../../..) is A's root", fid($up), $ROOT);
    want("openat(a $what directory, B's file)", "ENOENT", syscall(257, $fd, my $q = "../../../b-only/secret", 0, 0));
    control("openat(a $what directory, B's file)", syscall(257, $fd, my $r = "../../../a-only/secret", 0, 0));
}

# Symlinks in A that name what only B's root has, and the same links to
# A's own (the controls). The links themselves are A's.
my $only = $B{only};
for (["absolute", $only, "/a-only/secret"],
    ["relative", "../b-only/secret", "../a-only/secret"],
    ["above the root", "../../../../../b-only/secret", "../../../../../a-only/secret"],
    ["to a link", "/b-only/link", "/a-only/link"],
    ["to a directory", "/b-only", "/a-only"],
    ["to a link to B's", "/a-only/sym-absolute", "/a-only/own-absolute"],
    ["through a directory", "sym-to_a_directory/secret", "own-to_a_directory/secret"]) {
    my ($kind, $theirs, $mine) = @$_;
    (my $name = $kind) =~ tr/ /_/;
    my ($sym, $own) = ("/a-only/sym-$name", "/a-only/own-$name");
    control("symlink ($kind)", syscall(88, my $t = $theirs, my $s = $sym));
    symlink($mine, $own) or die "symlink $own: $!";
    control("lstat a symlink ($kind)", syscall(6, my $l = $sym, $st));
    same("readlink a symlink ($kind)", readlink($sym), $theirs);
    my $dir = $kind eq "to a directory";
    my $x = $sym;
    my $o = $own;
    want("stat a symlink ($kind)", "ENOENT", syscall(4, $x, $st));
    control("stat a symlink ($kind)", syscall(4, $o, $st));
    want("open a symlink ($kind)", "ENOENT", syscall(2, $x, 0, 0));
    control("open a symlink ($kind)", syscall(2, $o, 0, 0));
    want("access a symlink ($kind)", "ENOENT", syscall(21, $x, 0));
    control("access a symlink ($kind)", syscall(21, $o, 0));
    want("chmod a symlink ($kind)", "ENOENT", syscall(90, $x, 0700));
    control("chmod a symlink ($kind)", syscall(90, $o, 0700));
    if ($dir) {
        want("chdir a symlink ($kind)", "ENOENT", syscall(80, $x));
        control("chdir a symlink ($kind)", syscall(80, $o));
        chdir("/") or die "chdir: $!";
        next;
    }
    want("truncate a symlink ($kind)", "ENOENT", syscall(76, $x, 5));
    control("truncate a symlink ($kind)", syscall(76, $o, 11));
    want("open a symlink to write ($kind)", "ENOENT", syscall(2, $x, O_WRONLY | O_TRUNC, 0));
    control("open a symlink to write ($kind)", syscall(2, $o, O_WRONLY, 0));
    # B's directory is not here to make the file in.
    want("open a symlink with O_CREAT ($kind)", "ENOENT", syscall(2, $x, O_WRONLY | O_CREAT, 0600));
    control("open a symlink with O_CREAT ($kind)", syscall(2, $o, O_WRONLY | O_CREAT, 0600));
    my ($stolen, $linked) = ("/a-only/stolen-$name", "/a-only/linked-$name");
    want("linkat(AT_SYMLINK_FOLLOW) of a symlink ($kind)", "ENOENT", syscall(265, $CWD, $x, $CWD, $stolen, $FOLLOW));
    control("linkat(AT_SYMLINK_FOLLOW) of a symlink ($kind)", syscall(265, $CWD, $o, $CWD, $linked, $FOLLOW));
}
my ($upath, $apath) = ($B{upath}, "/a-only/sock");
symlink($upath, "/a-only/sym-sock") && symlink($apath, "/a-only/own-sock") or die "symlink: $!";
sub dial {
    socket(my $s, AF_UNIX, SOCK_STREAM, 0) or die "socket: $!";
    my $a = pack_sockaddr_un($_[0]);
    syscall(42, fileno($s), $a, length($a));
}
want("connect through a symlink to B's socket", "ENOENT", dial("/a-only/sym-sock"));
control("connect through a symlink to B's socket", dial("/a-only/own-sock"));

# Files made in B are absent in A, whatever the call.
my $rootfd = fd_of("/");
for (["file", $only, "/a-only/secret"], ["directory", "/b-only", "/a-only"],
    ["symlink", "/b-only/link", "/a-only/link"], ["socket", $upath, "/a-only/sock"],
    ["file from above the root", "/../../b-only/secret", "/../../a-only/secret"]) {
    my ($what, $x, $o) = @$_;
    want("stat B's $what", "ENOENT", syscall(4, $x, $st));
    control("stat B's $what", syscall(4, $o, $st));
    want("lstat B's $what", "ENOENT", syscall(6, $x, $st));
    control("lstat B's $what", syscall(6, $o, $st));
    want("access B's $what", "ENOENT", syscall(21, $x, 0));
    control("access B's $what", syscall(21, $o, 0));
    want("open(O_PATH) B's $what", "ENOENT", syscall(2, $x, $OPATH, 0));
    control("open(O_PATH) B's $what", syscall(2, $o, $OPATH, 0));
    my ($xr, $or) = (substr($x, 1), substr($o, 1));
    want("openat(/, O_PATH) B's $what", "ENOENT", syscall(257, $rootfd, $xr, $OPATH, 0));
    control("openat(/, O_PATH) B's $what", syscall(257, $rootfd, $or, $OPATH, 0));
}
my $lbuf = "\0" x 4096;
want("readlink B's symlink", "ENOENT", syscall(89, my $bl = "/b-only/link", $lbuf, 4096));
control("readlink B's symlink", syscall(89, my $al = "/a-only/link", $lbuf, 4096));
want("open B's file", "ENOENT", syscall(2, my $bf = $only, 0, 0));
control("open B's file", syscall(2, my $af = "/a-only/secret", 0, 0));
want("chdir to B's directory", "ENOENT", syscall(80, my $bd = "/b-only"));
control("chdir to B's directory", syscall(80, my $ad = "/a-only"));
chdir("/") or die "chdir: $!";
(my $uname = $upath) =~ s{.*/}{};
same("A's /tmp does not list B's socket", (grep { $_ eq $uname } split /,/, ls("/tmp")) ? "listed" : "absent", "absent");

# Links, renames and removals: from B's names, and into B's directory. Each
# call on B's names has files of B's to itself (v1 to v6, vd1 and vd2; the
# harness checks that they are all still there), so that one that worked
# would not hide the next. Each control is the same call on A's own names.
my $mine = "/a-only/secret";
spew("/a-only/r$_", "A's file $_\n") for (1 .. 7);
mkdir("/a-only/$_") or die "mkdir: $!" for ("d1", "d2", "in");
for my $c (
    ["link(B's file, A's name)", 86, ["/b-only/v1", "/a-only/stolen1"], [$mine, "/a-only/hard"]],
    ["link(A's file, B's directory)", 86, [$mine, "/b-only/planted1"], [$mine, "/a-only/in/planted1"]],
    ["linkat(B's file, A's name)", 265, [$rootfd, "b-only/v1", $rootfd, "a-only/stolen2", 0],
        [$rootfd, "a-only/secret", $rootfd, "a-only/hard2", 0]],
    ["rename(B's file, A's name)", 82, ["/b-only/v2", "/a-only/stolen3"], ["/a-only/r1", "/a-only/renamed"]],
    ["rename(B's directory, A's name)", 82, ["/b-only/vd1", "/a-only/stolen4"], ["/a-only/d1", "/a-only/renamed-dir"]],
    ["rename(A's file, B's directory)", 82, ["/a-only/r6", "/b-only/planted2"], ["/a-only/r2", "/a-only/in/planted2"]],
    ["rename(A's file, B's directory above the root)", 82, ["/a-only/r7", "/../../b-only/planted3"],
        ["/a-only/r3", "/../../a-only/in/planted3"]],
    ["renameat(B's file, A's name)", 264, [$rootfd, "b-only/v3", $rootfd, "a-only/stolen5"],
        [$rootfd, "a-only/r4", $rootfd, "a-only/renamed2"]],
    ["renameat2(B's file, A's name)", 316, [$CWD, "/b-only/v4", $CWD, "/a-only/stolen6", 1], # RENAME_NOREPLACE
        [$CWD, "/a-only/r5", $CWD, "/a-only/renamed3", 1]],
    ["symlink in B's directory", 88, ["x", "/b-only/symlink"], ["x", "/a-only/in/symlink"]],
    ["mkdir in B's directory", 83, ["/b-only/mkdir", 0755], ["/a-only/in/mkdir", 0755]],
    ["mkdirat in B's directory", 258, [$rootfd, "b-only/mkdirat", 0755], [$rootfd, "a-only/in/mkdirat", 0755]],
    ["mknod (a FIFO) in B's directory", 133, ["/b-only/fifo", 0010000 | 0600, 0], ["/a-only/fifo", 0010000 | 0600, 0]],
    ["open(O_CREAT) in B's directory", 2, ["/b-only/made", O_WRONLY | O_CREAT, 0600],
        ["/a-only/in/made", O_WRONLY | O_CREAT, 0600]],
    ["unlink(B's file)", 87, ["/b-only/v5"], ["/a-only/in/planted1"]],
    ["unlinkat(B's file)", 263, [$rootfd, "b-only/v6", 0], [$rootfd, "a-only/in/planted2", 0]],
    ["rmdir(B's directory)", 84, ["/b-only/vd2"], ["/a-only/d2"]],
) {
    my ($what, $nr, $theirs, $own) = @$c;
    want($what, "ENOENT", syscall($nr, @$theirs));
    control($what, syscall($nr, @$own));
}

# A link or rename aimed above the root ends in the root.
spew("/a-only/up1", "up\n");
my $up1 = id("/a-only/up1");
control("link to ../../../a-linked", syscall(86, my $u1 = "/a-only/up1", my $u2 = "/../../../a-linked"));
same("the link above the root is in A's root", id("/a-linked"), $up1);
control("rename to ../../../a-renamed", syscall(82, $u1, my $u3 = "/../../../a-renamed"));
same("the rename above the root is in A's root", id("/a-renamed"), $up1);
control("symlink at ../../../a-symlink", syscall(88, my $u4 = "x", my $u5 = "/../../../a-symlink"));
same("the symlink above the root is in A's root", readlink("/a-symlink"), "x");
control("mkdir ../../../a-dir", syscall(83, my $u6 = "/../../../a-dir", 0755));
same("the directory above the root is in A's root", (-d "/a-dir") ? "there" : "absent", "there");
# No directory can be cut loose from the root.
want("rename(a directory, into itself)", "EINVAL", syscall(82, my $u7 = "/a-dir", my $u8 = "/a-dir/inside"));
control("rename(a directory, into itself)", syscall(82, $u7, my $u9 = "/a-dir2"));

# A file of A's under B's very path is A's: A's link to B's file now reads
# it, and (the harness checks B's secret after this section) writing and
# removing it leaves B's alone.
control("mkdir B's directory name", syscall(83, my $s1 = "/b-only", 0755));
spew($only, "A's own\n");
same("A's file under B's name is A's", slurp($only), "A's own\n");
same("A's symlink to B's path reads A's own file", slurp("/a-only/sym-absolute"), "A's own\n");
same("A's directory under B's name holds only A's file", ls("/b-only"), "secret");
control("unlink A's file under B's name", syscall(87, $only));
control("rmdir A's directory under B's name", syscall(84, $s1));
want("stat B's file after A removed its own", "ENOENT", syscall(4, $only, $st));
control("stat B's file after A removed its own", syscall(4, $mine, $st));

# The files of the image both roots start from are changed in A only: one
# written, one removed, a directory moved.
open(my $issue, ">>", "/etc/issue") or die "issue: $!";
print $issue "written in A\n";
close $issue or die "issue: $!";
same("A wrote to an image file", slurp("/etc/issue") =~ /written in A\n\z/ ? "written" : "not", "written");
control("unlink an image file", syscall(87, my $i1 = "/etc/issue.net"));
control("rename an image directory", syscall(82, my $i2 = "/etc/skel", my $i3 = "/a-only/skel"));
same("the image directory is at its new name in A", (-e "/a-only/skel/.bashrc") ? "there" : "absent", "there");

# A's own ptys: numbered from 0 as B's are, and other ptys.
sub pty {
    sysopen(my $m, "/dev/ptmx", O_RDWR | O_NOCTTY) or die "ptmx: $!";
    my ($n, $u) = (pack("i", 0), pack("i", 0));
    ioctl($m, 0x80045430, $n) or die "TIOCGPTN: $!";
    ioctl($m, 0x40045431, $u) or die "unlockpt: $!";
    ($m, unpack("i", $n));
}
my ($m0, $n0) = pty();
same("A's first pty has B's first number", $n0, $PTS[0]);
same("A's devpts lists only A's pty", ls("/dev/pts"), "0");
want("open /dev/pts/1 (B's) while A has 0", "ENOENT", syscall(2, my $p1 = "/dev/pts/1", O_RDWR | O_NOCTTY, 0));
control("stat /dev/pts/N (B's)", syscall(4, my $p0 = "/dev/pts/$n0", $st));
my $s0 = syscall(2, $p0, O_RDWR | O_NOCTTY, 0);
control("open /dev/pts/N (B's)", $s0);
control("openat(/dev/pts, N) (B's)", my $s00 = syscall(257, $ptsfd, my $pn = "$n0", O_RDWR | O_NOCTTY, 0));
# A node of B's number made by hand would name B's pty; none can be made.
want("mknod(a node with B's pty's device number)", "EPERM", syscall(133, my $k1 = "/a-only/pts-dev", 0020000 | 0666, (136 << 8) | $PTS[1]));
control("mknod(a node with B's pty's device number)", syscall(133, my $k2 = "/a-only/pts-fifo", 0010000 | 0666, 0));
# What A's slave says and sets is heard on A's master (B's masters are
# checked by the harness).
my $size = pack("S4", 33, 77, 0, 0);
open(my $slave, "+<&=", $s0) or die "fdopen: $!";
ioctl($slave, 0x5414, $size) or die "TIOCSWINSZ: $!";
my $seen = "\0" x 8;
ioctl($m0, 0x5413, $seen) or die "TIOCGWINSZ: $!";
same("A's pty has the size A's slave set", join("x", (unpack("S4", $seen))[0, 1]), "33x77");
syswrite($slave, "from A\n") == 7 or die "slave: $!";
my ($heard, $rin) = ("", "");
vec($rin, fileno($m0), 1) = 1;
sysread($m0, $heard, 100) if select(my $rout = $rin, undef, undef, 5) > 0;
same("A's master hears A's slave", $heard, "from A\r\n");
# Another name for A's node, kept past its pty: A's number 0 is then nobody's
# in A while B still has a pty 0, and the node opens neither.
my $keep = "/a-only/pts-node";
control("link(/dev/pts/N) (B's)", syscall(86, $p0, $keep));
my $s1k = syscall(2, $keep, O_RDWR | O_NOCTTY, 0);
control("open a node of A's old pty", $s1k);
POSIX::close($_) for ($s1k, $s00);
close $slave;
close $m0;
same("A's devpts is empty again", ls("/dev/pts"), "");
want("open a node of A's old pty", "EIO", syscall(2, $keep, O_RDWR | O_NOCTTY, 0));
unlink($keep) or die "unlink: $!";
done();
