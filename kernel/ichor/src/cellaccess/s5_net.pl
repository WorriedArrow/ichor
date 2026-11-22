# Section 5 (perl part): networks. A cannot bind B's address; cell to cell
# TCP is allowed (ADR-0010) and carries A's own address; loopback is per
# cell; A has no raw sockets to forge another source with. B's Unix path
# and abstract names do not reach from A, SO_PEERCRED names A's own peer,
# and SCM_RIGHTS works inside A but has no way to B.
$RULE = "networks_are_scoped_to_their_cell";
my %B = kv(@ARGV);
my $ME = $B{self_ip};
sub sock { socket(my $s, $_[0], $_[1], 0) or die "socket: $!"; $s }
sub inaddr { pack_sockaddr_in($_[1], inet_aton($_[0])) }

# bind: B's address is not A's.
my $s = sock(AF_INET, SOCK_STREAM);
want("bind(B's address)", "EADDRNOTAVAIL", syscall(49, fileno($s), my $ba = inaddr($B{ip}, 0), 16));
close $s;
$s = sock(AF_INET, SOCK_STREAM);
control("bind(B's address)", syscall(49, fileno($s), my $aa = inaddr($ME, 0), 16));
close $s;
my $u = sock(AF_INET, SOCK_DGRAM);
want("bind(B's address) for UDP", "EADDRNOTAVAIL", syscall(49, fileno($u), my $bu = inaddr($B{ip}, 0), 16));
close $u;

# Cell to cell TCP is allowed by ADR-0010's policy (the switch forwards by
# assigned address); the connection comes from A's own address.
my $c = sock(AF_INET, SOCK_STREAM);
control("connect(B's address and port) [allowed by ADR-0010]", syscall(42, fileno($c), my $bp = inaddr($B{ip}, $B{port}), 16));
my ($lport, $laddr) = unpack_sockaddr_in(getsockname($c));
same("A's end of the connection has A's address", inet_ntoa($laddr), $ME);
my $got = "";
sysread($c, $got, 100);
same("B's server answered", $got, "B tcp\n");
close $c;
print "cellaccess: $RULE: A connected to B from $ME:$lport\n";
# Loopback is per cell: 127.0.0.1 in A is A's own stack, where nothing
# listens on B's port.
$c = sock(AF_INET, SOCK_STREAM);
want("connect(127.0.0.1, B's port) [loopback is per cell]", "ECONNREFUSED", syscall(42, fileno($c), my $lo = inaddr("127.0.0.1", $B{port}), 16));
close $c;
my $l = sock(AF_INET, SOCK_STREAM);
setsockopt($l, SOL_SOCKET, SO_REUSEADDR, 1);
bind($l, inaddr("127.0.0.1", $B{port})) or die "bind: $!";
listen($l, 4) or die "listen: $!";
$c = sock(AF_INET, SOCK_STREAM);
control("connect(127.0.0.1, B's port) [loopback is per cell]", syscall(42, fileno($c), my $lo2 = inaddr("127.0.0.1", $B{port}), 16));
close $c;
close $l;
# No raw or packet sockets, so A cannot send a packet with another source.
want("socket(AF_INET, SOCK_RAW)", "EPERM", syscall(41, AF_INET, 3, 255));
want("socket(AF_PACKET, SOCK_RAW)", "EAFNOSUPPORT", syscall(41, 17, 3, 0));
# rtnetlink answers for A's own interfaces: A's address, never B's.
socket(my $nl, 16, 2, 0) or die "netlink: $!"; # AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE
my $dump = "";
for my $type (18, 22, 26) { # RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE
    my $ask = pack("LSSLL", 20, $type, 0x301, $type, 0) . "\0\0\0\0"; # NLM_F_REQUEST|NLM_F_DUMP
    syswrite($nl, $ask) == 20 or die "netlink send: $!";
    my ($answer, $end) = ("", 0);
    while (!$end) {
        my $rin = "";
        vec($rin, fileno($nl), 1) = 1;
        select(my $ro = $rin, undef, undef, 5) == 1 or last;
        sysread($nl, my $buf, 32768) or last;
        $answer .= $buf;
        my $at = 0;
        while ($at + 16 <= length($buf)) {
            my ($len, $t) = unpack("LS", substr($buf, $at, 6));
            $end = 1 if $t == 3 || $t == 2; # NLMSG_DONE, NLMSG_ERROR
            last if $len < 16;
            $at += ($len + 3) & ~3;
        }
    }
    $dump .= $answer;
}
same("rtnetlink shows A's own address", index($dump, inet_aton($ME)) >= 0 ? "shown" : "absent", "shown");
same("rtnetlink does not show B's address", index($dump, inet_aton($B{ip})) >= 0 ? "shown" : "absent", "absent");

# Unix sockets: B's path is not in A's root; B's abstract names are B's.
my $us = sock(AF_UNIX, SOCK_STREAM);
my $bpath = pack_sockaddr_un($B{upath});
want("connect(B's Unix path)", "ENOENT", syscall(42, fileno($us), $bpath, length($bpath)));
close $us;
my $babs = pack_sockaddr_un("\0$B{abstract}");
$us = sock(AF_UNIX, SOCK_STREAM);
want("connect(B's abstract name)", "ECONNREFUSED", syscall(42, fileno($us), $babs, length($babs)));
close $us;
my $bdg = pack_sockaddr_un("\0$B{dgram}");
my $ud = sock(AF_UNIX, SOCK_DGRAM);
my $msg = "from A";
want("sendto(B's abstract datagram name)", "ECONNREFUSED", syscall(44, fileno($ud), $msg, length($msg), 0, $bdg, length($bdg)));
# A descriptor sent to B's datagram name fails like any other send there
# (before A binds that name in its own namespace below).
open(my $pass, "<", "/etc/debian_version") or die "debian_version: $!";
my $data = "fd";
my $iov = pack("QQ", ptr($data), length($data));
my $ctl = pack("QiiI", 20, 1, 1, fileno($pass)) . ("\0" x 4); # SOL_SOCKET, SCM_RIGHTS
my $mh = msghdr(\$bdg, \$iov, \$ctl);
want("sendmsg(SCM_RIGHTS) to B's abstract datagram name", "ECONNREFUSED", syscall(46, fileno($ud), $mh, 0));
# Controls: the same names, made by A in A.
my $apath = "/tmp/ichor-a.sock";
my $al = sock(AF_UNIX, SOCK_STREAM);
bind($al, pack_sockaddr_un($apath)) or die "bind $apath: $!";
listen($al, 4) or die "listen: $!";
my $aabs = sock(AF_UNIX, SOCK_STREAM);
bind($aabs, pack_sockaddr_un("\0$B{abstract}")) or die "bind abstract: $!"; # B's name, in A's namespace
listen($aabs, 4) or die "listen: $!";
my $adg = sock(AF_UNIX, SOCK_DGRAM);
bind($adg, pack_sockaddr_un("\0$B{dgram}")) or die "bind dgram: $!";
ok("A can bind B's abstract names in its own namespace");
$us = sock(AF_UNIX, SOCK_STREAM);
my $ap = pack_sockaddr_un($apath);
control("connect(B's Unix path)", syscall(42, fileno($us), $ap, length($ap)));
close $us;
accept(my $drop, $al) or die "accept: $!"; # off the backlog before SO_PEERCRED
close $drop;
$us = sock(AF_UNIX, SOCK_STREAM);
control("connect(B's abstract name)", syscall(42, fileno($us), $babs, length($babs)));
close $us;
control("sendto(B's abstract datagram name)", syscall(44, fileno($ud), $msg, length($msg), 0, $bdg, length($bdg)));
recv($adg, my $m, 100, 0);
same("A's own datagram name got A's datagram", $m, $msg);

# SO_PEERCRED names the peer as A's cell knows it.
my $kid = fork() // die "fork: $!";
if ($kid == 0) {
    my $k = sock(AF_UNIX, SOCK_STREAM);
    connect($k, pack_sockaddr_un($apath)) or POSIX::_exit(1);
    sysread($k, my $x, 1);
    POSIX::_exit(0);
}
accept(my $peer, $al) or die "accept: $!";
my ($ppid, $puid, $pgid) = unpack("iII", getsockopt($peer, SOL_SOCKET, SO_PEERCRED));
same("SO_PEERCRED names A's child (pid, uid, gid)", "$ppid $puid $pgid", "$kid 0 0");
syswrite($peer, "x");
waitpid($kid, 0);
close $peer;

# SCM_RIGHTS: the control, a descriptor passed over A's own socketpair.
sub msghdr {
    my ($name, $iov, $ctl) = @_;
    pack("QLx4QQQQix4", defined $name ? ptr($$name) : 0, defined $name ? length($$name) : 0,
        ptr($$iov), 1, ptr($$ctl), length($$ctl), 0);
}
socketpair(my $x, my $y, AF_UNIX, SOCK_DGRAM, 0) or die "socketpair: $!";
my $mh2 = msghdr(undef, \$iov, \$ctl);
control("sendmsg(SCM_RIGHTS) to B's abstract datagram name", syscall(46, fileno($x), $mh2, 0));
my $rbuf = "\0" x 16;
my $riov = pack("QQ", ptr($rbuf), 16);
my $rctl = "\0" x 24;
my $rmh = msghdr(undef, \$riov, \$rctl);
same("recvmsg got the passed descriptor's bytes", syscall(47, fileno($y), $rmh, 0), 2);
my (undef, $lv, $ty, $fd) = unpack("QiiI", $rctl);
same("the control message is SCM_RIGHTS", "$lv $ty", "1 1");
open(my $back, "<&=", $fd) or die "fdopen: $!";
same("the passed descriptor reads A's file", scalar(<$back>), do { seek($pass, 0, 0); scalar(<$pass>) });
done();
