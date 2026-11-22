# A cell's last act: listen, take one connection, write 400 KiB (more than
# the peer's window, so the rest is still in this stack's buffer), close
# and exit. The harness destroys the cell the moment this exits.
$RULE = "a_destroyed_cell_leaves_no_network";
socket(my $l, AF_INET, SOCK_STREAM, 0) or die "socket: $!";
setsockopt($l, SOL_SOCKET, SO_REUSEADDR, 1) or die "SO_REUSEADDR: $!";
bind($l, pack_sockaddr_in(7200, INADDR_ANY)) or die "bind: $!";
listen($l, 4) or die "listen: $!";
put("serving", "yes");
accept(my $c, $l) or die "accept: $!";
my ($data, $off) = ("x" x 409_600, 0);
while ($off < length($data)) {
    my $w = syswrite($c, $data, 65536, $off) // die "write: $!";
    $off += $w;
}
close $c;
exit 0;
