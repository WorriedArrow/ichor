# A connects to the dying cell, waits until it is gone (the harness says
# when), and only then reads: everything it wrote must still arrive.
$RULE = "a_destroyed_cell_leaves_no_network";
my %B = kv(@ARGV);
socket(my $c, AF_INET, SOCK_STREAM, 0) or die "socket: $!";
connect($c, pack_sockaddr_in(7200, inet_aton($B{dying}))) or die "connect: $!";
put("connected", "yes");
get("read");
my ($got, $end) = (0, "open");
while (1) {
    my $r = sysread($c, my $buf, 65536);
    if (!defined $r) { $end = en($! + 0); last }
    if ($r == 0) { $end = "end of file"; last }
    $got += $r;
}
same("all a destroyed cell had written arrives, then end of file", "$got $end", "409600 end of file");
done();
