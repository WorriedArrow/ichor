# The harness works: A has B's identifiers (from the harness only), and a
# path that exists only in B's root is absent in A while A's own is there.
$RULE = "harness";
my %B = kv(@ARGV);
same("B's identifiers arrived", (defined $B{pid} && $B{pid} =~ /^\d+$/) ? "yes" : "no", "yes");
same("B is another process", $B{pid} == $$ ? "same" : "other", "other");
my $st = "\0" x 144;
want("stat B's file", "ENOENT", syscall(4, $B{only}, $st));
control("stat B's file", syscall(4, my $own = "/etc/debian_version", $st));
done();
