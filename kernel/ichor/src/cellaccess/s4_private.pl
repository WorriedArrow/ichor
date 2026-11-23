# Section 4: a process in B', whose root opted out of page sharing, reads
# two files through its private cache namespace.
$RULE = "shared_cache_pages_never_carry_writes_between_cells";
for my $p ("/usr/bin/dash", "/usr/bin/perl") {
    open(my $f, "<", $p) or die "$p: $!";
    my $n = 0;
    while (my $r = sysread($f, my $buf, 1 << 16)) { $n += $r }
    close $f;
    same("B' read $p through its private namespace", $n == -s $p ? "whole" : "short", "whole");
}
done();
