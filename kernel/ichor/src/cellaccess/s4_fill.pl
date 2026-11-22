# Section 4: A reads every file it can see (up to 160 MiB), more distinct
# data than the shared page cache holds, so the cache has to evict (the
# harness checks that it did).
$RULE = "shared_cache_pages_never_carry_writes_between_cells";
my ($total, $files, $max) = (0, 0, 160 << 20);
my @dirs = ("/usr", "/mirror", "/var", "/etc");
while (@dirs && $total < $max) {
    my $d = shift @dirs;
    opendir(my $h, $d) or next;
    my @names = sort grep { $_ ne "." && $_ ne ".." } readdir($h);
    closedir $h;
    for my $n (@names) {
        my $p = "$d/$n";
        next if -l $p;
        if (-d _) { push @dirs, $p; next }
        next unless -f _;
        open(my $f, "<", $p) or next;
        while (my $r = sysread($f, my $buf, 1 << 16)) { $total += $r }
        close $f;
        $files++;
        last if $total >= $max;
    }
}
print "cellaccess: $RULE: A read $total bytes from $files files\n";
same("A read the image's files", $total >= (40 << 20) ? "yes" : "only $total bytes", "yes");
done();
