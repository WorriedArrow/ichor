# Section 4: A reads more distinct file data than the shared page cache
# holds (48 MiB of files under /usr), so the cache has to evict.
$RULE = "shared_cache_pages_never_carry_writes_between_cells";
my ($total, $files) = (0, 0);
my @dirs = ("/usr");
while (@dirs && $total < (48 << 20)) {
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
        last if $total >= (48 << 20);
    }
}
print "cellaccess: $RULE: A read $total bytes from $files files\n";
same("A read more than the shared cache holds", $total >= (40 << 20) ? "yes" : "only $total bytes", "yes");
done();
