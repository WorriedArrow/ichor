# Section 2: /proc and /sys. B's /proc/<pid> trees are absent in A, the
# /proc listing shows only A, and /proc/self's links resolve inside A's
# root. Global files are read and recorded, not judged (the report says
# what each one shows about other cells).
$RULE = "proc_and_sys_show_only_their_cell";
my %B = kv(@ARGV);
my $st = "\0" x 144;
my $lbuf = "\0" x 4096;
for my $p ($B{pid}, $B{child}, $B{futex_pid}) {
    for my $f ("", "/status", "/stat", "/cmdline", "/cwd", "/exe", "/fd", "/fd/0", "/maps", "/root", "/mem", "/mounts") {
        want("stat /proc/$p$f (B)", "ENOENT", syscall(4, my $x = "/proc/$p$f", $st));
    }
    want("readlink /proc/$p/cwd (B)", "ENOENT", syscall(89, my $x = "/proc/$p/cwd", $lbuf, 4096));
    want("open /proc/$p/status (B)", "ENOENT", syscall(2, my $y = "/proc/$p/status", 0, 0));
}
for my $f ("", "/status", "/stat", "/cmdline", "/cwd", "/exe", "/fd", "/fd/0", "/maps", "/mounts") {
    control("stat /proc/<pid>$f (A's own pid)", syscall(4, my $x = "/proc/" . $$ . $f, $st));
}
control("readlink /proc/<pid>/cwd (A's own pid)", syscall(89, my $c = "/proc/" . $$ . "/cwd", $lbuf, 4096));
control("open /proc/<pid>/status (A's own pid)", syscall(2, my $s = "/proc/" . $$ . "/status", 0, 0));
# Not in Ichor's /proc yet, for A's own process either.
want("stat /proc/self/root [not in /proc yet]", "ENOENT", syscall(4, my $r = "/proc/self/root", $st));
want("stat /proc/self/mem [not in /proc yet]", "ENOENT", syscall(4, my $m = "/proc/self/mem", $st));

# Listing /proc: the only process directory is A's own.
opendir(my $d, "/proc") or die "opendir /proc: $!";
my @pids = sort { $a <=> $b } grep { /^\d+$/ } readdir($d);
closedir $d;
same("/proc lists only A's process", join(",", @pids), $$);

# /proc/self's links name A's own files and resolve in A's root.
chdir("/tmp") or die "chdir: $!";
same("/proc/self/cwd names A's working directory", readlink("/proc/self/cwd"), "/tmp");
open(my $mine, ">", "/tmp/a-file") or die "a-file: $!";
print $mine "A's file\n";
close $mine;
open(my $via, "<", "/tmp/a-file") or die "a-file: $!";
same("A's file is there", scalar(<$via>), "A's file\n");
close $via;
# procfs does not follow a link partway through a path yet, so these are
# ENOENT for A's own file too (recorded; the B case cannot fail open).
want("open /proc/self/cwd/a-file [links not followed mid-path yet]", "ENOENT", syscall(2, my $ac = "/proc/self/cwd/a-file", 0, 0));
want("open /proc/self/cwd/../b-only/secret", "ENOENT", syscall(2, my $bc = "/proc/self/cwd/../b-only/secret", 0, 0));
open(my $fdf, "<", "/tmp/a-file") or die "a-file: $!";
# procfs names open files anon_inode:[file] when it cannot find their path
# (documented as partial in procfs.rs); anything else must be A's file.
my $link = readlink("/proc/self/fd/" . fileno($fdf)) // "none: $!";
print "cellaccess: $RULE: /proc/self/fd/N for /tmp/a-file reads $link\n";
same("/proc/self/fd/N names A's open file (or the documented placeholder)",
    $link =~ m{^(/tmp/a-file|anon_inode:\[file\])$} ? "A's" : $link, "A's");
opendir(my $fdd, "/proc/self/fd") or die "fd dir: $!";
my @fds = grep { /^\d+$/ } readdir($fdd);
closedir $fdd;
same("/proc/self/fd lists A's descriptors", (grep { $_ == fileno($fdf) } @fds) ? "listed" : "missing", "listed");
same("/proc/self/exe is A's program", readlink("/proc/self/exe"), "/usr/bin/perl");
open(my $maps, "<", "/proc/self/maps") or die "maps: $!";
my $mtext = do { local $/; <$maps> };
close $maps;
my $bva = sprintf("%x", $B{futex_va});
same("A's maps do not show B's mapping at $bva", index($mtext, "$bva-") < 0 ? "absent" : "present", "absent");
same("A's maps show A's own perl", $mtext =~ m{/usr/bin/perl|r-xp} ? "present" : "absent", "present");

# Global files: what each one shows (recorded for the report).
sub show {
    my ($path, $lines) = @_;
    open(my $f, "<", $path) or do { print "cellaccess: global: $path: $!\n"; return };
    my @l = <$f>;
    close $f;
    chomp @l;
    my @keep = defined $lines ? grep { $_ =~ $lines } @l : @l;
    print "cellaccess: global: $path: ", join(" | ", @keep[0 .. ($#keep < 5 ? $#keep : 5)]), "\n";
}
show("/proc/meminfo", qr/^Mem/);
show("/proc/loadavg");
show("/proc/stat", qr/^(processes|procs|btime|cpu )/);
show("/proc/mounts");
show("/proc/cpuinfo", qr/^processor/);
show("/proc/uptime");
show("/proc/version");
show("/proc/sys/kernel/hostname");
show("/proc/sys/kernel/pid_max");
show("/sys/devices/system/cpu/online");
show("/sys/devices/system/cpu/possible");
done();
