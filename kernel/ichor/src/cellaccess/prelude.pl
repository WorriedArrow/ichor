use strict; use warnings; use POSIX (); use Socket; use Fcntl; use Errno ();
no warnings 'portable'; # 64-bit hexadecimal addresses
# Shared by B's helper and A's checks (cellaccess.rs prepends it).
#
# The channel to the harness: files under /run/ichor in this cell's own
# root. put(NAME, TEXT) writes out-NAME (via a temporary name and a
# rename, so the harness never reads half of it); get(NAME) waits for
# in-NAME from the harness, removes it and returns its text.
our $RULE = "harness";
our ($PASSES, $FAILS) = (0, 0);
sub put {
    my ($name, $text) = @_;
    my $t = "/run/ichor/.out-$name.$$";
    open(my $f, ">", $t) or die "cellaccess: $t: $!\n";
    print $f $text;
    close $f or die "cellaccess: close $t: $!\n";
    rename($t, "/run/ichor/out-$name") or die "cellaccess: rename $t: $!\n";
}
sub poll_in {
    my ($name) = @_;
    my $p = "/run/ichor/in-$name";
    open(my $f, "<", $p) or return undef;
    local $/;
    my $v = <$f>;
    close $f;
    unlink $p;
    return $v // "";
}
sub get {
    my ($name, $secs) = @_;
    $secs //= 300;
    for (1 .. $secs * 50) {
        my $v = poll_in($name);
        return $v if defined $v;
        select(undef, undef, undef, 0.02);
    }
    die "cellaccess: no in-$name from the harness\n";
}
# key=value words (B's identifiers) into a hash; numbers stay numbers.
sub kv {
    my %h;
    for (@_) {
        my ($k, $v) = split /=/, $_, 2;
        $v //= "";
        $h{$k} = $v =~ /^\d+$/ ? $v + 0 : $v;
    }
    %h;
}

# Errno names both ways, from the C library's own values.
our %ENAME;
for my $n (@Errno::EXPORT_OK) {
    my $f = Errno->can($n) or next;
    my $v = eval { $f->() };
    $ENAME{$v} //= $n if defined $v;
}
sub en { my $v = shift; $ENAME{$v} // "errno $v" }
sub ev { my $n = shift; my $f = Errno->can($n) or die "cellaccess: no errno $n\n"; $f->() }

# Checks. want(CHECK, ERRNO, RESULT) passes if the call returned -1 with
# exactly that errno (perl's syscall() sets $! and returns -1); any
# success or other errno fails, naming what came back. control(CHECK,
# RESULT) passes if the call succeeded. same(CHECK, GOT, WANT) compares
# two values. Every function reads $! first, before anything can clobber it.
sub ok { $PASSES++; print "cellaccess: $RULE: $_[0]: ok\n" }
sub bad { $FAILS++; print "cellaccess FAILED: $RULE: $_[0]: $_[1]\n" }
sub want {
    my $e = $! + 0;
    my ($check, $name, $r) = @_;
    if (defined $r && $r == -1 && $e == ev($name)) { ok("$check ($name)") }
    elsif (defined $r && $r == -1) { bad($check, "expected $name, got " . en($e)) }
    else { bad($check, "expected $name, got success (" . ($r // "undef") . ")") }
}
sub control {
    my $e = $! + 0;
    my ($check, $r) = @_;
    if (defined $r && $r != -1) { ok("$check: control") }
    else { bad("$check: control", "expected success, got " . en($e)) }
}
sub same {
    my ($check, $got, $want) = @_;
    $got = "undef" unless defined $got;
    if ($got eq $want) { ok($check) } else { bad($check, "expected [$want], got [$got]") }
}
sub done {
    print "cellaccess: $RULE: $PASSES checks passed, $FAILS failed\n";
    exit($FAILS ? 1 : 0);
}
# syscall() may write through any string argument, so a literal must be
# passed as a variable: syscall(4, my $p = "/etc", ...). Numbers from the
# harness arrive as strings and must be made numbers (+ 0), or they would
# be passed as pointers.
#
# A pointer to a perl string's bytes (for syscall arguments that are
# structures holding pointers), and memory read at an address.
sub ptr { unpack("Q", pack("p", $_[0])) }
sub peek { my ($addr, $n) = @_; unpack("P$n", pack("Q", $addr)) }
