#!/usr/bin/env perl
#
# freeze-regression-fixture.pl
#   Distil the work-stream B coverage into a FROZEN, committed regression
#   fixture for work-stream C (threat-model docs/threat-model.md §6 C; plan
#   docs/honeypot-C-plan.md). Where B *measured* would-block coverage in detect
#   mode, C *asserts* it in ENFORCE mode against this fixture: every vector the
#   WAF blocks TODAY is captured with its frozen verdict {expected_reason,
#   expected_status}, and run-regression-tests.sh later asserts those verdicts
#   have not silently changed.
#
#   TWO-PASS PROBE per dimension, against an ALREADY-RUNNING regression-nginx
#   (this script does NOT start nginx -- the operator / harness does, exactly
#   like the sibling build-header-fixtures.pl):
#     1. DETECT pass  -> the detect vhost (waf detect, X-WAF-Reason on) yields
#        the authoritative reason. A vector enters the fixture iff its detect
#        reason != none (= the "covered" set, the partner's "mind" decision).
#     2. ENFORCE pass -> the SAME covered vectors against the enforce vhost
#        (waf on, --enforce) yield the real HTTP status (404 / 403 / 444).
#   Frozen verdict = { reason: from detect, status: from enforce }. On a 444
#   (NGX_HTTP_CLOSE) no X-WAF-Reason reaches the wire, which is exactly why the
#   reason is taken from the detect pass and the enforce assert is status-only.
#
#   JOIN KEY. The path matcher only inspects method+uri (these vhosts carry NO
#   method filter), so a uri's verdict is method-independent and identical
#   across the ~12k duplicate (method,uri) feed rows. We therefore DEDUP by uri
#   (path/args) / value (headers) and join detect+enforce on that key. The
#   enforce pass runs ONLY on the deduped covered subset, so it is ~35k fresh
#   Connection: close sockets, not the full 85k feed.
#
#   SKIP PARITY. Both passes run the SAME replay-client.pl, so CONNECT /
#   absolute-URI (path) and CRLF (header) skips are identical -- the fixture can
#   never contain a vector the replay would skip.
#
#   SECURITY (security-officer guardrail #2):
#     - The client is spawned with LIST-form system() ONLY; no fixture byte ever
#       reaches a shell.
#     - Every temp path is a FIXED, code-controlled name under corpus/.freeze-tmp/
#       keyed on the dimension name from a hard-coded list -- NEVER derived from
#       a uri / header value.
#     - IP-free: the feeds carry no remote_addr by construction (the extractor
#       never emits field 0); any IP inside a uri/value is attacker-supplied
#       payload, not a client address.
#
#   core-perl only (JSON::PP ships with perl >= 5.14); NO CPAN, NO docker.
#   This script is the durable, committable generator; its committed OUTPUTS are
#   regression-vectors.jsonl + regression-headers.jsonl. Its per-run temp files
#   under .freeze-tmp/ are gitignored.
#
use strict;
use warnings;
use JSON::PP ();
use File::Basename qw(dirname);
use File::Path qw(make_path);

# --------------------------------------------------------------------------
# paths / options (script lives in tools/; defaults target ../tests/corpus/)
# --------------------------------------------------------------------------
my $here   = dirname(__FILE__);
my %opt = (
    host   => '127.0.0.1',
    perl   => $^X,                       # the running interpreter
    client => "$here/../tests/replay-client.pl",
    corpus => "$here/../tests/corpus",
    tmp    => "$here/../tests/corpus/.freeze-tmp",
);
while (@ARGV) {
    my $a = shift @ARGV;
    if    ($a eq '--host')   { $opt{host}   = shift @ARGV; }
    elsif ($a eq '--corpus') { $opt{corpus} = shift @ARGV; }
    elsif ($a eq '--client') { $opt{client} = shift @ARGV; }
    elsif ($a eq '--tmp')    { $opt{tmp}    = shift @ARGV; }
    elsif ($a eq '-h' || $a eq '--help') {
        print "usage: perl freeze-regression-fixture.pl "
            . "[--host H] [--corpus DIR] [--client PATH] [--tmp DIR]\n"
            . "  (requires a running regression-nginx on ports 283xx)\n";
        exit 0;
    }
    else { die "unknown option: $a\n"; }
}
make_path($opt{tmp}) unless -d $opt{tmp};

my $JP  = JSON::PP->new->utf8;               # reader
my $OUT = JSON::PP->new->utf8->canonical;    # writer: stable key order -> clean diffs

# --------------------------------------------------------------------------
# dimension tables. [L2] args is generated against the ARGS vhost (28303/28304),
# never by reusing the path probe -- so the frozen dim/reason matches the vhost
# that will route it at assert time.
# --------------------------------------------------------------------------
my @PATH_DIMS = (
    { dim => 'path', detect => 28301, enforce => 28302 },
    { dim => 'args', detect => 28303, enforce => 28304 },
);
my @HEADER_DIMS = (
    { dim => 'ua',      header => 'User-Agent', detect => 28305, enforce => 28306, feed => 'fixtures/ua.jsonl'      },
    { dim => 'referer', header => 'Referer',    detect => 28307, enforce => 28308, feed => 'fixtures/referer.jsonl' },
    { dim => 'cookie',  header => 'Cookie',     detect => 28309, enforce => 28310, feed => 'fixtures/cookie.jsonl'  },
    { dim => 'fakebot', header => 'User-Agent', detect => 28311, enforce => 28312, feed => 'fixtures/fakebot.jsonl' },
);
my $PATH_FEED = "$opt{corpus}/replay-vectors.jsonl";   # path + args share this feed

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

# spawn replay-client.pl -- LIST form ONLY (security #2: no shell, no interpolation).
sub run_client {
    my (%a) = @_;   # kind, port, in, out, header?, enforce?
    my @cmd = ($opt{perl}, $opt{client},
        '--kind', $a{kind},
        '--host', $opt{host},
        '--port', $a{port},
        '--in',   $a{in},
        '--out',  $a{out});
    push @cmd, ('--header', $a{header}) if defined $a{header};
    push @cmd, '--enforce' if $a{enforce};
    my $rc = system(@cmd);
    die sprintf("replay-client failed (rc=%d, exit=%d) kind=%s port=%s\n"
            . "  (is the regression-nginx running on the 283xx ports?)\n",
            $rc, ($rc >> 8), $a{kind}, $a{port})
        if $rc != 0;
}

# read a replay-client / feed JSONL file into a list of hashrefs.
sub read_jsonl {
    my ($path) = @_;
    my @rows;
    open my $F, '<', $path or die "cannot read $path: $!\n";
    binmode $F;
    while (my $l = <$F>) {
        next unless $l =~ /\S/;
        my $o = eval { $JP->decode($l) };
        push @rows, $o if $o && ref $o eq 'HASH';
    }
    close $F;
    return @rows;
}

# a covered reason is any non-none, non-MISSING token.
sub is_covered { my ($r) = @_; defined $r && $r ne 'none' && $r ne 'MISSING'; }

# --------------------------------------------------------------------------
# PATH-shaped dimensions (path, args) -> regression-vectors.jsonl
# --------------------------------------------------------------------------
sub freeze_path_dim {
    my ($d, $emit) = @_;
    my $dim = $d->{dim};

    # (1) canonical feed records, deduped by uri (method first-seen; classes
    #     unioned; count summed -- count is REPORT METADATA only, never asserted).
    my %feed;
    for my $r (read_jsonl($PATH_FEED)) {
        my $uri = $r->{uri};
        next unless defined $uri;
        my $e = $feed{$uri} ||= { method => $r->{method} // 'GET', cls => {}, count => 0 };
        $e->{count} += ($r->{count} || 1);
        $e->{cls}{$_} = 1 for @{ $r->{classes} || [] };
    }

    # (2) DETECT pass -> authoritative reason per uri (all dupes agree).
    my $det_out = "$opt{tmp}/detect-$dim.out";
    run_client(kind => 'path', port => $d->{detect}, in => $PATH_FEED, out => $det_out);
    my %reason;
    for my $r (read_jsonl($det_out)) {
        next unless is_covered($r->{reason});
        $reason{ $r->{key} } = $r->{reason};
    }

    # (3) covered-subset feed (fixed name; deterministic order).
    my $sub_feed = "$opt{tmp}/subset-$dim.feed";
    open my $SF, '>', $sub_feed or die "cannot write $sub_feed: $!\n";
    binmode $SF;
    for my $uri (sort keys %reason) {
        my $e = $feed{$uri} or next;
        print $SF $OUT->encode({
            method  => $e->{method},
            uri     => $uri,
            count   => $e->{count},
            classes => [ sort keys %{ $e->{cls} } ],
        }), "\n";
    }
    close $SF;

    # (4) ENFORCE pass over the covered subset -> real status per uri.
    my $enf_out = "$opt{tmp}/enforce-$dim.out";
    run_client(kind => 'path', port => $d->{enforce}, in => $sub_feed, out => $enf_out, enforce => 1);
    my %status;
    for my $r (read_jsonl($enf_out)) { $status{ $r->{key} } = $r->{status}; }

    # (5) emit frozen verdicts.
    my $n = 0;
    for my $uri (sort keys %reason) {
        my $e  = $feed{$uri};
        my $st = $status{$uri};
        unless (defined $st) {
            warn "freeze[$dim]: covered uri has no enforce status (skipped): $uri\n";
            next;
        }
        $emit->({
            dim             => $dim,
            method          => $e->{method},
            uri             => $uri,
            classes         => [ sort keys %{ $e->{cls} } ],
            count           => $e->{count},
            expected_reason => $reason{$uri},
            expected_status => $st + 0,
        });
        $n++;
    }
    printf STDERR "  dim=%-8s covered=%d\n", $dim, $n;
    return $n;
}

# --------------------------------------------------------------------------
# HEADER-shaped dimensions (ua, referer, cookie, fakebot) -> regression-headers.jsonl
# --------------------------------------------------------------------------
sub freeze_header_dim {
    my ($d, $emit) = @_;
    my $dim  = $d->{dim};
    my $feed = "$opt{corpus}/$d->{feed}";

    # (1) canonical feed by value (the header fixtures are already deduped by
    #     value; we keep first-seen src and sum count). @order keeps a stable
    #     feed order for the subset write.
    my (%val, @order);
    for my $r (read_jsonl($feed)) {
        my $v = $r->{value};
        next unless defined $v;
        unless (exists $val{$v}) { push @order, $v; $val{$v} = { count => 0, src => $r->{src} // '' }; }
        $val{$v}{count} += ($r->{count} || 1);
    }

    # (2) DETECT pass -> authoritative reason per value.
    my $det_out = "$opt{tmp}/detect-$dim.out";
    run_client(kind => 'header', port => $d->{detect}, in => $feed, out => $det_out, header => $d->{header});
    my %reason;
    for my $r (read_jsonl($det_out)) {
        next unless is_covered($r->{reason});
        $reason{ $r->{key} } = $r->{reason};   # key = raw header value
    }

    # (3) covered-subset feed.
    my $sub_feed = "$opt{tmp}/subset-$dim.feed";
    open my $SF, '>', $sub_feed or die "cannot write $sub_feed: $!\n";
    binmode $SF;
    for my $v (@order) {
        next unless exists $reason{$v};
        print $SF $OUT->encode({ value => $v, count => $val{$v}{count}, src => $val{$v}{src} }), "\n";
    }
    close $SF;

    # (4) ENFORCE pass -> real status per value.
    my $enf_out = "$opt{tmp}/enforce-$dim.out";
    run_client(kind => 'header', port => $d->{enforce}, in => $sub_feed, out => $enf_out, header => $d->{header}, enforce => 1);
    my %status;
    for my $r (read_jsonl($enf_out)) { $status{ $r->{key} } = $r->{status}; }

    # (5) emit.
    my $n = 0;
    for my $v (@order) {
        next unless exists $reason{$v};
        my $st = $status{$v};
        unless (defined $st) {
            warn "freeze[$dim]: covered value has no enforce status (skipped)\n";
            next;
        }
        $emit->({
            dim             => $dim,
            header          => $d->{header},
            value           => $v,
            src             => $val{$v}{src},
            count           => $val{$v}{count},
            expected_reason => $reason{$v},
            expected_status => $st + 0,
        });
        $n++;
    }
    printf STDERR "  dim=%-8s covered=%d\n", $dim, $n;
    return $n;
}

# --------------------------------------------------------------------------
# write a fixture file with a stable order: count desc, then key cmp, then dim.
# (mirrors build-header-fixtures.pl:135 write_fixture's deterministic ordering.)
# --------------------------------------------------------------------------
sub write_fixture_file {
    my ($path, $rows, $key) = @_;
    my @sorted = sort {
        $b->{count} <=> $a->{count}
            or ($a->{$key} // '') cmp ($b->{$key} // '')
            or ($a->{dim} cmp $b->{dim})
    } @$rows;
    open my $W, '>', $path or die "cannot write $path: $!\n";
    binmode $W;
    for my $r (@sorted) { print $W $OUT->encode($r), "\n"; }
    close $W;
    printf "wrote: %s  (%d vectors)\n", $path, scalar @sorted;
    return scalar @sorted;
}

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
print STDERR "=== freeze-regression-fixture: path/args dimensions ===\n";
my @vec_rows;
freeze_path_dim($_, sub { push @vec_rows, $_[0] }) for @PATH_DIMS;

print STDERR "=== freeze-regression-fixture: header dimensions ===\n";
my @hdr_rows;
freeze_header_dim($_, sub { push @hdr_rows, $_[0] }) for @HEADER_DIMS;

write_fixture_file("$opt{corpus}/regression-vectors.jsonl", \@vec_rows, 'uri');
write_fixture_file("$opt{corpus}/regression-headers.jsonl", \@hdr_rows, 'value');

# status histogram (transparency for the {404,403,444} expectation).
my %hist;
$hist{ $_->{expected_status} }++ for (@vec_rows, @hdr_rows);
print "expected_status histogram: ", join(', ', map { "$_=$hist{$_}" } sort keys %hist), "\n";
print "done.\n";
