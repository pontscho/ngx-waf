#!/usr/bin/env perl
#
# build-header-fixtures.pl
#   Assemble per-dimension header fixtures for work-stream B detect-mode replay
#   (threat-model docs/threat-model.md §6 B; sources docs/threat-intel-sources.md).
#
#   INPUTS:
#     - corpus feeds  (extract-replay-vectors.pl --ua-vectors/--referer-vectors):
#         replay-ua-vectors.jsonl, replay-referer-vectors.jsonl   [carry volume]
#     - external lists pulled to fixtures/raw/ (gitignored):
#         crs-scanners-user-agents.data, seclists-useragents.fuzz.txt,
#         bad-referrers.list, crawler-user-agents.json, fuzzdb-*.txt
#     - the WAF's own classifier lists (lists/crawler.list, lists/ai-crawler.list)
#         -> the fake-bot fixture stays in sync with what the module classifies.
#
#   OUTPUT (fixtures/, gitignored derivatives):
#     ua.jsonl  referer.jsonl  cookie.jsonl  fakebot.jsonl
#       each line: {"value":"<header value>","count":N,"src":"<provenance>"}
#       count = corpus volume for corpus-derived rows, 1 for external rows
#       (lets the coverage report weight by volume and break down by source).
#
#   SANITIZATION (security-officer: SecLists is uncurated/parser-breaking):
#     strip CR, drop lines with any control byte (framing/parser safety), drop
#     blank / '#' comment lines, decode the basic HTML entities SecLists leaks,
#     dedup. NO fixture byte is ever passed to a shell -- pure perl file I/O.
#
#   IP-free: the corpus feeds carry no remote_addr by construction (the
#   extractor never emits field 0); external lists are public threat-intel.
#
#   core-perl only (JSON::PP ships with perl >= 5.14); NO CPAN, NO docker.
#   This script is the durable, committable step-2 deliverable; its OUTPUTS are
#   gitignored corpus derivatives.
#
use strict;
use warnings;
use JSON::PP ();
use File::Basename qw(dirname);
use File::Path qw(make_path);

# --------------------------------------------------------------------------
# paths (script lives in tools/; defaults target ../tests/corpus/ + ../lists/)
# --------------------------------------------------------------------------
my $here   = dirname(__FILE__);
my %opt = (
    corpus => "$here/../tests/corpus",              # where the replay-*-vectors.jsonl live
    raw    => "$here/../tests/corpus/fixtures/raw", # external pulls
    lists  => "$here/../lists",                     # the module's classifier lists
    out    => "$here/../tests/corpus/fixtures",     # fixture output dir
);
while (@ARGV) {
    my $a = shift @ARGV;
    if    ($a eq '--corpus') { $opt{corpus} = shift @ARGV; }
    elsif ($a eq '--raw')    { $opt{raw}    = shift @ARGV; }
    elsif ($a eq '--lists')  { $opt{lists}  = shift @ARGV; }
    elsif ($a eq '--out')    { $opt{out}    = shift @ARGV; }
    elsif ($a eq '-h' || $a eq '--help') {
        print "usage: perl build-header-fixtures.pl "
            . "[--corpus DIR] [--raw DIR] [--lists DIR] [--out DIR]\n";
        exit 0;
    }
    else { die "unknown option: $a\n"; }
}
make_path($opt{out}) unless -d $opt{out};
my $JP = JSON::PP->new;

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

# sanitize one header VALUE; return undef to drop it.
sub clean {
    my ($s) = @_;
    return undef unless defined $s;
    chomp $s;                                       # drop the read line's newline
    $s =~ s/\r//g;                                  # strip CR (framing safety)
    $s =~ s/[ \t]+$//;                              # trailing blanks
    return undef if $s eq '' || $s =~ /^\s*#/;       # blank / comment
    return undef if $s =~ /[\x00-\x08\x0b-\x1f\x7f]/; # any control byte -> drop
    return $s;
}

# decode the handful of HTML entities SecLists leaks (it was scraped from HTML).
sub html_decode {
    my ($s) = @_;
    $s =~ s/&lt;/</g;
    $s =~ s/&gt;/>/g;
    $s =~ s/&quot;/"/g;
    $s =~ s/&#(\d{1,7});/chr($1 & 0xff)/ge;
    $s =~ s/&amp;/&/g;                               # last: &amp;lt; -> &lt;
    return $s;
}

# read a plain list file (drop '#'/blank), return cleaned values.
sub read_list {
    my ($path, $decode) = @_;
    my @out;
    open my $F, '<', $path or do { warn "skip $path: $!\n"; return @out; };
    binmode $F;
    while (my $l = <$F>) {
        $l = html_decode($l) if $decode;
        my $c = clean($l);
        push @out, $c if defined $c;
    }
    close $F;
    return @out;
}

# read a corpus *-vectors.jsonl, return list of [value, count].
sub read_corpus_jsonl {
    my ($path) = @_;
    my @out;
    open my $F, '<', $path or do { warn "skip $path: $!\n"; return @out; };
    binmode $F;
    while (my $l = <$F>) {
        next unless $l =~ /\S/;
        my $o = eval { $JP->decode($l) };
        next unless $o && defined $o->{value};
        my $c = clean($o->{value});  # ctrl bytes decode back here and get dropped
        push @out, [ $c, ($o->{count} || 1) ] if defined $c;
    }
    close $F;
    return @out;
}

# write a fixture: rows = [ [value,count,src], ... ]; dedup by value (first wins,
# summing count), deterministic order (count desc, then value).
sub write_fixture {
    my ($name, @rows) = @_;
    my (%cnt, %src, @order);
    for my $r (@rows) {
        my ($v, $c, $s) = @$r;
        if (!exists $cnt{$v}) { push @order, $v; $src{$v} = $s; }
        $cnt{$v} += $c;
    }
    @order = sort { $cnt{$b} <=> $cnt{$a} or $a cmp $b } @order;
    my $path = "$opt{out}/$name";
    open my $W, '>', $path or die "cannot write $path: $!\n";
    binmode $W;
    for my $v (@order) {
        print $W $JP->encode({ value => $v, count => $cnt{$v}, src => $src{$v} }), "\n";
    }
    close $W;
    printf "wrote: %s  (%d distinct values)\n", $path, scalar(@order);
    return scalar(@order);
}

# --------------------------------------------------------------------------
# UA fixture: corpus raw UAs + CRS scanner-UA substrings + SecLists fuzz UAs
# --------------------------------------------------------------------------
{
    my @rows;
    push @rows, map { [ $_->[0], $_->[1], 'corpus' ] }
                    read_corpus_jsonl("$opt{corpus}/replay-ua-vectors.jsonl");
    push @rows, map { [ $_, 1, 'crs' ] }
                    read_list("$opt{raw}/crs-scanners-user-agents.data");
    push @rows, map { [ $_, 1, 'seclists' ] }
                    read_list("$opt{raw}/seclists-useragents.fuzz.txt", 1);
    write_fixture('ua.jsonl', @rows);
}

# --------------------------------------------------------------------------
# Referer fixture: corpus raw referers + bad-referrers (bare domain -> URL)
# --------------------------------------------------------------------------
{
    my @rows;
    push @rows, map { [ $_->[0], $_->[1], 'corpus' ] }
                    read_corpus_jsonl("$opt{corpus}/replay-referer-vectors.jsonl");
    for my $d (read_list("$opt{raw}/bad-referrers.list")) {
        # the list is bare hostnames; the WAF substring-matches the Referer
        # header, so wrap as a URL the substring will appear in.
        my $v = $d =~ m{^[a-z][a-z0-9+.-]*://}i ? $d : "http://$d/";
        push @rows, [ $v, 1, 'bad-referrers' ];
    }
    write_fixture('referer.jsonl', @rows);
}

# --------------------------------------------------------------------------
# Cookie fixture: synthetic guaranteed-TP markers + FuzzDB SQLi (coverage gap)
# --------------------------------------------------------------------------
{
    my @rows;
    # synthetic TP -- each contains a lists/cookie.list signature verbatim.
    push @rows, [ 'sessionid=sqlmap/1.7-dev; path=/',          1, 'synthetic' ];
    push @rows, [ 'tracking=acunetix_wvs_security_test',       1, 'synthetic' ];
    push @rows, [ 'pref=<script>alert(document.cookie)</script>', 1, 'synthetic' ];
    # FuzzDB SQLi payloads as cookie values -- most will NOT trip the narrow
    # cookie.list (sqlmap/acunetix/<script); the low hit-rate IS the finding.
    for my $f (qw(fuzzdb-xplatform.txt fuzzdb-oracle.txt
                  fuzzdb-GenericBlind.txt fuzzdb-MySQL.txt)) {
        for my $p (read_list("$opt{raw}/$f")) {
            push @rows, [ "sid=$p", 1, 'fuzzdb-sqli' ];
        }
    }
    write_fixture('cookie.jsonl', @rows);
}

# --------------------------------------------------------------------------
# Fake-bot fixture: real crawler UA instances (monperrus/crawler-user-agents)
# whose string matches the module's OWN crawler/ai-crawler classifier tokens,
# so a replay from the loopback peer (outside the verified CIDR) is classified
# crawler and trips would_block[fake_bot]. (truth #2: the UA is benign; the
# wrong source IP is the attack.)
# --------------------------------------------------------------------------
{
    my @frag;
    for my $lf (qw(crawler.list ai-crawler.list)) {
        push @frag, read_list("$opt{lists}/$lf");
    }
    my @rows;
    if (@frag) {
        my $re = qr/(?:@{[ join '|', @frag ]})/i;
        my $path = "$opt{raw}/crawler-user-agents.json";
        if (open my $F, '<', $path) {
            binmode $F;
            local $/;
            my $arr = eval { $JP->decode(<$F>) };
            close $F;
            if ($arr && ref $arr eq 'ARRAY') {
                for my $o (@$arr) {
                    next unless $o->{instances} && ref $o->{instances} eq 'ARRAY';
                    for my $ua (@{ $o->{instances} }) {
                        my $c = clean($ua);
                        next unless defined $c && $c =~ $re;
                        push @rows, [ $c, 1, 'crawler-ua' ];
                    }
                }
            }
        }
        else { warn "skip $path: $!\n"; }
    }
    else { warn "no classifier fragments read from $opt{lists}; fakebot empty\n"; }
    write_fixture('fakebot.jsonl', @rows);
}

print "done.\n";
