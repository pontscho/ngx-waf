#!/usr/bin/env perl
#
# honeypot-d-report.pl
#   Work-stream D (docs/threat-model.md §6.D): join the per-IP volume feed
#   (replay-ip-volume.jsonl, from extract-replay-vectors.pl --ip-volume) with
#   the geo DB (resolved through the standalone reference/geolookup binary) and
#   emit blocklist / ASN / country / flag tuning CANDIDATES.
#
# Pure analysis -> a markdown report with evidence columns + a paste-ready
# directive block for the partner to review and apply by hand. Writes NO list
# the WAF loads and changes no module .c. The runtime levers it feeds
# (waf_blocklist / waf_asn_block / waf_geo_block / waf_flag_block) already exist.
#
# Core-perl only (JSON::PP + Socket); NO libloc, NO `location` CLI, NO docker.
# The geo values come exclusively from `geolookup` (the bounds-guarded waf_geo.c
# port), never from libloc.
#
# Usage:
#   perl honeypot-d-report.pl [--ip-volume replay-ip-volume.jsonl]
#                             [--geodb ../../../../geodb/location.db]
#                             [--geolookup /tmp/geolookup]
#                             [--out honeypot-d-report.md]
#                             [--top-prefix 40] [--min-prefix-hostile 500]
#                             [--top-asn 30] [--top-cc 20] [--flag-min-pct 20]
#
# The IP-bearing input and the report are gitignored (Decision #75): the report
# enumerates source networks and must not be committed.
#
use strict;
use warnings;
use JSON::PP;
use Socket qw(inet_pton inet_ntop AF_INET AF_INET6);

# --------------------------------------------------------------------------
# options
# --------------------------------------------------------------------------
my %opt = (
    ip_volume          => 'replay-ip-volume.jsonl',
    geodb              => 'geodb/location.db',
    geolookup          => $ENV{GEOLOOKUP} // '/tmp/geolookup',
    out                => 'honeypot-d-report.md',
    top_prefix         => 40,
    min_prefix_hostile => 500,
    top_asn            => 30,
    top_cc             => 20,
    flag_min_pct       => 20,
);
while (@ARGV) {
    my $a = shift @ARGV;
    if    ($a eq '--ip-volume')          { $opt{ip_volume}          = shift @ARGV; }
    elsif ($a eq '--geodb')              { $opt{geodb}              = shift @ARGV; }
    elsif ($a eq '--geolookup')          { $opt{geolookup}          = shift @ARGV; }
    elsif ($a eq '--out')                { $opt{out}                = shift @ARGV; }
    elsif ($a eq '--top-prefix')         { $opt{top_prefix}         = shift @ARGV; }
    elsif ($a eq '--min-prefix-hostile') { $opt{min_prefix_hostile} = shift @ARGV; }
    elsif ($a eq '--top-asn')            { $opt{top_asn}            = shift @ARGV; }
    elsif ($a eq '--top-cc')             { $opt{top_cc}             = shift @ARGV; }
    elsif ($a eq '--flag-min-pct')       { $opt{flag_min_pct}       = shift @ARGV; }
    elsif ($a eq '-h' || $a eq '--help') { print usage(); exit 0; }
    else                                 { die "unknown option: $a\n" . usage(); }
}

sub usage {
    return "usage: perl honeypot-d-report.pl [--ip-volume FILE] [--geodb FILE] "
         . "[--geolookup PATH] [--out FILE] [--top-prefix N] "
         . "[--min-prefix-hostile N] [--top-asn N] [--top-cc N] "
         . "[--flag-min-pct P]\n";
}

# --------------------------------------------------------------------------
# libloc network-flag bits (waf_geo.h:33-36). `tor` is the T1 country code,
# NOT a flag bit, so it surfaces in the CC table, not here.
# --------------------------------------------------------------------------
my @FLAG_BITS = (
    [ 0x0001, 'anonymous-proxy' ],
    [ 0x0002, 'satellite'       ],
    [ 0x0004, 'anycast'         ],
    [ 0x0008, 'drop'            ],
);

sub flag_names {
    my ($f) = @_;
    my @n;
    for my $b (@FLAG_BITS) { push @n, $b->[1] if $f & $b->[0]; }
    return @n ? join('+', @n) : '-';
}

# /24 (v4) or /64 (v6) network of an IP, or undef if unparseable.
sub prefix_of {
    my ($ip) = @_;
    if (index($ip, ':') >= 0) {
        my $b = inet_pton(AF_INET6, $ip);
        return undef unless defined $b && length($b) == 16;
        my $net = substr($b, 0, 8) . ("\0" x 8);
        return inet_ntop(AF_INET6, $net) . '/64';
    }
    my $b = inet_pton(AF_INET, $ip);
    return undef unless defined $b && length($b) == 4;
    my @o = unpack 'C4', $b;
    return "$o[0].$o[1].$o[2].0/24";
}

# key with the maximum weight in a {key=>weight} hash (string tiebreak).
sub dominant {
    my ($h) = @_;
    my @k = sort { $h->{$b} <=> $h->{$a} or $a cmp $b } keys %$h;
    return @k ? $k[0] : '?';
}

# --------------------------------------------------------------------------
# 1. read the per-IP volume feed
# --------------------------------------------------------------------------
my $json = JSON::PP->new->utf8;
open my $V, '<', $opt{ip_volume}
    or die "cannot open $opt{ip_volume}: $!\n(run extract-replay-vectors.pl --ip-volume first)\n";
binmode $V;

my @rows;
while (<$V>) {
    chomp; next unless /\S/;
    my $d = eval { $json->decode($_) } or next;
    push @rows, $d;
}
close $V;
die "no records in $opt{ip_volume}\n" unless @rows;

# --------------------------------------------------------------------------
# 2. resolve every distinct IP through the geolookup binary (fork+exec, no
#    shell -> no injection from log-derived strings). geolookup prints one TSV
#    line per input IP (no-match -> "??\t0\t0x0000").
# --------------------------------------------------------------------------
-x $opt{geolookup}
    or die "geolookup not executable: $opt{geolookup}\n"
         . "(build it: cc -O2 -Wall -Wextra -o $opt{geolookup} reference/geolookup.c)\n";
-r $opt{geodb}
    or die "geo database not readable: $opt{geodb}\n";

my %seen_ip;
$seen_ip{ $_->{ip} } = 1 for @rows;
my @ips = keys %seen_ip;

my $tmp = "$opt{out}.ips.$$";
open my $T, '>', $tmp or die "cannot write $tmp: $!\n";
print $T "$_\n" for @ips;
close $T;

my %geo;   # ip => { cc, asn, flags }
my $pid = open my $G, '-|';
defined $pid or die "fork failed: $!\n";
if ($pid == 0) {
    open STDIN, '<', $tmp or die "child: reopen stdin: $!\n";
    exec $opt{geolookup}, $opt{geodb}
        or die "child: exec $opt{geolookup}: $!\n";
}
while (<$G>) {
    chomp;
    my ($ip, $cc, $asn, $flags) = split /\t/, $_, 4;
    next unless defined $flags;
    $geo{$ip} = { cc => $cc, asn => ($asn + 0), flags => hex($flags) };
}
close $G;
unlink $tmp;

# --------------------------------------------------------------------------
# 3. aggregate by /24-or-/64 prefix, ASN, country, and flag
# --------------------------------------------------------------------------
my (%PFX, %ASN, %CC, %FLAG);
my ($tot_hostile, $tot_junk, $n_norecord) = (0, 0, 0);

for my $r (@rows) {
    my $ip      = $r->{ip};
    my $total   = $r->{total}   // 0;
    my $hostile = $r->{hostile} // 0;
    my $junk    = $r->{junk}    // 0;

    my $g     = $geo{$ip} // { cc => '??', asn => 0, flags => 0 };
    my $cc    = $g->{cc};
    my $asn   = $g->{asn};
    my $flags = $g->{flags};

    $tot_hostile += $hostile;
    $tot_junk    += $junk;
    $n_norecord++ if $cc eq '??' && $asn == 0 && $flags == 0;

    my $pfx = prefix_of($ip);
    if (defined $pfx) {
        my $p = ($PFX{$pfx} //= { total => 0, hostile => 0, junk => 0,
                                  ips => {}, cc => {}, asn => {}, flags => 0 });
        $p->{total}   += $total;
        $p->{hostile} += $hostile;
        $p->{junk}    += $junk;
        $p->{ips}{$ip} = 1;
        $p->{cc}{$cc}   += $hostile;
        $p->{asn}{$asn} += $hostile;
        $p->{flags}     |= $flags;
    }

    {
        my $a = ($ASN{$asn} //= { total => 0, hostile => 0, junk => 0,
                                  ips => {}, nets => {}, cc => {} });
        $a->{total}   += $total;
        $a->{hostile} += $hostile;
        $a->{junk}    += $junk;
        $a->{ips}{$ip} = 1;
        $a->{nets}{$pfx} = 1 if defined $pfx;
        $a->{cc}{$cc}   += $hostile;
    }

    {
        my $c = ($CC{$cc} //= { total => 0, hostile => 0, junk => 0, ips => {} });
        $c->{total}   += $total;
        $c->{hostile} += $hostile;
        $c->{junk}    += $junk;
        $c->{ips}{$ip} = 1;
    }

    for my $b (@FLAG_BITS) {
        $FLAG{ $b->[1] } += $hostile if $flags & $b->[0];
    }
}

# --------------------------------------------------------------------------
# 4. rank + threshold
# --------------------------------------------------------------------------
my @pfx_rank =
    grep { $PFX{$_}{hostile} >= $opt{min_prefix_hostile} }
    sort { $PFX{$b}{hostile} <=> $PFX{$a}{hostile} or $a cmp $b }
    keys %PFX;
@pfx_rank = @pfx_rank[0 .. $opt{top_prefix} - 1] if @pfx_rank > $opt{top_prefix};

my @asn_rank =
    sort { $ASN{$b}{hostile} <=> $ASN{$a}{hostile} or $a <=> $b }
    keys %ASN;
@asn_rank = @asn_rank[0 .. $opt{top_asn} - 1] if @asn_rank > $opt{top_asn};

my @cc_rank =
    sort { $CC{$b}{hostile} <=> $CC{$a}{hostile} or $a cmp $b }
    keys %CC;
@cc_rank = @cc_rank[0 .. $opt{top_cc} - 1] if @cc_rank > $opt{top_cc};

my @flag_rank = sort { $FLAG{$b} <=> $FLAG{$a} or $a cmp $b } keys %FLAG;

# --------------------------------------------------------------------------
# 5. emit markdown
# --------------------------------------------------------------------------
open my $O, '>', $opt{out} or die "cannot write $opt{out}: $!\n";
binmode $O;   # source literals are already UTF-8 bytes (§, —, ≥); pass through raw

my $n_ips = scalar @ips;
my $n_resolved = $n_ips - $n_norecord;

print $O <<"HDR";
# Honeypot D — ASN / geo tuning candidates

_Generated by `honeypot-d-report.pl`, joining `$opt{ip_volume}` × `$opt{geodb}`
(resolved through the bounds-guarded `reference/geolookup.c` port — never libloc).
Offline analysis: these are **candidates to review**, nothing is applied. See
`docs/threat-model.md` §6.D._

- distinct source IPs: **$n_ips**  (resolved: $n_resolved, no geo record: $n_norecord)
- total hostile (non-baseline path) requests: **$tot_hostile**
- total protocol-junk (§4 malformed) lines: **$tot_junk**
- thresholds: /24 floor hostile ≥ $opt{min_prefix_hostile} (top $opt{top_prefix}); ASN top $opt{top_asn}; CC top $opt{top_cc}; flag ≥ $opt{flag_min_pct}% of hostile

Hostility metric (partner decision, §6.D): **hostile** = kept non-baseline path
requests (§3 attack classes + uncatalogued); **junk** = §4 protocol-junk
(mass TLS/port-scan signal, a separate column); legit baseline is excluded from
ranking. `total` is shown beside `hostile` so a coarse lever's collateral on
legitimate traffic stays visible.

HDR

# --- /24 // /64 blocklist candidates ---
printf $O "## /24 (v4) // /64 (v6) blocklist candidates\n\n";
printf $O "Sorted by hostile desc; floor hostile ≥ %d; top %d. `waf_blocklist` is "
        . "the most surgical lever (single CIDR → 403).\n\n", $opt{min_prefix_hostile}, $opt{top_prefix};
printf $O "| prefix | total | hostile | junk | IPs | CC | ASN | flags |\n";
printf $O "|---|---:|---:|---:|---:|---|---:|---|\n";
for my $k (@pfx_rank) {
    my $p = $PFX{$k};
    my $cc  = dominant($p->{cc});
    my $asn = dominant($p->{asn});
    my $ccx  = (keys %{$p->{cc}}  > 1) ? "$cc+"  : $cc;
    my $asnx = (keys %{$p->{asn}} > 1) ? "$asn+" : $asn;
    printf $O "| `%s` | %d | %d | %d | %d | %s | %s | %s |\n",
        $k, $p->{total}, $p->{hostile}, $p->{junk},
        scalar(keys %{$p->{ips}}), $ccx, $asnx, flag_names($p->{flags});
}
print $O "\n";

# --- ASN block candidates ---
printf $O "## ASN block candidates\n\n";
printf $O "Top %d by hostile. `asn==0` / no-record **fails open** (shown for "
        . "context, never emitted as a candidate).\n\n", $opt{top_asn};
printf $O "| ASN | total | hostile | junk | IPs | /24s | CC |\n";
printf $O "|---|---:|---:|---:|---:|---:|---|\n";
for my $k (@asn_rank) {
    my $a = $ASN{$k};
    my $cc  = dominant($a->{cc});
    my $ccx = (keys %{$a->{cc}} > 1) ? "$cc+" : $cc;
    my $label = ($k == 0) ? '0 _(no record)_' : $k;
    printf $O "| %s | %d | %d | %d | %d | %d | %s |\n",
        $label, $a->{total}, $a->{hostile}, $a->{junk},
        scalar(keys %{$a->{ips}}), scalar(keys %{$a->{nets}}), $ccx;
}
print $O "\n";

# --- Country (advisory) ---
printf $O "## Country distribution (advisory — coarse)\n\n";
printf $O "Top %d by hostile. A country block also drops legitimate traffic "
        . "from that country — emitted **commented** in the paste-ready block.\n\n", $opt{top_cc};
printf $O "| CC | total | hostile | junk | IPs |\n";
printf $O "|---|---:|---:|---:|---:|\n";
for my $k (@cc_rank) {
    my $c = $CC{$k};
    printf $O "| %s | %d | %d | %d | %d |\n",
        $k, $c->{total}, $c->{hostile}, $c->{junk}, scalar(keys %{$c->{ips}});
}
print $O "\n";

# --- Flag distribution (advisory) ---
printf $O "## Network-flag distribution (advisory)\n\n";
printf $O "Hostile share per libloc network flag. A `waf_flag_block` candidate "
        . "is surfaced when a flag covers ≥ %d%% of hostile volume.\n\n", $opt{flag_min_pct};
printf $O "| flag | hostile | %% of hostile |\n";
printf $O "|---|---:|---:|\n";
if (@flag_rank) {
    for my $k (@flag_rank) {
        my $pct = $tot_hostile ? 100.0 * $FLAG{$k} / $tot_hostile : 0;
        printf $O "| %s | %d | %.1f%% |\n", $k, $FLAG{$k}, $pct;
    }
} else {
    print $O "| _(none set)_ | 0 | 0.0% |\n";
}
print $O "\n";

# --------------------------------------------------------------------------
# 6. paste-ready directive fragments (coarse/advisory levers commented out)
# --------------------------------------------------------------------------
print $O "## Paste-ready directives\n\n";
print $O "Review before applying. Surgical levers (`waf_blocklist`, `waf_asn_block`) "
       . "are live; coarse/advisory levers (`waf_geo_block`, `waf_flag_block`) are "
       . "commented out — they drop legitimate traffic too.\n\n";
print $O "```nginx\n";

print $O "# --- blocklist (§6.D /24 candidates, hostile ≥ $opt{min_prefix_hostile}) ---\n";
for my $k (@pfx_rank) {
    my $p = $PFX{$k};
    my $cc  = dominant($p->{cc});
    my $asn = dominant($p->{asn});
    my $asnstr = ($asn && $asn ne '?') ? " AS$asn" : '';
    printf $O "waf_blocklist %s;%s# %d hostile / %d total, %d IPs, CC=%s%s\n",
        $k, (' ' x (20 - length($k) > 0 ? 20 - length($k) : 1)),
        $p->{hostile}, $p->{total}, scalar(keys %{$p->{ips}}), $cc, $asnstr;
}

print $O "\n# --- ASN block (§6.D top ASNs; asn==0/no-record skipped, fails open) ---\n";
for my $k (@asn_rank) {
    next if $k == 0;                 # no record -> fails open, cannot block
    my $a = $ASN{$k};
    next if $a->{hostile} == 0;      # context-only row, not a candidate
    my $cc = dominant($a->{cc});
    printf $O "waf_asn_block  %s;%s# %d hostile across %d /24s, CC=%s\n",
        $k, (' ' x (12 - length($k) > 0 ? 12 - length($k) : 1)),
        $a->{hostile}, scalar(keys %{$a->{nets}}), $cc;
}

print $O "\n# --- country (advisory: coarse, drops legit too — review before uncommenting) ---\n";
for my $k (@cc_rank) {
    next if $k eq '??';
    my $c = $CC{$k};
    next if $c->{hostile} == 0;      # context-only row, not a candidate
    printf $O "# waf_geo_block %s;%s# advisory: %d hostile / %d total, %d IPs\n",
        $k, (' ' x (6 - length($k) > 0 ? 6 - length($k) : 1)),
        $c->{hostile}, $c->{total}, scalar(keys %{$c->{ips}});
}

print $O "\n# --- flag (advisory: ≥ $opt{flag_min_pct}% of hostile — review before uncommenting) ---\n";
my $emitted_flag = 0;
for my $k (@flag_rank) {
    my $pct = $tot_hostile ? 100.0 * $FLAG{$k} / $tot_hostile : 0;
    next if $pct < $opt{flag_min_pct};
    printf $O "# waf_flag_block %s;%s# advisory: %.1f%% of hostile from %s networks\n",
        $k, (' ' x (16 - length($k) > 0 ? 16 - length($k) : 1)), $pct, $k;
    $emitted_flag = 1;
}
print $O "# (no flag reached the threshold)\n" unless $emitted_flag;

print $O "```\n";
close $O;

# compact echo for the runner
printf "wrote: %s\n", $opt{out};
printf "prefixes=%d (candidates=%d) asns=%d ccs=%d flags=%d hostile=%d junk=%d ips=%d\n",
    scalar(keys %PFX), scalar(@pfx_rank), scalar(keys %ASN),
    scalar(keys %CC), scalar(keys %FLAG), $tot_hostile, $tot_junk, $n_ips;
