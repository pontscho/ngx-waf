#!/usr/bin/env perl
#
# extract-replay-vectors.pl
#   Corpus -> replay-vectors extraction  (threat-model docs/threat-model.md, §6 step 0).
#
# Reads the real pre-WAF edge access log (ngxlogs/access.log: ~270 MB, ~1.65M
# requests) in a single pass and emits the deduplicated set of valid HTTP
# *attack vectors* needed by work-streams B (detect-mode FP/TP replay) and C
# (real-attack regression fixture).
#
# READ-ONLY on the input log. libc/core-perl only -- NO external modules, NO
# libloc, NO docker.  This script IS the durable, reproducible deliverable.
#
# A "valid attack vector" (partner's definition) = any syntactically valid HTTP
# request whose DECODED path is NOT legit example.com baseline traffic.
#
# Pipeline (one pass, see threat-model §3/§4/§5):
#   1. parse:   remote_addr - - [time] "request" status bytes "referer" "ua"
#               nginx escapes embedded '"' as \x22, so exactly 6 literal quotes
#               delimit request / referer / user-agent -> split on '"' is safe.
#   2. drop:    remote_addr in 10.0.0.0/24  (internal health-check, §5.1).
#   3. drop:    request not well-formed 'METHOD SP URI SP HTTP/x.y'
#               (§4 parser-junk: TLS/SSH/RDP/binary banners nginx 400s at the
#                request-line parser -- never reaches the WAF phases).
#   4. decode:  decoded_path = %XX-decoded(uri, query stripped), lowercased.
#               Used ONLY for baseline-check + class labeling (the module also
#               matches the decoded r->uri via ngx_unescape_uri).
#   5. drop:    decoded_path in the legit baseline (root / app.* / static exts /
#               favicon|robots|sitemap).
#   6. label:   classes[] from the §3 taxonomy (overlapping; empty=uncatalogued).
#   7. dedup:   (method, raw_uri, ua, referer) -> count accumulates, first-seen
#               status preserved.
#   8. emit:    replay-vectors.jsonl (count desc) + replay-vectors.summary.txt.
#
# Usage:
#   perl extract-replay-vectors.pl --in <access.log> [--outdir DIR]
#                                  [--collapse-ua] [--top-excluded N]
#                                  [--ua-vectors] [--referer-vectors]
#
#   --collapse-ua      replace the UA in the dedup key with a coarse UA-class
#                      (cardinality control: enable if unique vectors > ~200k).
#   --top-excluded     how many baseline-excluded top paths to list (default 25).
#   --ua-vectors       also emit replay-ua-vectors.jsonl: distinct RAW
#                      User-Agent strings on attack-shaped requests, with
#                      volume (work-stream B header-fixture feed). Independent
#                      of --collapse-ua (always raw). IP-free.
#   --referer-vectors  also emit replay-referer-vectors.jsonl: distinct RAW
#                      Referer strings on attack-shaped requests, with volume.
#                      IP-free.
#
use strict;
use warnings;
use File::Path qw(make_path);

# --------------------------------------------------------------------------
# options
# --------------------------------------------------------------------------
my %opt = (
    in              => undef,
    outdir          => '.',
    top_excluded    => 25,
    collapse_ua     => 0,
    ua_vectors      => 0,
    referer_vectors => 0,
);
my @pos;
while (@ARGV) {
    my $a = shift @ARGV;
    if    ($a eq '--in')           { $opt{in}           = shift @ARGV; }
    elsif ($a eq '--outdir')       { $opt{outdir}       = shift @ARGV; }
    elsif ($a eq '--top-excluded') { $opt{top_excluded} = shift @ARGV; }
    elsif ($a eq '--collapse-ua')  { $opt{collapse_ua}  = 1; }
    elsif ($a eq '--ua-vectors')      { $opt{ua_vectors}      = 1; }
    elsif ($a eq '--referer-vectors') { $opt{referer_vectors} = 1; }
    elsif ($a eq '-h' || $a eq '--help') { usage(); exit 0; }
    elsif ($a =~ /^-/)             { die "unknown option: $a\n"; }
    else                          { push @pos, $a; }
}
$opt{in} //= shift @pos;
die usage() unless defined $opt{in};

sub usage {
    return "usage: perl extract-replay-vectors.pl --in <access.log> "
         . "[--outdir DIR] [--collapse-ua] [--top-excluded N] "
         . "[--ua-vectors] [--referer-vectors]\n";
}

# --------------------------------------------------------------------------
# legit baseline (decoded+lowercase path) -- excluded as NON-attack traffic.
# partner decision; §3.1 "legitimate-shaped noise".
# --------------------------------------------------------------------------
my @BASELINE = (
    qr{^/$},                                                                # root
    qr{^/app\.},                                                            # app.css / app.js / app.json ...
    qr{\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf)$}, # static assets
    qr{^/favicon\.ico$},
    qr{^/robots\.txt$},
    qr{^/sitemap\.xml$},
);

# --------------------------------------------------------------------------
# attack-class rules (decoded+lowercase path), §3 taxonomy / scanners.list.
# ordered; classes OVERLAP (one path may match several) -> array per vector.
# patterns are lowercase because the path is lowercased before matching.
# --------------------------------------------------------------------------
my @CLASS_RULES = (
    [ php        => qr{\.php} ],
    [ wordpress  => qr{(?:^|/)wp-} ],            # nested installs too (/blog/wp-login.php)
    [ wordpress  => qr{(?:^|/)xmlrpc\.php} ],
    [ wordpress  => qr{(?:^|/)wordpress} ],
    [ secret_vcs => qr{(?:^|/)\.env} ],
    [ secret_vcs => qr{(?:^|/)\.git} ],
    [ router_iot => qr{^/boaform/} ],
    [ router_iot => qr{^/cgi-bin/} ],
    [ router_iot => qr{^/sdk/weblanguage} ],
    [ router_iot => qr{(?:^|/)hnap} ],           # D-Link HNAP1 RCE
    [ router_iot => qr{^/gponform} ],            # GPON router RCE
    [ router_iot => qr{^/goform} ],              # GoAhead/router form RCE
    [ legacy_ext => qr{\.(?:cgi|asp|aspx|jsp|cfm|pl)$} ],
    [ phpadmin   => qr{phpmyadmin} ],            # all variants: /phpMyAdmin-5.2.0/, /db/phpMyAdmin/, /1phpmyadmin/ ...
    [ phpadmin   => qr{^/pma/} ],
    [ backup     => qr{\.bak$} ],
    [ backup     => qr{^/backup} ],
    [ appliance  => qr{^/actuator} ],
    [ appliance  => qr{^/geoserver} ],
    [ appliance  => qr{^/solr/} ],
    [ appliance  => qr{^/manager/(?:html|text)} ],
    [ webmail    => qr{^/owa} ],
    [ webmail    => qr{^/ecp} ],
    [ webmail    => qr{^/autodiscover} ],
);

# canonical output order for classes
my @CLASS_ORDER = qw(php wordpress secret_vcs router_iot legacy_ext
                     phpadmin backup appliance webmail uncatalogued);
my %CLASS_RANK = map { $CLASS_ORDER[$_] => $_ } 0 .. $#CLASS_ORDER;

# §3 known per-class volumes -> correctness gate (printed beside measured).
my %REF_VOL = (
    php        => 364455, secret_vcs => 161302, wordpress => 139228,
    router_iot => 22060,  legacy_ext => 15290,  phpadmin  => 13462,
    backup     => 10837,  appliance  => 10082,  webmail   => 4217,
);

# coarse scanner-UA tokens for --collapse-ua (§5.2).
my @UA_TOKENS = qw(
    zgrab masscan ivre-masscan l9explore libredtail leakix censysinspect
    expanse go-http-client python-requests httpx fasthttp custom-asynchttpclient
    nmap shodan curl wget zmap nuclei nikto sqlmap wpscan
);

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

# decode the request URI for baseline + class labeling ONLY.
# strips the query, single %XX-decodes (mirrors ngx_unescape_uri), lowercases.
sub decode_path {
    my ($uri) = @_;
    (my $p = $uri) =~ s/\?.*\z//s;                      # strip query
    $p =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge;          # single %XX decode
    return lc $p;
}

# collapse a User-Agent to a coarse class (only used with --collapse-ua).
sub ua_class {
    my ($ua) = @_;
    return '-' if !defined $ua || $ua eq '' || $ua eq '-';
    my $l = lc $ua;
    for my $tok (@UA_TOKENS) {
        return $tok if index($l, $tok) >= 0;
    }
    return 'mozilla-spoofed' if index($l, 'mozilla') >= 0;
    return 'other-ua';
}

# minimal JSON string encoder (fields are printable ASCII; nginx escapes
# bytes <0x20 / >=0x7f / '"' / '\' to literal \xNN text already).
sub jstr {
    my ($s) = @_;
    $s = '' unless defined $s;
    $s =~ s/\\/\\\\/g;                                  # backslash
    $s =~ s/"/\\"/g;                                    # quote
    $s =~ s/([\x00-\x1f])/sprintf('\\u%04x', ord($1))/ge; # controls (defensive)
    return '"' . $s . '"';
}

# --------------------------------------------------------------------------
# single pass
# --------------------------------------------------------------------------
open my $IN, '<', $opt{in} or die "cannot open $opt{in}: $!\n";
binmode $IN;

my ($lines, $unparseable, $internal, $malformed, $baseline_drop) = (0, 0, 0, 0, 0);
my %V;          # dedup key => [count, first_status, classes_csv]
my %EXCL;       # decoded_path => volume   (baseline-excluded, for the sanity gate)
my %path_class; # decoded_path => classes_csv | "\x01BASE"   (label cache)
my %UA_VOL;      # raw User-Agent => volume  (--ua-vectors header fixture feed)
my %REFERER_VOL; # raw Referer    => volume  (--referer-vectors header fixture feed)

while (my $line = <$IN>) {
    $lines++;
    chomp $line;

    # exactly 6 literal quotes delimit request/referer/ua (embedded " -> \x22).
    my @f = split /"/, $line, -1;
    if (@f < 6) { $unparseable++; next; }
    my $pre     = $f[0];   # 'remote_addr - user [time] '
    my $request = $f[1];
    my $mid     = $f[2];   # ' status bytes '
    my $referer = $f[3];
    my $ua      = $f[5];

    # (2) drop internal health-check net 10.0.0.0/24 (§5.1) -- before §4 so
    #     the internal TLS-on-plaintext noise is counted as internal, not junk.
    my ($addr) = $pre =~ /^(\S+)/;
    $addr //= '';
    if ($addr =~ /^192\.168\.2\./) { $internal++; next; }

    # (3) request-line grammar METHOD SP URI SP HTTP/x.y  (§4 junk -> drop).
    my ($method, $uri) = $request =~ m{^([A-Z]{1,12}) (\S+) HTTP/\d\.\d$};
    unless (defined $method) { $malformed++; next; }

    # first-seen status = first 3-digit run of ' status bytes '.
    my ($status) = $mid =~ /(\d{3})/;
    $status //= 0;

    # (4) decoded+lowercase path -- baseline + labeling input ONLY.
    my $dp = decode_path($uri);

    # (6) class labeling FIRST, cached per decoded path. A path is treated as
    #     legit baseline ONLY if it matches NO attack class -- otherwise a
    #     hostile path that merely ends in a static extension (e.g.
    #     /owa/auth/x.js, /.env;.jpg) would be wrongly dropped as baseline.
    my $cached = $path_class{$dp};
    if (!defined $cached) {
        my %seen;
        for my $rule (@CLASS_RULES) {
            my ($cls, $re) = @$rule;
            $seen{$cls} = 1 if $dp =~ $re;
        }
        my @classes = sort { $CLASS_RANK{$a} <=> $CLASS_RANK{$b} } keys %seen;
        if (@classes) {
            $cached = join(',', @classes);
        }
        else {
            # (5) no attack class -> baseline if legit-shaped, else uncatalogued.
            my $is_base = 0;
            for my $re (@BASELINE) { if ($dp =~ $re) { $is_base = 1; last; } }
            $cached = $is_base ? "\x01BASE" : 'uncatalogued';
        }
        $path_class{$dp} = $cached;
    }

    # (5) drop legit baseline (no attack class AND legit-shaped path).
    if ($cached eq "\x01BASE") { $baseline_drop++; $EXCL{$dp}++; next; }

    # (B step 1) header-fixture feeds: accumulate RAW UA / referer volume for
    # every kept (attack-shaped) request -- independent of --collapse-ua, which
    # only affects the path-vector dedup key. Empty/'-' carry no string signal
    # (empty-UA is exercised by sending no UA header), so they are not emitted.
    if ($opt{ua_vectors} && defined $ua && $ua ne '' && $ua ne '-') {
        $UA_VOL{$ua}++;
    }
    if ($opt{referer_vectors} && defined $referer && $referer ne '' && $referer ne '-') {
        $REFERER_VOL{$referer}++;
    }

    # (7) dedup key (UA optionally collapsed for cardinality control).
    my $ua_key = $opt{collapse_ua} ? ua_class($ua) : $ua;
    my $key = join("\x00", $method, $uri, $ua_key, $referer);
    if (my $r = $V{$key}) {
        $r->[0]++;
    }
    else {
        $V{$key} = [ 1, $status, $cached ];
    }
}
close $IN;

# --------------------------------------------------------------------------
# emit
# --------------------------------------------------------------------------
make_path($opt{outdir}) unless -d $opt{outdir};
my $jsonl_path   = "$opt{outdir}/replay-vectors.jsonl";
my $summary_path = "$opt{outdir}/replay-vectors.summary.txt";

# count desc, stable tiebreak on the composite key.
my @keys = sort { $V{$b}[0] <=> $V{$a}[0] or $a cmp $b } keys %V;

open my $J, '>', $jsonl_path or die "cannot write $jsonl_path: $!\n";
binmode $J;

my (%cls_vol, %cls_vec);
my $total_vol = 0;
for my $key (@keys) {
    my ($count, $status, $ccsv) = @{ $V{$key} };
    my ($method, $uri, $ua, $ref) = split /\x00/, $key, 4;
    $total_vol += $count;
    my @classes = split /,/, $ccsv;
    for my $c (@classes) { $cls_vol{$c} += $count; $cls_vec{$c}++; }
    my $cjson = '[' . join(',', map { jstr($_) } @classes) . ']';
    print $J '{'
        . '"count":' . $count
        . ',"classes":' . $cjson
        . ',"method":'  . jstr($method)
        . ',"status":'  . ($status + 0)
        . ',"uri":'     . jstr($uri)
        . ',"ua":'      . jstr($ua)
        . ',"referer":' . jstr($ref)
        . "}\n";
}
close $J;

# --------------------------------------------------------------------------
# summary (human sanity gate)
# --------------------------------------------------------------------------
my $unique = scalar @keys;
open my $S, '>', $summary_path or die "cannot write $summary_path: $!\n";

print  $S "# replay-vectors summary (threat-model \xc2\xa76 step 0)\n";
printf $S "# source: %s%s\n\n", $opt{in},
          ($opt{collapse_ua} ? "  [UA collapsed to class]" : "");

print  $S "[intake]\n";
printf $S "  lines_read            %10d\n", $lines;
printf $S "  unparseable_lines     %10d\n", $unparseable;
printf $S "  dropped_internal_net  %10d   (10.0.0.0/24, \xc2\xa75.1)\n", $internal;
printf $S "  dropped_malformed     %10d   (request != 'METHOD SP URI SP HTTP/x.y', \xc2\xa74)\n", $malformed;
printf $S "  dropped_baseline      %10d   (legit example.com traffic)\n", $baseline_drop;
printf $S "  kept_volume           %10d   (attack-shaped requests)\n", $total_vol;

print  $S "\n[vectors]\n";
printf $S "  unique_vectors        %10d   ((method,uri,ua,referer))\n", $unique;
printf $S "  total_matched_volume  %10d\n", $total_vol;

print  $S "\n[per-class]  (classes overlap; volume=sum(count), vectors=distinct tuples)\n";
printf $S "  %-13s %12s %10s %12s %9s\n", 'class', 'volume', 'vectors', 'ref(\xc2\xa73)', 'delta%';
for my $c (@CLASS_ORDER) {
    my $vol = $cls_vol{$c} // 0;
    my $vec = $cls_vec{$c} // 0;
    if (exists $REF_VOL{$c}) {
        my $ref = $REF_VOL{$c};
        my $d   = $ref ? sprintf('%+.1f', 100 * ($vol - $ref) / $ref) : 'n/a';
        printf $S "  %-13s %12d %10d %12d %9s\n", $c, $vol, $vec, $ref, $d;
    }
    else {
        printf $S "  %-13s %12d %10d %12s %9s\n", $c, $vol, $vec, '-', '-';
    }
}

printf $S "\n[baseline-excluded top %d paths]  (sanity: NONE should look hostile)\n",
          $opt{top_excluded};
my @ex = sort { $EXCL{$b} <=> $EXCL{$a} or $a cmp $b } keys %EXCL;
my $n  = @ex < $opt{top_excluded} ? scalar(@ex) : $opt{top_excluded};
for my $i (0 .. $n - 1) {
    printf $S "  %12d  %s\n", $EXCL{ $ex[$i] }, $ex[$i];
}
close $S;

# --------------------------------------------------------------------------
# header-fixture feeds (B step 1): IP-free raw UA / referer, volume desc.
# Each line: {"count":N,"value":"..."}  (jstr-encoded; never a remote_addr).
# --------------------------------------------------------------------------
if ($opt{ua_vectors}) {
    my $p = "$opt{outdir}/replay-ua-vectors.jsonl";
    open my $U, '>', $p or die "cannot write $p: $!\n";
    binmode $U;
    for my $v (sort { $UA_VOL{$b} <=> $UA_VOL{$a} or $a cmp $b } keys %UA_VOL) {
        print $U '{"count":' . $UA_VOL{$v} . ',"value":' . jstr($v) . "}\n";
    }
    close $U;
    printf "wrote: %s (%d distinct UA)\n", $p, scalar(keys %UA_VOL);
}
if ($opt{referer_vectors}) {
    my $p = "$opt{outdir}/replay-referer-vectors.jsonl";
    open my $R, '>', $p or die "cannot write $p: $!\n";
    binmode $R;
    for my $v (sort { $REFERER_VOL{$b} <=> $REFERER_VOL{$a} or $a cmp $b } keys %REFERER_VOL) {
        print $R '{"count":' . $REFERER_VOL{$v} . ',"value":' . jstr($v) . "}\n";
    }
    close $R;
    printf "wrote: %s (%d distinct referer)\n", $p, scalar(keys %REFERER_VOL);
}

# compact machine-readable echo for the runner.
print "unique_vectors=$unique total_volume=$total_vol lines_read=$lines\n";
print "dropped: internal=$internal malformed=$malformed baseline=$baseline_drop unparseable=$unparseable\n";
for my $c (@CLASS_ORDER) {
    printf "class %-12s vol=%d vec=%d\n", $c, $cls_vol{$c} // 0, $cls_vec{$c} // 0;
}
print "wrote: $jsonl_path\n";
print "wrote: $summary_path\n";
