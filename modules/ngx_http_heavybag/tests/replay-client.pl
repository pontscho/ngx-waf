#!/usr/bin/perl
#
# replay-client.pl — raw-socket HTTP/1.1 WAF detect-mode replay client
#
# Security invariants:
#   S1: TCP socket ALWAYS connects to --host:--port only.
#       The target is NEVER derived from any vector/fixture byte.
#   S2: NO fixture/corpus byte is passed to a shell or interpolated into a
#       command line. Only file reads and raw socket writes; no exec/system.
#   S3: Per-header CRLF framing: a header value NEVER injects a sibling header.
#       kind=header CRLF-containing values are skipped, never sent.
#
# core-perl only: IO::Socket::INET + JSON::PP.

use strict;
use warnings;
use IO::Socket::INET;
use JSON::PP;
use Getopt::Long qw(:config no_ignore_case);

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
my $host      = '127.0.0.1';
my $port;
my $kind;
my $in_file;
my $header_name;
my $out_file;
my $limit     = 0;
my $benign_ua = 'Mozilla/5.0 (replay-benign)';
my $enforce   = 0;

GetOptions(
    'host=s'      => \$host,
    'port=i'      => \$port,
    'kind=s'      => \$kind,
    'in=s'        => \$in_file,
    'header=s'    => \$header_name,
    'out=s'       => \$out_file,
    'limit=i'     => \$limit,
    'benign-ua=s' => \$benign_ua,
    'enforce'     => \$enforce,
) or die "Usage: $0 --port N --kind {path|header|baseline} [--enforce] [options]\n";

die "--port is required\n"  unless defined $port;
die "--kind is required\n"  unless defined $kind;
die "--kind must be path, header, or baseline\n"
    unless $kind eq 'path' || $kind eq 'header' || $kind eq 'baseline';
die "--in FILE is required for --kind $kind\n"
    if ($kind eq 'path' || $kind eq 'header') && !defined $in_file;
die "--header NAME is required for --kind header\n"
    if $kind eq 'header' && !defined $header_name;
die "--header must be User-Agent, Referer, or Cookie\n"
    if defined $header_name
    && $header_name ne 'User-Agent'
    && $header_name ne 'Referer'
    && $header_name ne 'Cookie';
die "--out FILE is required\n" unless defined $out_file;

# enforce mode: assert the REAL HTTP status (404/403, and 444 via connection
# close). Each request goes on a FRESH socket with "Connection: close", so a
# byte-0 EOF on the status line is unambiguously a 444 (NGX_HTTP_CLOSE) -- the
# stateful keep-alive idle-close ambiguity disappears. Detect mode (the
# default) stays byte-for-byte unchanged.
my $conn_hdr = $enforce ? 'close' : 'keep-alive';

# ---------------------------------------------------------------------------
# JSON encoder (core-perl)
# ---------------------------------------------------------------------------
my $json = JSON::PP->new->utf8->allow_nonref;

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
my $sent             = 0;
my $reconnects       = 0;
my $skipped_absolute = 0;
my $skipped_connect  = 0;
my $skipped_crlf     = 0;
my $xnn_in_path      = 0;
my $missing_header   = 0;
my %reason_hist;

# ---------------------------------------------------------------------------
# Baseline paths (kind=baseline)
# ---------------------------------------------------------------------------
my @BASELINE_PATHS = qw(
    /
    /index.html
    /app.css
    /app.js
    /favicon.ico
    /robots.txt
    /sitemap.xml
    /css/site.css
    /js/main.js
    /images/logo.png
    /static/app.js
);

# ---------------------------------------------------------------------------
# Socket management
# ---------------------------------------------------------------------------
my $sock;

sub connect_sock {
    $sock = IO::Socket::INET->new(
        PeerAddr => $host,   # S1: always connects to --host:--port
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 10,
    ) or die "Cannot connect to $host:$port: $!\n";
    $sock->autoflush(1);
}

# enforce mode reconnects per request (fresh socket per vector); this initial
# connect is only for the keep-alive detect-mode sweep.
connect_sock() unless $enforce;

# ---------------------------------------------------------------------------
# Response reading
# ---------------------------------------------------------------------------
# Read exactly $n bytes from socket (loop for short reads).
# Returns bytes read or undef on EOF/error.
sub read_exact {
    my ($n) = @_;
    my $buf = '';
    while (length($buf) < $n) {
        my $chunk;
        my $r = $sock->read($chunk, $n - length($buf));
        return undef unless defined $r && $r > 0;
        $buf .= $chunk;
    }
    return $buf;
}

# Read one line (\r\n or \n terminated) from socket.
# Returns the line without line terminator, or undef on EOF.
# $prefix: bytes already consumed from the socket that belong at the line head
# (used by the enforce-mode first-byte probe). It is a single status-line byte
# ('H'), never a terminator, so the loop's "\n" check below is unaffected.
sub read_line {
    my ($prefix) = @_;
    my $line = defined $prefix ? $prefix : '';
    while (1) {
        my $byte;
        my $r = $sock->read($byte, 1);
        return undef unless defined $r && $r > 0;
        if ($byte eq "\n") {
            $line =~ s/\r$//;
            return $line;
        }
        $line .= $byte;
    }
}

# Read chunked body; discard data, consume framing.
sub read_chunked {
    while (1) {
        my $size_line = read_line();
        return unless defined $size_line;
        $size_line =~ s/;.*//;   # strip chunk extensions
        $size_line =~ s/^\s+|\s+$//g;
        my $size = hex($size_line);
        last if $size == 0;
        # read chunk data + CRLF
        read_exact($size + 2);
    }
    # trailing headers (empty line)
    while (1) {
        my $tl = read_line();
        last unless defined $tl && $tl ne '';
    }
}

# Read a full HTTP response; returns (status_code, waf_reason) or undef on EOF.
# $no_body: true for HEAD requests (RFC 7230 §3.3: no message body on HEAD response)
# and for 1xx/204/304 status codes.
sub read_response {
    my ($no_body) = @_;
    $no_body //= 0;

    # [H2] enforce-mode first-byte probe: a 444 (NGX_HTTP_CLOSE) is zero response
    # bytes -- the very first read sees EOF. We MUST distinguish that from a
    # truncated mid-response (a hard error, never silently a 444). So probe one
    # byte first: EOF here == byte-0 close == 444 ('CLOSED' sentinel). A byte
    # here means a real response is coming; we prepend it to the status line and
    # parse as usual. After this point, any EOF is mid-response truncation and
    # returns undef -> the caller maps it to a reserved hard-error status, NOT
    # 444. In detect mode $prefix stays '' and this is byte-for-byte the old path.
    my $prefix = '';
    if ($enforce) {
        my $first = read_exact(1);
        return ('CLOSED', undef) unless defined $first;
        $prefix = $first;
    }

    my $status_line = read_line($prefix);
    return undef unless defined $status_line && $status_line ne '';

    my ($code) = $status_line =~ m{^HTTP/\d\.\d\s+(\d+)};
    return undef unless defined $code;

    # 1xx, 204, 304 never have a body regardless of Content-Length
    if ($code == 204 || $code == 304 || $code < 200) {
        $no_body = 1;
    }

    my $waf_reason;
    my $content_length;
    my $chunked = 0;

    while (1) {
        my $hl = read_line();
        return undef unless defined $hl;
        last if $hl eq '';
        if ($hl =~ /^x-waf-reason\s*:\s*(.+)$/i) {
            $waf_reason = $1;
            $waf_reason =~ s/\s+$//;
        }
        if ($hl =~ /^content-length\s*:\s*(\d+)/i) {
            $content_length = int($1);
        }
        if ($hl =~ /^transfer-encoding\s*:\s*chunked/i) {
            $chunked = 1;
        }
    }

    # HEAD (and no-body status codes): headers only, never consume a body
    unless ($no_body) {
        if ($chunked) {
            read_chunked();
        } elsif (defined $content_length && $content_length > 0) {
            read_exact($content_length);
        }
        # If neither Content-Length nor chunked, we treat as 0-body.
    }

    return ($code, $waf_reason);
}

# ---------------------------------------------------------------------------
# Send one request with reconnect-on-EOF logic
# $no_body: pass 1 for HEAD requests (no response body expected)
# ---------------------------------------------------------------------------
sub send_request_and_read {
    my ($request_bytes, $no_body) = @_;
    $no_body //= 0;

    # [H1] enforce: a FRESH socket per request (Connection: close). The reconnect
    # target is ALWAYS the literal ($host,$port) inside connect_sock() -- never
    # derived from a vector/response byte (S1). No resend loop: with one
    # connection per request a byte-0 EOF is a deterministic 444, not a
    # keep-alive idle close, so the [security #5] max-one-resend is moot here.
    if ($enforce) {
        connect_sock();
        print $sock $request_bytes;
        my ($code, $reason) = read_response($no_body);
        # [M1] map the 'CLOSED' sentinel to the 444 INTEGER before record_result
        # (status+0): 'CLOSED'+0 == 0 is a Perl trap we must not hit.
        return (444, $reason) if defined $code && $code eq 'CLOSED';
        # mid-response truncation (read_response returned undef AFTER the probe
        # byte): a hard error. Reserved status 0 -- never equals an expected
        # 404/403/444, so the harness flags it loudly instead of miscounting.
        return (0, undef) unless defined $code;
        return ($code, $reason);
    }

    for my $attempt (1..2) {
        print $sock $request_bytes;
        my ($code, $reason) = read_response($no_body);

        if (defined $code) {
            return ($code, $reason);
        }

        # EOF before full response — server closed keep-alive
        if ($attempt == 1) {
            $reconnects++;
            connect_sock();
        }
    }
    return (undef, undef);
}

# ---------------------------------------------------------------------------
# Output file
# ---------------------------------------------------------------------------
open(my $out_fh, '>', $out_file) or die "Cannot open --out '$out_file': $!\n";

# ---------------------------------------------------------------------------
# Item processing
# ---------------------------------------------------------------------------
sub record_result {
    my (%args) = @_;
    # args: reason, status, count, classes_ref, key, src
    my $reason = defined $args{reason} ? $args{reason} : 'MISSING';
    $reason_hist{$reason}++;
    $missing_header++ unless defined $args{reason};

    my $line = $json->encode({
        reason  => $reason,
        status  => $args{status} + 0,
        count   => $args{count}  + 0,
        classes => $args{classes} || [],
        key     => $args{key},
        src     => $args{src},
    });
    print $out_fh $line, "\n";
}

sub process_path {
    my ($rec, $src) = @_;
    my $method  = $rec->{method} // 'GET';
    my $uri     = $rec->{uri}    // '/';
    my $count   = $rec->{count}  // 1;
    my $classes = $rec->{classes} || [];

    # Skip CONNECT
    if ($method eq 'CONNECT') {
        $skipped_connect++;
        return;
    }
    # Skip absolute-form URI
    if ($uri =~ /^[A-Za-z][A-Za-z0-9+.\-]*:\/\//) {
        $skipped_absolute++;
        return;
    }

    # Count \x sequences (literal 4-char: backslash x HH)
    $xnn_in_path++ if index($uri, '\x') >= 0;

    # Build request — S2: never interpolated into shell; S3: URI on request line
    my $req = "$method $uri HTTP/1.1\r\n"
            . "Host: replay\r\n"
            . "User-Agent: $benign_ua\r\n"
            . "Connection: $conn_hdr\r\n"
            . "\r\n";

    # HEAD responses carry headers but no body (RFC 7230 §3.3)
    my $no_body = ($method eq 'HEAD') ? 1 : 0;
    my ($code, $reason) = send_request_and_read($req, $no_body);
    return unless defined $code;
    $sent++;

    record_result(
        reason  => $reason,
        status  => $code,
        count   => $count,
        classes => $classes,
        key     => $uri,
        src     => $src,
    );
}

sub process_header {
    my ($rec) = @_;
    my $raw_value = $rec->{value} // '';
    my $count     = $rec->{count} // 1;
    my $src       = $rec->{src}   // '';

    # Re-expand \xHH (literal 4 chars: backslash x two hex digits) -> single byte
    # S3: ONLY within this one value — never affects framing bytes
    my $value = $raw_value;
    $value =~ s/\\x([0-9A-Fa-f]{2})/chr(hex($1))/ge;

    # S3: CRLF guard — skip if expanded value contains CR or LF
    if ($value =~ /[\x0d\x0a]/) {
        $skipped_crlf++;
        return;
    }

    # Build request
    my $req = "GET / HTTP/1.1\r\n"
            . "Host: replay\r\n";
    unless ($header_name eq 'User-Agent') {
        $req .= "User-Agent: $benign_ua\r\n";
    }
    # S3: exactly one header line; value has been verified free of CR/LF
    $req .= "$header_name: $value\r\n"
          . "Connection: $conn_hdr\r\n"
          . "\r\n";

    my ($code, $reason) = send_request_and_read($req);
    return unless defined $code;
    $sent++;

    record_result(
        reason  => $reason,
        status  => $code,
        count   => $count,
        classes => [],
        key     => $raw_value,
        src     => $src,
    );
}

sub process_baseline {
    my ($path) = @_;
    my $req = "GET $path HTTP/1.1\r\n"
            . "Host: replay\r\n"
            . "User-Agent: $benign_ua\r\n"
            . "Connection: $conn_hdr\r\n"
            . "\r\n";

    my ($code, $reason) = send_request_and_read($req);
    return unless defined $code;
    $sent++;

    record_result(
        reason  => $reason,
        status  => $code,
        count   => 1,
        classes => [],
        key     => $path,
        src     => 'baseline',
    );
}

# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------
if ($kind eq 'baseline') {
    for my $path (@BASELINE_PATHS) {
        process_baseline($path);
    }
} elsif ($kind eq 'path') {
    open(my $in_fh, '<', $in_file) or die "Cannot open '$in_file': $!\n";
    my $n = 0;
    while (my $line = <$in_fh>) {
        chomp $line;
        next unless $line =~ /\S/;
        my $rec = eval { $json->decode($line) };
        next unless defined $rec && ref $rec eq 'HASH';
        process_path($rec, 'path');
        $n++;
        last if $limit > 0 && $n >= $limit;
    }
    close $in_fh;
} elsif ($kind eq 'header') {
    open(my $in_fh, '<', $in_file) or die "Cannot open '$in_file': $!\n";
    my $n = 0;
    while (my $line = <$in_fh>) {
        chomp $line;
        next unless $line =~ /\S/;
        my $rec = eval { $json->decode($line) };
        next unless defined $rec && ref $rec eq 'HASH';
        process_header($rec);
        $n++;
        last if $limit > 0 && $n >= $limit;
    }
    close $in_fh;
}

close $out_fh;
close $sock if $sock;

# ---------------------------------------------------------------------------
# STDERR summary
# ---------------------------------------------------------------------------
print STDERR "=== replay-client summary ===\n";
print STDERR "kind:              $kind\n";
print STDERR "port:              $port\n";
print STDERR "mode:              ", ($enforce ? 'enforce' : 'detect'), "\n";
print STDERR "sent:              $sent\n";
print STDERR "reconnects:        $reconnects\n";
print STDERR "skipped_absolute:  $skipped_absolute\n";
print STDERR "skipped_connect:   $skipped_connect\n";
print STDERR "skipped_crlf:      $skipped_crlf\n";
print STDERR "xnn_in_path:       $xnn_in_path\n";
print STDERR "missing_header:    $missing_header\n";
print STDERR "reason histogram:\n";
for my $r (sort keys %reason_hist) {
    printf STDERR "  %-30s %d\n", $r, $reason_hist{$r};
}
