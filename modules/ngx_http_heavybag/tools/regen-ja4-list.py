#!/usr/bin/env python3
"""
Offline (re)generator for ja4.list -- the JA4 fingerprint -> coarse TLS-family
table consumed by $waf_ua_is_spoofed.

The canonical source is ja4db.com, but it is frequently unreachable from build
hosts; this script ingests one or more committed/downloaded CSV exports and
maps each fingerprint's application/library label to a coarse family. It is a
one-time OFFLINE step (no build-time network); the result, ja4.list, is what
the module loads.

Data sources (both reachable on raw.githubusercontent.com):
  1. Niicolaa/ja4db-export -- a daily mirror of the full ja4db.com dataset:
       https://raw.githubusercontent.com/Niicolaa/ja4db-export/main/csv/ja4_fingerprint.csv
  2. FoxIO-LLC/ja4 -- the official curated reference mapping (client `ja4` col):
       https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv

Refresh procedure:
    curl -fsSL <url 1> -o /tmp/ja4_fingerprint.csv
    curl -fsSL <url 2> -o /tmp/ja4plus-mapping.csv
    python3 modules/ngx_http_heavybag/tools/regen-ja4-list.py \
        /tmp/ja4_fingerprint.csv /tmp/ja4plus-mapping.csv \
        modules/ngx_http_heavybag/lists/ja4.list

Conflict resolution: a JA4 seen with >1 distinct family (or 0 recognizable
ones) is OMITTED -> absent at lookup == HEAVYBAG_TLSFAM_UNKNOWN, so an ambiguous
fingerprint can never produce a false-positive spoof. Only fingerprints whose
every labelled record agrees on exactly ONE family are emitted, sorted by the
ja4 bytes (the loader also sorts; a pre-sorted file is reviewable).

Usage: regen-ja4-list.py <in.csv> [<in2.csv> ...] <out ja4.list>
"""
import csv
import re
import sys

JA4_RE = re.compile(r'^[a-z0-9]+_[0-9a-f]{12}_[0-9a-f]{12}$')

# Ordered classifiers; the first family whose any-token matches the lowercased
# "application + library" label wins for that record. Tokens match clean ja4db
# application labels (e.g. "Chromium Browser", "Go-http", "Mozilla Firefox",
# "Googlebot"), not full UA strings.
TOOL = (
    "curl", "libcurl", "wget", "python", "requests", "urllib", "aiohttp",
    "httpx", "okhttp", "java", "openssl", "s_client", "node", "nodejs",
    "axios", "reqwest", ".net", "dotnet", "httpclient", "postman", "insomnia",
    "libwww", "perl", "ruby", "faraday", "guzzle", "undici", "go-http",
    "golang", "powershell", "wininet", "winhttp", "boto", "scrapy",
)
BOT = (
    "bot", "crawl", "spider", "scanner", "nmap", "masscan", "zgrab", "nuclei",
    "censys", "shodan", "slurp", "sqlmap", "nikto", "indexer", "fetcher",
)
CHROMIUM = (
    "chrom", "edge", "brave", "opera", "vivaldi", "samsung", "yandex",
    "electron", "webview", "wechat", "duckduckgo", "whale",
)
FIREFOX = (
    "firefox", "gecko", "tor browser", "iceweasel", "waterfox", "librewolf",
    "palemoon", "mozilla", "thunderbird",
)
SAFARI = ("safari", "webkit", "apple")


def classify(app, lib):
    """Classify a curated application/library label."""
    s = (app + " " + lib).lower()
    if any(t in s for t in TOOL):
        return "tool"
    if any(t in s for t in BOT):
        return "bot"
    if any(t in s for t in CHROMIUM):
        return "chromium"
    if any(t in s for t in FIREFOX):
        return "firefox"
    if any(t in s for t in SAFARI):
        return "safari"
    return None


# Library/tool tokens as they appear in a raw User-Agent STRING (the ja4db
# user_agent_string column), which is the ground-truth attribution for the
# vast majority of fingerprints (the curated `application` label is sparse).
TOOL_UA = (
    "curl/", "libcurl", "wget/", "python-requests", "python-httpx",
    "python-urllib", "aiohttp", "go-http-client", "java/", "okhttp",
    "node-fetch", "axios", "reqwest", "guzzlehttp", "undici", "libwww-perl",
    "apache-httpclient", "postmanruntime", "got (", "dart/", "ruby",
)
# Chromium-engine markers (incl. every derivative that rides on Chrome/),
# tested before the Safari fallback because Chrome UAs also contain "Safari".
CHROMIUM_UA = (
    "chrome/", "chromium/", "crios/", "edg/", "edge/", "edga/", "edgios/",
    "opr/", "oprgx/", "yabrowser/", "samsungbrowser/", "vivaldi/",
    "headlesschrome/", "ucbrowser/", "huaweibrowser/", "whale/", " wv)",
)


def classify_ua(ua):
    """
    Derive the coarse TLS-stack family from a raw User-Agent string, mirroring
    the C parser's engine ordering. ENGINE families only -- never `bot`: a
    chromium-engine crawler has chromium TLS, and expected_tls_family() never
    returns bot, so labelling an engine fingerprint `bot` from its UA would
    create false-positive spoofs. A pure-bot UA with no engine token yields
    None (omitted -> UNKNOWN at lookup, safe).
    """
    s = ua.lower()
    if any(t in s for t in TOOL_UA):
        return "tool"
    if any(t in s for t in CHROMIUM_UA):
        return "chromium"
    if "firefox/" in s or "fxios/" in s:
        return "firefox"
    if "safari/" in s or "applewebkit/" in s:
        return "safari"
    return None


HEADER = """\
# ngx_http_heavybag_module - JA4 fingerprint -> coarse TLS-family table
#
# Loaded by `waf_ja4_list <path>` and consumed by $waf_ua_is_spoofed: when a
# request's JA4 family contradicts the family its User-Agent browser should
# present, the UA is flagged as spoofed (the unforgeable, HTTPS-only half of
# the signal). One entry per line:
#
#     <ja4-fingerprint> <family>
#
# <family> is one of: chromium | firefox | safari | tool | bot | unknown
# '#' comment lines and blank lines are ignored. Unrecognized family tokens
# map to UNKNOWN -> never produce a spoof signal.
#
# ---------------------------------------------------------------------------
# GENERATED -- do not hand-edit. Built by lists/regen-ja4-list.py from ja4db
# CSV exports (Niicolaa/ja4db-export, a daily mirror of ja4db.com, + the
# official FoxIO-LLC/ja4 ja4plus-mapping.csv -- ja4db.com itself is unreachable
# from the build host). See that script's header for the refresh procedure.
# Family mapping: the curated application/library label when present, else the
# observed user_agent_string (engine family only) -> tool/bot/chromium/firefox/
# safari. The UA fallback is what gives broad coverage; the curated label is
# sparse (most ja4db rows carry only an observed UA).
# CONFLICT RULE: a fingerprint seen with more than one family (or none
# recognized) is OMITTED, so an ambiguous JA4 is absent here and resolves to
# UNKNOWN at lookup -- it can never trigger a false-positive spoof. Only
# single-family-consensus fingerprints are emitted.
# ---------------------------------------------------------------------------
"""


def main():
    *srcs, out = sys.argv[1:]
    if not srcs:
        sys.exit("usage: regen-ja4-list.py <in.csv> [<in2.csv> ...] <out ja4.list>")
    fams = {}        # ja4 -> set(family)
    rows = 0
    for src in srcs:
        with open(src, newline="", encoding="utf-8", errors="replace") as f:
            r = csv.DictReader(f)
            # tolerate canonical (Niicolaa) or capitalized (FoxIO) headers; for
            # the FoxIO multi-column file only the client `ja4` column is used.
            for row in r:
                rows += 1
                ja4 = (row.get("ja4_fingerprint") or row.get("ja4")
                       or row.get("JA4") or "").strip()
                if not ja4 or not JA4_RE.match(ja4):
                    continue
                app = (row.get("application") or row.get("Application") or "").strip()
                lib = (row.get("library") or row.get("Library") or "").strip()
                fam = classify(app, lib)
                if fam is None:
                    # fall back to the observed UA string (ground truth for the
                    # bulk of fingerprints, which carry no curated label)
                    ua = (row.get("user_agent_string")
                          or row.get("User-Agent") or "").strip()
                    if ua:
                        fam = classify_ua(ua)
                if fam is None:
                    continue
                fams.setdefault(ja4, set()).add(fam)

    emitted = {ja4: next(iter(s)) for ja4, s in fams.items() if len(s) == 1}
    conflict = sum(1 for s in fams.values() if len(s) > 1)

    with open(out, "w", encoding="ascii") as o:
        o.write(HEADER)
        o.write("\n")
        for ja4 in sorted(emitted):
            o.write("%s %s\n" % (ja4, emitted[ja4]))

    from collections import Counter
    by_fam = Counter(emitted.values())
    sys.stderr.write(
        "rows=%d  ja4_with_family=%d  emitted=%d  conflict_omitted=%d\n"
        % (rows, len(fams), len(emitted), conflict))
    sys.stderr.write("by_family=%s\n" % dict(by_fam))


if __name__ == "__main__":
    main()
