# Implementation Plan: User-Agent Descriptive Parser + JA4/UA Spoof Detection for heavybag

## Requirements Summary

Port the standalone Lua User-Agent parser (`user-agent.lua`) into the heavybag C module
(`modules/ngx_http_heavybag`) and expose its output as five read-only nginx variables:

| Variable | Type | Meaning |
|---|---|---|
| `$waf_ua_browser` | string | Browser/client identifier (`chrome`, `firefox`, `safari`, `curl`, `headlesschrome`, …) |
| `$waf_ua_browser_version` | string | Version token extracted from the UA (major-only reliable for Chromium) |
| `$waf_ua_category` | string | `mobile` / `tablet` / `pc` / `tv` / `console` / `unknown`, **overridden** by threat class `scanner` / `ai-crawler` / `crawler` / `bot` when the existing threat classifier matched |
| `$waf_ua_vendor` | string | `apple` / `google` / `microsoft` / `mozilla` / `yandex` / … |
| `$waf_ua_is_spoofed` | string `"0"`/`"1"` | UA↔JA4 family contradiction (primary) OR verified-bot CIDR mismatch (reinforcement) |

The module **only produces data**. It introduces **no new blocking decisions**. Downstream
nginx configuration consumes the variables and decides what to do (log, `map`, `return 403`,
rate-limit keys, etc.).

### Success Criteria

- [ ] All five variables resolve in `nginx.conf` (`log_format`, `map`, `if`, `add_header`) and return the parsed values.
- [ ] `$waf_ua_browser` / `$waf_ua_browser_version` / `$waf_ua_vendor` match the reference Lua parser output for a fixture corpus of real UAs (the C port is behaviour-compatible with the **fixed** Lua, see Step 9).
- [ ] `$waf_ua_category` returns the device class for human UAs and the threat label (`scanner`/`ai-crawler`/`crawler`/`bot`) when `ctx->ua` is a bot class.
- [ ] `$waf_ua_is_spoofed` returns `"1"` for: (a) a TLS request whose JA4 family contradicts the UA browser family; (b) any request (HTTP or HTTPS) whose UA claims a verified-bot vendor but whose client IP is outside that vendor's verified CIDR. Returns `"0"`/not_found otherwise.
- [ ] The enriched `lists/*.list` files load at config time without PCRE2 compile errors.
- [ ] `lists/ja4.list` loads, maps known fingerprints to coarse families, and ambiguous fingerprints resolve to `unknown` (no false-positive spoof).
- [ ] `user-agent.lua` is corrected (3 bugs) and remains a valid behavioural oracle.
- [ ] Existing `$waf_type` / fake-bot / reputation behaviour is unchanged (no regression).
- [ ] Module builds via the existing `config` + `./configure` + `cmake --build --target heavybag_module` flow.

### Scope

**In Scope:**
- New C file `src/heavybag_ua_parse.c` + `src/heavybag_ua_parse.h` implementing the descriptive parser (substring chain, 1:1 with the Lua priority order, 3 bugs fixed).
- New enums for browser / os / device-category / vendor / TLS-family in `ngx_http_heavybag.h`.
- New `ngx_http_heavybag_ctx_t` fields + `ua_parsed:1` lazy guard.
- Copying the JA4 string from SSL ex-data into the request ctx at preaccess time.
- New `lists/ja4.list` (JA4 fingerprint → coarse family) + a dedicated key→value loader.
- `is_spoofed` computation (JA4-family vs UA-family + verified-bot CIDR reinforcement).
- Five new nginx variable getters + registration.
- Enrichment of `lists/ai-crawler.list`, `lists/crawler.list`, `lists/bot.list`, `lists/scanner-ua.list` with the curated 2026 token set (A1).
- New browser/OS tokens in the parser (DuckDuckGo, Whale, UCBrowser, HuaweiBrowser, OPRGX; HarmonyOS).
- Bug fixes in `user-agent.lua` (reference oracle).
- `config` build wiring + reconfigure.
- ctest.h unit tests for the parser, the JA4 family mapping, and the spoof matrix.

**Out of Scope (documented as future):**
- Any blocking/`return`/rate-limit decision based on the new variables (left to nginx config).
- Parsing `Sec-CH-UA*` Client-Hint headers for accurate minor versions (UA reduction froze them).
- "Improbable" UA-internal combinations (e.g. Safari on Windows) as a spoof signal — these are *improbable*, not impossible; they are NOT folded into `is_spoofed`.
- Full verbatim `ai.robots.txt/robots.json` (~180 entries) import — A1 uses a curated subset.
- Detecting Brave / Arc (they ship a Chrome-identical UA by design — undetectable server-side from UA).
- iPadOS-as-desktop-Safari and visionOS-as-Mac de-masquerading (no reliable UA-only fix).
- Regenerating the AI-crawler list from the network at build time (self-contained build is a project constraint).

### Assumptions & Constraints

**Assumptions:**
- The Phase 0 definition research is complete (captured in this plan) and is the source for the curated token additions and the ja4db normalization rule.
- The descriptive parser runs lazily, guarded by a new `ua_parsed:1` bit, mirroring the existing `classified:1` pattern.
- JA4 family granularity is coarse: a single `chromium` family covers Chrome/Edge/Brave/Opera/Vivaldi/Samsung/YaBrowser, because their TLS fingerprints are near-identical.
- The ja4db import is committed as a generated `lists/ja4.list`; the import/normalization is a one-time offline step re-runnable when the DB updates.

**Constraints:**
- **No Docker, no external CLI dependency, no network access at build time** (project rule). The ja4db import is performed offline and the result committed.
- **No libloc / `location` CLI** — geo/ASN already handled by the embedded nanolibloc reader; not touched here.
- Adding a new `.c` file requires editing `modules/ngx_http_heavybag/config` (`heavybag_srcs`+`heavybag_deps`) and **re-running nginx `./configure`** before `cmake --build`.
- After re-running `./configure`, `touch` the OpenSSL `ssl.h` before `make` to avoid a doomed full OpenSSL rebuild (known build trap).
- Match existing module code style (tab indentation, snake_case, early returns, nginx `ngx_*` idioms).

### Non-Functional Requirements
- **Performance**: parser is an ordered substring chain over the UA string (no regex, no allocation for the descriptive fields — values point at static literals or are sliced in place). JA4 lookup is O(1)/O(log n) via a config-time-built hash/sorted table. Parsing is lazy and cached per request.
- **Security**: read-only feature; the UA is never copied into a writable buffer, never used to build a command/path/query. The JA4 list is config-data only. Output safety is **by construction**: four of the five variables are static enum-table strings, and `ua_version` is charset-restricted to `[0-9A-Za-z._-]` at the source (Step 3) — so none can carry control-char/CRLF/quote injection into a downstream log or response-header sink. (Consumer-side escaping remains good practice as defense-in-depth, but is no longer load-bearing.)
  - **CIDR-signal trust boundary (CWE-290, documented limitation):** the `cidr_signal` half of `is_spoofed` matches against `ctx->client_sa`, which is X-Forwarded-For-derived. If XFF is honored from an untrusted hop, an attacker can forge a source IP inside a verified-bot CIDR and suppress the CIDR signal (false negative), or land outside it to force a false positive. This is **not a new risk** — the existing fake-bot block (`:1010-1030`) shares the exact same trust boundary — and the `ja4_signal` (TLS-level, unforgeable via XFF) is the primary signal precisely for this reason. The plan does NOT widen XFF trust. Document that `cidr_signal` is only as trustworthy as the deployment's `set_real_ip_from` / trusted-proxy configuration; on plain HTTP with untrusted XFF, treat `is_spoofed` as advisory.
- **Scalability**: per-request cost is one substring scan + one JA4 hash lookup; all tables are shared, immutable, config-time structures.

## Architecture Analysis

### Existing UA threat layer (do NOT duplicate)
- `ngx_http_heavybag_ua_e` enum — `src/ngx_http_heavybag.h:43-53`:
  `HEAVYBAG_UA_SCANNER=0, HEAVYBAG_UA_AI_CRAWLER, HEAVYBAG_UA_CRAWLER, HEAVYBAG_UA_BOT, HEAVYBAG_UA_LIST_MAX(=4), HEAVYBAG_UA_REGULAR(=4), HEAVYBAG_UA_EMPTY, HEAVYBAG_UA_MAX(=6)`.
- `ngx_http_heavybag_ua_classify()` — `src/heavybag_match.c:419-452`: reads `r->headers_in.user_agent->value` (no copy), iterates `wlcf->ua_re[0..HEAVYBAG_UA_LIST_MAX)` in enum priority order, `ngx_regex_exec()` boolean match, stores into `ctx->ua`, sets `ctx->classified=1`.
- 4 compiled PCRE2 buckets from `lists/scanner-ua.list`, `lists/ai-crawler.list`, `lists/crawler.list`, `lists/bot.list` (CASELESS alternation, one regex per category).
- `$waf_type` getter — `src/ngx_http_heavybag_module.c:1983-2015` — already exposes `ctx->ua` via a static `heavybag_type_str[]` table.
- Fake-bot block — `src/ngx_http_heavybag_module.c:1010-1030`: when `ctx->ua` ∈ {CRAWLER, AI_CRAWLER} and the per-class verified CIDR list is configured and `ngx_cidr_match(sa, verified_bot_cidrs[ctx->ua]) != NGX_OK` → 403 `HEAVYBAG_REASON_FAKE_BOT`. The canonical client addr is `ctx->client_sa` (resolved POST_READ, `src/ngx_http_heavybag_module.c:447-463`).

The new descriptive parser is a **second, independent layer**. `$waf_ua_category` reuses the threat result (overriding device class), but browser/version/vendor are new.

### Request context (extend here)
`ngx_http_heavybag_ctx_t` — `src/ngx_http_heavybag.h:137-155` — flat struct, `ngx_pcalloc`'d (zero = "unknown"):
```c
typedef struct {
    unsigned          spoof_swap:1;
    unsigned          spoof_done:1;
    unsigned          classified:1;   /* ua field already computed */
    ngx_str_t         spoof_body;
    struct sockaddr  *client_sa;
    socklen_t         client_socklen;
    ngx_http_heavybag_ua_e ua;             /* $waf_type outcome */
    unsigned              geo_done:1;
    unsigned              verdict_set:1;
    u_char                country[2];
    ngx_http_heavybag_reason_e reason;
    unsigned              asn_done:1;
    uint32_t              asn;
} ngx_http_heavybag_ctx_t;
```
Allocation sites: POST_READ `src/ngx_http_heavybag_module.c:440-444`; PREACCESS `:831-835` (guarded `ctx==NULL` at `:829`); each getter lazily allocs too.

### Variable registration (imperative, extend here)
`ngx_http_heavybag_preconfiguration()` — `src/ngx_http_heavybag_module.c:1934-1975` — five `ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE)` calls, each sets `var->get_handler`. **No array.** Installed at `ngx_http_heavybag_module_ctx.preconfiguration` (`:385`). Add five more calls here.

### JA4 (read for `is_spoofed`)
- JA4 string = 36-char `t13d1516h2_8daaf6152771_e5627efa2ab1`; `HEAVYBAG_JA4_LEN`=37 (`src/heavybag_ja4.h:32`). The ClientHello callback calls `ngx_http_heavybag_ja4_compute()` (`src/heavybag_ja4.c:312`), which wraps `ngx_http_heavybag_ja4_build()` (`:171`).
- Computed in the ClientHello callback `ngx_http_heavybag_ja4_client_hello_cb` (`src/ngx_http_heavybag_module.c:2386-2411`, store at `:2394-2399`), stored on the SSL connection via `SSL_set_ex_data(ssl_conn, ngx_http_heavybag_ja4_ssl_index, ja4)` — **NOT in ctx**. Index: `src/ngx_http_heavybag_module.c:34` (`ngx_http_heavybag_ja4_ssl_index`).
- The ClientHello callback runs **before** all nginx phase handlers, so the JA4 is available at PREACCESS.
- `$waf_ja4_hash` getter reads it back: `src/ngx_http_heavybag_module.c:2183-2211` via `SSL_get_ex_data(ssl_conn, ngx_http_heavybag_ja4_ssl_index)`.
- JA4 is a **purely opaque hash** — no semantic decoding, no known-fingerprint table anywhere in code or `lists/`. We add the table (`lists/ja4.list`).

### Build wiring
`modules/ngx_http_heavybag/config` — `heavybag_deps` (10 headers) lines 14-23, `heavybag_srcs` (10 sources) lines 25-34. No module-local `CMakeLists.txt`; the top-level `CMakeLists.txt:130` passes `--add-dynamic-module=.../modules/ngx_http_heavybag`. Output `.so` at `nginx/objs/ngx_http_heavybag_module.so` copied to sandbox (`CMakeLists.txt:151-153`).

## Captured Information (for implementation phase)

### File Locations
| Purpose | File Path | Location/Line |
|---------|-----------|---------------|
| New enums (browser/os/category/vendor/tls-family) | `src/ngx_http_heavybag.h` | After `ngx_http_heavybag_ua_e` (`:53`) |
| ctx new fields + `ua_parsed:1` + `ja4` | `src/ngx_http_heavybag.h` | Inside `ngx_http_heavybag_ctx_t` (`:137-155`) |
| Parser implementation | `src/heavybag_ua_parse.c` | **new file** |
| Parser API | `src/heavybag_ua_parse.h` | **new file** |
| JA4 list loader (`ja4.list` → table) | `src/heavybag_match.c` | Near `ngx_http_heavybag_ua_list_compile` (`:320-363`) |
| JA4 list directive setter | `src/ngx_http_heavybag_module.c` | Near `ngx_http_heavybag_set_ua_list` (`:1402`) + commands table |
| Copy JA4 ex-data → ctx | `src/ngx_http_heavybag_module.c` | PREACCESS handler, after `ua_classify` call (`:974`) |
| `is_spoofed` computation | `src/heavybag_ua_parse.c` | New `ngx_http_heavybag_ua_spoof_eval()` |
| 5 variable getters | `src/ngx_http_heavybag_module.c` | After existing getters (`~:2211`) |
| 5 `add_variable` calls | `src/ngx_http_heavybag_module.c` | In `ngx_http_heavybag_preconfiguration` (`:1934-1975`) |
| Build wiring | `modules/ngx_http_heavybag/config` | `heavybag_srcs` (`:25-34`), `heavybag_deps` (`:14-23`) |
| Curated token enrichment | `modules/ngx_http_heavybag/lists/{ai-crawler,crawler,bot,scanner-ua}.list` | append |
| JA4 seed data | `modules/ngx_http_heavybag/lists/ja4.list` | **new file** |
| Reference oracle fix | `user-agent.lua` | lines 121, 352, 419-427 |
| Unit tests | `modules/ngx_http_heavybag/tests/unit/` (alongside `test-ja4.c`) | new test file `test_heavybag_ua_parse.c`, registered with the existing ctest harness |

### Imports/Includes (parser .c)
```c
#include <ngx_config.h>      /* ngx types */
#include <ngx_core.h>        /* ngx_str_t, ngx_strlcasestrn, ngx_pnalloc */
#include <ngx_http.h>        /* ngx_http_request_t */
#include "ngx_http_heavybag.h"    /* enums, ctx, loc_conf */
#include "heavybag_ua_parse.h"    /* own API */
```

### Type Definitions (NEW — to add in `ngx_http_heavybag.h`)
```c
/* Descriptive browser family — values are stable string-table indices.
 * 0 == UNKNOWN so ngx_pcalloc'd ctx defaults correctly. */
typedef enum {
    HEAVYBAG_BROWSER_UNKNOWN = 0,
    HEAVYBAG_BROWSER_MSIE, HEAVYBAG_BROWSER_EDGE, HEAVYBAG_BROWSER_FIREFOX, HEAVYBAG_BROWSER_CHROME,
    HEAVYBAG_BROWSER_YABROWSER, HEAVYBAG_BROWSER_SAFARI, HEAVYBAG_BROWSER_SAMSUNG,
    HEAVYBAG_BROWSER_XIAOMIBROWSER, HEAVYBAG_BROWSER_OPERA, HEAVYBAG_BROWSER_SLEIPNIR,
    HEAVYBAG_BROWSER_VIVALDI, HEAVYBAG_BROWSER_ANDROIDBROWSER, HEAVYBAG_BROWSER_SILK,
    HEAVYBAG_BROWSER_CURL, HEAVYBAG_BROWSER_WGET, HEAVYBAG_BROWSER_FFMPEG,
    HEAVYBAG_BROWSER_APPLECOREMEDIA, HEAVYBAG_BROWSER_LIBMPV,
    /* 2026 additions */
    HEAVYBAG_BROWSER_DUCKDUCKGO, HEAVYBAG_BROWSER_WHALE, HEAVYBAG_BROWSER_UCBROWSER,
    HEAVYBAG_BROWSER_HUAWEIBROWSER, HEAVYBAG_BROWSER_OPERAGX,
    HEAVYBAG_BROWSER_HEADLESSCHROME, HEAVYBAG_BROWSER_PYTHON, HEAVYBAG_BROWSER_GOHTTP,
    HEAVYBAG_BROWSER_JAVA, HEAVYBAG_BROWSER_OKHTTP,
    HEAVYBAG_BROWSER_MAX
} ngx_http_heavybag_ua_browser_e;

typedef enum {
    HEAVYBAG_OS_UNKNOWN = 0,
    HEAVYBAG_OS_WINDOWS, HEAVYBAG_OS_IPHONE, HEAVYBAG_OS_IPAD, HEAVYBAG_OS_IPOD, HEAVYBAG_OS_MACOS,
    HEAVYBAG_OS_ANDROID, HEAVYBAG_OS_LINUX, HEAVYBAG_OS_BSD, HEAVYBAG_OS_CROS,
    HEAVYBAG_OS_XBOX360, HEAVYBAG_OS_XBOXONE, HEAVYBAG_OS_PSP, HEAVYBAG_OS_PSVITA,
    HEAVYBAG_OS_PS3, HEAVYBAG_OS_PS4, HEAVYBAG_OS_PS5,
    HEAVYBAG_OS_NINTENDO3DS, HEAVYBAG_OS_NINTENDODSI, HEAVYBAG_OS_NINTENDOWII, HEAVYBAG_OS_NINTENDOWIIU,
    HEAVYBAG_OS_INETTV, HEAVYBAG_OS_BLACKBERRY10, HEAVYBAG_OS_BLACKBERRY,
    HEAVYBAG_OS_WATCHOS, HEAVYBAG_OS_WEBOS, HEAVYBAG_OS_WPHONE,
    HEAVYBAG_OS_HARMONYOS,  /* 2026 addition — match BEFORE android fallback */
    HEAVYBAG_OS_MAX
} ngx_http_heavybag_ua_os_e;

/* Device class; the bot-class values mirror ngx_http_heavybag_ua_e and are taken
 * over from ctx->ua when it is a threat class. */
typedef enum {
    HEAVYBAG_CAT_UNKNOWN = 0,
    HEAVYBAG_CAT_MOBILE, HEAVYBAG_CAT_TABLET, HEAVYBAG_CAT_PC, HEAVYBAG_CAT_TV, HEAVYBAG_CAT_CONSOLE,
    HEAVYBAG_CAT_SCANNER, HEAVYBAG_CAT_AI_CRAWLER, HEAVYBAG_CAT_CRAWLER, HEAVYBAG_CAT_BOT,
    HEAVYBAG_CAT_MAX
} ngx_http_heavybag_ua_category_e;

typedef enum {
    HEAVYBAG_VENDOR_UNKNOWN = 0,
    HEAVYBAG_VENDOR_APPLE, HEAVYBAG_VENDOR_MOZILLA, HEAVYBAG_VENDOR_GOOGLE, HEAVYBAG_VENDOR_MS,
    HEAVYBAG_VENDOR_OPERA, HEAVYBAG_VENDOR_SAMSUNG, HEAVYBAG_VENDOR_XIAOMI, HEAVYBAG_VENDOR_MEGAINDEX,
    HEAVYBAG_VENDOR_YAHOO, HEAVYBAG_VENDOR_BAIDU, HEAVYBAG_VENDOR_YANDEX, HEAVYBAG_VENDOR_FACEBOOK,
    HEAVYBAG_VENDOR_DUCKDUCKGO, HEAVYBAG_VENDOR_PINTEREST, HEAVYBAG_VENDOR_ALEXA, HEAVYBAG_VENDOR_TWITTER,
    HEAVYBAG_VENDOR_HUAWEI, HEAVYBAG_VENDOR_NAVER,  /* additions */
    HEAVYBAG_VENDOR_MAX
} ngx_http_heavybag_ua_vendor_e;

/* Coarse TLS client family for JA4<->UA comparison. JA4 cannot split
 * Chromium variants, so chromium is one family. */
typedef enum {
    HEAVYBAG_TLSFAM_UNKNOWN = 0,
    HEAVYBAG_TLSFAM_CHROMIUM, HEAVYBAG_TLSFAM_FIREFOX, HEAVYBAG_TLSFAM_SAFARI,
    HEAVYBAG_TLSFAM_TOOL,   /* curl, go, python, java, okhttp, wget, ... */
    HEAVYBAG_TLSFAM_BOT,    /* fingerprints attributed to crawlers/automation */
    HEAVYBAG_TLSFAM_MAX
} ngx_http_heavybag_tls_family_e;
```

### ctx additions (in `ngx_http_heavybag_ctx_t`)
```c
    /* descriptive UA parse (lazy) */
    unsigned                    ua_parsed:1;
    ngx_http_heavybag_ua_browser_e   ua_browser;
    ngx_http_heavybag_ua_os_e        ua_os;
    ngx_http_heavybag_ua_category_e  ua_category;
    ngx_http_heavybag_ua_vendor_e    ua_vendor;
    ngx_str_t                   ua_version;     /* slice into r->headers_in.user_agent->value, NOT copied */
    /* spoof */
    unsigned                    spoof_evaluated:1;
    unsigned                    is_spoofed:1;
    ngx_str_t                   ja4;            /* copied from SSL ex-data at preaccess; len 0 = no TLS */
```

### Parser API (`heavybag_ua_parse.h`)
```c
#ifndef HEAVYBAG_UA_PARSE_H
#define HEAVYBAG_UA_PARSE_H
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_heavybag.h"

/* Fill ctx->ua_browser/ua_os/ua_category/ua_vendor/ua_version from the UA header.
 * Lazy: no-op if ctx->ua_parsed is already set. Requires ctx->classified
 * (calls ngx_http_heavybag_ua_classify if needed) so category can take over the
 * threat label. */
void ngx_http_heavybag_ua_parse(ngx_http_request_t *r,
    ngx_http_heavybag_loc_conf_t *wlcf, ngx_http_heavybag_ctx_t *ctx);

/* Evaluate ctx->is_spoofed (lazy via spoof_evaluated). Uses ctx->ja4 (TLS),
 * the parsed UA family, and verified-bot CIDR reinforcement. */
void ngx_http_heavybag_ua_spoof_eval(ngx_http_request_t *r,
    ngx_http_heavybag_loc_conf_t *wlcf, ngx_http_heavybag_ctx_t *ctx);

/* Static string-table accessors for the variable getters. */
ngx_str_t *ngx_http_heavybag_browser_str(ngx_http_heavybag_ua_browser_e b);
ngx_str_t *ngx_http_heavybag_category_str(ngx_http_heavybag_ua_category_e c);
ngx_str_t *ngx_http_heavybag_vendor_str(ngx_http_heavybag_ua_vendor_e v);

/* JA4 string -> coarse TLS family via the loaded ja4.list table. */
ngx_http_heavybag_tls_family_e ngx_http_heavybag_ja4_family(ngx_http_heavybag_loc_conf_t *wlcf,
    ngx_str_t *ja4);

/* Map a parsed UA browser to the coarse TLS family it SHOULD present. */
ngx_http_heavybag_tls_family_e ngx_http_heavybag_ua_expected_tls_family(
    ngx_http_heavybag_ua_browser_e b);
#endif
```

### Reference Implementation (existing getter pattern to copy — `$waf_type`, `src/ngx_http_heavybag_module.c:1983-2015`)
```c
static ngx_int_t
ngx_http_heavybag_type_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_str_t                *s;
    ngx_http_heavybag_ctx_t       *ctx;
    ngx_http_heavybag_loc_conf_t  *wlcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_heavybag_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_heavybag_ctx_t));
        if (ctx == NULL) { return NGX_ERROR; }
        ngx_http_set_ctx(r, ctx, ngx_http_heavybag_module);
    }
    if (!ctx->classified) {
        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_heavybag_module);
        ngx_http_heavybag_ua_classify(r, wlcf, ctx);
    }
    s = &heavybag_type_str[ctx->ua];
    v->len = s->len; v->data = s->data;
    v->valid = 1; v->no_cacheable = 1; v->not_found = 0;
    return NGX_OK;
}
```

### Integer-rendered-as-string pattern (existing `$waf_asn`, `src/ngx_http_heavybag_module.c:2162-2172`)
```c
    p = ngx_pnalloc(r->pool, NGX_INT32_LEN);
    if (p == NULL) { return NGX_ERROR; }
    v->len  = ngx_sprintf(p, "%uD", ctx->asn) - p;
    v->data = p;
    v->valid = 1; v->no_cacheable = 1; v->not_found = 0;
```

### not_found pattern (existing `$waf_country` absent case)
```c
    v->valid = 0; v->no_cacheable = 1; v->not_found = 1;
    return NGX_OK;
```

### JA4 read-back pattern (existing `$waf_ja4_hash` getter, `src/ngx_http_heavybag_module.c:2183-2211`)
```c
    ngx_ssl_conn_t *ssl_conn;
    ngx_str_t      *j;
    if (r->connection->ssl == NULL) { /* not_found */ }
    ssl_conn = r->connection->ssl->connection;
    j = SSL_get_ex_data(ssl_conn, ngx_http_heavybag_ja4_ssl_index);
    /* j == NULL -> not_found; else j->data / j->len is the 36-char hash */
```
> Note: `ngx_http_heavybag_ja4_ssl_index` is `static` in `ngx_http_heavybag_module.c:34`. The PREACCESS copy into `ctx->ja4` should be done in that file (where the index is visible), then `heavybag_ua_parse.c` reads `ctx->ja4`.

### UA list loader to mirror for the JA4 loader (`ngx_http_heavybag_ua_list_compile`, `src/heavybag_match.c:320-363`)
Reads the file via `ngx_http_heavybag_read_file`, iterates lines via `ngx_http_heavybag_next_line` (strips `#` comments / blanks / whitespace). For UA lists it compiles a PCRE2 alternation. **The JA4 loader differs**: each line is `"<ja4> <family>"`; parse into a key→value table (see Step 4).

### Build System Entry (append to `modules/ngx_http_heavybag/config`)
```sh
# heavybag_deps (after src/heavybag_ja4.h):
                 $ngx_addon_dir/src/heavybag_ua_parse.h"
# heavybag_srcs (after src/heavybag_ja4.c):
                 $ngx_addon_dir/src/heavybag_ua_parse.c"
```
> **Quote/continuation mechanics:** the current last entry of each list (`config:23` `...heavybag_ja4.h"` and `:34` `...heavybag_ja4.c"`) terminates with a closing `"`. To append, change that trailing `"` into ` \` (line continuation) and put the closing `"` on the new final line. Pasting the snippet literally without fixing the quote would break the shell variable.

## Phase 0 — Definition Research Results (curated for A1 + B2)

These are the curated additions from the 2026 research sweep. Match **case-insensitively**
(the existing lists compile with `NGX_REGEX_CASELESS`). Entries the lists already contain are
omitted. During implementation, re-check current membership of each list before appending to
avoid duplicates.

### `lists/ai-crawler.list` — ADD (high-signal subset)
```
ChatGPT\ Agent           # OpenAI agent (note literal space)
Claude-Web               # Anthropic legacy
Claude-SearchBot         # Anthropic
Claude-Code              # Anthropic coding agent
GoogleOther              # Google
GoogleOther-Image
GoogleOther-Video
Google-CloudVertexBot
meta-externalfetcher     # Meta
FacebookBot              # Meta (distinct from facebookexternalhit)
TikTokSpider             # ByteDance
bedrockbot               # Amazon
Perplexity-User          # Perplexity
ImagesiftBot
omgili
omgilibot
Webzio-Extended
Timpibot
DuckAssistBot            # DuckDuckGo
Bravebot                 # Brave SEARCH crawler (NOT the browser)
DeepSeekBot
MistralAI-User
PanguBot                 # Huawei
AI2Bot
FirecrawlAgent
ApifyBot
ExaBot
PhindBot
kagi-fetcher
```
(Existing: `GPTBot`, `OAI-SearchBot`, `ChatGPT-User`, `ClaudeBot`, `anthropic-ai`, `Claude-User`, `CCBot`, `Bytespider`, `Google-Extended`, `PerplexityBot`, `Amazonbot`, `meta-externalagent`, `Applebot-Extended`, `cohere-ai`, `Diffbot`, `YouBot`.)

### `lists/crawler.list` — ADD
```
Googlebot-Image
Googlebot-Video
Google-InspectionTool
SemanticScholarBot
```
(Existing: `Googlebot`, `bingbot`, `Slurp`, `Baiduspider`, `YandexBot`, `DuckDuckBot`, `Applebot`, `Sogou`, `PetalBot`, `SeznamBot`, `archive\.org_bot`, `heritrix`.)

### `lists/bot.list` — ADD
```
hey/                     # load tester (was Lua 'benchmark' category)
WhatsApp                 # Meta link preview
Pinterestbot
StatusCake
Site24x7
Chrome-Lighthouse
python-httpx
aiohttp
Python-urllib
GuzzleHttp
node-fetch
undici
reqwest
```
(Existing: `facebookexternalhit`, `Twitterbot`, `LinkedInBot`, `Slackbot`, `Discordbot`, `TelegramBot`, `redditbot`, `AhrefsBot`, `SemrushBot`, `MJ12bot`, `dotbot`, `UptimeRobot`, `Pingdom`, `Feedly`, `python-requests`, `Go-http-client`, `curl/`, `^Java/`, `okhttp`, `axios`, `Scrapy`, `libwww-perl`, `Wget`, `Apache-HttpClient`.)

### `lists/scanner-ua.list` — ADD
```
Censys
CensysInspect
Shodan
InternetMeasurement      # Driftnet
Expanse                  # Palo Alto
l9explore
l9tcpid
```
(Existing: `sqlmap`, `nikto`, `nmap`, `masscan`, `zgrab`, `nuclei`, `dirbuster`, `gobuster`, `wpscan`, `acunetix`, `nessus`, `netsparker`, `fimap`, `hydra`, `arachni`, `dirsearch`, `openvas`.)

### Parser browser/OS/vendor token additions (in `heavybag_ua_parse.c`)
| UA substring | browser enum | vendor | note |
|---|---|---|---|
| `Ddg/` or `DuckDuckGo/` | `HEAVYBAG_BROWSER_DUCKDUCKGO` | `HEAVYBAG_VENDOR_DUCKDUCKGO` | iOS/Android app token |
| `Whale/` | `HEAVYBAG_BROWSER_WHALE` | `HEAVYBAG_VENDOR_NAVER` | |
| `UCBrowser/` | `HEAVYBAG_BROWSER_UCBROWSER` | — | |
| `HuaweiBrowser/` | `HEAVYBAG_BROWSER_HUAWEIBROWSER` | `HEAVYBAG_VENDOR_HUAWEI` | |
| `OPRGX/` | `HEAVYBAG_BROWSER_OPERAGX` | `HEAVYBAG_VENDOR_OPERA` | appears alongside `OPR/` |
| `HeadlessChrome/` | `HEAVYBAG_BROWSER_HEADLESSCHROME` | `HEAVYBAG_VENDOR_GOOGLE` | automation signal; check BEFORE `Chrome/` |
| `python-requests/` `python-httpx` `aiohttp` | `HEAVYBAG_BROWSER_PYTHON` | — | |
| `Go-http-client/` | `HEAVYBAG_BROWSER_GOHTTP` | — | |
| `Java/` | `HEAVYBAG_BROWSER_JAVA` | — | |
| `okhttp/` | `HEAVYBAG_BROWSER_OKHTTP` | — | |
| `HarmonyOS` | (os) `HEAVYBAG_OS_HARMONYOS` | `HEAVYBAG_VENDOR_HUAWEI` | match BEFORE `Android` fallback |

> **Brave / Arc:** ship a Chrome-identical UA by design → classified as `chrome`. Add a code comment in `try_browser` so nobody adds a `Brave`/`Arc` matcher expecting hits.
> **iPadOS / visionOS:** report a Macintosh/Safari UA (desktop masquerade); will be classified as `macos`/`safari`. Documented known limitation; no UA-only fix.
> **Ordering caveat:** `HeadlessChrome/` must be tested before `Chrome/`; `YaBrowser/` (and `OPRGX/`/`OPR/`, `Edg/`, `SamsungBrowser/`, `Vivaldi/` — all carry `Chrome/`) must be tested before `Chrome/`; and `HarmonyOS` before the `Android` branch, to avoid the generic match winning first. **Do NOT mirror the dead Lua order at `user-agent.lua:121`** — there `Chrome/` (`:119`) wins before the `YaBrowser/` branch, so YaBrowser is never detected. The C port has a `HEAVYBAG_BROWSER_YABROWSER` enum and intends to detect it, so it must check the Chromium-derivative tokens before the bare `Chrome/`.

### ja4db normalization rule (B2 — for generating `lists/ja4.list`)
Offline one-time step (committed result, no build-time network):
1. Obtain the public ja4db dump (ja4db.com / FoxIO `ja4db`).
2. For each record, map its `application`/`library` to a coarse family:
   - Chrome, Chromium, Edge, Brave, Opera, Vivaldi, Samsung Internet, Yandex → `chromium`
   - Firefox, Tor Browser, Mozilla → `firefox`
   - Safari, WebKit (Apple) → `safari`
   - curl, libcurl, wget, Go, Go-http-client, Python, requests, urllib, aiohttp, Java, okhttp, OpenSSL s_client, Node, axios, reqwest → `tool`
   - Named crawlers/automation (Googlebot, bots, scanners) → `bot`
3. **Conflict resolution:** if a single JA4 maps to more than one family across records → emit `unknown` (so it can never trigger a false-positive spoof).
4. Output one line per fingerprint: `<ja4> <family>` into `lists/ja4.list`.

## Alternative Approaches Evaluated

### Option 1: Port to C as a substring chain (RECOMMENDED)
**Pros:** runs in the hot path with zero new runtime deps; substring-only (no PCRE2 needed for the descriptive parse) → fast and allocation-free; integrates with the existing ctx/variable/lists machinery; lets `is_spoofed` combine UA + JA4 + CIDR which a log-time tool cannot.
**Cons:** re-implements the Lua logic in C (mitigated: the fixed Lua stays as a behavioural oracle for tests).

### Option 2: Keep the parser in Lua, call it from nginx via lua-nginx-module
**Pros:** reuse the existing Lua verbatim.
**Cons:** the module does **not** link lua-nginx-module; adding it is a heavy new dependency for a hot-path classifier; cannot cleanly share the C-side JA4/CIDR state. **Rejected.**

### Option 3: Express the descriptive parse as PCRE2 buckets like the threat lists
**Pros:** reuses `ngx_http_heavybag_compile_bucket`.
**Cons:** the Lua is ordered substring matching with version extraction — regex is overkill, slower, and version slicing doesn't fit the boolean bucket model. **Rejected.**

### Recommended Approach: Option 1
A new `heavybag_ua_parse.c` implementing an ordered substring chain (1:1 with the fixed Lua priority order) using `ngx_strlcasestrn`/`ngx_strstrn`, plus a coarse JA4-family table loaded from `lists/ja4.list`, plus `is_spoofed` evaluation. Values are static-literal/sliced (no copy). `$waf_ua_category` reuses `ctx->ua`.

## Implementation Strategy

### Data Model / API Changes
- New enums + ctx fields (additive; `ngx_pcalloc` zero-init keeps "unknown" default).
- New `lists/ja4.list` + a `waf_ja4_list` directive to point at it (mirrors the `waf_*_ua_list` directive family).
- Five new nginx variables (additive; no change to existing variables/behaviour).

### Backwards Compatibility & Migration
- Purely additive. Existing `$waf_type`, fake-bot, reputation, JA4-hash behaviour untouched.
- If `lists/ja4.list` / `waf_ja4_list` is not configured, `$waf_ua_is_spoofed` falls back to the CIDR-only signal (TLS family lookup yields `unknown` → no JA4 trigger). No hard failure.
- New variables simply do not appear unless referenced — no config break for existing deployments.

### New Dependencies
None. No new libraries. ja4db data is committed, not fetched.

### Configuration Changes
- New directive `waf_ja4_list <path>;` (loc/srv level, same scope as the other list directives) to load `lists/ja4.list`.
- No new env vars, no feature flag (the feature is inert until a variable is referenced and/or the list is configured).

## Step-by-Step Implementation Plan

1. **Enums** — add the five enums (`ngx_http_heavybag_ua_browser_e`, `_os_e`, `_category_e`, `_vendor_e`, `ngx_http_heavybag_tls_family_e`) in `src/ngx_http_heavybag.h` after `ngx_http_heavybag_ua_e` (`:53`). `UNKNOWN=0` for all.

2. **ctx fields** — add the descriptive fields + `ua_parsed:1`, `spoof_evaluated:1`, `is_spoofed:1`, `ja4` to `ngx_http_heavybag_ctx_t` (`:137-155`). No alloc-site changes needed (flat struct).

3. **Parser file** — create `src/heavybag_ua_parse.{c,h}`:
   - `ngx_http_heavybag_ua_parse()`: read `r->headers_in.user_agent`; if empty → all UNKNOWN. Implement `try_os` → `try_browser(os)` → device-class, **1:1 with the fixed Lua order** (but respect the ordering caveats below), using **`ngx_strlcasestrn(s, last, token, n-1)` with an explicit `last = value.data + value.len`** for bounded scanning (note the nginx `n-1` convention: pass `sizeof("Token") - 2`, i.e. token length minus 1, NOT the raw length). **Note:** `ngx_strstrn` is NOT length-bounded (no `last` arg — it relies on `s1` being NUL-terminated); header values *are* NUL-terminated so it is safe in practice, but prefer `ngx_strlcasestrn` and never pass a non-header (non-NUL-terminated) buffer to `ngx_strstrn`, and never rely on it stopping at `value.len`. Extract version by locating the token and slicing **until the first byte not in the conservative version charset `[0-9A-Za-z._-]`** (in-place `ngx_str_t`, no copy), bounded by `value.data + value.len`. **This charset restriction is a security control, not cosmetic:** `ua_version` is the only one of the five variables that exposes raw attacker-controlled UA bytes (the other four are static enum-table strings), so terminating at the first non-version byte neutralizes control-char / CR / LF / `"` injection at the source, making all five variables safe-by-construction regardless of how a downstream config logs or reflects them. (Real version tokens are `[0-9A-Za-z._-]` only — e.g. `120.0.0.0`, `17.4.1` — so this loses no signal.) **`len` semantics:** on early termination set `ua_version.len` to the truncated length (distance from token-start to the first out-of-charset byte), NOT to the next space; a token consisting entirely of out-of-charset bytes yields `len 0` → the getter returns `not_found` (Step 7). Add an explicit test asserting the truncated `len`. Apply the 3 bug fixes. Add the 2026 tokens (table above; respect ordering caveats). Then set `ua_category`: if `ctx->ua` ∈ {SCANNER,AI_CRAWLER,CRAWLER,BOT} → corresponding `HEAVYBAG_CAT_*` threat label; else the device class. Set `ua_parsed=1`.
   - String tables `heavybag_browser_str[]`, `heavybag_category_str[]`, `heavybag_vendor_str[]` + accessors.

4. **JA4 list loader** — in `src/heavybag_match.c`, add `ngx_http_heavybag_ja4_list_compile()` mirroring `ngx_http_heavybag_ua_list_compile` for file reading (reuses the file-static `ngx_http_heavybag_read_file` `:41` / `ngx_http_heavybag_next_line` `:102` — which is why the loader MUST live in `heavybag_match.c`), but parse each line as `"<ja4> <family>"` into a config-pool table. Store in `wlcf` (new field, e.g. `ngx_hash_t ja4_hash` built via `ngx_hash_init`, or a sorted `ngx_array_t` + bsearch). Add `ngx_http_heavybag_ja4_family()` lookup. **Directive wiring (follow the existing `verified_bot_list[]` / `sig_list[]` pattern exactly):**
   - Add the `wlcf` table field **and** a path-sentinel field for dup-guard + merge-inherit (mirror `verified_bot_list[]` at `ngx_http_heavybag.h:96` and the dup-guard in `ngx_http_heavybag_set_ua_list` at `:1411`).
   - Add the `waf_ja4_list` `ngx_command_t` entry to the commands array.
   - Add the directive setter near `ngx_http_heavybag_set_ua_list` (`:1402`).
   - **Touch BOTH** `ngx_http_heavybag_create_loc_conf` (init the new field) **and** `ngx_http_heavybag_merge_loc_conf` (inherit-on-merge, mirroring how the other list buckets/CIDR lists are merged).

5. **Copy JA4 into ctx** — in the PREACCESS handler (`src/ngx_http_heavybag_module.c`, after the `ua_classify` call at `:974`), if `r->connection->ssl`, read `SSL_get_ex_data(ssl_conn, ngx_http_heavybag_ja4_ssl_index)` and set `ctx->ja4` (point at the existing ex-data `ngx_str_t`, no copy). This file sees the `static` index.
   - **MANDATORY: wrap the read block in `#if (NGX_HTTP_SSL)`.** The index (`:34`) and every existing use (getter `:2187`, cb `:2373`) are inside `#if (NGX_HTTP_SSL)`; an unguarded read breaks the no-SSL build. The `ngx_str_t ja4` ctx field itself stays unguarded (len 0 default = "no TLS").

6. **Spoof evaluation** — `ngx_http_heavybag_ua_spoof_eval()`:
   ```
   ja4_signal  = ctx->ja4.len > 0
                 && fam_ja4 = ja4_family(ctx->ja4) != UNKNOWN
                 && fam_ua  = expected_tls_family(ctx->ua_browser) != UNKNOWN
                 && fam_ja4 != fam_ua
   cidr_signal = UA claims a verified-bot vendor (ctx->ua ∈ {CRAWLER,AI_CRAWLER}
                 with a configured verified CIDR) && ngx_cidr_match(client_sa, cidr) != OK
   ctx->is_spoofed = ja4_signal || cidr_signal
   ```
   Reuse the exact CIDR check already in the fake-bot path (`:1010-1030`). **Compute the client addr with the same NULL-fallback as `:853`/`:1013`:** `sa = (ctx->client_sa != NULL) ? ctx->client_sa : r->connection->sockaddr` — do NOT pass `ctx->client_sa` raw to `ngx_cidr_match` (it is set in POST_READ `:447`, but a getter on a `waf off` path can run spoof eval before POST_READ, leaving it NULL → crash). Lazy via `spoof_evaluated`. **Plain HTTP:** `ctx->ja4.len==0` → only `cidr_signal`. **TLS:** both.

7. **Variable getters** — add 5 getters after the existing ones (`~:2211`), copying the `$waf_type` pattern for the four string vars (point `v->data` at the static table or at `ctx->ua_version`), and the `"0"/"1"` static-literal pattern for `is_spoofed`. `browser_version` → `not_found` when len 0.

8. **Register variables** — add 5 `ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE)` calls in `ngx_http_heavybag_preconfiguration` (`:1934-1975`), each wiring its getter.

9. **Fix `user-agent.lua`** (reference oracle): line 352 `_oss.pad` → `_oss.ipad`; remove the dead duplicate `YaBrowser/` branch (line 121); add `browser_version = "unknown"` to the nil/empty return table (`:419-427`) for output-shape consistency. (Done in implementation phase; not during planning.)

10. **Enrich lists** — append the curated tokens (Phase 0 tables) to `ai-crawler.list`, `crawler.list`, `bot.list`, `scanner-ua.list` (re-check membership first). Generate `lists/ja4.list` from the ja4db dump per the normalization rule (offline, committed).

11. **Build wiring** — add `heavybag_ua_parse.c`/`.h` to `config` `heavybag_srcs`/`heavybag_deps`. Re-run nginx `./configure`, `touch` OpenSSL `ssl.h`, then `cmake --build --target heavybag_module`.

12. **Tests** — add ctest.h unit tests in `modules/ngx_http_heavybag/tests/unit/test_heavybag_ua_parse.c` and register it with the existing ctest harness (alongside `test-ja4.c`). See Testing Strategy.

13. **(Optional) status counters** — `heavybag_status.c` already has `http_ua[HEAVYBAG_UA_MAX]`; optionally add per-category/per-browser counters + a `spoofed` counter. Deferred unless requested.

## Error Handling & Edge Cases

### Error Scenarios
- **Missing/empty UA** → all descriptive fields UNKNOWN; `category` from `ctx->ua` (which becomes `HEAVYBAG_UA_EMPTY` → expose as `unknown` device class; default `unknown`). `is_spoofed` via CIDR only.
- **JA4 list not configured / file unreadable at config time** → config-time error for the bad path (consistent with other list directives); at runtime a missing table → `ja4_family` returns UNKNOWN → no JA4 spoof trigger (graceful).
- **JA4 present but not in table** → UNKNOWN family → no spoof trigger (avoids false positives).
- **`ngx_pnalloc` failure in a getter** → `return NGX_ERROR` (matches existing getters).

### Edge Cases
- **Plain HTTP** (`r->connection->ssl == NULL`) → `ctx->ja4.len = 0`; spoof = CIDR-only.
- **Ambiguous JA4** (multiple families) → normalized to `unknown` at list-generation time.
- **Chromium UA reduction** → `browser_version` minor/patch frozen `0.0.0`; only major reliable. Documented, not an error.
- **iPad/visionOS desktop masquerade**, **Brave/Arc** → classified as macOS/Safari resp. Chrome; documented limitation.
- **Version token at end of UA (no trailing space)** → slice to end of string (bounded by `value.data + value.len`).
- **Control chars / CRLF / quotes in the UA** → the four enum-backed variables are static strings (immune); `ua_version` is charset-restricted to `[0-9A-Za-z._-]` at the source (Step 3), so it cannot carry injection bytes into a log/header sink.

### Validation
- UA is treated as opaque bytes; only read, never executed/interpolated by the module.
- JA4 string length/charset is already validated by the JA4 builder; the lookup only compares bytes.

## Testing Strategy

### Unit Tests (ctest.h — new `test_heavybag_ua_parse.c`)
- Browser detection: one case per browser token (incl. new 2026 tokens) → assert `ua_browser` + `ua_version`.
- OS detection: Windows/macOS/iOS/Android/Linux/consoles/HarmonyOS; assert HarmonyOS wins over Android.
- Device category: mobile/tablet/pc/tv/console; assert threat-class override (feed a UA that the threat bucket matches → `category` == scanner/ai-crawler/crawler/bot).
- Vendor: Apple/Google/MS/Mozilla/Yandex/Huawei/Naver + crawler-vendor attribution.
- **Bug-fix regressions:** iPad Safari → vendor `apple` (was broken); nil/empty UA return shape includes `browser_version`.
- JA4 family mapping: known chromium/firefox/safari/tool fingerprints → correct family; ambiguous → unknown; absent → unknown.
- **Spoof matrix:** {HTTP, TLS} × {UA family == JA4 family, UA family != JA4 family, JA4 unknown} × {verified-vendor + CIDR hit/miss} → assert `is_spoofed`.

### Integration Tests
- Load the enriched lists + `lists/ja4.list` in a test nginx config; assert no config-time compile error.
- `log_format` referencing all five variables; assert they render.

### Manual Testing
- [ ] `curl -A 'Mozilla/5.0 ... Chrome/120.0.0.0 ...'` over HTTPS → `$waf_ua_browser=chrome`, `$waf_ua_is_spoofed=1` (curl's JA4 is a tool fingerprint, contradicting the Chrome UA).
- [ ] Real Chrome over HTTPS → `$waf_ua_browser=chrome`, `$waf_ua_is_spoofed=0` (matching JA4).
- [ ] `curl -A 'Googlebot/2.1 ...'` from a non-Google IP → `$waf_ua_is_spoofed=1` (CIDR), HTTP and HTTPS.
- [ ] Empty UA → all `unknown`, no crash.

### Security Testing
- [ ] Oversized / binary / control-char UA → parser bounds-safe (no overread; `ngx_strlcasestrn` with explicit `last`; never rely on `ngx_strstrn` stopping at `value.len`).
- [ ] **Injection: UA with embedded CR/LF/quote/control chars in a version-position token** → `$waf_ua_browser_version` is truncated at the first non-`[0-9A-Za-z._-]` byte → no injection bytes reach a `log_format` / `add_header` sink. Verify with a `log_format` + `add_header` referencing all five variables.
- [ ] **CIDR-signal XFF trust**: forged `X-Forwarded-For` does not flip `is_spoofed` unless XFF is configured as trusted — confirm `cidr_signal` follows the same trust boundary as the existing fake-bot block.

### Edge Case Testing
- [ ] UA with version token at end (no trailing space).
- [ ] iPad Safari (Mac UA) → macos/safari, documented.

## Monitoring & Observability

### Logging
- No new module logging in the hot path (parser is silent). Config-time: log the count of loaded `ja4.list` entries at `info` (mirrors other list loaders).
- Consumers log `$waf_ua_*` via `log_format` as they wish.

### Metrics/Telemetry
- Optional (deferred): extend `heavybag_status.c` shared counters with per-category or per-browser tallies and a `spoofed` counter.

### Debugging
- Config-time `info` log: "heavybag: loaded N ja4 fingerprints".
- The five variables themselves are the runtime debug surface.

## Documentation Updates Required

### Code Documentation
- [ ] Doxygen-style headers for the new public functions in `heavybag_ua_parse.h` (`@param`/`@return`).
- [ ] Comment on Brave/Arc undetectability and the UA-reduction version caveat in `try_browser`.
- [ ] Comment on the ja4db normalization rule at the top of `lists/ja4.list`.

### External Documentation
- [ ] Module README/usage: document the five variables, the `waf_ja4_list` directive, and the known limitations (iPad/visionOS/Brave/Arc, Chromium version freeze).
- [ ] Note that the module is data-only and the consumer decides actions.
- [ ] **Operator guidance (explicit sentence):** do NOT gate authentication/access decisions on `$waf_ua_is_spoofed` on plain-HTTP or untrusted-`X-Forwarded-For` deployments — the `cidr_signal` half is only trustworthy behind a correctly-configured `set_real_ip_from`/trusted-proxy; the `ja4_signal` (HTTPS-only) is the unforgeable half. Treat the variable as advisory.

### New Documentation
- [ ] Short note on regenerating `lists/ja4.list` from a ja4db dump (offline procedure + normalization mapping).

## Dependencies & Sequencing
- Steps 1→2 first (types). Step 3 depends on 1-2. Step 4 (JA4 loader) is independent of 3 and can be parallel. Step 5 (ctx copy) depends on 2. Step 6 (spoof) depends on 3,4,5. Steps 7-8 (vars) depend on 3,6. Step 9 (Lua) independent. Step 10 (lists) independent (but Step 6 testing needs `ja4.list`). Step 11 (build) after 3-8 files exist. Step 12 (tests) last.

## Potential Challenges
- **ja4db size & noise** → mitigated by coarse-family normalization + ambiguous→unknown.
- **Maintaining UA token freshness** → curated A1 subset is committed; documented refresh procedure.
- **JA4 family granularity** → Chromium variants share one family by design; `expected_tls_family` maps all Chromium browsers to `chromium` to avoid false mismatches.
- **PREACCESS JA4 timing** → confirmed: ClientHello callback runs before phase handlers, so `ctx->ja4` is populated in time.
- **Static `ngx_http_heavybag_ja4_ssl_index`** → the ctx copy must live in `ngx_http_heavybag_module.c`; `heavybag_ua_parse.c` only reads `ctx->ja4`.

## Critical Files for Implementation
- `src/ngx_http_heavybag.h` — new enums + ctx fields.
- `src/heavybag_ua_parse.c` / `.h` — **new** parser + spoof eval + string tables + JA4-family/expected-family helpers.
- `src/heavybag_match.c` — new `ngx_http_heavybag_ja4_list_compile` (+ optional `ja4_family` lookup).
- `src/ngx_http_heavybag_module.c` — PREACCESS JA4-copy, 5 getters, 5 `add_variable`, `waf_ja4_list` directive + `wlcf` field + merge.
- `modules/ngx_http_heavybag/config` — `heavybag_srcs` + `heavybag_deps`.
- `modules/ngx_http_heavybag/lists/{ai-crawler,crawler,bot,scanner-ua}.list` — curated additions.
- `modules/ngx_http_heavybag/lists/ja4.list` — **new** generated seed.
- `user-agent.lua` — 3 bug fixes (reference oracle).

## Post-Implementation Checklist
- [ ] All outputs in English
- [ ] Plan/docs follow English standards
- [ ] All tests passing (unit, integration, manual)
- [ ] Error handling tested (empty UA, no TLS, missing list, ambiguous JA4)
- [ ] Config-time logging in place
- [ ] Config-time list loads verified (no PCRE2 / parse errors)
- [ ] Documentation updated (variables, directive, limitations, ja4.list refresh)
- [ ] Performance: parser allocation-free for descriptive fields; JA4 lookup O(1)/O(log n)
- [ ] Security review completed (read-only feature; consumer-escaping note)
- [ ] No regression in `$waf_type` / fake-bot / reputation / JA4-hash
- [ ] Build via `config` + `./configure` (+ `touch` openssl ssl.h) + `cmake --build --target heavybag_module`
