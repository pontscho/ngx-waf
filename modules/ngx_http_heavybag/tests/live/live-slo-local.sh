#!/bin/bash
# Runs ON the prod box: vegeta against loopback (no path jitter) + local mpstat/pidstat.
# Separates nginx CPU from vegeta's own CPU (co-located load).
set -u
VEGETA=/tmp/vegeta
TARGET="https://127.0.0.1/"
HOSTH="${HOSTH:-example.com}"
UA="${UA:-Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Firefox/128.0}"
RATES="${RATES:-1000 2000 4000 6000 8000 10000}"
DUR="${DUR:-15}"; SETTLE="${SETTLE:-3}"; SAMP="${SAMP:-8}"; TARGET_MS="${TARGET_MS:-25}"
LABEL="${LABEL:-localhost}"

echo "=== heavybag SLO LOCALHOST  label=$LABEL  loopback  p99<=${TARGET_MS}ms  dur=${DUR}s  rates=[$RATES] ==="
pkill -x mpstat 2>/dev/null; pkill -x pidstat 2>/dev/null
printf "\n%-7s %-9s %-9s %-9s %-12s %-9s %-11s %-11s %-5s\n" \
  "rate" "p50" "p95" "p99" "codes" "all-cpu" "nginx-cpu" "vegeta-cpu" "SLO"

best=0
for R in $RATES; do
  echo "GET $TARGET" | $VEGETA attack -insecure -rate="${R}/1s" -duration="${DUR}s" \
      -header "Host: $HOSTH" -header "User-Agent: $UA" -timeout=10s >"/tmp/vl_${R}.bin" 2>/dev/null &
  VPID=$!
  sleep "$SETTLE"
  LC_ALL=C stdbuf -oL mpstat -P ALL 1 "$SAMP" >/tmp/lmp.log 2>&1 &
  LC_ALL=C stdbuf -oL pidstat 1 "$SAMP" >/tmp/lpid.log 2>&1 &
  wait "$VPID"
  sleep 1
  pkill -x mpstat 2>/dev/null; pkill -x pidstat 2>/dev/null

  rep=$(LC_ALL=C $VEGETA report -type=text <"/tmp/vl_${R}.bin")
  codes=$(echo "$rep" | awk -F'Status Codes  ' '/Status Codes/{print $2}' | tr -d '[:space:]')
  read p50 p95 p99 p99ms <<<"$(echo "$rep" | awk -F']' '
      function toms(x){ if(x ~ /µs/){sub(/µs/,"",x); return x/1000}
                        else if(x ~ /ms/){sub(/ms/,"",x); return x+0}
                        else if(x ~ /s/){sub(/s/,"",x); return x*1000}
                        return x+0 }
      /Latencies/{ n=split($2,a,","); for(i=1;i<=n;i++)gsub(/ /,"",a[i]);
        printf "%s %s %s %.1f", a[3], a[5], a[6], toms(a[6]) }')"

  allcpu=$(awk '$2=="all"{b=100-$NF; s+=b; n++} END{if(n)printf "%.0f", s/n; else printf "?"}' /tmp/lmp.log)
  ngx=$(awk '$NF=="nginx"{sum[$1]+=$(NF-2)} END{t=0;n=0;for(k in sum){t+=sum[k];n++} if(n)printf "%.0f", t/n; else printf "0"}' /tmp/lpid.log)
  veg=$(awk '$NF=="vegeta"{sum[$1]+=$(NF-2)} END{t=0;n=0;for(k in sum){t+=sum[k];n++} if(n)printf "%.0f", t/n; else printf "0"}' /tmp/lpid.log)

  slo="ok"; awk "BEGIN{exit !($p99ms>$TARGET_MS)}" && slo="OVER"
  [ "$slo" = "ok" ] && best="$R"
  printf "%-7s %-9s %-9s %-9s %-12s %-9s %-11s %-11s %-5s\n" \
    "$R" "$p50" "$p95" "$p99" "${codes:-?}" "${allcpu}%" "${ngx}%/600" "${veg}%/600" "$slo"
done
echo
echo ">>> max loopback rate with p99 <= ${TARGET_MS}ms : ~${best} req/s  (label=$LABEL)"
