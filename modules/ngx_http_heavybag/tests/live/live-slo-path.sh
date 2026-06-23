#!/bin/bash
# heavybag Track-A SLO finder: vegeta constant-arrival rate sweep (open-loop, real p99) +
# mid-load CPU sampling over ssh. Finds max req/s where p99 <= TARGET_MS.
set -u
export PATH="$HOME/.local/bin:$PATH"

SSH_HOST="${SSH_HOST:-v}"
TARGET="${TARGET:-https://example.com/}"
UA="${UA:-Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Firefox/128.0}"
RATES="${RATES:-1000 2000 3000 4000 5000 6000 8000}"
DUR="${DUR:-15}"
SETTLE="${SETTLE:-3}"
SAMP="${SAMP:-8}"
TARGET_MS="${TARGET_MS:-25}"
LABEL="${LABEL:-enforce}"

echo "=== heavybag Track-A SLO  label=$LABEL  p99-target<=${TARGET_MS}ms  dur=${DUR}s  rates=[$RATES] ==="
ssh "$SSH_HOST" 'pkill -x mpstat 2>/dev/null; pkill -x pidstat 2>/dev/null; true'
printf "\n%-7s %-9s %-9s %-9s %-9s %-12s %-9s %-11s %-5s\n" \
  "rate" "actual" "p50" "p95" "p99" "codes" "all-cpu" "nginx-tot" "SLO"

best=0
for R in $RATES; do
  echo "GET $TARGET" | vegeta attack -rate="${R}/1s" -duration="${DUR}s" -header "User-Agent: $UA" -timeout=10s >"/tmp/vg_${R}.bin" 2>/dev/null &
  VPID=$!
  sleep "$SETTLE"
  mon=$(ssh "$SSH_HOST" "stdbuf -oL pidstat -C nginx 1 $SAMP >/tmp/hb_pid.log 2>&1 & pp=\$!; LC_ALL=C stdbuf -oL mpstat -P ALL 1 $SAMP; wait \$pp; echo '===PIDSTAT==='; cat /tmp/hb_pid.log")
  wait "$VPID"
  rep=$(vegeta report -type=text <"/tmp/vg_${R}.bin")

  actual=$(echo "$rep" | awk '/^Requests/{print $5}' | tr -d ',')
  codes=$(echo "$rep"  | awk -F'Status Codes  ' '/Status Codes/{print $2}' | tr -d '[:space:]')
  read p50 p95 p99 p99ms <<<"$(echo "$rep" | awk -F']' '
      function toms(x){ if(x ~ /µs/){sub(/µs/,"",x); return x/1000}
                        else if(x ~ /ms/){sub(/ms/,"",x); return x+0}
                        else if(x ~ /s/){sub(/s/,"",x); return x*1000}
                        return x+0 }
      /Latencies/{ n=split($2,a,","); for(i=1;i<=n;i++)gsub(/ /,"",a[i]);
        printf "%s %s %s %.1f", a[3], a[5], a[6], toms(a[6]) }')"

  mpart=$(echo "$mon" | sed -n '1,/===PIDSTAT===/p')
  ppart=$(echo "$mon" | sed -n '/===PIDSTAT===/,$p')
  allcpu=$(echo "$mpart" | awk '$2=="all"{b=100-$NF; s+=b; n++} END{if(n)printf "%.0f", s/n; else printf "?"}')
  ngx=$(echo "$ppart"    | awk '$NF ~ /nginx/{sum[$1]+=$(NF-2)} END{t=0;n=0;for(k in sum){t+=sum[k];n++} if(n)printf "%.0f", t/n; else printf "?"}')

  slo="ok"; awk "BEGIN{exit !($p99ms>$TARGET_MS)}" && slo="OVER"
  [ "$slo" = "ok" ] && best="$R"
  printf "%-7s %-9s %-9s %-9s %-9s %-12s %-9s %-11s %-5s\n" \
    "$R" "${actual:-?}" "$p50" "$p95" "$p99" "${codes:-?}" "${allcpu}%" "${ngx}%/600" "$slo"
done
echo
echo ">>> max sustained rate with p99 <= ${TARGET_MS}ms : ~${best} req/s  (label=$LABEL)"
echo "(codes: e.g. 404:NNNN = passed; 429:* would mean rate-limit still ON)"
