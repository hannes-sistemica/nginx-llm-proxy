#!/usr/bin/env bash
# Reload nginx on the deploy host only once in-flight /v1 requests drain to 0,
# so a graceful reload never overlaps active requests (which would let a
# request hit a draining old-code worker). Falls back to reloading anyway
# after RELOAD_WAIT seconds so a deploy can't hang on a busy proxy.
set -euo pipefail
HOST="${DEPLOY_HOST:?DEPLOY_HOST unset}"
PROXY="${PROXY_URL:?PROXY_URL unset}"
PW="${ADMIN_PASSWORD:?ADMIN_PASSWORD unset}"
MAX="${RELOAD_WAIT:-30}"
SSH="ssh -o ConnectTimeout=8"

inflight() {
  curl -s --max-time 4 "$PROXY/admin/api/health" -H "X-Admin-Password: $PW" \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const b=JSON.parse(s).backends||{};let t=0;for(const k in b)t+=(b[k].inflight||0);console.log(t)}catch(e){console.log("0")}})'
}

for i in $(seq 1 "$MAX"); do
  n=$(inflight)
  if [ "$n" = "0" ]; then
    echo "  in-flight=0 → reloading nginx"
    $SSH "$HOST" 'nginx -t && nginx -s reload'
    exit $?
  fi
  echo "  in-flight=$n, waiting for idle ($i/$MAX)…"
  sleep 1
done
echo "  WARN: still busy after ${MAX}s — reloading anyway (graceful drain still applies)"
$SSH "$HOST" 'nginx -t && nginx -s reload'
