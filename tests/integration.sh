#!/usr/bin/env bash
# Integration tests against a real nginx.
#
# Runs unprivileged against a private nginx prefix, so it works both on a
# developer box and inside the Docker image (tests/Dockerfile).
#
#   ./tests/integration.sh
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/nginx-ratelimit"
PORT="${NRL_TEST_PORT:-18080}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/nrl-integration.XXXXXX")"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ $# -gt 1 ] && printf '       %s\n' "$2"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
    if [ -f "$WORK/nginx.pid" ]; then kill -QUIT "$(cat "$WORK/nginx.pid")" 2>/dev/null; fi
    sleep 0.3
    rm -rf "$WORK"
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# A private nginx: own prefix, own logs, unprivileged port.
# --------------------------------------------------------------------------
mkdir -p "$WORK/conf.d" "$WORK/logs" "$WORK/html" "$WORK/state"
echo "ok" > "$WORK/html/index.html"

cat > "$WORK/nginx.conf" <<EOF
daemon on;
pid $WORK/nginx.pid;
error_log $WORK/logs/error.log warn;
events { worker_connections 256; }
http {
    log_format plain '\$remote_addr \$status';
    access_log $WORK/logs/access.log plain;
    client_body_temp_path $WORK/logs/cbt;
    proxy_temp_path $WORK/logs/pt;
    fastcgi_temp_path $WORK/logs/ft;
    uwsgi_temp_path $WORK/logs/ut;
    scgi_temp_path $WORK/logs/st;
    include $WORK/conf.d/*.conf;
    server {
        listen 127.0.0.1:$PORT;
        root $WORK/html;
        # NOTE: a real content handler, deliberately. \`return 200\` is handled
        # in the rewrite phase, which runs *before* the preaccess phase where
        # limit_req lives -- a location that returns early is never limited,
        # and a test built on one silently passes no matter what.
        location / { index index.html; }
    }
}
EOF

export NGINX_RATELIMIT_CONF="$WORK/conf.d/nginx-ratelimit.conf"
export NGINX_RATELIMIT_STATE_DIR="$WORK/state"
export NGINX_RATELIMIT_NGINX_ARGS="-c $WORK/nginx.conf -p $WORK -e $WORK/logs/error.log"
export NGINX_RATELIMIT_SKIP_ROOT_CHECK=1
export NGINX_RATELIMIT_ACCESS_LOG="$WORK/logs/access.log"
export NGINX_RATELIMIT_ERROR_LOG="$WORK/logs/error.log"

nrl() { "$TOOL" --reload-interval 0 "$@"; }

nginx -c "$WORK/nginx.conf" -p "$WORK" -e "$WORK/logs/error.log" || {
    echo "could not start test nginx"; exit 1; }
sleep 0.5

# Fire N requests over one keepalive connection and tally status codes.
burst() {
    local n="$1" urls=""
    for _ in $(seq "$n"); do urls="$urls http://127.0.0.1:$PORT/"; done
    : > "$WORK/logs/access.log"
    curl -s -o /dev/null --max-time 60 $urls >/dev/null 2>&1
    sleep 0.2
}
# The shared zone deliberately survives reloads, so excess accumulated by one
# burst carries into the next level. Drain it before measuring: at the
# strictest rate under test (3r/s) clearing ~40 excess needs well over 10s.
DRAIN="${NRL_TEST_DRAIN:-15}"
drain() { sleep "$DRAIN"; }

count_status() { grep -c " $1\$" "$WORK/logs/access.log" 2>/dev/null | head -1; }

# --------------------------------------------------------------------------
head_ "1. Every level generates a config that passes nginx -t"
# --------------------------------------------------------------------------
for level in off relaxed normal strict lockdown; do
    if out=$(nrl set "$level" 2>&1); then
        if nginx -t -c "$WORK/nginx.conf" -p "$WORK" -e "$WORK/logs/error.log" >/dev/null 2>&1; then
            ok "set $level -> nginx -t passes"
        else
            bad "set $level -> nginx -t fails"
        fi
    else
        bad "set $level exited $?" "$out"
    fi
done

# --------------------------------------------------------------------------
head_ "2. Idempotency: no duplicate limit_req_zone, second set is a no-op"
# --------------------------------------------------------------------------
nrl set normal >/dev/null 2>&1
zones=$(grep -c '^limit_req_zone' "$NGINX_RATELIMIT_CONF")
[ "$zones" -eq 1 ] && ok "exactly one limit_req_zone" || bad "found $zones limit_req_zone lines"

before=$(nrl --json status | python3 -c 'import sys,json; print(json.load(sys.stdin)["reload_count"])')
out=$(nrl --json set normal); rc=$?
changed=$(echo "$out" | python3 -c 'import sys,json; print(json.load(sys.stdin)["changed"])')
after=$(nrl --json status | python3 -c 'import sys,json; print(json.load(sys.stdin)["reload_count"])')
[ "$rc" -eq 0 ] && ok "repeat set exits 0" || bad "repeat set exited $rc"
[ "$changed" = "False" ] && ok "repeat set reports changed=false" || bad "repeat set reported changed=$changed"
[ "$before" = "$after" ] && ok "repeat set did not reload (count stayed $after)" \
    || bad "reload count moved $before -> $after"

zones=$(grep -c '^limit_req_zone' "$NGINX_RATELIMIT_CONF")
[ "$zones" -eq 1 ] && ok "still exactly one limit_req_zone after repeat" || bad "found $zones"

# --------------------------------------------------------------------------
head_ "3. The zone name, size and key never change across levels"
# --------------------------------------------------------------------------
decls=""
for level in off relaxed normal strict lockdown; do
    nrl set "$level" >/dev/null 2>&1
    decls="$decls$(grep '^limit_req_zone' "$NGINX_RATELIMIT_CONF" | sed 's/ rate=.*//')\n"
done
uniq_count=$(printf "$decls" | sort -u | grep -c .)
[ "$uniq_count" -eq 1 ] \
    && ok "zone declaration identical across all 5 levels" \
    || bad "zone declaration varied ($uniq_count distinct forms)"

# --------------------------------------------------------------------------
head_ "4. A config nginx rejects triggers rollback and leaves the original"
# --------------------------------------------------------------------------
nrl set normal >/dev/null 2>&1
original=$(cat "$NGINX_RATELIMIT_CONF")

# A stub nginx that rejects only the candidate (any config containing the
# strict level's rate) and accepts everything else -- so the restore verifies
# clean, exactly as it would with a genuinely bad template.
cat > "$WORK/fake-nginx" <<FAKE
#!/usr/bin/env bash
for a in "\$@"; do [ "\$a" = "-t" ] && mode=t; [ "\$a" = "reload" ] && mode=reload; done
if [ "\${mode:-}" = "t" ]; then
    if grep -q 'rate=3r/s' "$NGINX_RATELIMIT_CONF" 2>/dev/null; then
        echo "nginx: [emerg] simulated rejection of the candidate config" >&2
        echo "nginx: configuration file test failed" >&2
        exit 1
    fi
    echo "nginx: configuration file test is successful"; exit 0
fi
[ "\${mode:-}" = "reload" ] && { echo "UNEXPECTED RELOAD" >&2; exit 0; }
exit 0
FAKE
chmod +x "$WORK/fake-nginx"

reloads_before=$(nrl --json status | python3 -c 'import sys,json; print(json.load(sys.stdin)["reload_count"])')
out=$(NGINX_RATELIMIT_NGINX_BIN="$WORK/fake-nginx" NGINX_RATELIMIT_NGINX_ARGS="" \
      "$TOOL" --reload-interval 0 set strict 2>&1); rc=$?
[ "$rc" -eq 2 ] && ok "rejected config exits 2" || bad "expected exit 2, got $rc" "$out"
[ "$(cat "$NGINX_RATELIMIT_CONF")" = "$original" ] \
    && ok "original config restored byte-for-byte" \
    || bad "config was not restored"
echo "$out" | grep -qi 'rolled back' && ok "reports the rollback" || bad "no rollback message" "$out"
echo "$out" | grep -q 'UNEXPECTED RELOAD' && bad "a failed nginx -t reached the reload" \
    || ok "failed nginx -t never reached a reload"
reloads_after=$(nrl --json status | python3 -c 'import sys,json; print(json.load(sys.stdin)["reload_count"])')
[ "$reloads_before" = "$reloads_after" ] && ok "reload count unchanged after rollback" \
    || bad "reload count moved $reloads_before -> $reloads_after"
backups=$(ls "$WORK/state/backups"/*.conf 2>/dev/null | wc -l)
[ "$backups" -gt 0 ] && ok "a backup was taken ($backups on disk)" || bad "no backups found"

# --------------------------------------------------------------------------
head_ "5. The minimum reload interval is respected"
# --------------------------------------------------------------------------
# The invariant is the gap between consecutive *reloads*, not the wall time of
# one command -- timing the command from the shell also counts the gap since
# the previous run finished, which is not part of the interval.
reload_epoch() {
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["last_reload_epoch"])' \
        "$WORK/state/state.json"
}
nrl set normal >/dev/null 2>&1
t0=$(reload_epoch)
"$TOOL" --reload-interval 3 set strict >/dev/null 2>&1
t1=$(reload_epoch)
gap=$(echo "$t1 - $t0" | bc)
awk -v g="$gap" 'BEGIN{exit !(g >= 3.0)}' \
    && ok "consecutive reloads were ${gap}s apart (>= 3s)" \
    || bad "reloads only ${gap}s apart, interval was 3s"

nrl set normal >/dev/null 2>&1
t0=$(reload_epoch)
"$TOOL" --reload-interval 3 --force set strict >/dev/null 2>&1
t1=$(reload_epoch)
gap=$(echo "$t1 - $t0" | bc)
awk -v g="$gap" 'BEGIN{exit !(g < 2.0)}' \
    && ok "--force bypasses the interval (${gap}s apart)" \
    || bad "--force still waited ${gap}s"

# --------------------------------------------------------------------------
head_ "6. --dry-run changes nothing"
# --------------------------------------------------------------------------
nrl set normal >/dev/null 2>&1
before_hash=$(sha256sum "$NGINX_RATELIMIT_CONF" | cut -d' ' -f1)
before_reloads=$(nrl --json status | python3 -c 'import sys,json; print(json.load(sys.stdin)["reload_count"])')
out=$(nrl --dry-run set lockdown 2>&1); rc=$?
after_hash=$(sha256sum "$NGINX_RATELIMIT_CONF" | cut -d' ' -f1)
after_reloads=$(nrl --json status | python3 -c 'import sys,json; print(json.load(sys.stdin)["reload_count"])')
[ "$rc" -eq 0 ] && ok "dry-run exits 0" || bad "dry-run exited $rc" "$out"
[ "$before_hash" = "$after_hash" ] && ok "dry-run left the config untouched" || bad "dry-run modified the config"
[ "$before_reloads" = "$after_reloads" ] && ok "dry-run did not reload" || bad "dry-run reloaded"
echo "$out" | grep -q '^+limit_req zone=perip burst=2;' && ok "dry-run prints the diff" \
    || bad "dry-run diff missing the expected line" "$out"

# --------------------------------------------------------------------------
head_ "7. State recovery: level survives a deleted state.json"
# --------------------------------------------------------------------------
nrl set strict >/dev/null 2>&1
rm -f "$WORK/state/state.json"
recovered=$(nrl --json status | python3 -c 'import sys,json; print(json.load(sys.stdin)["level"])')
[ "$recovered" = "strict" ] && ok "level recovered from the config comment" \
    || bad "recovered '$recovered', expected 'strict'"
echo "{ corrupt" > "$WORK/state/state.json"
recovered=$(nrl --json status | python3 -c 'import sys,json; print(json.load(sys.stdin)["level"])')
[ "$recovered" = "strict" ] && ok "level recovered from corrupt state.json" \
    || bad "recovered '$recovered', expected 'strict'"

# --------------------------------------------------------------------------
head_ "8. up / down stepping"
# --------------------------------------------------------------------------
nrl set relaxed >/dev/null 2>&1
nrl down >/dev/null 2>&1
[ "$(nrl --json status | python3 -c 'import sys,json; print(json.load(sys.stdin)["level"])')" = "off" ] \
    && ok "down from relaxed lands on off" || bad "down from relaxed did not reach off"
nrl up >/dev/null 2>&1
[ "$(nrl --json status | python3 -c 'import sys,json; print(json.load(sys.stdin)["level"])')" = "relaxed" ] \
    && ok "up from off lands on relaxed" || bad "up from off did not reach relaxed"
nrl set lockdown >/dev/null 2>&1
nrl up >/dev/null 2>&1
[ "$(nrl --json status | python3 -c 'import sys,json; print(json.load(sys.stdin)["level"])')" = "lockdown" ] \
    && ok "up from lockdown stays at lockdown" || bad "up past lockdown moved"

# --------------------------------------------------------------------------
head_ "9. Behavioural: the 429 share rises as the level rises"
# --------------------------------------------------------------------------
declare -A rejected
for level in off relaxed normal strict; do
    nrl --force set "$level" >/dev/null 2>&1
    drain
    burst 40
    rejected[$level]=$(count_status 429)
    printf '  %-9s 200=%-3s 429=%s\n' "$level" "$(count_status 200)" "${rejected[$level]}"
done
[ "${rejected[off]}" -eq 0 ] && ok "off rejects nothing" || bad "off rejected ${rejected[off]}"
[ "${rejected[strict]}" -gt "${rejected[normal]}" ] \
    && ok "strict rejects more than normal" \
    || bad "strict=${rejected[strict]} not > normal=${rejected[normal]}"
[ "${rejected[normal]}" -gt "${rejected[relaxed]}" ] \
    && ok "normal rejects more than relaxed" \
    || bad "normal=${rejected[normal]} not > relaxed=${rejected[relaxed]}"

# --------------------------------------------------------------------------
head_ "10. lockdown queues rather than rejects"
# --------------------------------------------------------------------------
nrl --force set lockdown >/dev/null 2>&1
drain
start=$(date +%s.%N)
burst 6
elapsed=$(echo "$(date +%s.%N) - $start" | bc)
awk -v e="$elapsed" 'BEGIN{exit !(e >= 3.0)}' \
    && ok "6 requests at 1r/s took ${elapsed}s (throttled, not rejected)" \
    || bad "expected throttling; 6 requests took only ${elapsed}s"
[ "$(count_status 429)" -eq 0 ] && ok "lockdown returned no 429s" \
    || bad "lockdown returned $(count_status 429) 429s"

# --------------------------------------------------------------------------
head_ "11. Whitelisted clients are exempt"
# --------------------------------------------------------------------------
nrl --force set strict >/dev/null 2>&1
drain
burst 40
before=$(count_status 429)
[ "$before" -gt 0 ] && ok "strict limits 127.0.0.1 before the allow ($before 429s)" \
    || bad "expected 429s before the allow"
nrl --force allow 127.0.0.1 >/dev/null 2>&1
drain
burst 40
[ "$(count_status 429)" -eq 0 ] && ok "whitelisted 127.0.0.1 is exempt" \
    || bad "whitelisted client still got $(count_status 429) 429s"
grep -q '127.0.0.1/32 1;' "$NGINX_RATELIMIT_CONF" && ok "whitelist entry is in the geo block" \
    || bad "whitelist entry missing from the config"
nrl --force deny 127.0.0.1 >/dev/null 2>&1
grep -q '127.0.0.1/32 1;' "$NGINX_RATELIMIT_CONF" \
    && bad "deny did not remove the entry" || ok "deny removed the entry"

# --------------------------------------------------------------------------
head_ "12. off keeps the zone declared but stops enforcing"
# --------------------------------------------------------------------------
nrl --force set off >/dev/null 2>&1
grep -q '^limit_req_zone' "$NGINX_RATELIMIT_CONF" && ok "off keeps limit_req_zone" \
    || bad "off dropped the zone declaration"
grep -q '^limit_req zone=' "$NGINX_RATELIMIT_CONF" \
    && bad "off still emits limit_req" || ok "off omits limit_req"
: > "$WORK/logs/error.log"
nginx -c "$WORK/nginx.conf" -p "$WORK" -e "$WORK/logs/error.log" -s reload 2>/dev/null
sleep 0.6
grep -qi 'warn.*perip\|unused' "$WORK/logs/error.log" \
    && bad "nginx warned about the declared-but-unused zone" \
    || ok "no warning for the declared-but-unused zone"

# --------------------------------------------------------------------------
head_ "13. check runs and reports"
# --------------------------------------------------------------------------
out=$(nrl --json check 2>&1); rc=$?
echo "$out" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert "findings" in d' 2>/dev/null \
    && ok "check emits valid JSON with findings" || bad "check JSON malformed" "$out"
echo "$out" | grep -q '"check": "module"' && ok "check reports on the limit_req module" \
    || bad "no module finding"

# --------------------------------------------------------------------------
head_ "14. A missing conf.d include is refused, and setup repairs it"
# --------------------------------------------------------------------------
# Second nginx instance, identical except that nothing includes conf.d. Without
# a guard the tool writes the file, passes nginx -t, reloads, and reports the
# new level -- while nothing at all is limited.
NOINC="$WORK/noinc"
mkdir -p "$NOINC/conf.d" "$NOINC/logs" "$NOINC/html"
echo ok > "$NOINC/html/index.html"
cat > "$NOINC/nginx.conf" <<EOF
daemon on;
pid $NOINC/nginx.pid;
error_log $NOINC/logs/error.log warn;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $NOINC/logs/cbt;
    proxy_temp_path $NOINC/logs/pt;
    fastcgi_temp_path $NOINC/logs/ft;
    uwsgi_temp_path $NOINC/logs/ut;
    scgi_temp_path $NOINC/logs/st;
    server {
        listen 127.0.0.1:$((PORT + 1));
        root $NOINC/html;
        location / { index index.html; }
    }
}
EOF
if nginx -c "$NOINC/nginx.conf" -p "$NOINC" -e "$NOINC/logs/error.log" 2>/dev/null; then
    sleep 0.5
    out=$(NGINX_RATELIMIT_CONF="$NOINC/conf.d/nginx-ratelimit.conf" \
          NGINX_RATELIMIT_STATE_DIR="$NOINC/state" \
          NGINX_RATELIMIT_NGINX_ARGS="-c $NOINC/nginx.conf -p $NOINC -e $NOINC/logs/error.log" \
          "$TOOL" --reload-interval 0 set strict 2>&1); rc=$?
    [ "$rc" -eq 4 ] && ok "refuses with exit 4" || bad "expected exit 4, got $rc" "$out"
    echo "$out" | grep -q 'would limit nothing' && ok "explains that nothing would be limited" \
        || bad "message does not explain the consequence" "$out"
    echo "$out" | grep -q 'include' && ok "names the fix" || bad "message does not name the fix"
    [ ! -f "$NOINC/conf.d/nginx-ratelimit.conf" ] \
        && ok "left no config behind" || bad "wrote a config that nginx cannot read"

    # --- setup repairs it -------------------------------------------------
    export NGINX_RATELIMIT_CONF="$NOINC/conf.d/nginx-ratelimit.conf"
    export NGINX_RATELIMIT_STATE_DIR="$NOINC/state"
    export NGINX_RATELIMIT_NGINX_ARGS="-c $NOINC/nginx.conf -p $NOINC -e $NOINC/logs/error.log"

    conf_before=$(sha256sum "$NOINC/nginx.conf" | cut -d' ' -f1)
    "$TOOL" --dry-run setup >/dev/null 2>&1
    [ "$(sha256sum "$NOINC/nginx.conf" | cut -d' ' -f1)" = "$conf_before" ] \
        && ok "setup --dry-run leaves nginx.conf untouched" \
        || bad "setup --dry-run modified nginx.conf"

    out=$("$TOOL" setup 2>&1); rc=$?
    [ "$rc" -eq 0 ] && ok "setup exits 0" || bad "setup exited $rc" "$out"
    [ "$(grep -c 'conf.d/\*.conf;' "$NOINC/nginx.conf")" -eq 1 ] \
        && ok "setup added exactly one include" \
        || bad "expected one include, found $(grep -c 'conf.d/\*.conf;' "$NOINC/nginx.conf")"
    nginx -t -c "$NOINC/nginx.conf" -p "$NOINC" -e "$NOINC/logs/error.log" >/dev/null 2>&1 \
        && ok "nginx.conf still passes nginx -t" || bad "setup broke nginx.conf"
    ls "$NOINC/state/backups"/nginx.conf.* >/dev/null 2>&1 \
        && ok "setup backed up nginx.conf" || bad "no nginx.conf backup"

    out=$("$TOOL" setup 2>&1)
    echo "$out" | grep -q 'already included' && ok "setup is idempotent" \
        || bad "second setup did not detect the existing include" "$out"
    [ "$(grep -c 'conf.d/\*.conf;' "$NOINC/nginx.conf")" -eq 1 ] \
        && ok "second setup added no duplicate" || bad "duplicate include added"

    # --- and the level now actually applies -------------------------------
    "$TOOL" --reload-interval 0 set strict >/dev/null 2>&1
    rc=$?
    [ "$rc" -eq 0 ] && ok "set strict now succeeds" || bad "set strict exited $rc"
    # A reload is graceful: it returns once the signal is sent, and the old
    # workers keep serving until they drain. Give the new ones a moment.
    sleep 1.5
    urls=""; for _ in $(seq 40); do urls="$urls http://127.0.0.1:$((PORT + 1))/"; done
    # -o applies to the first URL only, so the remaining bodies would land on
    # stdout and pollute the tally; keep just the status lines.
    codes=$(curl -s -w '%{http_code}\n' --max-time 30 $urls 2>/dev/null \
            | grep -Ex '[0-9]{3}' | sort | uniq -c)
    n429=$(echo "$codes" | awk '$2 == 429 {print $1}'); n429=${n429:-0}
    [ "$n429" -gt 0 ] && ok "limiting is live after setup ($n429 of 40 rejected)" \
        || bad "still no limiting after setup" "$codes"

    [ -f "$NOINC/nginx.pid" ] && kill -QUIT "$(cat "$NOINC/nginx.pid")" 2>/dev/null
    export NGINX_RATELIMIT_CONF="$WORK/conf.d/nginx-ratelimit.conf"
    export NGINX_RATELIMIT_STATE_DIR="$WORK/state"
    export NGINX_RATELIMIT_NGINX_ARGS="-c $WORK/nginx.conf -p $WORK -e $WORK/logs/error.log"
else
    bad "could not start the no-include nginx instance"
fi

# --------------------------------------------------------------------------
printf '\n\033[1mSummary:\033[0m %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
