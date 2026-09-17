#!/bin/sh
# Wazuh active response: raise and clear nginx rate limiting.
#
# Install on the agent that runs nginx:
#   install -o root -g wazuh -m 750 nginx-ratelimit-ar.sh \
#       /var/ossec/active-response/bin/nginx-ratelimit-ar.sh
#
# ossec.conf (manager):
#   <command>
#     <name>nginx-ratelimit</name>
#     <executable>nginx-ratelimit-ar.sh</executable>
#     <timeout_allowed>yes</timeout_allowed>
#   </command>
#
#   <active-response>
#     <command>nginx-ratelimit</command>
#     <location>local</location>
#     <rules_id>31151,31153</rules_id>
#     <timeout>600</timeout>
#   </active-response>
#
# `add` raises the level, `delete` clears it. With <timeout_allowed>yes</timeout_allowed>
# Wazuh calls `delete` itself once <timeout> expires.
#
# Configuration, via /etc/default/nginx-ratelimit-ar or the environment:
#   AR_LEVEL          level to set on `add`     (default: strict)
#   AR_RESTORE_LEVEL  level to set on `delete`  (default: off)
#   AR_LOCK_WAIT      seconds to wait on a concurrent run (default: 30)
#   NGINX_RATELIMIT_BIN, AR_LOG, AR_LOCK
#
# IMPORTANT: if the site normally runs with limiting on, set
# AR_RESTORE_LEVEL=normal. The default of `off` leaves no limiting in place
# after the timeout, which is correct only if `off` is your steady state.
#
# POSIX sh: Wazuh agents are not guaranteed to have bash.

set -u

[ -r /etc/default/nginx-ratelimit-ar ] && . /etc/default/nginx-ratelimit-ar

AR_LEVEL="${AR_LEVEL:-strict}"
AR_RESTORE_LEVEL="${AR_RESTORE_LEVEL:-off}"
AR_LOG="${AR_LOG:-/var/ossec/logs/active-responses.log}"
AR_LOCK="${AR_LOCK:-/var/run/nginx-ratelimit-ar.lock}"
# How long to wait for a concurrent invocation to finish before giving up.
# Keep it well under the manager's active-response timeout.
AR_LOCK_WAIT="${AR_LOCK_WAIT:-30}"
NGINX_RATELIMIT_BIN="${NGINX_RATELIMIT_BIN:-/usr/local/sbin/nginx-ratelimit}"

PROG="nginx-ratelimit-ar"

log() {
    # Wazuh tails this file; one line per event, timestamped like its own scripts.
    printf '%s %s: %s\n' "$(date '+%Y/%m/%d %H:%M:%S')" "$PROG" "$*" >> "$AR_LOG" 2>/dev/null
}

die() {
    log "ERROR $*"
    exit 1
}

# --------------------------------------------------------------------------
# Work out what we were asked to do.
#
# Wazuh 4.x sends a JSON object on stdin. Older agents (and a manual test) pass
# positional arguments, $1 being add|delete. Support both.
# --------------------------------------------------------------------------
COMMAND=""
EXTRA=""
SRCIP=""
RULE=""

if [ $# -gt 0 ] && { [ "$1" = "add" ] || [ "$1" = "delete" ]; }; then
    COMMAND="$1"
    SRCIP="${3:-}"
    RULE="${5:-}"
else
    # Read stdin if there is any. The timeout keeps a manual invocation with no
    # input from hanging forever.
    INPUT=""
    if [ ! -t 0 ]; then
        INPUT=$(timeout 5 cat 2>/dev/null || true)
    fi

    if [ -n "$INPUT" ]; then
        # python3 is already a hard dependency of nginx-ratelimit, so parsing
        # the JSON properly costs nothing and beats grepping for quotes.
        PARSED=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
p = d.get("parameters") or {}
a = (p.get("alert") or {})
extra = p.get("extra_args") or []
if not isinstance(extra, list):
    extra = []
print(d.get("command", ""))
print(" ".join(str(x) for x in extra))
print((a.get("data") or {}).get("srcip", ""))
print((a.get("rule") or {}).get("id", ""))
' 2>/dev/null) || die "could not parse the active-response JSON on stdin"

        COMMAND=$(printf '%s' "$PARSED" | sed -n 1p)
        EXTRA=$(printf '%s' "$PARSED" | sed -n 2p)
        SRCIP=$(printf '%s' "$PARSED" | sed -n 3p)
        RULE=$(printf '%s' "$PARSED" | sed -n 4p)
    fi
fi

[ -n "$COMMAND" ] || die "no command given (expected add or delete, on argv or as JSON on stdin)"

# extra_args may name a level, e.g. <rules_id>...</rules_id> with extra args
# "lockdown". First recognised level wins.
if [ -n "$EXTRA" ]; then
    for arg in $EXTRA; do
        case "$arg" in
            off|relaxed|normal|strict|lockdown) AR_LEVEL="$arg"; break ;;
        esac
    done
fi

case "$COMMAND" in
    add)    TARGET="$AR_LEVEL" ;;
    delete) TARGET="$AR_RESTORE_LEVEL" ;;
    *)      die "unsupported command '$COMMAND' (expected add or delete)" ;;
esac

case "$TARGET" in
    off|relaxed|normal|strict|lockdown) ;;
    *) die "'$TARGET' is not a valid level (off relaxed normal strict lockdown)" ;;
esac

# --------------------------------------------------------------------------
# Preconditions
# --------------------------------------------------------------------------
[ -x "$NGINX_RATELIMIT_BIN" ] || {
    # Fall back to PATH before giving up.
    if command -v nginx-ratelimit >/dev/null 2>&1; then
        NGINX_RATELIMIT_BIN=$(command -v nginx-ratelimit)
    else
        die "nginx-ratelimit not found at $NGINX_RATELIMIT_BIN and not on PATH"
    fi
}

# NGINX_RATELIMIT_SKIP_ROOT_CHECK is nginx-ratelimit's own test-only override;
# honouring it here lets this script be exercised without root too.
if [ "$(id -u)" -ne 0 ] && [ "${NGINX_RATELIMIT_SKIP_ROOT_CHECK:-}" != "1" ]; then
    die "must run as root (Wazuh active response normally does)"
fi

# --------------------------------------------------------------------------
# Serialise. An alert storm fires this repeatedly; without a lock several
# invocations would queue inside nginx-ratelimit's own reload interval and pile
# up processes. Whoever holds the lock is already applying a level, so a
# concurrent caller has nothing useful to add.
# --------------------------------------------------------------------------
run_tool() {
    # No --force: the reload interval exists to stop rapid reloads accumulating
    # shutting-down workers, and an alert storm is exactly that case.
    "$NGINX_RATELIMIT_BIN" --quiet set "$TARGET" 2>&1
}

CONTEXT="command=$COMMAND level=$TARGET"
[ -n "$SRCIP" ] && CONTEXT="$CONTEXT srcip=$SRCIP"
[ -n "$RULE" ] && CONTEXT="$CONTEXT rule=$RULE"

if command -v flock >/dev/null 2>&1; then
    OUTPUT=$(flock -w "$AR_LOCK_WAIT" 9 || exit 99; run_tool) 9>"$AR_LOCK"
    RC=$?
    if [ "$RC" -eq 99 ]; then
        log "SKIP $CONTEXT -- another invocation holds the lock"
        exit 0
    fi
else
    OUTPUT=$(run_tool)
    RC=$?
fi

# --------------------------------------------------------------------------
# Report. nginx-ratelimit's exit codes:
#   0 applied or already active   1 usage   2 rolled back
#   3 not root                    4 nginx missing, not running, or conf.d not included
# --------------------------------------------------------------------------
case "$RC" in
    0) log "OK $CONTEXT" ;;
    2) log "FAILED $CONTEXT -- nginx rejected the config and it was rolled back; nginx was NOT reloaded: $OUTPUT" ;;
    4) log "FAILED $CONTEXT -- nginx unavailable or $(basename "$NGINX_RATELIMIT_BIN")'s conf.d is not included: $OUTPUT" ;;
    *) log "FAILED $CONTEXT -- exit $RC: $OUTPUT" ;;
esac

exit "$RC"
