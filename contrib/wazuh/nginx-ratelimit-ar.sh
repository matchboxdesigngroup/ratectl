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
#   AR_KEY            check_keys handshake key (default: nginx-ratelimit)
#   AR_HANDSHAKE      1 to perform the stateful handshake, 0 to skip (default: 1)
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
# The stateful check_keys handshake. Our action is global -- one escalation at
# a time -- so the key is a constant rather than a per-source value the way
# firewall-drop keys on srcip.
AR_KEY="${AR_KEY:-nginx-ratelimit}"
AR_HANDSHAKE="${AR_HANDSHAKE:-1}"
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

read_line() {
    # One line from stdin, or empty on timeout. The protocol is newline
    # delimited in both directions.
    timeout "${1:-5}" head -n 1 2>/dev/null || true
}

json_field() {
    # $1 = json, $2 = top-level key
    printf '%s' "$1" | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get(sys.argv[1], ""))
except Exception:
    print("")
' "$2" 2>/dev/null
}

check_keys() {
    # Stateful handshake: announce our key, then honour execd's verdict.
    # Returns 0 to proceed, 1 if execd says this response is already active.
    printf '{"version":1,"origin":{"name":"%s","module":"active-response"},"command":"check_keys","parameters":{"keys":["%s"]}}\n' \
        "$PROG" "$AR_KEY"

    REPLY=$(read_line 10)
    if [ -z "$REPLY" ]; then
        # Older execd, or a manual invocation. Proceeding is the safe default:
        # the worst case is a redundant set, which nginx-ratelimit no-ops.
        log "handshake: no reply from execd, proceeding"
        return 0
    fi
    [ "$(json_field "$REPLY" command)" = "abort" ] && return 1
    return 0
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
STDIN_MODE=0

if [ $# -gt 0 ] && { [ "$1" = "add" ] || [ "$1" = "delete" ]; }; then
    COMMAND="$1"
    SRCIP="${3:-}"
    RULE="${5:-}"
else
    # Read exactly one line. `cat` would block until EOF, and for a stateful
    # response execd holds the pipe open waiting for our handshake -- slurping
    # stdin stalls every invocation for the full timeout. dash has no `read -t`,
    # hence `timeout ... head -n 1`.
    INPUT=""
    if [ ! -t 0 ]; then
        INPUT=$(read_line 5)
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

        STDIN_MODE=1
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
CONTEXT="command=$COMMAND level=$TARGET"
[ -n "$SRCIP" ] && CONTEXT="$CONTEXT srcip=$SRCIP"
[ -n "$RULE" ] && CONTEXT="$CONTEXT rule=$RULE"

run_tool() {
    # No --force: the reload interval exists to stop rapid reloads accumulating
    # shutting-down workers, and an alert storm is exactly that case.
    "$NGINX_RATELIMIT_BIN" --quiet set "$TARGET" 2>&1
}

if [ "$COMMAND" = "add" ] && [ "$STDIN_MODE" -eq 1 ] && [ "$AR_HANDSHAKE" = "1" ]; then
    if ! check_keys; then
        # execd believes this response is already active. Trust the real system
        # state over its bookkeeping: if the level really is applied, we are
        # genuinely redundant; if it is not, execd is stale (a missed delete, a
        # manual `set off`) and refusing would leave us unprotected.
        CURRENT=$("$NGINX_RATELIMIT_BIN" --json status 2>/dev/null \
            | python3 -c 'import json,sys
try: print(json.load(sys.stdin)["level"])
except Exception: print("")' 2>/dev/null)
        if [ "$CURRENT" = "$TARGET" ]; then
            log "SKIP $CONTEXT -- execd reports it active and the level is already $TARGET"
            exit 0
        fi
        log "OVERRIDE $CONTEXT -- execd reports it active but the level is '${CURRENT:-unknown}'; applying anyway"
    fi
fi

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
