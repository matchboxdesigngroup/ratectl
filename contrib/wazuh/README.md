# Wazuh active response

`nginx-ratelimit-ar.sh` lets Wazuh raise and clear nginx rate limiting in
response to alerts. `add` sets a level (default `strict`), `delete` clears it
(default `off`).

## Install (on the agent running nginx)

```bash
sudo install -o root -g wazuh -m 750 nginx-ratelimit-ar.sh \
    /var/ossec/active-response/bin/nginx-ratelimit-ar.sh
```

`nginx-ratelimit` itself must already be installed at
`/usr/local/sbin/nginx-ratelimit` (or on `PATH`).

## Manager configuration

```xml
<command>
  <name>nginx-ratelimit</name>
  <executable>nginx-ratelimit-ar.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>nginx-ratelimit</command>
  <location>local</location>
  <rules_id>31151,31153</rules_id>
  <timeout>600</timeout>
</active-response>
```

`31151` is "Multiple web server 400 error codes from same source IP" and `31153`
"Multiple web server 500 error codes". Pick whatever rules actually indicate
pressure on your estate — these are a starting point, not a recommendation.

With `<timeout_allowed>yes</timeout_allowed>` Wazuh calls `delete` itself once
`<timeout>` expires, so the level backs off automatically.

## Configuration

Set in the environment or in `/etc/default/nginx-ratelimit-ar`:

| Variable | Default | Meaning |
|---|---|---|
| `AR_LEVEL` | `strict` | level set on `add` |
| `AR_RESTORE_LEVEL` | `off` | level set on `delete` |
| `AR_LOCK_WAIT` | `30` | seconds to wait on a concurrent invocation |
| `AR_LOG` | `/var/ossec/logs/active-responses.log` | where events are logged |
| `NGINX_RATELIMIT_BIN` | `/usr/local/sbin/nginx-ratelimit` | tool location |

**If your site normally runs with limiting on, set `AR_RESTORE_LEVEL=normal`.**
The default of `off` is correct only if `off` is your steady state — otherwise
the timeout will leave you with no limiting at all.

A level can also be passed per-rule from the manager via `extra_args`, which
overrides `AR_LEVEL`:

```xml
<active-response>
  <command>nginx-ratelimit</command>
  <location>local</location>
  <rules_id>31153</rules_id>
  <extra_args>lockdown</extra_args>
  <timeout>900</timeout>
</active-response>
```

Only a recognised level name is accepted from `extra_args`; anything else is
ignored and the default stands.

## Stateful handshake

Wazuh's [custom AR protocol](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)
defines a `check_keys` handshake for stateful responses. On `add` (and only via
the stdin protocol, not legacy argv) the script writes:

```json
{"version":1,"origin":{"name":"nginx-ratelimit-ar","module":"active-response"},"command":"check_keys","parameters":{"keys":["nginx-ratelimit"]}}
```

and reads back `continue` or `abort`. The key is the constant `nginx-ratelimit`,
not a per-source value: this response is global -- one escalation at a time --
unlike `firewall-drop`, which keys on the offending `srcip`.

Two deliberate deviations from the obvious implementation:

**`abort` is checked against reality.** If execd says the response is already
active, the script reads the actual level first. Already at the target, it logs
`SKIP` and exits 0. Not at the target -- a missed `delete`, or somebody ran
`nginx-ratelimit set off` by hand -- execd's bookkeeping is stale, and refusing
would leave the site unprotected, so it logs `OVERRIDE` and applies anyway.

**No reply is not fatal.** An older execd that never answers leaves the script
waiting up to 10s, after which it logs and proceeds. The worst case is a
redundant `set`, which `nginx-ratelimit` no-ops.

Set `AR_HANDSHAKE=0` to skip the handshake entirely.

The protocol is newline-delimited in both directions, so the script reads
exactly one line rather than slurping stdin -- execd holds the pipe open
awaiting the handshake, and reading to EOF stalls every invocation for the full
read timeout.

## Behaviour worth knowing

**Alert storms are cheap.** Repeated `add` while already at the target level is
a no-op inside `nginx-ratelimit` — no write, no reload. Concurrent invocations
serialise on a lock; a caller that cannot get it within `AR_LOCK_WAIT` logs
`SKIP` and exits 0, because whoever holds the lock is already applying a level.

**Reloads stay rate-limited.** The script deliberately does not pass `--force`.
`nginx-ratelimit`'s minimum reload interval exists to stop rapid reloads
accumulating shutting-down worker processes under long-lived connections, and an
alert storm is precisely that case.

**It is global, not per-source.** This raises the limit for every client, so it
pairs with — rather than replaces — `firewall-drop` for blocking a single
offending IP. `$binary_remote_addr` is the key, so if nginx sits behind a CDN or
load balancer without `set_real_ip_from`/`real_ip_header`, every client shares
one bucket. Run `nginx-ratelimit check` before relying on this.

## Log output

Every invocation writes one line to the active-responses log:

```
2026/09/17 03:27:44 nginx-ratelimit-ar: OK command=add level=strict srcip=203.0.113.9 rule=31151
2026/09/17 03:27:44 nginx-ratelimit-ar: OK command=delete level=off srcip=203.0.113.9 rule=31151
2026/09/17 03:28:23 nginx-ratelimit-ar: SKIP command=add level=strict -- another invocation holds the lock
2026/09/17 03:28:01 nginx-ratelimit-ar: ERROR 'apocalypse' is not a valid level (off relaxed normal strict lockdown)
```

Exit status is `nginx-ratelimit`'s own: `0` applied or already active, `1` usage
or a bad level, `2` nginx rejected the config and it was rolled back (nginx was
*not* reloaded), `3` not root, `4` nginx unavailable or its `conf.d` is not
included by the running config.
