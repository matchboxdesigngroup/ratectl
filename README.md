# nginx-ratelimit

A Unix CLI for Ubuntu that manages nginx rate limiting as a set of named levels,
with validated config changes and graceful rollback.

Python 3 standard library only — no pip dependencies.

## Install

```bash
sudo install -m 0755 nginx-ratelimit /usr/local/sbin/nginx-ratelimit
```

## Usage

```
nginx-ratelimit status                 # current level, rate/burst, last change, reload count
nginx-ratelimit set <level>            # jump directly to a level
nginx-ratelimit up                     # one level stricter
nginx-ratelimit down                   # one level looser
nginx-ratelimit off                    # alias for `set off`
nginx-ratelimit levels                 # print the table
nginx-ratelimit allow <cidr>           # add to whitelist, regenerate, reload
nginx-ratelimit deny <cidr>            # remove from whitelist
nginx-ratelimit check                  # diagnostics
nginx-ratelimit setup                  # add the conf.d include to nginx.conf if missing
```

Global flags: `--dry-run`, `--quiet`, `--json`, `--force`, `--reload-interval SECONDS`.

Exit codes: `0` success or no-op, `1` usage/argument error, `2` validation failed
and config was rolled back, `3` not root, `4` nginx not installed or not running.

| Level      | rate   | burst | nodelay | Intent                                |
|------------|--------|-------|---------|---------------------------------------|
| `off`      | —      | —     | —       | Zone declared, no `limit_req` emitted |
| `relaxed`  | 30r/s  | 60    | yes     | Barely-there backstop                 |
| `normal`   | 10r/s  | 20    | yes     | Default steady state                  |
| `strict`   | 3r/s   | 10    | yes     | Elevated pressure                     |
| `lockdown` | 1r/s   | 2     | no      | Queue rather than reject; last resort |

Everything is written to a single generated file,
`/etc/nginx/conf.d/nginx-ratelimit.conf`. No existing config is ever parsed or
mutated. State lives in `/var/lib/nginx-ratelimit/state.json`, backups in
`/var/lib/nginx-ratelimit/backups/` (most recent 20).

## Verified against nginx during development

These were open questions in the spec. All were checked against nginx 1.30.4,
and the findings are baked into the implementation and the test suite.

**A declared-but-unused zone produces no warning.** At level `off` the
`limit_req_zone` declaration is kept and `limit_req` is omitted, so the shared
memory survives the transition and re-enabling does not reset client state.
nginx accepts this silently — `nginx -t` is clean and the error log stays quiet
across a reload. The spec's fallback (emitting `limit_req` against a `map`ped
empty key) is therefore not needed. The `geo`/`map` pair is still emitted at
every level, because it is what holds the *key expression* constant — see below.

**The zone key is part of the reload invariant, not just the name and size.**
Changing the key expression makes nginx refuse the reload outright:

```
[emerg] limit_req "perip" uses the "$binary_remote_addr" key
        while previously it used the "$rl_key" key
```

**`nginx -t` cannot catch this.** A test runs in a fresh process with no prior
zone to compare against, so it passes; the live master then rejects the SIGHUP
and keeps serving the old config. This is the one failure mode that slips past
validate-then-commit, so the tool checks the reload's exit status separately and
reports the config-on-disk/config-in-memory split explicitly if it happens.

The indirection through `$rl_key` is what makes `allow`/`deny` safe: the
whitelist changes inside the `geo` block while the key expression the zone was
created with never changes. Unit and integration tests both assert that the
`limit_req_zone` line is byte-identical (modulo `rate=`) across every level and
every whitelist.

**Measured behaviour** (40 requests over one keepalive connection):

| Level    | 200 | 429 |
|----------|-----|-----|
| off      | 40  | 0   |
| relaxed  | 40  | 0   |
| normal   | 21  | 19  |
| strict   | 11  | 29  |

which is exactly the leaky-bucket arithmetic: `1 + burst` admitted. At
`lockdown` (no `nodelay`) nothing is rejected — 6 requests take 5.2s at 1r/s,
confirming the intended queue-rather-than-reject behaviour.

**A testing trap worth knowing.** A location that ends in `return 200` is never
rate-limited: `return` is handled in nginx's *rewrite* phase, which runs before
the *preaccess* phase where `limit_req` lives. A test server built that way
reports success at every level no matter what the config says. The integration
harness uses a real static-file handler for this reason.

## If `conf.d` is not included by nginx.conf

This is the failure mode the tool used to handle worst, so it is worth stating
plainly. Ubuntu's stock `nginx.conf` has `include /etc/nginx/conf.d/*.conf;`
inside the `http` block, but a hand-edited one may not. When it does not, the
generated file is simply inert: `nginx -t` passes (the file is valid, it is
just never read), the reload succeeds, and nothing is limited.

Before the guard existed, `set strict` printed `Level strict: rate=3r/s
burst=10 nodelay. Reloaded.` and exited 0 while 40 out of 40 requests came back
200. `status` agreed, because it reads the state cache and the generated file,
not the running configuration. Only `check` caught it. During an incident you
could set `lockdown`, be told it applied, and have no protection at all.

Now the mutation path verifies it. After `nginx -t` passes the candidate is
already on disk, so `nginx -T` can say conclusively whether nginx read it —
every file nginx reads appears as a `# configuration file <path>` header. If
ours is absent, the write is rolled back and the command fails:

```
$ nginx-ratelimit set strict
nginx-ratelimit: /etc/nginx/conf.d/nginx-ratelimit.conf is not read by the
running nginx, so this level would limit nothing. Run `nginx-ratelimit setup`
to add `include /etc/nginx/conf.d/*.conf;` inside the http block of nginx.conf,
then retry. Nothing was changed.
$ echo $?
4
```

`nginx-ratelimit setup` performs that edit. It is a separate subcommand, not
something `set` does on your behalf, because it is the only place the tool
writes to a file it did not generate — the spec's "never hand-edit existing
configs in phase 1" rule, relaxed deliberately and only here.

It first checks whether anything already covers the path, matching every
`include` glob in the full `nginx -T` dump against the target, so an include
nested inside another included file counts and a second run is a no-op. To find
the insertion point it scans for the top-level `http {` block, tracking brace
depth and skipping comments and quoted strings. That is a deliberately small
scanner: enough to locate one block, nowhere near enough to justify parsing
nginx config in general. Anything beyond it belongs to crossplane in phase 3.

The edit follows the same discipline as every other write — back up `nginx.conf`
to `/var/lib/nginx-ratelimit/backups/nginx.conf.<ISO8601>`, write, run
`nginx -t`, restore and exit 2 on failure. nginx is not reloaded; the include
only matters once a level is set, and `set` reloads anyway. `--dry-run` prints
the diff and changes nothing.

Note that `nginx -T` reflects the configuration **on disk**, so the guard tells
you a reload will pick the file up. It cannot see what the running master
currently has in memory.

## Reloads are graceful, so a level is not live the instant the command returns

`nginx -s reload` returns once the signal is delivered. The master then spawns
new workers while the old ones finish their connections, so for a moment after
the CLI exits the previous level is still being served. Measured here: `set
strict` followed immediately by 40 requests returned 40× 200 (the old `off`
config), and `set off` followed immediately by 40 requests returned 11/29 (the
old `strict` config) — the results lag by exactly one level. After ~1s the new
config serves. This is the intended graceful-reload behaviour, not a defect,
but any test or script that asserts on behaviour straight after a level change
needs to wait.

## Design notes

**Reload interval.** The wait happens *before* the config is written, so the
write and the reload stay back-to-back and the on-disk file never sits in a
state the running nginx has not been told about. `last_reload` is also tracked
as a float epoch alongside the human-readable ISO timestamp — at whole-second
resolution the enforced interval came up short by up to a second.

**Idempotency.** The whole file is rewritten every time, never appended to, so a
duplicate `limit_req_zone` cannot arise. A repeat `set` compares the rendered
candidate against the file on disk (ignoring the `generated:` timestamp) and
exits 0 without writing or reloading.

**`--dry-run` validates standalone.** It renders the candidate into a synthetic
`http` context in a temp directory and runs `nginx -t` there, so the real config
is never touched, not even momentarily. This catches everything in what we
generate, but by construction cannot see interactions with the rest of the
server's configuration; the authoritative check remains the
write → `nginx -t` → roll-back cycle on the real path. Dry-run additionally
scans `conf.d` for a conflicting `perip` zone declaration, which is the
interaction most likely to bite.

**Root.** Mutating commands (`set`/`up`/`down`/`off`/`allow`/`deny`) require
EUID 0 and fail with exit 3 and a plain message. Read-only commands (`status`,
`levels`, `check`) and any `--dry-run` run unprivileged, so diagnostics are
available without sudo.

## Tests

```bash
./tests/run-all.sh                 # unit + integration
python3 tests/test_unit.py         # unit only: no root, no nginx needed
./tests/integration.sh             # integration: needs nginx, runs unprivileged
```

The integration suite builds its own nginx prefix on port 18080 (override with
`NRL_TEST_PORT`) and drives the real tool against it. It waits for the shared
zone to drain between levels — the zone surviving reloads is the whole point, so
excess from one burst carries into the next measurement. That drain dominates
the runtime (~2 minutes); shorten it with `NRL_TEST_DRAIN` at the cost of
flakiness.

In Docker, as the spec intends:

```bash
docker build -f tests/Dockerfile -t nginx-ratelimit-test .
docker run --rm nginx-ratelimit-test
```

Coverage: every level passes `nginx -t`; the zone declaration never varies; a
config nginx rejects is rolled back byte-for-byte and never reaches a reload;
`set` twice is a no-op; the reload interval is respected and `--force` bypasses
it; `--dry-run` changes nothing; state recovers from a deleted or corrupt
`state.json`; `up`/`down` stepping including both ends of the ordering;
the 429 share rises with the level; `lockdown` queues; whitelisted clients are
exempt; `off` keeps the zone without warning; a conf.d that nginx does not
include is refused rather than silently ignored, and `setup` repairs it
idempotently.

### Test-only environment overrides

The tool reads its paths from the environment so the suite can exercise the real
code paths without root and without touching the system nginx:
`NGINX_RATELIMIT_CONF`, `NGINX_RATELIMIT_STATE_DIR`, `NGINX_RATELIMIT_NGINX_BIN`,
`NGINX_RATELIMIT_NGINX_ARGS`, `NGINX_RATELIMIT_ACCESS_LOG`,
`NGINX_RATELIMIT_ERROR_LOG`, `NGINX_RATELIMIT_RELOAD_INTERVAL`, and
`NGINX_RATELIMIT_SKIP_ROOT_CHECK`. The last one bypasses a friendly guard, not a
permission — the kernel still enforces write access to `/etc/nginx` either way.

## Wazuh active response

`contrib/wazuh/nginx-ratelimit-ar.sh` raises the level on a Wazuh alert and
clears it when the alert's timeout expires. See
[contrib/wazuh/README.md](contrib/wazuh/README.md) for the `ossec.conf` snippet
and configuration.

## Not built yet

Phases 2–4 (auto-ramping daemon, per-site targeting via crossplane, `.deb`
packaging) are untouched, per the spec's instruction to build them only after
phase 1 is solid. `status` already reports the `pinned` flag the daemon's
pin/override will use, and state carries the field, but no daemon reads it yet.
