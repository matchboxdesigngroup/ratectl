#!/usr/bin/env python3
"""Unit tests: level ordering, config generation, state recovery, diff logic.

These need neither root nor a running nginx. The subset that shells out to
`nginx -t` (standalone candidate validation) is skipped when nginx is absent.
"""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "nginx-ratelimit")


def load_module(env_overrides):
    """Import the script fresh under a given environment.

    Paths are read at import time, so each test gets its own sandbox.
    """
    saved = {k: os.environ.get(k) for k in env_overrides}
    os.environ.update(env_overrides)
    try:
        name = "nginx_ratelimit_%d" % load_module.counter
        load_module.counter += 1
        spec = importlib.util.spec_from_loader(
            name, importlib.machinery.SourceFileLoader(name, SCRIPT)
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


load_module.counter = 0


class Sandbox:
    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="nrl-test.")
        self.conf_dir = os.path.join(self.root, "conf.d")
        os.makedirs(self.conf_dir)
        self.conf = os.path.join(self.conf_dir, "nginx-ratelimit.conf")
        self.state_dir = os.path.join(self.root, "state")

    def module(self):
        return load_module({
            "NGINX_RATELIMIT_CONF": self.conf,
            "NGINX_RATELIMIT_STATE_DIR": self.state_dir,
        })

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


class TestBase(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)
        self.m = self.box.module()


class TestLevelOrdering(TestBase):
    def test_order_is_loosest_to_strictest(self):
        self.assertEqual(self.m.LEVEL_NAMES,
                         ["off", "relaxed", "normal", "strict", "lockdown"])

    def test_rates_decrease_monotonically(self):
        rates = [float(lv.rate.replace("r/s", ""))
                 for lv in self.m.LEVELS if lv.enforcing]
        self.assertEqual(rates, sorted(rates, reverse=True))

    def test_bursts_decrease_monotonically(self):
        bursts = [lv.burst for lv in self.m.LEVELS if lv.enforcing]
        self.assertEqual(bursts, sorted(bursts, reverse=True))

    def test_down_from_relaxed_lands_on_off(self):
        index = self.m.LEVEL_NAMES.index("relaxed")
        self.assertEqual(self.m.LEVELS[index - 1].name, "off")

    def test_only_lockdown_queues(self):
        for lv in self.m.LEVELS:
            if lv.name == "lockdown":
                self.assertFalse(lv.nodelay)
            elif lv.enforcing:
                self.assertTrue(lv.nodelay, "%s should be nodelay" % lv.name)

    def test_table_matches_spec(self):
        expected = {
            "off": (None, None),
            "relaxed": ("30r/s", 60),
            "normal": ("10r/s", 20),
            "strict": ("3r/s", 10),
            "lockdown": ("1r/s", 2),
        }
        for name, (rate, burst) in expected.items():
            lv = self.m.LEVEL_BY_NAME[name]
            self.assertEqual((lv.rate, lv.burst), (rate, burst), name)


class TestZoneInvariant(TestBase):
    """Constraint 1: name, size and key are byte-identical at every level."""

    def test_zone_declaration_identical_across_levels(self):
        declarations = set()
        for lv in self.m.LEVELS:
            text = self.m.generate_config(lv, [])
            line = [l for l in text.splitlines() if l.startswith("limit_req_zone")]
            self.assertEqual(len(line), 1)
            # everything except the rate= parameter must be identical
            declarations.add(line[0].split(" rate=")[0])
        self.assertEqual(
            declarations,
            {"limit_req_zone $rl_key zone=perip:10m"},
            "zone name/size/key must never vary across levels",
        )

    def test_zone_declaration_identical_across_whitelists(self):
        a = self.m.generate_config(self.m.LEVEL_BY_NAME["normal"], [])
        b = self.m.generate_config(self.m.LEVEL_BY_NAME["normal"],
                                   ["10.0.0.0/8", "127.0.0.1/32"])
        pick = lambda t: [l for l in t.splitlines() if l.startswith("limit_req_zone")][0]
        self.assertEqual(pick(a), pick(b))

    def test_key_expression_never_varies(self):
        for lv in self.m.LEVELS:
            text = self.m.generate_config(lv, ["203.0.113.0/24"])
            self.assertIn("limit_req_zone $rl_key zone=perip:10m", text)


class TestGeneration(TestBase):
    def test_off_declares_zone_without_limit_req(self):
        text = self.m.generate_config(self.m.LEVEL_BY_NAME["off"], [])
        self.assertIn("limit_req_zone", text)
        self.assertNotIn("\nlimit_req zone=", text)

    def test_enforcing_levels_emit_limit_req(self):
        text = self.m.generate_config(self.m.LEVEL_BY_NAME["strict"], [])
        self.assertIn("limit_req zone=perip burst=10 nodelay;", text)

    def test_lockdown_omits_nodelay(self):
        text = self.m.generate_config(self.m.LEVEL_BY_NAME["lockdown"], [])
        self.assertIn("limit_req zone=perip burst=2;", text)
        self.assertNotIn("nodelay", text)

    def test_geo_map_always_emitted(self):
        for lv in self.m.LEVELS:
            text = self.m.generate_config(lv, [])
            self.assertIn("geo $rl_exempt {", text)
            self.assertIn("map $rl_exempt $rl_key {", text)

    def test_whitelist_entries_rendered_and_sorted(self):
        text = self.m.generate_config(
            self.m.LEVEL_BY_NAME["normal"],
            ["10.0.0.0/8", "127.0.0.1/32", "192.168.0.0/16"],
        )
        order = [l.strip() for l in text.splitlines() if l.endswith(" 1;")]
        self.assertEqual(order,
                         ["10.0.0.0/8 1;", "127.0.0.1/32 1;", "192.168.0.0/16 1;"])

    def test_status_and_log_level_always_present(self):
        for lv in self.m.LEVELS:
            text = self.m.generate_config(lv, [])
            self.assertIn("limit_req_status 429;", text)
            self.assertIn("limit_req_log_level warn;", text)

    def test_header_records_level(self):
        text = self.m.generate_config(self.m.LEVEL_BY_NAME["strict"], [])
        self.assertIn("# level: strict", text)
        self.assertTrue(text.startswith("# Managed by nginx-ratelimit."))


class TestIdempotency(TestBase):
    """Constraint 4: running the same command twice must not duplicate anything."""

    def test_regeneration_is_byte_identical_modulo_timestamp(self):
        import datetime
        lv = self.m.LEVEL_BY_NAME["normal"]
        t1 = datetime.datetime(2026, 9, 17, 10, 0, 0, tzinfo=datetime.timezone.utc)
        t2 = datetime.datetime(2026, 9, 17, 11, 30, 0, tzinfo=datetime.timezone.utc)
        a = self.m.generate_config(lv, ["127.0.0.1/32"], t1)
        b = self.m.generate_config(lv, ["127.0.0.1/32"], t2)
        self.assertNotEqual(a, b)                 # timestamps differ
        self.assertTrue(self.m.same_config(a, b))  # but the content is the same

    def test_never_duplicates_limit_req_zone(self):
        for lv in self.m.LEVELS:
            text = self.m.generate_config(lv, ["127.0.0.1/32"])
            self.assertEqual(text.count("limit_req_zone"), 1, lv.name)
            self.assertEqual(text.count("geo $rl_exempt"), 1, lv.name)
            self.assertEqual(text.count("map $rl_exempt"), 1, lv.name)

    def test_repeated_allow_does_not_duplicate_entry(self):
        whitelist = self.m.sort_whitelist(["10.0.0.0/8", "10.0.0.0/8"])
        self.assertEqual(whitelist, ["10.0.0.0/8"])
        text = self.m.generate_config(self.m.LEVEL_BY_NAME["normal"], whitelist)
        self.assertEqual(text.count("10.0.0.0/8 1;"), 1)


class TestStateRecovery(TestBase):
    def test_missing_state_and_missing_config_defaults_to_off(self):
        state = self.m.load_state()
        self.assertEqual(state["level"], "off")
        self.assertTrue(state["_recovered"])

    def test_missing_state_recovers_level_from_config(self):
        with open(self.box.conf, "w") as fh:
            fh.write(self.m.generate_config(self.m.LEVEL_BY_NAME["strict"],
                                            ["10.0.0.0/8"]))
        state = self.m.load_state()
        self.assertEqual(state["level"], "strict")
        self.assertEqual(state["whitelist"], ["10.0.0.0/8"])
        self.assertTrue(state["_recovered"])

    def test_corrupt_state_recovers_from_config(self):
        os.makedirs(self.box.state_dir, exist_ok=True)
        with open(os.path.join(self.box.state_dir, "state.json"), "w") as fh:
            fh.write("{not json at all")
        with open(self.box.conf, "w") as fh:
            fh.write(self.m.generate_config(self.m.LEVEL_BY_NAME["relaxed"], []))
        state = self.m.load_state()
        self.assertEqual(state["level"], "relaxed")

    def test_state_with_unknown_level_falls_back_to_config(self):
        os.makedirs(self.box.state_dir, exist_ok=True)
        with open(os.path.join(self.box.state_dir, "state.json"), "w") as fh:
            json.dump({"level": "apocalypse"}, fh)
        with open(self.box.conf, "w") as fh:
            fh.write(self.m.generate_config(self.m.LEVEL_BY_NAME["normal"], []))
        state = self.m.load_state()
        self.assertEqual(state["level"], "normal")

    def test_valid_state_is_used_verbatim(self):
        os.makedirs(self.box.state_dir, exist_ok=True)
        with open(os.path.join(self.box.state_dir, "state.json"), "w") as fh:
            json.dump({"level": "lockdown", "whitelist": ["192.0.2.0/24"],
                       "reload_count": 7, "last_reload": "2026-09-17T10:00:00Z"}, fh)
        state = self.m.load_state()
        self.assertEqual(state["level"], "lockdown")
        self.assertEqual(state["reload_count"], 7)
        self.assertFalse(state["_recovered"])

    def test_save_then_load_round_trips(self):
        state = self.m.load_state()
        state["level"] = "strict"
        state["reload_count"] = 3
        self.m.save_state(state)
        again = self.m.load_state()
        self.assertEqual(again["level"], "strict")
        self.assertEqual(again["reload_count"], 3)
        self.assertFalse(again["_recovered"])

    def test_parse_config_handles_garbage(self):
        level, whitelist = self.m.parse_config("this is not an nginx config")
        self.assertIsNone(level)
        self.assertEqual(whitelist, [])

    def test_never_crashes_on_unreadable_state(self):
        os.makedirs(self.box.state_dir, exist_ok=True)
        path = os.path.join(self.box.state_dir, "state.json")
        with open(path, "w") as fh:
            json.dump(["a", "list", "not", "an", "object"], fh)
        state = self.m.load_state()
        self.assertEqual(state["level"], "off")


class TestWhitelistValidation(TestBase):
    def test_accepts_bare_address(self):
        self.assertEqual(self.m.normalise_cidr("127.0.0.1"), "127.0.0.1/32")

    def test_accepts_cidr(self):
        self.assertEqual(self.m.normalise_cidr("10.0.0.0/8"), "10.0.0.0/8")

    def test_accepts_ipv6(self):
        self.assertEqual(self.m.normalise_cidr("2001:db8::/32"), "2001:db8::/32")

    def test_normalises_host_bits(self):
        self.assertEqual(self.m.normalise_cidr("10.1.2.3/8"), "10.0.0.0/8")

    def test_rejects_nonsense(self):
        for bad in ["not-an-ip", "999.1.1.1", "10.0.0.0/99", ""]:
            with self.assertRaises(self.m.ToolError):
                self.m.normalise_cidr(bad)

    def test_ipv4_sorts_before_ipv6(self):
        result = self.m.sort_whitelist(["2001:db8::/32", "10.0.0.0/8"])
        self.assertEqual(result, ["10.0.0.0/8", "2001:db8::/32"])


class TestDiffLogic(TestBase):
    def test_level_change_diff_touches_only_the_limit_req_line(self):
        import difflib
        a = self.m.generate_config(self.m.LEVEL_BY_NAME["normal"], [])
        b = self.m.generate_config(self.m.LEVEL_BY_NAME["strict"], [])
        changed = [l for l in difflib.unified_diff(a.splitlines(), b.splitlines(), n=0)
                   if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]
        body = [l for l in changed if not l[1:].startswith("# level:")]
        self.assertEqual(
            sorted(body),
            sorted(["-limit_req_zone $rl_key zone=perip:10m rate=10r/s;",
                    "+limit_req_zone $rl_key zone=perip:10m rate=3r/s;",
                    "-limit_req zone=perip burst=20 nodelay;",
                    "+limit_req zone=perip burst=10 nodelay;"]),
        )

    def test_whitelist_change_diff_is_one_line(self):
        import difflib
        a = self.m.generate_config(self.m.LEVEL_BY_NAME["normal"], [])
        b = self.m.generate_config(self.m.LEVEL_BY_NAME["normal"], ["127.0.0.1/32"])
        added = [l for l in difflib.unified_diff(a.splitlines(), b.splitlines(), n=0)
                 if l.startswith("+") and not l.startswith("+++")
                 and not l[1:].startswith("# level:")]
        self.assertEqual(added, ["+    127.0.0.1/32 1;"])

    def test_mask_generated_is_stable(self):
        text = self.m.generate_config(self.m.LEVEL_BY_NAME["normal"], [])
        self.assertIn("generated: -", self.m.mask_generated(text))


class TestBackupPruning(TestBase):
    def test_prunes_to_twenty_most_recent(self):
        self.m.ensure_dirs()
        for i in range(30):
            name = "2026091%02dT000000Z.conf" % (i % 10)
            with open(os.path.join(self.m.BACKUP_DIR, "%02d-%s" % (i, name)), "w") as fh:
                fh.write("x")
        self.m.prune_backups()
        remaining = [n for n in os.listdir(self.m.BACKUP_DIR) if n.endswith(".conf")]
        self.assertEqual(len(remaining), 20)

    def test_backup_returns_none_when_no_config(self):
        self.assertIsNone(self.m.backup_existing())

    def test_backup_copies_existing(self):
        with open(self.box.conf, "w") as fh:
            fh.write("original content\n")
        path = self.m.backup_existing()
        self.assertIsNotNone(path)
        with open(path) as fh:
            self.assertEqual(fh.read(), "original content\n")


@unittest.skipIf(shutil.which("nginx") is None, "nginx not installed")
class TestNginxAcceptsEveryLevel(TestBase):
    """Every level must render a config that nginx itself accepts."""

    def test_every_level_passes_nginx_t(self):
        for lv in self.m.LEVELS:
            text = self.m.generate_config(lv, ["127.0.0.1/32", "10.0.0.0/8"])
            code, output = self.m.validate_standalone(text)
            self.assertEqual(code, 0, "%s failed nginx -t:\n%s" % (lv.name, output))

    def test_declared_but_unused_zone_produces_no_warning(self):
        text = self.m.generate_config(self.m.LEVEL_BY_NAME["off"], [])
        code, output = self.m.validate_standalone(text)
        self.assertEqual(code, 0, output)
        self.assertNotIn("[warn]", output)

    def test_empty_whitelist_still_valid(self):
        text = self.m.generate_config(self.m.LEVEL_BY_NAME["normal"], [])
        code, output = self.m.validate_standalone(text)
        self.assertEqual(code, 0, output)

    def test_ipv6_whitelist_entry_valid(self):
        text = self.m.generate_config(self.m.LEVEL_BY_NAME["normal"], ["2001:db8::/32"])
        code, output = self.m.validate_standalone(text)
        self.assertEqual(code, 0, output)

    def test_corrupted_config_is_rejected(self):
        # Guards the rollback path: nginx -t must actually fail on bad input.
        code, _ = self.m.validate_standalone("limit_req_zone $rl_key zone=;\n")
        self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
