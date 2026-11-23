import tempfile
import unittest
from pathlib import Path

import core

CONFIG = """
# comment
Host web db
    HostName 10.0.0.1
    User alice
    Port 2222
    LocalForward 9701 localhost:9701
    LocalForward 9702 localhost:9702
    LocalForward 9703 localhost:9703
    LocalForward 18000 localhost:8000
    LocalForward 18001 localhost:8001
    LocalForward 127.0.0.1:15432 db.internal:5432

Host *
    User nobody
    ServerAliveInterval 30

Host gpu
    HostName=192.168.0.7
    IdentityFile "C:\\Users\\me\\.ssh\\key one"

Include extra.conf
"""


class SshConfigTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        d = Path(self.dir.name)
        (d / "config").write_text(CONFIG, encoding="utf-8")
        (d / "extra.conf").write_text("Host inc-host\n  HostName 1.2.3.4\n", encoding="utf-8")
        self.hosts = {h["alias"]: h for h in core.parse_ssh_config(d / "config")}

    def tearDown(self):
        self.dir.cleanup()

    def test_hosts_listed_without_wildcards(self):
        self.assertEqual(list(self.hosts), ["web", "db", "gpu", "inc-host"])

    def test_first_value_wins(self):
        self.assertEqual(self.hosts["web"]["user"], "alice")
        self.assertEqual(self.hosts["gpu"]["user"], "nobody")  # from Host *
        self.assertEqual(self.hosts["gpu"]["hostname"], "192.168.0.7")
        self.assertEqual(self.hosts["gpu"]["identityFile"], r"C:\Users\me\.ssh\key one")

    def test_forwards_compress_to_ranges(self):
        rules = core.forwards_to_rules(self.hosts["web"]["forwards"])
        got = [(r["local"], r["remoteHost"], r["remote"]) for r in rules]
        self.assertEqual(got, [
            ("", "localhost", "9701-9703"),
            ("15432", "db.internal", "5432"),
            ("18000-18001", "localhost", "8000-8001"),
        ])

    def test_normalize_rule(self):
        self.assertEqual(core.normalize_rule({"local": "9720-9739", "remote": ""})["remote"], "9720-9739")
        self.assertEqual(core.normalize_rule({"local": "9720-9739", "remote": ""})["local"], "")
        self.assertEqual(core.normalize_rule({"local": "80", "remote": "80"})["local"], "")
        self.assertEqual(core.normalize_rule({"local": "15432", "remote": "5432"})["local"], "15432")


class RuleTest(unittest.TestCase):
    def test_parse_spec(self):
        self.assertEqual(core.parse_port_spec("8080"), (8080, 8080))
        self.assertEqual(core.parse_port_spec(" 9720 - 9739 "), (9720, 9739))
        for bad in ("", "abc", "0", "70000", "10-5", "1-5000"):
            with self.assertRaises(ValueError, msg=bad):
                core.parse_port_spec(bad)

    def test_expand(self):
        self.assertEqual(core.expand_rule({"local": "18000-18001", "remote": "8000-8001"}),
                         [(18000, "localhost", 8000), (18001, "localhost", 8001)])
        with self.assertRaises(ValueError):
            core.expand_rule({"local": "1000-1002", "remote": "80"})
        # remote-only rule: local defaults to the same numbers
        self.assertEqual(core.expand_rule({"local": "", "remote": "9720-9721"}),
                         [(9720, "localhost", 9720), (9721, "localhost", 9721)])
        with self.assertRaises(ValueError):
            core.expand_rule({"local": "", "remote": ""})

    def test_validate_duplicates_and_disabled(self):
        rules = [
            {"local": "9720-9730", "enabled": True},
            {"local": "9725", "enabled": True},
            {"local": "9725", "enabled": False},
            {"local": "x", "enabled": True},
        ]
        fws, errs = core.validate_rules(rules)
        self.assertEqual(len(fws), 11)
        self.assertIsNone(errs[0])
        self.assertIn("중복", errs[1])
        self.assertIsNone(errs[2])
        self.assertIsNotNone(errs[3])


if __name__ == "__main__":
    unittest.main()
