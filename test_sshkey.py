import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sshkey

PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc+/= me@pc"


def find_sh():
    for c in ("sh", r"C:\Program Files\Git\usr\bin\sh.exe"):
        p = shutil.which(c) or (c if os.path.isfile(c) else None)
        if p:
            return p
    return None


class RemoteScript(unittest.TestCase):
    def test_rejects_non_keys(self):
        for bad in ["", "hello", "ssh-ed25519 AAAA'; rm -rf ~ #", 'ssh-ed25519 AAAA"$(x)"']:
            with self.assertRaises(ValueError):
                sshkey.remote_script(bad)

    def test_comment_is_sanitized(self):
        s = sshkey.remote_script("ssh-ed25519 AAAA me'\"$(x)`y`@pc")
        self.assertNotIn("'", s.replace("sh -c '", ""))
        self.assertIn("mexy@pc", s)

    @unittest.skipUnless(find_sh(), "no sh")
    def test_appends_once_and_fixes_newline(self):
        with tempfile.TemporaryDirectory() as home:
            ssh = Path(home, ".ssh")
            ssh.mkdir()
            ak = ssh / "authorized_keys"
            ak.write_bytes(b"ssh-rsa AAAAold old@x")  # no trailing newline
            cmd = sshkey.install_command("ssh", Path("cfg"), "h", PUB)[-1]
            env = dict(os.environ, HOME=home.replace("\\", "/"))
            for _ in range(2):
                r = subprocess.run([find_sh(), "-c", cmd], capture_output=True, text=True, env=env)
                self.assertIn(sshkey.OK_MARK, r.stdout, r.stderr)
            self.assertEqual(ak.read_text(), "ssh-rsa AAAAold old@x\n" + PUB + "\n")


class PickKey(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def pick(self, files):
        with mock.patch.object(sshkey, "identity_files", return_value=files), \
             mock.patch.object(sshkey, "DEFAULT_KEY", str(self.d / "id_ed25519")):
            return sshkey.pick_key("ssh", Path("cfg"), "h")

    def test_existing_pair_is_used(self):
        (self.d / "id_rsa").write_text("x")
        (self.d / "id_rsa.pub").write_text(PUB + "\n")
        k = self.pick([str(self.d / "nope"), str(self.d / "id_rsa")])
        self.assertTrue(k["exists"])
        self.assertEqual(k["pub"], PUB)

    def test_defaults_fall_back_to_ed25519(self):
        k = self.pick(sorted(sshkey.DEFAULT_IDENTITIES))
        self.assertEqual(k, {"path": str(self.d / "id_ed25519"), "exists": False, "pub": None, "blocked": False})

    def test_explicit_identityfile_is_created_there(self):
        k = self.pick([str(self.d / "work_key")])
        self.assertEqual(k["path"], str(self.d / "work_key"))
        self.assertFalse(k["blocked"])

    def test_private_key_without_pub_is_left_alone(self):
        (self.d / "cloud.pem").write_text("x")
        k = self.pick([str(self.d / "cloud.pem")])
        self.assertTrue(k["blocked"])


if __name__ == "__main__":
    unittest.main()
