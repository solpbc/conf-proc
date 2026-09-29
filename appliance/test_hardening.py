"""Regression checks for immutable-input handling and serving identities."""
import os
from pathlib import Path
import stat
import tempfile
import unittest

from spp_appliance import harden_service_identities, unit_asr, unit_gateway, unit_sglang


class HardeningTests(unittest.TestCase):
    def test_hardlinks_remain_unchanged_and_services_cannot_escalate(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            tree = base / "root"
            units = tree / "etc/systemd/system"
            units.mkdir(parents=True)
            for name, original in (("passwd", "root:x:0:0::/root:/bin/bash\n"),
                                   ("group", "root:x:0:\n")):
                source = base / name
                source.write_text(original)
                os.link(source, tree / "etc" / name)
            source = base / "setid"
            source.write_bytes(b"fixture")
            source.chmod(0o6755)
            (tree / "usr/bin").mkdir(parents=True)
            os.link(source, tree / "usr/bin/setid")
            for unit, make in (("spp-gateway", unit_gateway), ("spp-asr", unit_asr), ("sglang", unit_sglang)):
                (units / (unit + ".service")).write_text(make("prod"))
            (tree / "root/.cache").mkdir(parents=True)
            (tree / "root/.cache/unneeded").write_text("cache")
            harden_service_identities(tree)
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o6755)
            self.assertEqual((base / "passwd").read_text(), "root:x:0:0::/root:/bin/bash\n")
            self.assertEqual((base / "group").read_text(), "root:x:0:\n")
            self.assertEqual(stat.S_IMODE((tree / "usr/bin/setid").stat().st_mode), 0o755)
            self.assertFalse((tree / "root/.cache").exists())
            for unit, user in (("spp-gateway", "spp-gateway"), ("spp-asr", "spp-asr"), ("sglang", "spp-sglang")):
                text = (units / (unit + ".service")).read_text()
                self.assertIn(f"User={user}\nGroup={user}\n", text)
                self.assertIn("NoNewPrivileges=yes\nCapabilityBoundingSet=\n", text)
            access = (units / "spp-tpm-access.service").read_text()
            self.assertIn("chgrp spp-gateway /dev/tpmrm0", access)
            self.assertIn("chmod 0660 /dev/tpmrm0", access)


if __name__ == "__main__":
    unittest.main()
