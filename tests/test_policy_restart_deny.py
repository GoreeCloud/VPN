"""Management-plane policy regression tests; not packet-level VPN enforcement."""
import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore


def public_key(byte):
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


class PolicyRestartDenyTests(unittest.TestCase):
    def test_policy_persistence_revocation_and_default_deny_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            store = VPNStore(path)
            try:
                source = store.add_peer("client", public_key(41), ["clients"])
                target = store.add_peer("service", public_key(42), ["services"])
                rule = store.add_policy("clients", "services", "tcp", [443])
                store.approve_peer(source["id"])
                store.approve_peer(target["id"])
                self.assertTrue(store.allowed(source["id"], target["id"], "tcp", 443))
            finally:
                store.close()

            store = VPNStore(path)
            try:
                # Persisted allow does not grant reverse, wrong-port, or self access.
                self.assertTrue(store.allowed(source["id"], target["id"], "tcp", 443))
                self.assertFalse(store.allowed(target["id"], source["id"], "tcp", 443))
                self.assertFalse(store.allowed(source["id"], target["id"], "tcp", 80))
                self.assertFalse(store.allowed(source["id"], source["id"], "tcp", 443))
                self.assertFalse(store.allowed("unknown", target["id"], "tcp", 443))
                self.assertTrue(store.revoke_peer(target["id"]))
                self.assertFalse(store.allowed(source["id"], target["id"], "tcp", 443))
            finally:
                store.close()

            store = VPNStore(path)
            try:
                # Revocation survives process restart even while allow rule remains.
                self.assertFalse(store.allowed(source["id"], target["id"], "tcp", 443))
                self.assertFalse(store.approve_peer(target["id"]))
                self.assertTrue(store.delete_policy(rule["id"]))
                self.assertFalse(store.allowed(source["id"], target["id"], "tcp", 443))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
