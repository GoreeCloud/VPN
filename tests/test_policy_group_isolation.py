"""Regression checks for group-scoped policy isolation (management decisions only).

These tests do not assert packet-level enforcement or a working WireGuard tunnel.
"""
import base64
from pathlib import Path
import tempfile
import unittest

from goreecloud_vpn.core import VPNStore


def key(n):
    return base64.b64encode(bytes([n]) * 32).decode("ascii")


class PolicyGroupIsolationTests(unittest.TestCase):
    def test_group_overlap_never_implicitly_grants_access(self):
        with tempfile.TemporaryDirectory() as directory:
            store = VPNStore(Path(directory) / "state.db")
            try:
                source = store.add_peer("laptop", key(21), ["users", "shared"])
                target = store.add_peer("server", key(22), ["servers", "shared"])
                outsider = store.add_peer("guest", key(23), ["guests", "shared"])
                for peer in (source, target, outsider):
                    self.assertTrue(store.approve_peer(peer["id"]))

                # A shared group on both peers is not an implicit allow rule.
                for protocol, port in (("tcp", 22), ("udp", 53), ("icmp", None)):
                    self.assertFalse(store.allowed(source["id"], target["id"], protocol, port))

                store.add_policy("users", "servers", "tcp", [22])
                self.assertTrue(store.allowed(source["id"], target["id"], "tcp", 22))
                for src, dst in (
                    (target, source), (source, outsider), (outsider, target),
                    (outsider, source), (source, source),
                ):
                    self.assertFalse(store.allowed(src["id"], dst["id"], "tcp", 22))
                self.assertFalse(store.allowed(source["id"], target["id"], "udp", 22))
                self.assertFalse(store.allowed(source["id"], target["id"], "icmp"))

                # Revocation removes access even while the allow policy persists.
                self.assertTrue(store.revoke_peer(target["id"]))
                self.assertFalse(store.allowed(source["id"], target["id"], "tcp", 22))
                self.assertFalse(store.approve_peer(target["id"]))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
