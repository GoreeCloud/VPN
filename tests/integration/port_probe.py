"""Disposable WireGuard namespace TCP/UDP port probe.

Only the explicit rootless integration shell test invokes this helper. It
never probes external networks and only connects to its fixed lab address.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
import selectors
import socket
import time

LAB_TARGET = "10.77.0.11"
TCP_PORTS = (8443, 8444)
UDP_PORTS = (5353, 5354)
ACK = b"GoreeCloud-Lab-OK"


def _assert_isolated_lab() -> None:
    """Refuse to connect to any address unless in the rootless manual lab."""
    if os.environ.get("GOREECLOUD_ISOLATED_LAB_CHILD") != "1":
        raise RuntimeError("this network probe is for the isolated rootless lab only")
    try:
        current_net = os.readlink("/proc/self/ns/net")
        current_mount = os.readlink("/proc/self/ns/mnt")
        parent_net = os.environ["GOREECLOUD_PARENT_NETNS"]
        parent_mount = os.environ["GOREECLOUD_PARENT_MOUNTNS"]
        mapping = Path("/proc/self/uid_map").read_text(encoding="ascii").split()
    except (OSError, KeyError):
        raise RuntimeError("missing isolated namespace proof") from None
    if (os.geteuid() != 0 or len(mapping) != 3 or mapping[0] != "0"
            or not mapping[1].isdigit() or int(mapping[1]) == 0
            or mapping[2] != "1" or current_net == parent_net
            or current_mount == parent_mount or not parent_net or not parent_mount):
        raise RuntimeError("expected isolated rootless user, network and mount namespaces")


def serve(ready_file: Path) -> None:
    selector = selectors.DefaultSelector()
    sockets = []
    try:
        for port in TCP_PORTS:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((LAB_TARGET, port))
            server.listen(4)
            server.setblocking(False)
            selector.register(server, selectors.EVENT_READ, "tcp")
            sockets.append(server)

        for port in UDP_PORTS:
            server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server.bind((LAB_TARGET, port))
            server.setblocking(False)
            selector.register(server, selectors.EVENT_READ, "udp")
            sockets.append(server)

        with ready_file.open("x", encoding="ascii") as ready:
            ready.write("ready\n")
        ready_file.chmod(0o600)
        until = time.monotonic() + 25
        while time.monotonic() < until:
            for key, _ in selector.select(timeout=0.3):
                server = key.fileobj
                if key.data == "tcp":
                    connection, _ = server.accept()
                    with connection:
                        connection.settimeout(1)
                        connection.sendall(ACK)
                else:
                    _, address = server.recvfrom(64)
                    server.sendto(ACK, address)
    finally:
        selector.close()
        for server in sockets:
            server.close()


def probe(protocol: str, port: int) -> bool:
    if protocol == "tcp":
        if port not in TCP_PORTS:
            raise ValueError("unexpected TCP lab port")
        try:
            with socket.create_connection((LAB_TARGET, port), timeout=1.5) as client:
                client.settimeout(1.5)
                return client.recv(len(ACK)) == ACK
        except OSError:
            return False
    if protocol == "udp":
        if port not in UDP_PORTS:
            raise ValueError("unexpected UDP lab port")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(1.5)
                client.sendto(b"probe", (LAB_TARGET, port))
                return client.recvfrom(64)[0] == ACK
        except OSError:
            return False
    raise ValueError("unsupported lab protocol")


def main(argv=None) -> int:
    try:
        _assert_isolated_lab()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 4
    parser = argparse.ArgumentParser(description="Fixed-address isolated lab port probe")
    sub = parser.add_subparsers(dest="action", required=True)
    serve_command = sub.add_parser("serve")
    serve_command.add_argument("--ready", type=Path, required=True)
    check = sub.add_parser("check")
    check.add_argument("protocol", choices=["tcp", "udp"])
    check.add_argument("port", type=int)
    args = parser.parse_args(argv)
    if args.action == "serve":
        serve(args.ready)
        return 0
    return 0 if probe(args.protocol, args.port) else 1


if __name__ == "__main__":
    raise SystemExit(main())
