"""GoreeCloud VPN offline operator tools and local API launcher."""
import argparse
import os
from .app import serve
from .core import Store, render_server


def main():
    p = argparse.ArgumentParser(prog="goreevpn")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run loopback-only management API")
    render = sub.add_parser("render-server", help="render an OFFLINE server config")
    render.add_argument("--db", default=os.path.expanduser("~/.local/state/goreevpn/peers.sqlite3"))
    render.add_argument("--key-file", required=True)
    render.add_argument("--output", required=True)
    render.add_argument("--port", type=int, default=51820)
    args = p.parse_args()
    if args.cmd == "serve":
        serve()
    else:
        count = render_server(Store(args.db), args.key_file, args.output, args.port)
        print(f"Rendered private server config with {count} inventory records; NOT applied.")


if __name__ == "__main__":
    main()
