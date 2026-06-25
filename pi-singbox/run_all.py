#!/usr/bin/env python3
"""Launch NSS DNS bridge, sing-box, and Flask UI together."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


PROCS: list[subprocess.Popen] = []


def start(name: str, cmd: list[str], env: dict[str, str] | None = None) -> subprocess.Popen:
    print("+", " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd, env=env)
    PROCS.append(proc)
    return proc


def stop_all(signum=None, frame=None) -> None:  # noqa: ANN001
    for proc in PROCS:
        if proc.poll() is None:
            proc.terminate()
    for proc in PROCS:
        if proc.poll() is None:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    if signum is not None:
        raise SystemExit(128 + int(signum))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="surge_full.conf")
    parser.add_argument("--sing-box", default="./sing-box-1.13.13-linux-arm64/sing-box")
    parser.add_argument("--secret", default=os.environ.get("SING_BOX_SECRET", "change-this"))
    parser.add_argument("--web-secret", default=os.environ.get("WEB_SECRET", ""))
    parser.add_argument("--mixed-port", type=int, default=7890)
    parser.add_argument("--api-listen", default="127.0.0.1:9090")
    parser.add_argument("--web-host", default="0.0.0.0")
    parser.add_argument("--web-port", type=int, default=9091)
    parser.add_argument("--local-dns-listen", default="127.0.0.1")
    parser.add_argument("--local-dns-port", type=int, default=1053)
    parser.add_argument("--cache-path", default="./cache.db")
    args = parser.parse_args()

    here = Path(__file__).resolve().parent
    os.chdir(here)

    signal.signal(signal.SIGINT, stop_all)
    signal.signal(signal.SIGTERM, stop_all)

    python = sys.executable
    controller = "http://" + args.api_listen

    start(
        "nss-dns",
        [python, "nss_dns.py", "--listen", args.local_dns_listen, "--port", str(args.local_dns_port)],
    )

    start(
        "sing-box",
        [
            python,
            "surge2singbox.py",
            "run",
            args.profile,
            "--sing-box",
            args.sing_box,
            "--api-listen",
            args.api_listen,
            "--secret",
            args.secret,
            "--mixed-port",
            str(args.mixed_port),
            "--cache-path",
            args.cache_path,
            "--local-dns-server",
            args.local_dns_listen,
            "--local-dns-port",
            str(args.local_dns_port),
        ],
    )

    env = os.environ.copy()
    env.update(
        {
            "SING_BOX_CONTROLLER": controller,
            "SING_BOX_SECRET": args.secret,
            "WEB_SECRET": args.web_secret,
            "WEB_HOST": args.web_host,
            "WEB_PORT": str(args.web_port),
        }
    )
    start("web", [python, "web.py"], env=env)

    try:
        while True:
            for proc in PROCS:
                code = proc.poll()
                if code is not None:
                    print(f"process exited with code {code}; stopping all", file=sys.stderr, flush=True)
                    stop_all()
                    raise SystemExit(code)
            time.sleep(1)
    finally:
        stop_all()


if __name__ == "__main__":
    main()
