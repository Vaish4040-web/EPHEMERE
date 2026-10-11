"""Start EVERYTHING with one command:   python demo/run_all.py

Starts: IPFS (offline), proxy, access service, gateway, and the web app.
Stop with Ctrl+C. Logs go to .data/logs/ so this window stays readable.

Options:  --no-web    do not start the web app (handy for backend-only testing)
          --prod-web  run the web app from a production build (`npm run build` first)
"""
import argparse
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from api.common.config import Settings, load_env  # noqa: E402

IS_WINDOWS = os.name == "nt"
children: list[tuple[str, subprocess.Popen]] = []


def say(msg=""):
    print(msg, flush=True)


def ensure_env_file():
    """Create .env with a random internal secret the first time. It is never committed."""
    env_file = REPO / ".env"
    if not env_file.exists():
        env_file.write_text(f"# Created by demo/run_all.py. Never commit this file.\nINTERNAL_SECRET={secrets.token_urlsafe(32)}\n")
        say("Created .env with a new random INTERNAL_SECRET (never commit this file).")
    load_env()


def check_python_packages():
    if sys.version_info[:2] != (3, 11):
        say(f"WARNING: you are using Python {sys.version_info.major}.{sys.version_info.minor}. This project needs Python 3.11 "
            "(the umbral-pre library has no installer for newer versions).")
    missing = []
    for mod in ("fastapi", "uvicorn", "httpx", "umbral_pre"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        say(f"Missing Python packages: {', '.join(missing)}.\nRun:  pip install -r api/requirements.txt")
        sys.exit(1)


def find_ipfs() -> str:
    if os.environ.get("IPFS_BIN"):
        return os.environ["IPFS_BIN"]
    found = shutil.which("ipfs")
    if found:
        return found
    node = shutil.which("node")
    if node and (REPO / "demo" / "node_modules" / "kubo").exists():
        out = subprocess.run([node, "-e", "console.log(require('kubo').path())"], cwd=REPO / "demo",
                             capture_output=True, text=True)
        path = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else ""
        if path and Path(path).exists():
            return path
    say("Could not find the IPFS program (Kubo).\nRun:  cd demo && npm install   (the first run downloads about 120 MB)")
    sys.exit(1)


def start(name: str, cmd: list[str], cwd: Path, env: dict, log_dir: Path):
    log = open(log_dir / f"{name}.log", "w", encoding="utf-8")
    kwargs = {"cwd": cwd, "env": env, "stdout": log, "stderr": subprocess.STDOUT}
    if not IS_WINDOWS:
        kwargs["start_new_session"] = True      # so we can stop the whole process group later
    children.append((name, subprocess.Popen(cmd, **kwargs)))


def stop_all():
    for name, p in reversed(children):
        if p.poll() is not None:
            continue
        try:
            if IS_WINDOWS:
                subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True)
            else:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except Exception:
            pass
    time.sleep(1)


def up(url: str, method="GET") -> bool:
    try:
        req = urllib.request.Request(url, method=method, data=b"" if method == "POST" else None)
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status < 500
    except Exception:
        return False


def _stop_signal(*_):
    raise KeyboardInterrupt


def main():
    # Make Ctrl+C and a "stop" from an editor behave the same way, even if started from a background job.
    signal.signal(signal.SIGINT, _stop_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _stop_signal)

    ap = argparse.ArgumentParser()
    ap.add_argument("--no-web", action="store_true")
    ap.add_argument("--prod-web", action="store_true")
    args = ap.parse_args()

    ensure_env_file()
    check_python_packages()
    s = Settings.from_env()
    data = s.data_dir
    log_dir = data / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}

    # ---- IPFS (offline: nothing leaves this computer) ----
    ipfs = find_ipfs()
    ipfs_env = {**env, "IPFS_PATH": str(data / "ipfs")}
    if not (data / "ipfs" / "config").exists():
        say("Setting up the IPFS node (first run only)...")
        subprocess.run([ipfs, "init", "--profile=test"], env=ipfs_env, capture_output=True, check=True)
    subprocess.run([ipfs, "config", "Addresses.API", f"/ip4/127.0.0.1/tcp/{s.ipfs_api_port}"], env=ipfs_env, check=True)
    subprocess.run([ipfs, "config", "Addresses.Gateway", "/ip4/127.0.0.1/tcp/0"], env=ipfs_env, check=True)
    start("ipfs", [ipfs, "daemon", "--offline"], REPO, ipfs_env, log_dir)

    # ---- the three small servers ----
    for name, port in (("proxy", s.proxy_port), ("access", s.access_port), ("gateway", s.gateway_port)):
        start(name, [sys.executable, "-m", "uvicorn", f"api.{name}.main:create_app", "--factory",
                     "--host", "127.0.0.1", "--port", str(port)], REPO, env, log_dir)

    # ---- the web app ----
    web_url = f"http://localhost:{s.web_port}"
    if not args.no_web:
        npm = shutil.which("npm")
        if not npm or not (REPO / "web" / "node_modules").exists():
            say("The web app is not installed yet.\nRun:  cd web && npm install     (or start with --no-web)")
            stop_all()
            sys.exit(1)
        web_env = {**env, "GATEWAY_URL": f"http://127.0.0.1:{s.gateway_port}"}
        cmd = [npm, "run", "start" if args.prod_web else "dev", "--", "-p", str(s.web_port)]
        start("web", cmd, REPO / "web", web_env, log_dir)

    # ---- wait until everything answers ----
    checks = [("IPFS", f"{s.ipfs_url}/api/v0/version", "POST"),
              ("proxy", f"http://127.0.0.1:{s.proxy_port}/health", "GET"),
              ("access service", f"http://127.0.0.1:{s.access_port}/health", "GET"),
              ("gateway", f"http://127.0.0.1:{s.gateway_port}/health", "GET")]
    if not args.no_web:
        checks.append(("web app", f"{web_url}/vault", "GET"))
    say("Starting everything...")
    deadline = time.time() + 120
    pending = list(checks)
    while pending and time.time() < deadline:
        pending = [c for c in pending if not up(c[1], c[2])]
        dead = [n for n, p in children if p.poll() is not None]
        if dead:
            say(f"\n{dead[0]} stopped unexpectedly. See {log_dir / (dead[0] + '.log')}")
            stop_all()
            sys.exit(1)
        time.sleep(0.5)
    if pending:
        say("\nThese did not start in time: " + ", ".join(c[0] for c in pending) + f"\nLogs are in {log_dir}")
        stop_all()
        sys.exit(1)

    say("\nEverything is running:")
    say(f"  Vault (Asha)       {web_url}/vault" if not args.no_web else "  (web app not started)")
    if not args.no_web:
        say(f"  Company page       {web_url}/company")
        say(f"  Browser self-test  {web_url}/lab")
    say(f"  Gateway status     http://127.0.0.1:{s.gateway_port}/api/status")
    say(f"  Logs               {log_dir}")
    say("\nPress Ctrl+C to stop everything.")

    warned = set()
    try:
        while True:
            for n, p in children:
                if p.poll() is not None and n not in warned:
                    warned.add(n)
                    say(f"\nWARNING: {n} stopped. See {log_dir / (n + '.log')}\n"
                        "The other parts keep running and the status panel shows what is down. Ctrl+C stops everything.")
            if all(p.poll() is not None for _, p in children):
                break
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        say("\nStopping...")
        stop_all()


if __name__ == "__main__":
    main()
