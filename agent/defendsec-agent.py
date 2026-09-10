#!/usr/bin/env python3
"""DefendSec host agent: enroll + inventory check-in. Python 3 stdlib only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def run(cmd: list[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=8)
        return out.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def detect_platform() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "darwin"
    if system == "windows":
        return "windows"
    if system == "linux":
        return "linux"
    return "unknown"


def memory_mb() -> int:
    system = platform.system()
    if system == "Darwin":
        raw = run(["sysctl", "-n", "hw.memsize"])
        if raw.isdigit():
            return int(raw) // (1024 * 1024)
    if system == "Linux":
        try:
            with open("/proc/meminfo", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        return kb // 1024
        except OSError:
            return 0
    if system == "Windows":
        raw = run(["wmic", "ComputerSystem", "get", "TotalPhysicalMemory", "/value"])
        for part in raw.splitlines():
            if part.startswith("TotalPhysicalMemory=") and part.split("=")[1].isdigit():
                return int(part.split("=")[1]) // (1024 * 1024)
    return 0


def uptime_seconds() -> int:
    if platform.system() == "Linux":
        try:
            with open("/proc/uptime", encoding="utf-8") as fh:
                return int(float(fh.read().split()[0]))
        except (OSError, ValueError, IndexError):
            return 0
    if platform.system() == "Darwin":
        raw = run(["sysctl", "-n", "kern.boottime"])
        # { sec = 1710000000, usec = 0 } Sun Mar ...
        if "sec =" in raw:
            try:
                sec = int(raw.split("sec =")[1].split(",")[0].strip())
                return max(0, int(time.time()) - sec)
            except (ValueError, IndexError):
                return 0
    return 0


def disk_encryption() -> bool | None:
    system = platform.system()
    if system == "Darwin":
        raw = run(["fdesetup", "status"]).lower()
        if "on" in raw:
            return True
        if "off" in raw:
            return False
        return None
    if system == "Linux":
        raw = run(["lsblk", "-ln", "-o", "TYPE,MOUNTPOINT"])
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "crypt" and parts[-1] == "/":
                return True
        return None
    if system == "Windows":
        raw = run(["manage-bde", "-status"]).lower()
        if "protection on" in raw:
            return True
        if "protection off" in raw:
            return False
        return None
    return None


def firewall_on() -> bool | None:
    system = platform.system()
    if system == "Darwin":
        raw = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]).lower()
        if "enabled" in raw:
            return True
        if "disabled" in raw:
            return False
        return None
    if system == "Linux":
        ufw = run(["ufw", "status"]).lower()
        if "status: active" in ufw:
            return True
        if "status: inactive" in ufw:
            return False
        firewalld = run(["firewall-cmd", "--state"]).lower()
        if firewalld == "running":
            return True
        active = run(["systemctl", "is-active", "firewalld"]).lower()
        if active == "active":
            return True
        return None
    if system == "Windows":
        raw = run(["netsh", "advfirewall", "show", "allprofiles"]).lower()
        if "state                                 on" in raw:
            return True
        if "state                                 off" in raw:
            return False
        return None
    return None


def ip_addresses() -> list[str]:
    found: list[str] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if addr not in found and not addr.startswith("127.") and ":" not in addr:
                found.append(addr)
    except OSError:
        pass
    return found[:8]


def software_list() -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(name: str, version: str) -> None:
        key = name.lower()
        if key in seen or not name:
            return
        seen.add(key)
        items.append({"name": name, "version": version})

    system = platform.system()
    if system == "Linux":
        for pkg in (
            "openssh-server",
            "openssl",
            "docker.io",
            "docker-ce",
            "containerd",
            "git",
            "python3",
        ):
            raw = run(["dpkg-query", "-W", "-f=${Package}\t${Version}", pkg])
            if "\t" in raw:
                name, version = raw.split("\t", 1)
                add(name, version)
        raw = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
        for line in raw.splitlines()[:60]:
            if "\t" in line:
                name, version = line.split("\t", 1)
                add(name, version)
        if len(items) <= 7:
            raw = run(["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\n"])
            for line in raw.splitlines()[:60]:
                if "\t" in line:
                    name, version = line.split("\t", 1)
                    add(name, version)
    elif system == "Darwin":
        apps = Path("/Applications")
        if apps.exists():
            for path in sorted(apps.iterdir())[:40]:
                if path.suffix == ".app":
                    version = run(
                        ["defaults", "read", str(path / "Contents" / "Info"), "CFBundleShortVersionString"]
                    )
                    if not version:
                        version = run(["mdls", "-name", "kMDItemVersion", "-raw", str(path)])
                        if version in ("(null)", ""):
                            version = ""
                    add(path.stem, version)
    elif system == "Windows":
        raw = run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object -First 80 DisplayName, DisplayVersion | ConvertTo-Csv -NoTypeInformation",
            ]
        )
        lines = [line for line in raw.splitlines() if line.strip()]
        for line in lines[1:]:
            parts = [part.strip().strip('"') for part in line.split(",")]
            if parts and parts[0]:
                add(parts[0], parts[1] if len(parts) > 1 else "")
        if not items:
            raw = run(["wmic", "product", "get", "Name,Version", "/format:csv"])
            for line in raw.splitlines():
                cols = [col.strip() for col in line.split(",")]
                if len(cols) >= 3 and cols[1] and cols[1] != "Name":
                    add(cols[1], cols[2])
    return items


def pending_updates() -> tuple[list[dict[str, str]], str]:
    updates: list[dict[str, str]] = []
    if platform.system() != "Linux":
        return updates, "unsupported"
    if not shutil.which("apt"):
        return updates, "error"
    raw = run(["apt", "list", "--upgradable"])
    for line in raw.splitlines():
        if "/" not in line or "Listing" in line:
            continue
        name = line.split("/", 1)[0]
        available = ""
        current = ""
        parts = line.split()
        if len(parts) > 1:
            available = parts[1]
        if "upgradable from:" in line:
            current = line.split("upgradable from:", 1)[1].strip(" ]")
        updates.append({"name": name, "current": current, "available": available})
        if len(updates) >= 40:
            break
    return updates, "ok"


def hash_file(path: Path) -> dict | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    stat = path.stat()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": stat.st_size,
        "mtime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
    }


def fim_files() -> list[dict]:
    candidates: list[Path] = []
    system = platform.system()
    if system == "Linux":
        candidates = [
            Path("/etc/passwd"),
            Path("/etc/group"),
            Path("/etc/hosts"),
            Path("/etc/ssh/sshd_config"),
            Path("/etc/sudoers"),
        ]
    elif system == "Darwin":
        candidates = [Path("/etc/hosts"), Path("/etc/ssh/sshd_config")]
    elif system == "Windows":
        root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        candidates = [root / "System32" / "drivers" / "etc" / "hosts"]
    extra = os.environ.get("DEFENDSEC_FIM_PATHS", "")
    for item in extra.split(os.pathsep):
        if item.strip():
            candidates.append(Path(item.strip()))
    results = []
    for path in candidates:
        hashed = hash_file(path)
        if hashed:
            results.append(hashed)
    return results


def os_name_version() -> tuple[str, str]:
    system = platform.system()
    if system == "Darwin":
        return "macOS", platform.mac_ver()[0]
    if system == "Linux":
        os_release = Path("/etc/os-release")
        name, version = "Linux", platform.release()
        if os_release.exists():
            data = {}
            for line in os_release.read_text(encoding="utf-8").splitlines():
                if "=" in line:
                    key, val = line.split("=", 1)
                    data[key] = val.strip().strip('"')
            name = data.get("NAME", name)
            version = data.get("VERSION_ID", version)
        return name, version
    if system == "Windows":
        return "Windows", platform.version()
    return system or "Unknown", platform.release()


def hardware_model() -> str:
    system = platform.system()
    if system == "Darwin":
        return run(["sysctl", "-n", "hw.model"])
    if system == "Linux":
        for path in (
            Path("/sys/class/dmi/id/product_name"),
            Path("/sys/firmware/devicetree/base/model"),
        ):
            try:
                value = path.read_text(encoding="utf-8").strip()
                if value:
                    return value
            except OSError:
                continue
    return platform.machine()


def cpu_label() -> str:
    if platform.system() == "Darwin":
        brand = run(["sysctl", "-n", "machdep.cpu.brand_string"])
        if brand:
            return brand
    if platform.system() == "Linux":
        try:
            with open("/proc/cpuinfo", encoding="utf-8") as fh:
                for line in fh:
                    if line.lower().startswith("model name"):
                        return line.split(":", 1)[1].strip()
        except OSError:
            pass
    return platform.processor() or platform.machine()


def serial_number() -> str:
    if platform.system() == "Darwin":
        raw = run(["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"])
        for line in raw.splitlines():
            if "IOPlatformSerialNumber" in line and "=" in line:
                return line.split("=", 1)[1].strip().strip('"')
    if platform.system() == "Linux":
        path = Path("/sys/class/dmi/id/product_serial")
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return ""


def post_json(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def inventory() -> dict:
    os_name, os_version = os_name_version()
    updates, patch_inventory = pending_updates()
    return {
        "hostname": socket.gethostname(),
        "platform": detect_platform(),
        "osName": os_name,
        "osVersion": os_version,
        "arch": platform.machine(),
        "serial": serial_number(),
        "hardwareModel": hardware_model(),
        "cpu": cpu_label(),
        "memoryMb": memory_mb(),
        "diskEncryption": disk_encryption(),
        "firewall": firewall_on(),
        "ipAddresses": ip_addresses(),
        "username": os.environ.get("USER") or os.environ.get("USERNAME") or "",
        "uptimeSeconds": uptime_seconds(),
        "software": software_list(),
        "pendingUpdates": updates,
        "patchInventory": patch_inventory,
        "fim": fim_files(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="DefendSec host agent")
    parser.add_argument("--server", required=True, help="DefendSec server base URL")
    parser.add_argument("--enroll-secret", default=os.environ.get("DEFENDSEC_ENROLL_SECRET", ""))
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--state-file",
        default=str(Path(__file__).resolve().parent / ".defendsec-node-key"),
    )
    args = parser.parse_args()
    server = args.server.rstrip("/")
    state = Path(args.state_file)

def save_node_key(path: Path, node_key: str) -> None:
    path.write_text(node_key, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def enroll(server: str, secret: str, state: Path) -> str:
    enrolled = post_json(
        f"{server}/api/enroll",
        {"enrollSecret": secret, "hostname": socket.gethostname()},
    )
    node_key = enrolled["nodeKey"]
    save_node_key(state, node_key)
    existing = enrolled.get("existing")
    print(f"{'Reusing' if existing else 'Enrolled as'} {enrolled.get('deviceId')}")
    return node_key


def main() -> int:
    parser = argparse.ArgumentParser(description="DefendSec host agent")
    parser.add_argument("--server", required=True, help="DefendSec server base URL")
    parser.add_argument("--enroll-secret", default=os.environ.get("DEFENDSEC_ENROLL_SECRET", ""))
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--state-file",
        default=str(Path(__file__).resolve().parent / ".defendsec-node-key"),
    )
    args = parser.parse_args()
    server = args.server.rstrip("/")
    state = Path(args.state_file)

    node_key = state.read_text(encoding="utf-8").strip() if state.exists() else ""
    if node_key:
        try:
            os.chmod(state, 0o600)
        except OSError:
            pass
    if not node_key:
        if not args.enroll_secret:
            print("Missing --enroll-secret (or DEFENDSEC_ENROLL_SECRET)", file=sys.stderr)
            return 2
        try:
            node_key = enroll(server, args.enroll_secret, state)
        except urllib.error.HTTPError as exc:
            print(f"Enroll failed: {exc.read().decode('utf-8', errors='replace')}", file=sys.stderr)
            return 1

    backoff = 5
    while True:
        payload = inventory()
        payload["nodeKey"] = node_key
        try:
            result = post_json(f"{server}/api/checkin", payload)
            print(f"Checked in device {result.get('deviceId')} ({payload['hostname']})")
            backoff = 5
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if exc.code == 401:
                print(f"Check-in unauthorized: {body}", file=sys.stderr)
                if not args.enroll_secret:
                    return 1
                try:
                    if state.exists():
                        state.unlink()
                    node_key = enroll(server, args.enroll_secret, state)
                except urllib.error.HTTPError as enroll_exc:
                    print(
                        f"Re-enroll failed: {enroll_exc.read().decode('utf-8', errors='replace')}",
                        file=sys.stderr,
                    )
                    return 1
                if args.once:
                    continue
            else:
                print(f"Check-in failed ({exc.code}): {body}", file=sys.stderr)
                if args.once:
                    return 1
                time.sleep(backoff)
                backoff = min(backoff * 2, 300)
                continue
        except urllib.error.URLError as exc:
            print(f"Check-in error: {exc}", file=sys.stderr)
            if args.once:
                return 1
            time.sleep(backoff)
            backoff = min(backoff * 2, 300)
            continue
        if args.once:
            return 0
        time.sleep(max(5, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
