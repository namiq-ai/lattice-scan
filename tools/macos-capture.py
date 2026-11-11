#!/usr/bin/env python3
"""Read-only capture of what a Mac shows, for building and testing macOS support. Standard library only. No network. Writes nothing but one JSON file.

It reads: the system version file, `sw_vers`, `uname`, the hardware overview (identifiers dropped), the names and versions of apps in /Applications and
/System/Applications, the Homebrew Cellar layout (files only; `brew` is never run), and which Python versions exist. It does not read Desktop, Documents,
Downloads, iCloud, Photos or ~/Library (macOS would ask the user for permission), and it never prints serial numbers, UUIDs, user names or host names.

    python3 tools/macos-capture.py capture.json
"""
import json
import os
import platform
import plistlib
import subprocess
import sys
import time

DROP = ("serial", "uuid", "udid", "provisioning", "platform_cpu_serial", "host_name", "user_name", "hardware_uuid", "activation_lock", "boot_rom", "os_loader")


def run(cmd, timeout=20):
    t = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return {"rc": r.returncode, "out": r.stdout.strip(), "err": r.stderr.strip()[:300], "seconds": round(time.time() - t, 2)}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"rc": None, "out": "", "err": type(e).__name__, "seconds": round(time.time() - t, 2)}


def plist(path):
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception as e:   # unreadable, missing or not a plist: record why, never stop
        return {"_error": type(e).__name__}


def scrub(o):
    if isinstance(o, dict):
        return {k: scrub(v) for k, v in o.items() if not any(d in k.lower() for d in DROP)}
    if isinstance(o, list):
        return [scrub(v) for v in o]
    return o


def apps(folder):
    out = {}
    try:
        names = sorted(n for n in os.listdir(folder) if n.endswith(".app"))
    except OSError as e:
        return {"_error": type(e).__name__}
    for n in names:
        p = plist(os.path.join(folder, n, "Contents", "Info.plist"))
        out[n] = {k: p.get(k) for k in ("CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion") if k in p} or p
    return out


def cellar():
    for prefix in ("/opt/homebrew", "/usr/local"):
        c = os.path.join(prefix, "Cellar")
        if os.path.isdir(c):
            try:
                return {"prefix": prefix, "formulae": {n: sorted(os.listdir(os.path.join(c, n))) for n in sorted(os.listdir(c))[:400]}}
            except OSError as e:
                return {"prefix": prefix, "_error": type(e).__name__}
    return {"prefix": None}


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    sv = "/System/Library/CoreServices/SystemVersion.plist"
    data = {
        "captured": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": {"this": sys.version.split()[0], "platform": platform.platform()},
        "uname": run(["uname", "-a"])["out"].split(" ", 2)[0:1] + [platform.release(), platform.machine()],
        "systemVersionPlist": plist(sv),
        "swVers": {k: run(["sw_vers", f"--{k}"]) for k in ("productName", "productVersion", "productVersionExtra", "buildVersion")},
        "hardware": {},
        "apps": {"/Applications": apps("/Applications"), "/System/Applications": apps("/System/Applications")},
        "homebrew": cellar(),
        "pythonOnPath": {p: run([p, "--version"]) for p in ("/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3") if os.path.exists(p)},
        "runnerImage": {k: os.environ.get(k) for k in ("ImageOS", "ImageVersion", "RUNNER_ARCH") if os.environ.get(k)},
    }
    hw = run(["system_profiler", "SPHardwareDataType", "-json", "-detailLevel", "mini"], timeout=60)
    try:
        data["hardware"] = {"seconds": hw["seconds"], "rc": hw["rc"], "data": scrub(json.loads(hw["out"]))}
    except ValueError:
        data["hardware"] = {"seconds": hw["seconds"], "rc": hw["rc"], "error": "not JSON"}
    with open(sys.argv[1], "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.chmod(sys.argv[1], 0o600)
    print(f"wrote {sys.argv[1]}: {len(data['apps']['/Applications'])} apps in /Applications, Homebrew {data['homebrew'].get('prefix') or 'not found'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
