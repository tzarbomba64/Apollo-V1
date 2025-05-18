#Please kindly consider killing me
import subprocess
import random
import sys
import re
from urllib.parse import urlparse

# Fake log messages
FAKE_RESPONSES = [
    "Error code 0xC0000005 at module ntoskrnl.exe",
    "Driver load failure: usbcore",
    "Buffer overflow detected in process authd",
    "Segmentation fault at address 0x7ffdf000",
    "Kernel panic: not syncing: CPU stuck",
    "Hardware interrupt: 0x2F received with no handler",
    "Memory leak detected in daemon drserv",
    "Access violation at address 0x00400000",
    "Unhandled exception caught in service mgr",
    "Stack overflow in thread Thread-7",
    "Error in output: bot.net failed to load",
    "Running, please wait...ERROR at assets/rip/scripts",
    "Running, please wait...SUCCESS",
]

# Paths
EGGSHELL_PATH = "/home/kali/Downloads/eggshell.py"
APOLLO_PATH = "/home/kali/Downloads/apollo.py"

def run_shell(cmd, capture=False, timeout=None):
    """Run a shell command, optionally capture output, with optional timeout."""
    try:
        res = subprocess.run(
            cmd, shell=True,
            capture_output=capture, text=True,
            timeout=timeout
        )
        if capture:
            return (res.stdout or "") + (res.stderr or "")
        else:
            if res.stdout:
                sys.stdout.write(res.stdout)
            if res.stderr:
                # drop stderr silently
                pass
    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out: {cmd}")
    except Exception:
        pass
    return ""

def apollo_u():
    """Scan for admin accounts via Apollo -u"""
    target = input("Enter target URL for admin scan: ").strip()
    print("[+] Scanning for administrative accounts...")
    output = run_shell(f"python3 {APOLLO_PATH} -u {target}", capture=True, timeout=60)
    harvest = run_shell(
        f"theHarvester -d {urlparse(target).netloc} -l 50 -b all",
        capture=True, timeout=30
    )
    findings = []
    for line in (output + harvest).splitlines():
        if "admin" in line.lower() or re.search(r"@.+\..+", line):
            findings.append(line.strip())
    print("\n[+] Summary of potential admin leaks:")
    if findings:
        for i, f in enumerate(findings, 1):
            print(f"{i}. {f}")
    else:
        print("No admin-related data found.")

def apollo_s():
    """Perform website server scan with Apollo -s"""
    target = input("Enter website URL for server scan: ").strip()
    print("[+] Performing server scan on target...")
    # Here you can customize the actual scanning logic; for now, simulate
    print(f"[INFO] Scanning {target} for potential leaks...")
    # For demo, just simulate with a sleep and print results:
    import time
    time.sleep(3)
    print("[+] Found paths of interest:")
    print(" - /login")
    print(" - /signup")
    print(" - /user/profile")
    print("\n[+] Scan complete.")

def qore_browse_k():
    """Network scan for IPs and usernames."""
    print("[+] Scanning network for live hosts...")
    netscan = run_shell("nmap -sn 192.168.1.0/24", capture=True, timeout=30)
    hosts = re.findall(r"Nmap scan report for ([0-9\.]+)", netscan)
    summary = []
    for ip in hosts:
        out = run_shell(f"smbclient -L {ip} -N", capture=True, timeout=20)
        users = re.findall(r"Disk\s+(.+?)\s+", out)
        summary.append((ip, users or ["<no shares>"]))
    print("\n[+] Network host → users:")
    for ip, users in summary:
        print(f"{ip}: {', '.join(users)}")

def qore_browse_s():
    """Server scan for leaking traffic on a website."""
    target = input("Enter website URL for server scan: ").strip()
    host = urlparse(target if "://" in target else f"//{target}", scheme="http").hostname
    print("[+] Enumerating web paths...")
    gob = run_shell(
        f"gobuster dir -u http://{host} -w /usr/share/wordlists/dirb/common.txt",
        capture=True, timeout=30
    )
    creds = [l for l in gob.splitlines() if any(p in l.lower() for p in ("login","signup","user","id"))]
    print("\n[+] Paths of interest:")
    for p in creds:
        print(f" - {p}")

def main():
    while True:
        try:
            cmd = input("eggshell> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not cmd:
            continue

        lc = cmd.lower()
        if lc in ("exit", "quit"):
            break

        # Apollo commands
        if lc == "apollo -k":
            print("[+] Launching Apollo interactive scan...")
            run_shell(f"python3 {APOLLO_PATH} -K", timeout=350)
            continue
        if lc == "apollo -u":
            apollo_u()
            continue
        if lc == "apollo -s":
            apollo_s()
            continue

        # Qore.browse commands
        if lc == "qore.browse -k":
            qore_browse_k()
            continue
        if lc == "qore.browse -s":
            qore_browse_s()
            continue

        # Log unrecognized Apollo/bootsect commands
        if "apollo" in lc or "bootsect" in lc:
            print(random.choice(FAKE_RESPONSES))
            continue

        # Otherwise, try to run as shell command
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.stdout:
            sys.stdout.write(res.stdout)
        elif res.returncode != 0:
            # 20% chance for fake log on errors/unrecognized
            if random.random() < 0.2:
                print(random.choice(FAKE_RESPONSES))

    print("Session terminated.")

if __name__ == "__main__":
    main()
