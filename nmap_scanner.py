#!/usr/bin/env python3
"""
nmap_scanner.py — Interactive nmap scanning shell.

Python rewrite of a bash nmap menu tool, built around:
  - cmd.Cmd for a proper interactive shell — readline history/editing for
    free, real per-command help (`help syn`), tab completion of commands.
  - subprocess with argument lists instead of a shell string + eval — no
    injection risk, regardless of what ends up in a target or custom flags.
  - a VPN check ported from od-clone.sh's approach, but adapted for a real
    constraint specific to nmap: SYN/UDP/ACK/XMAS/NULL/FIN scans and OS
    detection all use raw sockets, which a SOCKS wrapper (torsocks/
    proxychains) CANNOT intercept the way it can for plain HTTP — those
    tools only see normal connect() calls. A VPN (network-layer tunnel)
    genuinely covers this traffic; a SOCKS proxy would either silently
    fail open or just error, either way giving false confidence. That's
    why there's no proxy-wrapper option here, only a VPN check.

Usage:
    python3 nmap_scanner.py
"""

import cmd
import ipaddress
import json
import os
import re
try:
    import readline  # noqa: F401 — enables line editing/history in cmd.Cmd
    HAVE_READLINE = True
except ImportError:
    # readline is Unix-only in the stdlib; on Windows this simply isn't
    # available (pyreadline3 is a possible substitute, but not required —
    # the shell still works fine without it, just without persistent
    # history/line-editing).
    HAVE_READLINE = False
import shlex
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

HISTORY_FILE = Path.home() / ".nmap_scanner_history"


# ---------- color helpers (no external deps) ----------
class C:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    MAGENTA = "\033[0;35m"
    CYAN = "\033[0;36m"
    WHITE = "\033[1;37m"
    GRAY = "\033[0;90m"
    BOLD = "\033[1m"
    NC = "\033[0m"


def use_color():
    return sys.stdout.isatty()


def paint(text, *codes):
    if not use_color():
        return text
    return "".join(codes) + text + C.NC


def ok(msg):
    print(f"{paint('✓', C.GREEN)} {msg}")


def err(msg):
    print(f"{paint('✗', C.RED)} {msg}")


def warn(msg):
    print(f"{paint('⚠', C.YELLOW)} {msg}")


def info(msg):
    print(f"{paint('ℹ', C.CYAN)} {msg}")


def section(title):
    bar = "━" * 60
    print(f"\n{paint(bar, C.BLUE, C.BOLD)}")
    print(paint(title, C.WHITE))
    print(f"{paint(bar, C.BLUE, C.BOLD)}\n")


BANNER = r"""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║              NMAP SCANNER TOOL — Python Edition                ║
║              Network Reconnaissance Made Easy                 ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""


def print_banner():
    print(paint(BANNER, C.CYAN, C.BOLD))


# ---------- scan type definitions ----------
# name -> (description, base nmap args, warning note or None)
SCAN_TYPES = {
    "syn":     ("TCP SYN Scan", ["-sS", "-T4", "-v"],
                "Raw sockets — needs root, and a VPN (not torsocks/proxychains) to actually cover the traffic."),
    "connect": ("TCP Connect Scan", ["-sT", "-T4", "-v"], None),
    "udp":     ("UDP Scan (top 100 ports)", ["-sU", "-T4", "-v", "--top-ports", "100"],
                "UDP scans are slow; limited to top 100 ports."),
    "ack":     ("TCP ACK Scan (firewall rule detection)", ["-sA", "-T4", "-v"],
                "Raw sockets — same VPN-only caveat as SYN."),
    "ping":    ("Ping Sweep", ["-sn"], None),
    "xmas":    ("XMAS Scan", ["-sX", "-T4", "-v"], "Raw sockets — VPN-only caveat applies."),
    "null":    ("NULL Scan", ["-sN", "-T4", "-v"], "Raw sockets — VPN-only caveat applies."),
    "fin":     ("FIN Scan", ["-sF", "-T4", "-v"], "Raw sockets — VPN-only caveat applies."),
    "os":      ("OS & Service Detection", ["-sV", "-O", "-A", "-T4", "-v"],
                "Aggressive, can take a while. Raw sockets — VPN-only caveat applies."),
    "quick":   ("Quick Scan (top 100 ports)", ["-T4", "-F", "-v"], None),
    "intense": ("Intense Scan (all 65535 ports)", ["-p-", "-T4", "-A", "-v"],
                "Scans every port — can take a long time."),
    "vuln":    ("Vulnerability Scan (NSE scripts)", ["-sV", "--script", "vuln", "-T4", "-v"], None),
    "noping":  ("No-Ping Scan (-Pn)", ["-Pn", "-T4", "-v"], "Scans even if the host appears to be down."),
}

GEO_SERVICES = [
    "https://ipinfo.io/json",
    "https://ifconfig.co/json",
    "https://api.ipify.org?format=json",
]


def geolocate_current_ip(timeout=6):
    """Best-effort public IP/geolocation lookup. Returns a dict or None."""
    for svc in GEO_SERVICES:
        try:
            req = urllib.request.Request(svc, headers={"User-Agent": "curl/8.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if "ip" in data:
                return {
                    "ip": data.get("ip", "unknown"),
                    "city": data.get("city", "unknown"),
                    "region": data.get("region", "unknown"),
                    "country": data.get("country", "unknown"),
                    "org": data.get("org", data.get("asn", "unknown")),
                }
        except (urllib.error.URLError, socket.timeout, TimeoutError, json.JSONDecodeError, ValueError):
            continue
    return None


def print_geo_box(geo):
    print()
    print("==================== CURRENT EGRESS IP ====================")
    print(f"  Public IP:  {geo['ip']}")
    print(f"  Location:   {geo['city']}, {geo['region']}, {geo['country']}")
    print(f"  Org/ASN:    {geo['org']}")
    print("=============================================================")


def yes(prompt):
    return input(prompt).strip().lower() in ("y", "yes")


def check_vpn():
    """
    Ported from od-clone.sh's VPN check. Unlike that tool, there is
    deliberately no torsocks/proxychains option — see module docstring for
    why (raw-socket scan types can't be routed through a SOCKS wrapper).
    """
    section("VPN CHECK")
    on_vpn = yes(paint("Are you currently running a VPN (e.g. ProtonVPN)? (yes/no): ", C.GREEN))

    if on_vpn:
        info("Pulling current public IP/geolocation so you can confirm it's your VPN exit...")
        geo = geolocate_current_ip()
        if geo:
            print_geo_box(geo)
            if not yes("Does the above look like your VPN exit (NOT your real ISP/location)? (yes/no): "):
                err("Aborted — verify your VPN is actually active/routing before re-running.")
                sys.exit(1)
            ok("VPN confirmed.")
        else:
            warn("Could not reach a geolocation service to verify your egress IP.")
            warn("This usually means your VPN/network is blocking outbound HTTPS to these")
            warn("lookup services specifically, or DNS is misbehaving — not necessarily that")
            warn("your VPN itself is down.")
            if not yes("Continue anyway, assuming your VPN is active? (yes/no): "):
                err("Aborted. Re-run once you've confirmed your VPN is active.")
                sys.exit(1)
        return True

    warn("No VPN reported.")
    warn("Unlike HTTP-based tools, torsocks/proxychains CANNOT cover most nmap scan")
    warn("types — SYN/UDP/ACK/XMAS/NULL/FIN scans and OS detection all use raw")
    warn("sockets, which SOCKS wrappers cannot intercept. Only a real VPN covers")
    warn("this traffic, which is why there's no proxy-wrapper option here.")
    if not yes("Proceed anyway, accepting your real IP will be visible to the target? (yes/no): "):
        err("Aborted.")
        sys.exit(1)
    return False


def check_root():
    section("SYSTEM CHECK")
    if os.geteuid() != 0:
        warn("Not running as root. Some scans need root for best results:")
        print(f"  {paint('SYN/ACK/XMAS/NULL/FIN scans and OS detection all need root.', C.GRAY)}")
        if input("Continue anyway? (y/n): ").strip().lower() != "y":
            sys.exit(0)
    else:
        ok("Running with root privileges")


def check_nmap():
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        err("nmap is not installed!")
        print(f"  {paint('Install it with: sudo apt install nmap   (mac: brew install nmap)', C.GRAY)}")
        sys.exit(1)
    try:
        version_line = subprocess.run(
            [nmap_path, "--version"], capture_output=True, text=True, timeout=10
        ).stdout.splitlines()[0]
    except Exception:
        version_line = nmap_path
    ok(f"nmap found: {version_line}")
    return nmap_path


# ---------- target validation ----------
def validate_target(target: str) -> bool:
    target = target.strip()
    if not target:
        return False

    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False

    m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", target)
    if m:
        prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
        try:
            ipaddress.ip_address(prefix + str(start))
        except ValueError:
            return False
        return 0 <= start <= 255 and 0 <= end <= 255 and start <= end

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # If it's shaped like an IPv4 address (four dot-separated numeric
    # groups) but failed ip_address() above, it's an invalid IP — don't
    # let it fall through to the hostname check just because a hostname
    # label is technically allowed to be all-digit (e.g. 999.999.999.999
    # would otherwise incorrectly validate as a "hostname").
    if re.match(r"^\d+(\.\d+)+$", target):
        return False

    # Hostname: dot-separated labels, alnum/hyphen, no leading/trailing hyphen
    return bool(re.match(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$", target
    ))


def safe_filename(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", target)


def make_scan_handler(name, desc, base_args, note):
    def handler(self, arg):
        target = self._resolve_target(arg)
        if not target:
            return
        if note:
            warn(note)
        self._run_scan(desc, list(base_args), target)
    handler.__doc__ = f"{name} [target]   — {desc}" + (f"  ({note})" if note else "")
    return handler


class NmapShell(cmd.Cmd):
    prompt_base = "nmap-scanner"
    intro = ""

    def __init__(self, nmap_path: str, output_dir: Path, on_vpn: bool):
        super().__init__()
        self.nmap_path = nmap_path
        self.output_dir = output_dir
        self.on_vpn = on_vpn
        self.target = None
        # Bind one do_<name> per scan type so `help` and tab-completion see
        # them as real commands, not a hand-rolled dispatch in default().
        for name, (desc, base_args, note) in SCAN_TYPES.items():
            setattr(self, f"do_{name}", make_scan_handler(name, desc, base_args, note).__get__(self))
        self.update_prompt()

    def get_names(self):
        # cmd.Cmd's default only inspects dir(self.__class__), which misses
        # the do_<scan> methods bound onto the instance in __init__ above —
        # without this override, `help` and tab-completion would silently
        # not know about syn/connect/ping/etc. even though they work fine
        # when actually typed (dispatch uses getattr(self, ...), which does
        # see instance attributes; only the enumeration for `help` doesn't).
        return list(super().get_names()) + [f"do_{name}" for name in SCAN_TYPES]

    def update_prompt(self):
        t = self.target or "(no target)"
        self.prompt = f"{paint(self.prompt_base, C.GREEN)}[{paint(t, C.BOLD)}]> "

    # ---------- built-in commands ----------
    def do_target(self, arg):
        "target [host|ip|cidr|range]   — set the current target, or show it with no argument"
        arg = arg.strip()
        if not arg:
            print(self.target or "(no target set)")
            return
        if not validate_target(arg):
            err(f"Invalid target format: {arg}")
            return
        self.target = arg
        ok(f"Target set: {arg}")
        self.update_prompt()

    def do_vpn(self, arg):
        "vpn   — re-run the VPN/egress-IP check"
        self.on_vpn = check_vpn()

    def do_scans(self, arg):
        "scans   — list available scan types"
        section("AVAILABLE SCANS")
        for name, (desc, _, note) in SCAN_TYPES.items():
            print(f"  {paint(name, C.GREEN):<10} {desc}")
            if note:
                print(f"             {paint(note, C.GRAY)}")
        print(f"\n  {paint('custom', C.GREEN):<10} Enter your own nmap flags")
        print("\nRun one with e.g.  syn   or  syn 192.168.1.5  (overrides target for this scan only)")

    def do_custom(self, arg):
        "custom [target]   — enter your own nmap flags interactively"
        target = self._resolve_target(arg)
        if not target:
            return
        flags = input(paint("Enter custom nmap flags: ", C.CYAN)).strip()
        try:
            extra_args = shlex.split(flags)
        except ValueError as e:
            err(f"Could not parse flags: {e}")
            return
        if not extra_args:
            err("No flags entered.")
            return
        self._run_scan("Custom Scan", extra_args, target)

    def do_output(self, arg):
        "output   — show where scan results are being saved"
        info(f"Scan results are saved in: {self.output_dir}")

    def do_exit(self, arg):
        "exit   — quit the tool"
        return self._goodbye()

    def do_quit(self, arg):
        "quit   — quit the tool"
        return self._goodbye()

    def do_EOF(self, arg):
        print()
        return self._goodbye()

    def emptyline(self):
        pass  # don't repeat the last command on a blank Enter (cmd's default)

    def default(self, line):
        cmd_name = line.split()[0] if line.split() else line
        err(f"Unknown command: {cmd_name!r}. Type 'scans' to list scan types or 'help' for all commands.")

    def _goodbye(self):
        print()
        section("GOODBYE")
        print(f"Scan results saved in: {paint(str(self.output_dir), C.CYAN)}")
        print(paint("Stay safe and scan responsibly!\n", C.GRAY))
        return True

    def _resolve_target(self, arg_target: str):
        arg_target = (arg_target or "").strip()
        if arg_target:
            if not validate_target(arg_target):
                err(f"Invalid target format: {arg_target}")
                return None
            return arg_target
        if not self.target:
            err("No target set. Use 'target <host>' first, or pass one inline: e.g. 'syn 192.168.1.5'")
            return None
        return self.target

    def _run_scan(self, description, args, target):
        section(f"EXECUTING: {description}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_base = self.output_dir / f"scan_{timestamp}_{safe_filename(target)}"
        txt_path = out_base.with_suffix(".txt")

        full_cmd = [self.nmap_path, *args, "-oN", str(txt_path), target]
        rendered = " ".join(shlex.quote(a) for a in full_cmd)
        print(paint(f"Command: {rendered}", C.GRAY))
        print()
        info("Scan in progress... (Ctrl+C to stop early)")
        print()

        header = (
            "============================================\n"
            f"Scan Type: {description}\n"
            f"Target: {target}\n"
            f"Date: {datetime.now()}\n"
            f"Command: {rendered}\n"
            "============================================\n\n"
        )
        print(header, end="")

        proc = None
        interrupted = False
        try:
            proc = subprocess.Popen(
                full_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )
            for line in proc.stdout:
                print(line, end="")
            proc.wait()
        except KeyboardInterrupt:
            interrupted = True
            warn("Interrupted — stopping nmap...")
            if proc:
                for attempt in range(3):
                    try:
                        if attempt == 0:
                            proc.terminate()
                        else:
                            proc.kill()
                        proc.wait(timeout=5)
                        break
                    except subprocess.TimeoutExpired:
                        continue
                    except KeyboardInterrupt:
                        # A second Ctrl+C arrived while we were already
                        # cleaning up from the first — escalate straight to
                        # a hard kill on the next loop iteration rather than
                        # letting this propagate as an unhandled traceback.
                        continue
                    except ProcessLookupError:
                        break
        except FileNotFoundError:
            err(f"Could not execute: {full_cmd[0]}")
            return

        # nmap's own -oN already wrote the plain-text report to txt_path;
        # wrap it with the same header/footer that was printed to screen so
        # the saved file matches what the user watched happen.
        try:
            existing = txt_path.read_text() if txt_path.exists() else ""
            footer = "\n--- INTERRUPTED BY USER ---\n" if interrupted else "\n"
            txt_path.write_text(header + existing + footer)
        except OSError as e:
            warn(f"Could not finalize output file: {e}")

        print()
        if interrupted:
            warn("Scan interrupted.")
        else:
            ok("Scan complete!")
        info(f"Results saved to: {txt_path}")


def main():
    print_banner()
    nmap_path = check_nmap()
    check_root()
    on_vpn = check_vpn()

    output_dir = Path.home() / "nmap_scans"
    output_dir.mkdir(parents=True, exist_ok=True)

    section("TARGET SELECTION")
    print("Enter target IP, range, CIDR, or hostname. Examples:")
    print(f"  {paint('192.168.1.1', C.CYAN)}        Single IP")
    print(f"  {paint('192.168.1.0/24', C.CYAN)}     CIDR notation")
    print(f"  {paint('192.168.1.1-50', C.CYAN)}     Range")
    print(f"  {paint('scanme.nmap.org', C.CYAN)}    Hostname")
    print()
    target = None
    while True:
        target = input(paint("Target: ", C.GREEN)).strip()
        if not target:
            err("Target cannot be empty")
            continue
        if validate_target(target):
            ok(f"Target validated: {target}")
            break
        err("Invalid target format")

    if HAVE_READLINE and HISTORY_FILE.exists():
        try:
            readline.read_history_file(HISTORY_FILE)
        except OSError:
            pass

    shell = NmapShell(nmap_path, output_dir, on_vpn)
    shell.target = target
    shell.update_prompt()

    section("READY")
    print("Type 'scans' to list scan types, 'help' for all commands, 'exit' to quit.\n")

    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print()
        shell._goodbye()
    finally:
        if HAVE_READLINE:
            try:
                readline.write_history_file(HISTORY_FILE)
            except OSError:
                pass


if __name__ == "__main__":
    main()
