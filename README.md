# nmap_scanner.py

An interactive nmap scanning shell — pick a target, pick a scan type (or write your own flags), and go. Built on Python's `cmd` module for a real interactive shell (command history, per-command help, tab-completion) instead of a numbered menu loop.

```bash
python3 nmap_scanner.py
```

## Why this exists

Typing out nmap flags from memory every time gets old, and a lot of "helpful" scanner wrapper scripts make it worse by piping user input through `eval` or a shell string — which means a stray character in a target or a custom flag can do a lot more than you intended. This tool exists to be the convenient version without that tradeoff: every nmap invocation is built as an argument list and executed directly, never through a shell.

It also does something most nmap wrappers don't bother with: it tells you honestly when your OPSEC cover isn't actually covering anything.

## Features

- **Interactive shell**, not a menu you re-read every loop — `cmd`-based, with command history (persisted across sessions in `~/.nmap_scanner_history`), line editing, and real per-command help (`help syn`).
- **No shell, no `eval`** — every nmap call is `subprocess.Popen([...])` with an argument list. A target or custom flag containing shell metacharacters can't do anything but fail target validation.
- **A VPN check that's honest about what it can't fix.** Unlike wrapping plain HTTP traffic, most of nmap's scan techniques (SYN, UDP, ACK, XMAS, NULL, FIN scans, and OS detection) use raw sockets — they bypass the normal `connect()` syscall entirely, which is the *only* thing a SOCKS wrapper like torsocks or proxychains can actually intercept. Offering a "pick your proxy" menu for these scan types would give false confidence, since the wrapper either silently does nothing or just errors. So this tool checks whether you're on a VPN (which operates at the network layer and genuinely does cover this traffic) and warns clearly if you're not — there's no proxy-wrapper option, on purpose.
- **13 built-in scan types**: SYN, TCP connect, UDP, ACK, ping sweep, XMAS, NULL, FIN, OS/service detection, quick (top 100 ports), intense (all 65535 ports), NSE vulnerability scan, and no-ping — plus a `custom` command for raw flags.
- **Per-target or per-scan targeting** — set a target once (`target 10.0.0.5`) and run scans against it, or override for a single scan inline (`syn 10.0.0.9`) without changing your working target.
- **Real output files** — every scan writes nmap's own `-oN` plain-text report to `~/nmap_scans/`, wrapped with a header recording the scan type, target, timestamp, and exact command run.
- **Clean Ctrl+C handling** — stops the running nmap process (escalating to a hard kill if needed) instead of leaving an orphaned scan running in the background, and marks the saved output file as interrupted.

## Requirements

- Python 3.7+ (uses only the standard library — no dependencies to install)
- `nmap` on your `PATH`

```bash
# macOS
brew install nmap

# Debian/Ubuntu
sudo apt install nmap
```

## Usage

```bash
python3 nmap_scanner.py
```

You'll be walked through:

1. **nmap/root check** — confirms nmap is installed and warns if you're not running as root (several scan types need it).
2. **VPN check** — are you on a VPN? If yes, pulls your public IP/geolocation so you can visually confirm it's your VPN exit. If no, you get an explicit warning about which scan types this doesn't protect and have to confirm you understand before proceeding.
3. **Target** — an IP, CIDR range, `a.b.c.d-e` style range, or hostname.

Then you're in the shell:

```
nmap-scanner[10.0.0.5]> scans          # list all scan types
nmap-scanner[10.0.0.5]> syn            # run a SYN scan against the current target
nmap-scanner[10.0.0.5]> udp 10.0.0.9   # run a UDP scan against a different host, just this once
nmap-scanner[10.0.0.5]> target 10.0.0.9  # change the working target
nmap-scanner[10.0.0.5]> custom         # enter raw nmap flags interactively
nmap-scanner[10.0.0.5]> vpn            # re-run the VPN/egress-IP check mid-session
nmap-scanner[10.0.0.5]> output         # show where results are being saved
nmap-scanner[10.0.0.5]> help syn       # see what a specific scan does before running it
nmap-scanner[10.0.0.5]> exit
```

Output lands in `~/nmap_scans/scan_<timestamp>_<target>.txt`.

## A note on the VPN check

If you say yes to being on a VPN, the tool pulls your current public IP/geolocation (via `ipinfo.io`/`ifconfig.co`/`api.ipify.org`) and asks you to visually confirm it looks like your VPN exit, not your real ISP/location — the same idea as checking your IP in a browser before doing anything sensitive, just built in so you don't forget.

If you say no, you get a direct explanation of why this specific tool doesn't offer a proxy-wrapper fallback the way an HTTP-based tool might: SYN/UDP/ACK/XMAS/NULL/FIN scans and OS detection craft raw packets, which never touch the code path a SOCKS proxy hooks into. A VPN is genuinely different here — it's a real network-layer tunnel, so it does carry this traffic. You can still proceed without either, but only after explicitly confirming you understand your real IP will be visible to the target.

## Known limitations

- No IPv6 target support currently.
- The custom-flags command doesn't validate the flags themselves — it'll pass along whatever nmap accepts (or doesn't). Target validation still applies to whatever target you give it.
- Single target per scan invocation; no batch/multi-target queueing.

## Disclaimer

For authorized security testing and research only. You are responsible for ensuring you have permission to scan any target you point this at.
