# 🔍 NMAP Scanner Tool - Enhanced Edition

A powerful, user-friendly Bash wrapper for Nmap that simplifies network reconnaissance with an intuitive interface, automatic output logging, and advanced scanning capabilities.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Bash](https://img.shields.io/badge/bash-5.0%2B-green.svg)
![Nmap](https://img.shields.io/badge/nmap-required-red.svg)

## ✨ Features

### 🎨 Beautiful Interface
- **Color-coded output** - Easy-to-read terminal interface with status indicators
- **ASCII art banner** - Professional presentation
- **Organized menus** - Scans categorized by type (Stealth, Advanced, Evasion, Comprehensive)
- **Progress indicators** - Real-time feedback during scans

### 🛡️ Comprehensive Scanning Options

#### Stealth & Recon Scans
- **TCP SYN Scan** - Fast, stealthy half-open scan
- **TCP Connect Scan** - Full connection (no root required)
- **Ping Sweep** - Discover live hosts on network

#### Advanced Scans
- **UDP Scan** - Detect open UDP ports
- **TCP ACK Scan** - Firewall rule detection
- **OS & Service Detection** - Fingerprint operating systems and services

#### Evasion Scans
- **XMAS Scan** - FIN, PSH, URG flags set
- **NULL Scan** - No TCP flags set
- **FIN Scan** - Only FIN flag set

#### Comprehensive Scans
- **Quick Scan** - Top 100 ports for fast results
- **Intense Scan** - All 65,535 ports with aggressive detection
- **Vulnerability Scan** - NSE vulnerability scripts

### 📊 Smart Features
- **Automatic output logging** - All scans saved to `~/nmap_scans/` with timestamps
- **Input validation** - Supports IPs, CIDR notation, ranges, and hostnames
- **Root privilege detection** - Warns when elevated privileges needed
- **Custom command mode** - Enter your own nmap flags
- **Scan metadata** - Each output includes timestamp, target, and command used

## 📋 Prerequisites

### Required
- **Bash** 4.0 or higher
- **Nmap** - Network scanning tool
- **Linux/Unix** environment (tested on Ubuntu/Debian)

### Installation

#### Install Nmap (if not already installed)

**Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install nmap
```

**RedHat/CentOS/Fedora:**
```bash
sudo yum install nmap
```

**macOS:**
```bash
brew install nmap
```

#### Download the Script
```bash
# Clone or download the script
wget https://leadrelic/nmap_scanner.sh
# Or
curl -O https://leadrelic/nmap_scanner.sh

# Make it executable
chmod +x nmap_scanner.sh
```

## 🚀 Usage

### Basic Usage
```bash
./nmap_scanner.sh
```

### With Root Privileges (Recommended)
```bash
sudo ./nmap_scanner.sh
```

> **Note:** Some scans (SYN, OS detection) require root privileges for optimal results.

### Example Session
```
1. Run the script
2. Enter target (e.g., 192.168.1.0/24)
3. Choose scan type from menu
4. View results in real-time
5. Results auto-saved to ~/nmap_scans/
```

## 🎯 Target Format Examples

| Format | Example | Description |
|--------|---------|-------------|
| Single IP | `192.168.1.1` | Scan one host |
| CIDR Notation | `192.168.1.0/24` | Scan entire subnet |
| IP Range | `192.168.1.1-50` | Scan IP range |
| Hostname | `scanme.nmap.org` | Scan by hostname |

## 📖 Scan Type Guide

### When to Use Each Scan

| Scan Type | Use Case | Speed | Stealth | Root Required |
|-----------|----------|-------|---------|---------------|
| **TCP SYN** | General port scanning | Fast | High | Yes |
| **TCP Connect** | When root unavailable | Medium | Low | No |
| **UDP** | Finding UDP services | Slow | Medium | Yes |
| **TCP ACK** | Testing firewall rules | Fast | High | Yes |
| **Ping Sweep** | Host discovery | Very Fast | Medium | No |
| **XMAS/NULL/FIN** | Firewall evasion | Medium | Very High | Yes |
| **OS Detection** | System fingerprinting | Slow | Low | Yes |
| **Quick Scan** | Fast overview | Very Fast | Low | No |
| **Intense Scan** | Complete assessment | Very Slow | Low | Yes |
| **Vuln Scan** | Security testing | Slow | Low | Yes |

## 📁 Output Files

All scan results are automatically saved to:
```
~/nmap_scans/scan_YYYYMMDD_HHMMSS_target.txt
```

### Output Format
Each file includes:
- Scan type and description
- Target information
- Timestamp
- Full nmap command used
- Complete scan results

### Example Output File
```
~/nmap_scans/scan_20260129_143022_192_168_1_0_24.txt
```

## ⚙️ Configuration

### Change Output Directory
Edit the script and modify:
```bash
OUTPUT_DIR="$HOME/nmap_scans"
```

### Adjust Default Timing
Scans use `-T4` timing by default. Modify in the script:
- `-T0` - Paranoid (slowest, most stealthy)
- `-T1` - Sneaky
- `-T2` - Polite
- `-T3` - Normal
- `-T4` - Aggressive (default)
- `-T5` - Insane (fastest, least stealthy)

## 🔒 Security & Legal Considerations

### ⚠️ IMPORTANT WARNINGS

1. **Only scan networks you own or have explicit permission to test**
2. **Unauthorized scanning may be illegal in your jurisdiction**
3. **Some scans are aggressive and may trigger IDS/IPS systems**
4. **Always obtain written permission before scanning**

### Ethical Usage
This tool is designed for:
- ✅ Learning and education
- ✅ Authorized security assessments
- ✅ Testing your own networks
- ✅ Bug bounty programs (with proper authorization)

Do NOT use for:
- ❌ Unauthorized network scanning
- ❌ Malicious reconnaissance
- ❌ Violating terms of service
- ❌ Any illegal activities

## 🐛 Troubleshooting

### "nmap: command not found"
**Solution:** Install nmap using your package manager (see Prerequisites)

### "Permission denied" errors
**Solution:** Run with sudo for scans requiring root privileges
```bash
sudo ./nmap_scanner.sh
```

### Slow UDP scans
**Solution:** UDP scans are inherently slow. The script limits to top 100 ports by default. For specific ports:
```bash
# Use custom command option (15) with:
-sU -p 53,161,162
```

### "Operation not permitted"
**Solution:** Some scans require root. Run with sudo or choose TCP Connect scan (option 2)

### Firewall blocking scans
**Solution:** 
- Ensure outbound traffic is allowed
- Try different scan types (XMAS, NULL, FIN for evasion)
- Use `-Pn` flag (option 7) to skip ping

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional scan presets
- Export to different formats (JSON, XML, CSV)
- Integration with vulnerability databases
- Scan result parsing and visualization
- Port to other shells (zsh, fish)

## 📝 Changelog

### Version 2.0 (Enhanced Edition)
- ✨ Complete UI overhaul with colors and formatting
- ✨ Added Quick, Intense, and Vulnerability scans
- ✨ Automatic output logging with timestamps
- ✨ Enhanced input validation
- ✨ Root privilege detection
- ✨ Custom command mode
- ✨ Organized scan categories
- 🐛 Fixed input validation edge cases
- 📚 Comprehensive documentation

### Version 1.0 (Original)
- Basic scan functionality
- Simple menu system
- 10 scan types

## 📜 License

MIT License - See LICENSE file for details

## 👨‍💻 Author

Created for security professionals, penetration testers, and network administrators who need a streamlined nmap interface.

## 🔗 Resources

- [Official Nmap Documentation](https://nmap.org/book/man.html)
- [Nmap NSE Scripts](https://nmap.org/nsedoc/)
- [Network Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## ⭐ Support

If you find this tool useful:
- Star the repository
- Report bugs via issues
- Submit pull requests
- Share with the community

---

**Remember:** With great power comes great responsibility. Always scan ethically and legally! 🛡️
