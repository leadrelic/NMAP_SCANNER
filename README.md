
# Nmap Scanner Tool

## Overview
This script is a Bash utility that leverages **Nmap**, a powerful network scanning tool, to perform various scans on a specified IP address or range. The script allows users to choose from different scan types and performs the selected scan on the target, providing flexibility and efficiency for network reconnaissance tasks.

## Features
- **Interactive Menu**: Allows users to choose from 10 different scan types, including TCP SYN, UDP, and OS fingerprinting.
- **Input Validation**: Ensures that the user provides a valid target IP or range and selects a valid scan option.
- **User Feedback**: Displays the selected target and the type of scan being performed.
- **Option to Quit**: Users can exit the script at any time by selecting the `QUIT` option.

## Available Scan Types
1. **TCP SYN Scan**: A stealthy scan that attempts to initiate a connection without completing the handshake.
2. **TCP CONNECT Scan**: Establishes a full connection to each port, providing a complete scan result.
3. **UDP Scan**: Checks for open UDP ports, which are often harder to scan.
4. **TCP ACK Scan**: Used to map out firewall rules and check if they are stateful.
5. **Ping Sweep Scan**: Identifies live hosts in the specified range.
6. **XMAS Scan**: Sends a sequence of flags to detect closed ports.
7. **Ping Sweep with Hosts' Ports**: Attempts to identify hosts while also scanning for open ports.
8. **NULL Scan**: Sends no TCP flags, often used to identify closed ports.
9. **FIN Scan**: Sends a FIN flag to detect closed ports.
10. **OS Fingerprinting Scan**: Attempts to detect the operating system of the target.

## Prerequisites
- **Bash**: Ensure you are running the script in a Unix-like environment.
- **Nmap**: Install Nmap using the following command:
  ```bash
  sudo apt-get install nmap
  ```

## Usage
1. Clone or download this script.
2. Make the script executable:
   ```bash
   chmod +x nmap_scanner.sh
   ```
3. Run the script:
   ```bash
   ./nmap_scanner.sh
   ```
4. Enter the target IP address or range when prompted.
5. Choose a scan option from the menu (1-11).

## Example
```bash
Enter Target IP or IP Range (e.g., 192.168.1.0/24 for a subnet):
Target: 192.168.1.0/24
Target IP is 192.168.1.0/24
[1] TCP SYN PORT SCAN
[2] TCP CONNECT PORT SCAN
[3] UDP PORT SCAN
[4] TCP ACK PORT SCAN
[5] PING SWEEP SCAN
[6] XMAS SCAN
[7] PING SWEEP WITH HOSTS PORTS
[8] NULL SCAN
[9] FIN SCAN
[10] OS FINGERPRINTING SCAN
[11] QUIT
Choose an option: 1
```
This example runs a **TCP SYN scan** on the specified IP range `192.168.1.0/24`.

## Notes
- Ensure that you have proper authorization before scanning any IP addresses or ranges.
- Some scan types may require elevated privileges (root access).
- Using Nmap for scanning networks without permission can be illegal and may result in consequences.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
