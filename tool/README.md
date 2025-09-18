# Ethical Hacking Reconnaissance Tool

A comprehensive Python-based reconnaissance tool designed for ethical hacking and penetration testing. This tool provides various reconnaissance capabilities to help security professionals gather information about their targets in a controlled and ethical manner.

## ⚠️ Legal Disclaimer

**This tool is for educational and authorized testing purposes only. Always ensure you have explicit written permission before testing any system. Unauthorized access to computer systems is illegal and unethical.**

## Features

### 🔍 Port Scanning
- Multi-threaded port scanning
- Customizable port ranges
- Common port detection
- Fast and efficient scanning

### 🌐 DNS Enumeration
- A, MX, NS, TXT record enumeration
- Subdomain discovery
- DNS information gathering
- Domain analysis

### 🕷️ Web Vulnerability Scanning
- HTTP/HTTPS status checking
- Server information detection
- Security header analysis
- Technology fingerprinting
- Basic vulnerability detection

### 📁 Directory Enumeration
- Common directory and file discovery
- Customizable wordlists
- Status code analysis
- Hidden resource detection

### 📧 Email Harvesting
- Email pattern discovery
- Common email address generation
- Contact information gathering

### 🌐 Network Discovery
- Host enumeration
- Ping sweep functionality
- Network mapping
- Alive host detection

## Installation

1. Clone or download this repository
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Full reconnaissance scan
python recon_tool.py -t example.com --full-scan

# Port scanning only
python recon_tool.py -t 192.168.1.1 --port-scan --ports 80,443,22,21

# DNS enumeration
python recon_tool.py -t example.com --dns-enum

# Web vulnerability scanning
python recon_tool.py -t example.com --web-scan

# Directory enumeration
python recon_tool.py -t example.com --dir-enum

# Email harvesting
python recon_tool.py -t example.com --email-harvest

# Network discovery
python recon_tool.py -t 192.168.1.0/24 --network-discovery
```

### Advanced Usage

```bash
# Custom port range with more threads
python recon_tool.py -t target.com --port-scan --ports 1-1000 --threads 200

# Save results to file
python recon_tool.py -t target.com --full-scan -o results.json

# Verbose output
python recon_tool.py -t target.com --full-scan -v

# Multiple scan types
python recon_tool.py -t target.com --port-scan --dns-enum --web-scan
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target host or IP address (required) |
| `-o, --output` | Output file for results (JSON format) |
| `-v, --verbose` | Verbose output |
| `--ports` | Comma-separated list of ports to scan |
| `--threads` | Number of threads for scanning (default: 100) |
| `--full-scan` | Run complete reconnaissance scan |
| `--port-scan` | Port scanning only |
| `--dns-enum` | DNS enumeration only |
| `--web-scan` | Web vulnerability scanning only |
| `--dir-enum` | Directory enumeration only |
| `--email-harvest` | Email harvesting only |
| `--network-discovery` | Network discovery only |

## Output

The tool provides:
- Real-time colored output to the terminal
- JSON-formatted results file (if specified)
- Detailed scan summaries
- Timestamped logs

## Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                    ETHICAL HACKING RECON TOOL                ║
║                        Version 1.0.0                         ║
╚══════════════════════════════════════════════════════════════╝

[14:30:15] [INFO] Starting full reconnaissance scan on example.com
[14:30:15] [INFO] Starting port scan...
[14:30:16] [INFO] Port 80 is open
[14:30:16] [INFO] Port 443 is open
[14:30:16] [INFO] Port scan completed. Found 2 open ports
[14:30:16] [INFO] Starting DNS enumeration...
[14:30:17] [INFO] A Record: 93.184.216.34
[14:30:17] [INFO] Found subdomain: www.example.com
[14:30:17] [INFO] DNS enumeration completed
[14:30:17] [INFO] Starting web vulnerability scan...
[14:30:18] [INFO] HTTPS Status: 200
[14:30:18] [INFO] Server: nginx/1.18.0
[14:30:18] [INFO] Web vulnerability scan completed
[14:30:18] [INFO] Full scan completed in 3.45 seconds

=== SCAN SUMMARY ===
Target: example.com
Timestamp: 2024-01-15T14:30:18.123456
Open Ports: 2 (80, 443)
Subdomains Found: 1
A Records: 1
Web Status: 200
Server: nginx/1.18.0
Directories Found: 0
Emails Found: 7
Alive Hosts: 0
```

## Dependencies

- `requests` - HTTP library for web requests
- `dnspython` - DNS toolkit for Python
- `colorama` - Cross-platform colored terminal text

## Ethical Guidelines

1. **Always obtain written permission** before testing any system
2. **Only test systems you own** or have explicit authorization to test
3. **Respect rate limits** and don't overwhelm target systems
4. **Use responsibly** and in accordance with local laws
5. **Report findings** to system owners through proper channels

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational purposes only. The authors are not responsible for any misuse of this tool. Always ensure you have proper authorization before conducting any security testing.
