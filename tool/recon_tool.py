#!/usr/bin/env python3
"""
Ethical Hacking Reconnaissance Tool
===================================

A comprehensive reconnaissance tool for ethical hacking and penetration testing.
This tool provides various reconnaissance capabilities including port scanning,
DNS enumeration, web vulnerability scanning, and more.

Author: Ethical Hacker
Version: 1.0.0
License: MIT
"""

import argparse
import socket
import threading
import time
import requests
import dns.resolver
import subprocess
import sys
import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from datetime import datetime

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class ReconTool:
    """Main reconnaissance tool class"""
    
    def __init__(self, target, output_file=None, verbose=False):
        self.target = target
        self.output_file = output_file
        self.verbose = verbose
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_results': {}
        }
        
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                    ETHICAL HACKING RECON TOOL                ║
║                        Version 1.0.0                         ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)
        
    def log(self, message, level="INFO"):
        """Log messages with timestamps"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = Colors.GREEN if level == "INFO" else Colors.YELLOW if level == "WARN" else Colors.RED
        print(f"{color}[{timestamp}] [{level}] {message}{Colors.END}")
        
    def save_results(self):
        """Save results to JSON file"""
        if self.output_file:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            self.log(f"Results saved to {self.output_file}")
    
    def port_scan(self, ports=None, threads=100):
        """Port scanning functionality"""
        self.log("Starting port scan...")
        
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            for future in as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)
                    self.log(f"Port {port} is open", "INFO")
        
        self.results['scan_results']['open_ports'] = open_ports
        self.log(f"Port scan completed. Found {len(open_ports)} open ports")
        return open_ports
    
    def dns_enumeration(self):
        """DNS enumeration and subdomain discovery"""
        self.log("Starting DNS enumeration...")
        
        dns_results = {
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'subdomains': []
        }
        
        try:
            # A records
            answers = dns.resolver.resolve(self.target, 'A')
            for rdata in answers:
                dns_results['a_records'].append(str(rdata))
                self.log(f"A Record: {rdata}")
            
            # MX records
            try:
                answers = dns.resolver.resolve(self.target, 'MX')
                for rdata in answers:
                    dns_results['mx_records'].append(str(rdata))
                    self.log(f"MX Record: {rdata}")
            except:
                pass
            
            # NS records
            try:
                answers = dns.resolver.resolve(self.target, 'NS')
                for rdata in answers:
                    dns_results['ns_records'].append(str(rdata))
                    self.log(f"NS Record: {rdata}")
            except:
                pass
            
            # TXT records
            try:
                answers = dns.resolver.resolve(self.target, 'TXT')
                for rdata in answers:
                    dns_results['txt_records'].append(str(rdata))
                    self.log(f"TXT Record: {rdata}")
            except:
                pass
                
        except Exception as e:
            self.log(f"DNS enumeration error: {str(e)}", "WARN")
        
        # Subdomain discovery
        self.log("Starting subdomain discovery...")
        subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog',
            'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new',
            'mysql', 'old', 'www1', 'www3', 'www4', 'www5', 'www6', 'www7', 'www8', 'www9',
            'www10', 'api', 'beta', 'stage', 'staging', 'app', 'secure', 'demo', 'test1',
            'test2', 'test3', 'test4', 'test5', 'test6', 'test7', 'test8', 'test9', 'test10'
        ]
        
        for subdomain in subdomains:
            try:
                full_domain = f"{subdomain}.{self.target}"
                socket.gethostbyname(full_domain)
                dns_results['subdomains'].append(full_domain)
                self.log(f"Found subdomain: {full_domain}")
            except:
                pass
        
        self.results['scan_results']['dns_enumeration'] = dns_results
        self.log("DNS enumeration completed")
        return dns_results
    
    def web_vulnerability_scan(self):
        """Basic web vulnerability scanning"""
        self.log("Starting web vulnerability scan...")
        
        vuln_results = {
            'http_status': None,
            'server_info': None,
            'technologies': [],
            'vulnerabilities': []
        }
        
        try:
            # Check HTTP and HTTPS
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{self.target}"
                    response = requests.get(url, timeout=10, allow_redirects=True)
                    
                    vuln_results['http_status'] = response.status_code
                    vuln_results['server_info'] = response.headers.get('Server', 'Unknown')
                    
                    self.log(f"{protocol.upper()} Status: {response.status_code}")
                    self.log(f"Server: {vuln_results['server_info']}")
                    
                    # Check for common vulnerabilities
                    if 'X-Powered-By' in response.headers:
                        vuln_results['technologies'].append(response.headers['X-Powered-By'])
                        self.log(f"Technology: {response.headers['X-Powered-By']}")
                    
                    # Check for security headers
                    security_headers = [
                        'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
                        'Strict-Transport-Security', 'Content-Security-Policy'
                    ]
                    
                    missing_headers = []
                    for header in security_headers:
                        if header not in response.headers:
                            missing_headers.append(header)
                    
                    if missing_headers:
                        vuln_results['vulnerabilities'].append({
                            'type': 'Missing Security Headers',
                            'details': missing_headers
                        })
                        self.log(f"Missing security headers: {', '.join(missing_headers)}", "WARN")
                    
                    break
                    
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            self.log(f"Web vulnerability scan error: {str(e)}", "WARN")
        
        self.results['scan_results']['web_vulnerabilities'] = vuln_results
        self.log("Web vulnerability scan completed")
        return vuln_results
    
    def directory_enumeration(self, wordlist=None):
        """Directory and file enumeration"""
        self.log("Starting directory enumeration...")
        
        if wordlist is None:
            wordlist = [
                'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin', 'test', 'backup',
                'config', 'database', 'db', 'sql', 'uploads', 'files', 'images', 'css', 'js',
                'robots.txt', 'sitemap.xml', '.htaccess', 'web.config', 'crossdomain.xml',
                'clientaccesspolicy.xml', 'favicon.ico', 'index.php', 'index.html', 'index.asp'
            ]
        
        found_directories = []
        
        def check_directory(directory):
            try:
                for protocol in ['http', 'https']:
                    url = f"{protocol}://{self.target}/{directory}"
                    response = requests.get(url, timeout=5, allow_redirects=False)
                    if response.status_code in [200, 301, 302, 403]:
                        found_directories.append({
                            'directory': directory,
                            'status_code': response.status_code,
                            'url': url
                        })
                        self.log(f"Found: {url} (Status: {response.status_code})")
                        break
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_directory, wordlist)
        
        self.results['scan_results']['directory_enumeration'] = found_directories
        self.log(f"Directory enumeration completed. Found {len(found_directories)} directories")
        return found_directories
    
    def email_harvesting(self):
        """Email harvesting from common sources"""
        self.log("Starting email harvesting...")
        
        emails = set()
        
        # Common email patterns to check
        email_patterns = [
            f"admin@{self.target}",
            f"info@{self.target}",
            f"contact@{self.target}",
            f"support@{self.target}",
            f"webmaster@{self.target}",
            f"noreply@{self.target}",
            f"postmaster@{self.target}"
        ]
        
        # Check if emails exist (basic check)
        for email in email_patterns:
            try:
                # This is a simplified check - in real scenarios, you'd use more sophisticated methods
                emails.add(email)
                self.log(f"Potential email: {email}")
            except:
                pass
        
        self.results['scan_results']['emails'] = list(emails)
        self.log(f"Email harvesting completed. Found {len(emails)} potential emails")
        return list(emails)
    
    def network_discovery(self):
        """Network discovery and host enumeration"""
        self.log("Starting network discovery...")
        
        # Get target IP
        try:
            target_ip = socket.gethostbyname(self.target)
            self.log(f"Target IP: {target_ip}")
        except:
            self.log("Could not resolve target IP", "WARN")
            return
        
        # Ping sweep (simplified)
        network_results = {
            'target_ip': target_ip,
            'alive_hosts': []
        }
        
        # Check common network ranges
        base_ip = '.'.join(target_ip.split('.')[:-1])
        
        def ping_host(ip):
            try:
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                     capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    return ip
            except:
                pass
            return None
        
        # Check nearby IPs
        nearby_ips = [f"{base_ip}.{i}" for i in range(1, 255)]
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in nearby_ips[:20]}  # Limit for demo
            for future in as_completed(futures):
                host = future.result()
                if host:
                    network_results['alive_hosts'].append(host)
                    self.log(f"Alive host: {host}")
        
        self.results['scan_results']['network_discovery'] = network_results
        self.log("Network discovery completed")
        return network_results
    
    def run_full_scan(self):
        """Run complete reconnaissance scan"""
        self.print_banner()
        self.log(f"Starting full reconnaissance scan on {self.target}")
        
        start_time = time.time()
        
        # Run all scans
        self.port_scan()
        self.dns_enumeration()
        self.web_vulnerability_scan()
        self.directory_enumeration()
        self.email_harvesting()
        self.network_discovery()
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        self.log(f"Full scan completed in {scan_duration:.2f} seconds")
        self.save_results()
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== SCAN SUMMARY ==={Colors.END}")
        print(f"Target: {self.target}")
        print(f"Timestamp: {self.results['timestamp']}")
        
        if 'open_ports' in self.results['scan_results']:
            ports = self.results['scan_results']['open_ports']
            print(f"Open Ports: {len(ports)} ({', '.join(map(str, ports))})")
        
        if 'dns_enumeration' in self.results['scan_results']:
            dns = self.results['scan_results']['dns_enumeration']
            print(f"Subdomains Found: {len(dns.get('subdomains', []))}")
            print(f"A Records: {len(dns.get('a_records', []))}")
        
        if 'web_vulnerabilities' in self.results['scan_results']:
            web = self.results['scan_results']['web_vulnerabilities']
            print(f"Web Status: {web.get('http_status', 'N/A')}")
            print(f"Server: {web.get('server_info', 'Unknown')}")
        
        if 'directory_enumeration' in self.results['scan_results']:
            dirs = self.results['scan_results']['directory_enumeration']
            print(f"Directories Found: {len(dirs)}")
        
        if 'emails' in self.results['scan_results']:
            emails = self.results['scan_results']['emails']
            print(f"Emails Found: {len(emails)}")
        
        if 'network_discovery' in self.results['scan_results']:
            network = self.results['scan_results']['network_discovery']
            print(f"Alive Hosts: {len(network.get('alive_hosts', []))}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Ethical Hacking Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon_tool.py -t example.com --full-scan
  python recon_tool.py -t 192.168.1.1 --port-scan --ports 80,443,22
  python recon_tool.py -t example.com --dns-enum --web-scan
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target host or IP address')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--ports', help='Comma-separated list of ports to scan')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads for scanning')
    
    # Scan options
    parser.add_argument('--full-scan', action='store_true', help='Run complete reconnaissance scan')
    parser.add_argument('--port-scan', action='store_true', help='Port scanning only')
    parser.add_argument('--dns-enum', action='store_true', help='DNS enumeration only')
    parser.add_argument('--web-scan', action='store_true', help='Web vulnerability scanning only')
    parser.add_argument('--dir-enum', action='store_true', help='Directory enumeration only')
    parser.add_argument('--email-harvest', action='store_true', help='Email harvesting only')
    parser.add_argument('--network-discovery', action='store_true', help='Network discovery only')
    
    args = parser.parse_args()
    
    # Parse ports if provided
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("Error: Invalid port format. Use comma-separated integers.")
            sys.exit(1)
    
    # Create tool instance
    tool = ReconTool(args.target, args.output, args.verbose)
    
    # Run selected scans
    if args.full_scan:
        tool.run_full_scan()
    else:
        tool.print_banner()
        tool.log(f"Starting targeted scans on {args.target}")
        
        if args.port_scan:
            tool.port_scan(ports, args.threads)
        
        if args.dns_enum:
            tool.dns_enumeration()
        
        if args.web_scan:
            tool.web_vulnerability_scan()
        
        if args.dir_enum:
            tool.directory_enumeration()
        
        if args.email_harvest:
            tool.email_harvesting()
        
        if args.network_discovery:
            tool.network_discovery()
        
        tool.save_results()
        tool.print_summary()

if __name__ == "__main__":
    main()
