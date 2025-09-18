#!/usr/bin/env python3
"""
Example usage of the Ethical Hacking Reconnaissance Tool
This script demonstrates how to use the tool programmatically
"""

from recon_tool import ReconTool
import json

def example_usage():
    """Example of using the reconnaissance tool programmatically"""
    
    # Initialize the tool
    target = "example.com"
    tool = ReconTool(target, output_file="example_results.json", verbose=True)
    
    print("=== Example: Ethical Hacking Reconnaissance Tool ===\n")
    
    # Print banner
    tool.print_banner()
    
    # Run individual scans
    print("1. Port Scanning...")
    open_ports = tool.port_scan(ports=[80, 443, 22, 21, 25, 53, 110, 143, 993, 995])
    
    print("\n2. DNS Enumeration...")
    dns_results = tool.dns_enumeration()
    
    print("\n3. Web Vulnerability Scanning...")
    web_results = tool.web_vulnerability_scan()
    
    print("\n4. Directory Enumeration...")
    dir_results = tool.directory_enumeration()
    
    print("\n5. Email Harvesting...")
    emails = tool.email_harvesting()
    
    print("\n6. Network Discovery...")
    network_results = tool.network_discovery()
    
    # Save results
    tool.save_results()
    
    # Print summary
    tool.print_summary()
    
    print("\n=== Example completed ===")
    print("Check 'example_results.json' for detailed results")

if __name__ == "__main__":
    example_usage()
