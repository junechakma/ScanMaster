#!/usr/bin/env python3

import argparse
import requests
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
import sys
from datetime import datetime
import whois
import re
from difflib import SequenceMatcher
import tldextract
import dns.resolver
from colorama import init, Fore, Back, Style
from tabulate import tabulate
init(autoreset=True)  # Initialize colorama

BANNER = '''
   _____                 __  ___           __           
  / ___/_________ ___  /  |/  /___ ______/ /____  _____
  \__ \/ ___/ __ `__ \/ /|_/ / __ `/ ___/ __/ _ \/ ___/
 ___/ / /__/ / / / / / /  / / /_/ (__  ) /_/  __/ /    
/____/\___/_/ /_/ /_/_/  /_/\__,_/____/\__/\___/_/     
                                                        
[ Cyber Security Project - Web Vulnerability Scanner | Version 1.0 ]
'''

class ScanMaster:
    def __init__(self, target_url, threads=5):
        self.target_url = target_url if target_url.startswith(('http://', 'https://')) else f'http://{target_url}'
        self.threads = threads
        self.domain = urlparse(self.target_url).netloc
        self.common_dirs = [
            'admin/', 'login/', 'wp-admin/', 'backup/', 'wp-content/',
            'uploads/', 'images/', 'includes/', 'tmp/', 'old/', 'backup/',
            'css/', 'js/', 'test/', 'demo/', 'database/', 'backup.sql',
            '.git/', '.env', 'config.php', 'phpinfo.php'
        ]
        self.open_ports = []
        self.legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'apple.com',
            'microsoft.com', 'paypal.com', 'netflix.com', 'instagram.com'
        ]
        self.findings = {
            'high': [],
            'medium': [],
            'low': []
        }

    def scan_directory(self, directory):
        try:
            url = urljoin(self.target_url, directory)
            response = requests.get(url, timeout=5, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                return f"[+] Found directory: {url} (Status: {response.status_code})"
        except:
            pass
        return None

    def directory_enumeration(self):
        print("\n[*] Starting Directory Enumeration...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(self.scan_directory, self.common_dirs)
            for result in results:
                if result:
                    print(result)

    def add_finding(self, risk_level, description):
        self.findings[risk_level].append(description)

    def check_headers(self):
        print("\n[*] Checking HTTP Headers...")
        try:
            response = requests.get(self.target_url)
            headers = response.headers
            
            security_headers = {
                'X-XSS-Protection': ('Missing XSS Protection Header', 'medium'),
                'X-Frame-Options': ('Missing Clickjacking Protection Header', 'medium'),
                'X-Content-Type-Options': ('Missing MIME Sniffing Protection Header', 'low'),
                'Strict-Transport-Security': ('Missing HSTS Header', 'high'),
                'Content-Security-Policy': ('Missing Content Security Policy Header', 'high')
            }

            for header, (message, risk) in security_headers.items():
                if header not in headers:
                    print(f"[-] {message}")
                    self.add_finding(risk, message)
                else:
                    print(f"[+] {header}: {headers[header]}")
                    
            server = headers.get('Server')
            if server:
                print(f"[+] Server: {server}")
                if server.lower() in ['apache', 'nginx', 'iis']:
                    self.add_finding('low', f'Server version disclosure: {server}')
        except Exception as e:
            print(f"[-] Error checking headers: {str(e)}")
            self.add_finding('medium', f'Error accessing headers: {str(e)}')

    def port_scan(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        target = self.target_url.split('://')[1].split('/')[0]
        result = sock.connect_ex((target, port))
        if result == 0:
            service = socket.getservbyport(port, 'tcp')
            self.open_ports.append(f"[+] Port {port} ({service}): Open")
        sock.close()

    def scan_ports(self):
        print("\n[*] Starting Port Scan...")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 8080, 8443]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.port_scan, common_ports)
        
        for result in sorted(self.open_ports):
            print(result)

    def check_ssl(self):
        print("\n[*] Checking SSL/TLS Configuration...")
        if not self.target_url.startswith('https'):
            print("[-] Site is not using HTTPS")
            self.add_finding('high', 'Site is not using HTTPS encryption')
            return False

        try:
            hostname = self.target_url.split('://')[1].split('/')[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        print("[-] SSL Certificate has expired!")
                        self.add_finding('high', 'SSL Certificate has expired')
                        return False
                    else:
                        print("[+] SSL Certificate is valid")
                    
                    days_to_expire = (not_after - datetime.now()).days
                    if days_to_expire < 30:
                        self.add_finding('medium', f'SSL Certificate expires soon ({days_to_expire} days)')
                    
                    print(f"[+] Certificate expires: {cert['notAfter']}")
                    print(f"[+] Issued to: {cert['subject'][-1][1]}")
                    print(f"[+] Issued by: {cert['issuer'][-1][1]}")
                    return True
        except Exception as e:
            print(f"[-] SSL/TLS Error: {str(e)}")
            self.add_finding('high', f'SSL/TLS Error: {str(e)}')
            return False

    def check_domain_age(self):
        print("\n[*] Checking Domain Age...")
        try:
            w = whois.whois(self.domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            domain_age = (datetime.now() - creation_date).days
            print(f"[+] Domain age: {domain_age} days")
            
            if domain_age < 30:
                print("[-] Warning: Domain is less than 30 days old!")
                self.add_finding('medium', 'Domain is less than 30 days old')
                return False
            return True
        except Exception as e:
            print(f"[-] Error checking domain age: {str(e)}")
            self.add_finding('medium', f'Error checking domain age: {str(e)}')
            return False

    def check_domain_similarity(self):
        print("\n[*] Checking Domain Similarity...")
        extracted = tldextract.extract(self.domain)
        domain_name = extracted.domain
        
        similar_domains = []
        for legitimate in self.legitimate_domains:
            legit_extracted = tldextract.extract(legitimate)
            legit_domain = legit_extracted.domain
            similarity = SequenceMatcher(None, domain_name, legit_domain).ratio()
            
            if similarity > 0.75:  # 75% similarity threshold
                similar_domains.append((legitimate, similarity * 100))
        
        if similar_domains:
            print("[-] Warning: Similar to legitimate domains:")
            for domain, similarity in similar_domains:
                print(f"    - {domain} (Similarity: {similarity:.2f}%)")
                self.add_finding('medium', f'Similar to legitimate domain: {domain} ({similarity:.2f}%)')
            return False
        return True

    def check_suspicious_patterns(self):
        print("\n[*] Checking Suspicious URL Patterns...")
        suspicious_patterns = [
            r'secure.*login',
            r'account.*verify',
            r'banking.*secure',
            r'signin.*verify',
            r'security.*check',
            r'update.*account',
            r'verify.*identity'
        ]
        
        url_string = self.target_url.lower()
        found_patterns = []
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url_string):
                found_patterns.append(pattern)
        
        if found_patterns:
            print("[-] Warning: Suspicious patterns found in URL:")
            for pattern in found_patterns:
                print(f"    - Matches pattern: {pattern}")
                self.add_finding('medium', f'Suspicious pattern found in URL: {pattern}')
            return False
        return True

    def analyze_dns_records(self):
        print("\n[*] Analyzing DNS Records...")
        try:
            domain = urlparse(self.target_url).netloc
            records_exist = False
            
            # Check MX Records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                print("[+] MX Records found:")
                for mx in mx_records:
                    print(f"    - {mx.exchange}")
                records_exist = True
            except:
                print("[-] No MX records found")
            
            # Check A Records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                print("[+] A Records found:")
                for a in a_records:
                    print(f"    - {a.address}")
                records_exist = True
            except:
                print("[-] No A records found")
            
            if not records_exist:
                self.add_finding('medium', 'No DNS records found')
            return records_exist
        except Exception as e:
            print(f"[-] Error analyzing DNS records: {str(e)}")
            self.add_finding('medium', f'Error analyzing DNS records: {str(e)}')
            return False

    def check_for_phishing(self):
        print("\n[*] Starting Phishing Detection...")
        print("=" * 60)
        
        checks = {
            "SSL Certificate": self.check_ssl(),
            "Domain Age": self.check_domain_age(),
            "Domain Similarity": self.check_domain_similarity(),
            "Suspicious Patterns": self.check_suspicious_patterns(),
            "DNS Records": self.analyze_dns_records()
        }
        
        failed_checks = [check for check, result in checks.items() if not result]
        
        print("\n[*] Phishing Detection Summary:")
        if failed_checks:
            print("[-] Warning: Potential phishing site detected!")
            print("[-] Failed checks:")
            for check in failed_checks:
                print(f"    - {check}")
        else:
            print("[+] No obvious phishing indicators detected")
        
        return len(failed_checks) == 0

    def generate_report(self):
        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}[*] Security Scan Report for {self.target_url}{Style.RESET_ALL}")
        print("=" * 60 + "\n")

        # High Risk Findings
        high_risk_table = []
        for finding in self.findings['high']:
            high_risk_table.append([finding])
        
        if high_risk_table:
            print(f"{Fore.RED}High Risk Findings:{Style.RESET_ALL}")
            print(tabulate(high_risk_table, tablefmt="grid", headers=["Description"]))
            print()

        # Medium Risk Findings
        medium_risk_table = []
        for finding in self.findings['medium']:
            medium_risk_table.append([finding])
        
        if medium_risk_table:
            print(f"{Fore.YELLOW}Medium Risk Findings:{Style.RESET_ALL}")
            print(tabulate(medium_risk_table, tablefmt="grid", headers=["Description"]))
            print()

        # Low Risk Findings
        low_risk_table = []
        for finding in self.findings['low']:
            low_risk_table.append([finding])
        
        if low_risk_table:
            print(f"{Fore.GREEN}Low Risk Findings:{Style.RESET_ALL}")
            print(tabulate(low_risk_table, tablefmt="grid", headers=["Description"]))
            print()

        # Summary
        total_findings = len(self.findings['high']) + len(self.findings['medium']) + len(self.findings['low'])
        summary_table = [
            ["High Risk", len(self.findings['high']), f"{Fore.RED}●{Style.RESET_ALL}"],
            ["Medium Risk", len(self.findings['medium']), f"{Fore.YELLOW}●{Style.RESET_ALL}"],
            ["Low Risk", len(self.findings['low']), f"{Fore.GREEN}●{Style.RESET_ALL}"],
            ["Total Findings", total_findings, ""]
        ]
        
        print(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(tabulate(summary_table, headers=["Risk Level", "Count", "Indicator"], tablefmt="grid"))

    def run_scan(self):
        print(f"\n[+] Starting vulnerability scan on {self.target_url}")
        print("=" * 60)
        
        self.directory_enumeration()
        self.check_headers()
        self.scan_ports()
        self.check_for_phishing()
        
        print("\n[+] Scan completed!")
        self.generate_report()

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    args = parser.parse_args()

    scanner = ScanMaster(args.url, args.threads)
    scanner.run_scan()

if __name__ == '__main__':
    main()
