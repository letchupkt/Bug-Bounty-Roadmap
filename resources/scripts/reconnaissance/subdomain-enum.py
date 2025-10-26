#!/usr/bin/env python3
"""
Advanced Subdomain Enumeration Tool

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech

This tool performs comprehensive subdomain enumeration using multiple techniques:
- Certificate Transparency logs
- DNS brute force
- Search engine enumeration
- Passive DNS databases
- Third-party APIs
"""

import requests
import dns.resolver
import concurrent.futures
import json
import time
import random
import argparse
from typing import List, Set
import urllib3
from urllib.parse import urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SubdomainEnumerator:
    def __init__(self, domain: str, threads: int = 50, timeout: int = 10):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.found_subdomains: Set[str] = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Common subdomains for brute force
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'prod', 'blog', 'shop', 'app', 'mobile', 'secure', 'vpn',
            'remote', 'portal', 'support', 'help', 'docs', 'wiki', 'forum',
            'chat', 'news', 'media', 'static', 'assets', 'cdn', 'img',
            'images', 'video', 'videos', 'download', 'downloads', 'files',
            'upload', 'uploads', 'backup', 'backups', 'old', 'new', 'beta',
            'alpha', 'demo', 'sandbox', 'lab', 'labs', 'research', 'data',
            'db', 'database', 'sql', 'mysql', 'postgres', 'mongo', 'redis',
            'cache', 'search', 'elastic', 'kibana', 'grafana', 'prometheus',
            'jenkins', 'ci', 'cd', 'build', 'deploy', 'git', 'gitlab',
            'github', 'bitbucket', 'svn', 'repo', 'code', 'src', 'source',
            'internal', 'intranet', 'extranet', 'private', 'public', 'external',
            'office', 'corporate', 'company', 'business', 'enterprise',
            'customer', 'client', 'partner', 'vendor', 'supplier', 'affiliate',
            'subdomain', 'sub', 'domain', 'host', 'server', 'node', 'cluster',
            'cloud', 'aws', 'azure', 'gcp', 'docker', 'k8s', 'kubernetes',
            'monitoring', 'metrics', 'logs', 'logging', 'analytics', 'stats',
            'status', 'health', 'ping', 'check', 'test1', 'test2', 'test3',
            'dev1', 'dev2', 'dev3', 'staging1', 'staging2', 'prod1', 'prod2',
            'web', 'web1', 'web2', 'app1', 'app2', 'api1', 'api2', 'v1', 'v2'
        ]
    
    def enumerate_subdomains(self) -> List[str]:
        """Main enumeration function"""
        print(f"[*] Starting subdomain enumeration for {self.domain}")
        
        # Certificate Transparency logs
        print("[*] Checking Certificate Transparency logs...")
        self.check_certificate_transparency()
        
        # DNS brute force
        print("[*] Performing DNS brute force...")
        self.dns_brute_force()
        
        # Search engine enumeration
        print("[*] Searching engines...")
        self.search_engine_enumeration()
        
        # Third-party APIs
        print("[*] Querying third-party APIs...")
        self.query_third_party_apis()
        
        # Validate and filter results
        print("[*] Validating discovered subdomains...")
        valid_subdomains = self.validate_subdomains()
        
        return sorted(list(valid_subdomains))
    
    def check_certificate_transparency(self):
        """Check Certificate Transparency logs"""
        ct_sources = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        ]
        
        for source in ct_sources:
            try:
                response = self.session.get(source, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    if 'crt.sh' in source:
                        self.parse_crt_sh_response(response.json())
                    elif 'certspotter' in source:
                        self.parse_certspotter_response(response.json())
                        
            except Exception as e:
                print(f"[!] Error checking CT logs from {source}: {e}")
    
    def parse_crt_sh_response(self, data):
        """Parse crt.sh response"""
        for cert in data:
            name_value = cert.get('name_value', '')
            if name_value:
                # Handle multiple domains in one certificate
                domains = name_value.split('\n')
                for domain in domains:
                    domain = domain.strip()
                    if domain.endswith(f'.{self.domain}') or domain == self.domain:
                        # Remove wildcard prefix
                        if domain.startswith('*.'):
                            domain = domain[2:]
                        self.found_subdomains.add(domain)
    
    def parse_certspotter_response(self, data):
        """Parse CertSpotter response"""
        for cert in data:
            dns_names = cert.get('dns_names', [])
            for name in dns_names:
                if name.endswith(f'.{self.domain}') or name == self.domain:
                    # Remove wildcard prefix
                    if name.startswith('*.'):
                        name = name[2:]
                    self.found_subdomains.add(name)
    
    def dns_brute_force(self):
        """Brute force DNS subdomains"""
        print(f"[*] Testing {len(self.common_subdomains)} common subdomains...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for subdomain in self.common_subdomains:
                future = executor.submit(self.check_subdomain, subdomain)
                futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.found_subdomains.add(result)
                    print(f"[+] Found: {result}")
    
    def check_subdomain(self, subdomain: str) -> str:
        """Check if subdomain exists via DNS resolution"""
        try:
            full_domain = f"{subdomain}.{self.domain}"
            
            # Try A record
            try:
                dns.resolver.resolve(full_domain, 'A')
                return full_domain
            except:
                pass
            
            # Try CNAME record
            try:
                dns.resolver.resolve(full_domain, 'CNAME')
                return full_domain
            except:
                pass
                
        except Exception:
            pass
        
        return None
    
    def search_engine_enumeration(self):
        """Search engines for subdomains"""
        search_queries = [
            f"site:{self.domain}",
            f"site:*.{self.domain}",
        ]
        
        for query in search_queries:
            try:
                # Note: This is a simplified example
                # In practice, you'd need to handle search engine APIs properly
                # and respect rate limits and terms of service
                self.search_bing(query)
                time.sleep(random.uniform(1, 3))  # Rate limiting
                
            except Exception as e:
                print(f"[!] Error in search enumeration: {e}")
    
    def search_bing(self, query: str):
        """Search Bing for subdomains"""
        try:
            url = "https://www.bing.com/search"
            params = {'q': query, 'count': 50}
            
            response = self.session.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                # Simple regex to extract domains from search results
                import re
                pattern = r'https?://([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')'
                matches = re.findall(pattern, response.text)
                
                for match in matches:
                    if match not in self.found_subdomains:
                        self.found_subdomains.add(match)
                        print(f"[+] Found via search: {match}")
                        
        except Exception as e:
            print(f"[!] Error searching Bing: {e}")
    
    def query_third_party_apis(self):
        """Query third-party APIs for subdomain data"""
        apis = [
            self.query_virustotal,
            self.query_securitytrails,
            self.query_shodan
        ]
        
        for api_func in apis:
            try:
                api_func()
                time.sleep(1)  # Rate limiting
            except Exception as e:
                print(f"[!] Error querying API: {e}")
    
    def query_virustotal(self):
        """Query VirusTotal API"""
        # Note: Requires API key for full functionality
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': 'YOUR_API_KEY', 'domain': self.domain}
            
            # This is a placeholder - you'd need a real API key
            # response = self.session.get(url, params=params, timeout=self.timeout)
            pass
            
        except Exception as e:
            print(f"[!] Error querying VirusTotal: {e}")
    
    def query_securitytrails(self):
        """Query SecurityTrails API"""
        # Note: Requires API key
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {'APIKEY': 'YOUR_API_KEY'}
            
            # This is a placeholder - you'd need a real API key
            # response = self.session.get(url, headers=headers, timeout=self.timeout)
            pass
            
        except Exception as e:
            print(f"[!] Error querying SecurityTrails: {e}")
    
    def query_shodan(self):
        """Query Shodan API"""
        # Note: Requires API key
        try:
            url = f"https://api.shodan.io/shodan/host/search"
            params = {'key': 'YOUR_API_KEY', 'query': f'hostname:{self.domain}'}
            
            # This is a placeholder - you'd need a real API key
            # response = self.session.get(url, params=params, timeout=self.timeout)
            pass
            
        except Exception as e:
            print(f"[!] Error querying Shodan: {e}")
    
    def validate_subdomains(self) -> Set[str]:
        """Validate discovered subdomains"""
        valid_subdomains = set()
        
        print(f"[*] Validating {len(self.found_subdomains)} discovered subdomains...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for subdomain in self.found_subdomains:
                future = executor.submit(self.validate_subdomain, subdomain)
                futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    valid_subdomains.add(result)
        
        return valid_subdomains
    
    def validate_subdomain(self, subdomain: str) -> str:
        """Validate a single subdomain"""
        try:
            # DNS resolution check
            dns.resolver.resolve(subdomain, 'A')
            
            # HTTP/HTTPS check
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = self.session.head(url, timeout=5, verify=False)
                    if response.status_code < 400:
                        return subdomain
                except:
                    continue
            
            # If DNS resolves but HTTP doesn't work, still consider it valid
            return subdomain
            
        except Exception:
            return None
    
    def save_results(self, subdomains: List[str], filename: str):
        """Save results to file"""
        try:
            with open(filename, 'w') as f:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
            print(f"[*] Results saved to {filename}")
        except Exception as e:
            print(f"[!] Error saving results: {e}")
    
    def generate_report(self, subdomains: List[str]) -> dict:
        """Generate detailed report"""
        report = {
            'domain': self.domain,
            'total_subdomains': len(subdomains),
            'subdomains': subdomains,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'methodology': [
                'Certificate Transparency logs',
                'DNS brute force',
                'Search engine enumeration',
                'Third-party APIs'
            ]
        }
        
        return report

def main():
    parser = argparse.ArgumentParser(description='Advanced Subdomain Enumeration Tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-j', '--json', help='JSON output file for detailed report')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    # Initialize enumerator
    enumerator = SubdomainEnumerator(args.domain, args.threads, args.timeout)
    
    # Start enumeration
    start_time = time.time()
    subdomains = enumerator.enumerate_subdomains()
    end_time = time.time()
    
    # Display results
    print(f"\n[*] Enumeration completed in {end_time - start_time:.2f} seconds")
    print(f"[*] Found {len(subdomains)} subdomains for {args.domain}:")
    print("-" * 50)
    
    for subdomain in subdomains:
        print(f"  {subdomain}")
    
    # Save results
    if args.output:
        enumerator.save_results(subdomains, args.output)
    
    # Generate JSON report
    if args.json:
        report = enumerator.generate_report(subdomains)
        try:
            with open(args.json, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[*] Detailed report saved to {args.json}")
        except Exception as e:
            print(f"[!] Error saving JSON report: {e}")

if __name__ == "__main__":
    main()