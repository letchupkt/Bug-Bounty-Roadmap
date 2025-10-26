# 🛠️ Phase 4: Essential Tools and Technologies (Months 5-9)

> **Goal**: Master advanced security tools, automation frameworks, and reconnaissance at scale

## 📚 Learning Objectives

By the end of this phase, you will:
- ✅ Master all essential bug bounty hunting tools
- ✅ Build custom automation scripts and workflows
- ✅ Perform reconnaissance at enterprise scale
- ✅ Understand advanced exploitation frameworks
- ✅ Create your own security testing toolkit

## 🎯 Phase Overview

| Month | Focus Area | Tools Mastered | Key Skills |
|-------|------------|----------------|------------|
| 5 | HTTP Proxies & Traffic Analysis | Burp Suite Pro, OWASP ZAP | Advanced web testing |
| 6 | Reconnaissance Automation | Subfinder, Amass, Nuclei | Scalable asset discovery |
| 7 | Vulnerability Scanners | Custom tools, Frameworks | Automated vulnerability detection |
| 8 | Exploitation Frameworks | Metasploit, Custom exploits | Advanced exploitation |
| 9 | Custom Tool Development | Python, Bash, Go | Building your own tools |

## 🕷️ HTTP Proxies and Traffic Analyzers

### 🔥 Burp Suite Professional - The Industry Standard

#### Why Burp Suite Professional?
- **87% of HackerOne users** voted it as most helpful tool
- **Professional scanner** with advanced detection capabilities
- **Extensive extension ecosystem** for specialized testing
- **Industry recognition** - Used by top security professionals

#### 💰 Investment Analysis
```
Burp Suite Professional: $475/year
ROI Calculation:
- Find 1 medium bug ($500) = Tool pays for itself
- Average professional finds 10+ bugs/year
- Potential earnings: $5,000-$50,000/year
- ROI: 1000%+ for active hunters
```

#### 🚀 Advanced Features Deep Dive

##### Professional Scanner
```bash
# Automated scanning capabilities
- Crawling and auditing web applications
- Advanced injection testing (SQL, XSS, XXE)
- Logic flaw detection
- Custom scan configurations
- Integration with manual testing workflow
```

**Scanner Configuration Best Practices:**
```
1. Audit Optimization:
   - Enable all audit checks for comprehensive coverage
   - Configure custom insertion points
   - Set appropriate crawl limits
   - Use session handling rules

2. Performance Tuning:
   - Adjust thread count based on target capacity
   - Configure request delays to avoid rate limiting
   - Use smart crawling to reduce noise
   - Enable response caching for efficiency
```

##### Intruder Module - Advanced Attacks
```bash
# Attack Types:
1. Sniper: Single payload set, single insertion point
2. Battering Ram: Single payload set, multiple insertion points
3. Pitchfork: Multiple payload sets, synchronized
4. Cluster Bomb: Multiple payload sets, all combinations
```

**Advanced Intruder Techniques:**
```python
# Custom payload processing with Python
def process_payload(payload):
    # Base64 encode
    import base64
    encoded = base64.b64encode(payload.encode()).decode()
    
    # URL encode
    import urllib.parse
    url_encoded = urllib.parse.quote(encoded)
    
    # Custom transformation
    return f"{{\"data\":\"{url_encoded}\"}}"

# Grep extraction for response analysis
# Extract session tokens, CSRF tokens, etc.
```

##### Extensions Ecosystem
```bash
# Essential Extensions:
1. Logger++ - Enhanced logging and analysis
2. Autorize - Authorization testing automation
3. Param Miner - Hidden parameter discovery
4. Backslash Powered Scanner - Advanced injection detection
5. Software Vulnerability Scanner - CVE detection
6. Turbo Intruder - High-speed attacks
7. Active Scan++ - Additional scan checks
8. Retire.js - JavaScript library vulnerability detection
```

**Custom Extension Development:**
```python
# Burp Extension Template
from burp import IBurpExtender, IHttpListener, ITab
from java.awt import Component
from javax.swing import JPanel, JLabel

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Custom Bug Bounty Extension")
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Process HTTP requests/responses
        if messageIsRequest:
            request = messageInfo.getRequest()
            # Analyze request
        else:
            response = messageInfo.getResponse()
            # Analyze response for vulnerabilities
    
    def getTabCaption(self):
        return "Bug Bounty Helper"
    
    def getUiComponent(self):
        panel = JPanel()
        panel.add(JLabel("Custom Bug Bounty Testing Tools"))
        return panel
```

### 🆓 OWASP ZAP - Free Alternative

#### Advanced ZAP Usage
```bash
# Command Line Automation
zap-cli start --start-options '-config api.disablekey=true'
zap-cli open-url https://target.com
zap-cli spider https://target.com
zap-cli active-scan https://target.com
zap-cli report -o zap_report.html -f html

# API Integration
curl "http://localhost:8080/JSON/spider/action/scan/?url=https://target.com"
curl "http://localhost:8080/JSON/ascan/action/scan/?url=https://target.com"
```

#### Custom ZAP Scripts
```python
# ZAP Scripting - Passive Scanner
def scan(ps, msg, src):
    # Check for custom vulnerabilities
    body = msg.getResponseBody().toString()
    
    if "debug=true" in body:
        ps.raiseAlert(
            risk=2,  # Medium
            confidence=3,  # High
            name="Debug Information Disclosure",
            description="Application exposes debug information",
            uri=msg.getRequestHeader().getURI().toString(),
            param="debug",
            attack="",
            otherInfo="Debug mode detected in response",
            solution="Disable debug mode in production",
            reference="",
            evidence="debug=true"
        )
```

## 🔍 Advanced Reconnaissance Tools

### 🎯 Subdomain Enumeration at Scale

#### Subfinder - Passive Discovery
```bash
# Advanced Subfinder Usage
subfinder -d target.com -all -recursive -o subdomains.txt

# API Configuration for Maximum Results
cat > ~/.config/subfinder/provider-config.yaml << EOF
virustotal:
  - "your_virustotal_api_key"
passivetotal:
  - "your_passivetotal_api_key"
securitytrails:
  - "your_securitytrails_api_key"
shodan:
  - "your_shodan_api_key"
censys:
  - "your_censys_api_id:your_censys_secret"
github:
  - "your_github_token"
EOF

# Automation Script
#!/bin/bash
echo "Starting subdomain enumeration for $1"
subfinder -d $1 -all -o subfinder_$1.txt
amass enum -passive -d $1 -o amass_$1.txt
assetfinder $1 | tee assetfinder_$1.txt

# Combine and deduplicate
cat subfinder_$1.txt amass_$1.txt assetfinder_$1.txt | sort -u > all_subdomains_$1.txt
echo "Found $(wc -l < all_subdomains_$1.txt) unique subdomains"
```

#### Amass - Comprehensive Asset Discovery
```bash
# Advanced Amass Configuration
cat > amass_config.ini << EOF
[data_sources]
[data_sources.AlienVault]
[data_sources.Censys]
api_key = your_censys_api_key
secret = your_censys_secret
[data_sources.Shodan]
api_key = your_shodan_api_key
[data_sources.SecurityTrails]
api_key = your_securitytrails_api_key
EOF

# Comprehensive enumeration
amass enum -config amass_config.ini -active -d target.com -o amass_results.txt

# Network mapping
amass intel -d target.com -whois
amass viz -d3 -d target.com
```

### 🌐 Content Discovery and Crawling

#### Katana - Next-Gen Web Crawler
```bash
# Installation
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Advanced crawling
katana -u https://target.com -d 5 -jc -kf robotstxt,sitemapxml -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o crawled_urls.txt

# JavaScript parsing
katana -u https://target.com -jc -xhr -jsluice -o js_endpoints.txt

# Custom headers and authentication
katana -u https://target.com -H "Authorization: Bearer token" -H "User-Agent: Custom" -o authenticated_crawl.txt
```

#### Hakrawler - Fast Web Crawler
```bash
# Basic usage
echo "https://target.com" | hakrawler -depth 3 -plain

# With custom options
echo "https://target.com" | hakrawler -depth 4 -forms -linkfinder -plain -o crawled.txt

# Piped with other tools
echo "target.com" | subfinder -silent | httpx -silent | hakrawler -depth 2 -plain | sort -u
```

### ⚡ Nuclei - Vulnerability Scanner

#### Template System Mastery
```bash
# Update templates
nuclei -update-templates

# Run specific template categories
nuclei -u https://target.com -t cves/
nuclei -u https://target.com -t vulnerabilities/
nuclei -u https://target.com -t exposures/
nuclei -u https://target.com -t misconfiguration/

# Custom severity filtering
nuclei -u https://target.com -severity critical,high
nuclei -u https://target.com -severity medium,low -o medium_low_findings.txt

# Rate limiting and performance
nuclei -l targets.txt -rate-limit 10 -bulk-size 25 -c 25
```

#### Custom Template Development
```yaml
# custom-template.yaml
id: custom-debug-disclosure

info:
  name: Debug Information Disclosure
  author: letchupkt
  severity: medium
  description: Detects debug information disclosure in web applications
  tags: debug,disclosure,information

requests:
  - method: GET
    path:
      - "{{BaseURL}}/debug"
      - "{{BaseURL}}/debug.php"
      - "{{BaseURL}}/debug.jsp"
      - "{{BaseURL}}/?debug=true"
      - "{{BaseURL}}/?debug=1"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "debug"
          - "stack trace"
          - "error"
        condition: or
        case-insensitive: true

      - type: status
        status:
          - 200

    extractors:
      - type: regex
        regex:
          - 'debug[^"]*'
        group: 1
```

#### Nuclei Automation Workflow
```bash
#!/bin/bash
# nuclei-automation.sh

TARGET=$1
OUTPUT_DIR="nuclei_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "[+] Starting Nuclei scan for $TARGET"

# Critical and High severity
nuclei -u $TARGET -severity critical,high -o $OUTPUT_DIR/critical_high.txt

# Medium severity
nuclei -u $TARGET -severity medium -o $OUTPUT_DIR/medium.txt

# CVE checks
nuclei -u $TARGET -t cves/ -o $OUTPUT_DIR/cves.txt

# Technology detection
nuclei -u $TARGET -t technologies/ -o $OUTPUT_DIR/technologies.txt

# Misconfigurations
nuclei -u $TARGET -t misconfiguration/ -o $OUTPUT_DIR/misconfig.txt

# Generate summary report
echo "Nuclei Scan Summary for $TARGET" > $OUTPUT_DIR/summary.txt
echo "Scan Date: $(date)" >> $OUTPUT_DIR/summary.txt
echo "Critical/High: $(wc -l < $OUTPUT_DIR/critical_high.txt)" >> $OUTPUT_DIR/summary.txt
echo "Medium: $(wc -l < $OUTPUT_DIR/medium.txt)" >> $OUTPUT_DIR/summary.txt
echo "CVEs: $(wc -l < $OUTPUT_DIR/cves.txt)" >> $OUTPUT_DIR/summary.txt

echo "[+] Scan complete. Results saved in $OUTPUT_DIR"
```

## 🔧 Specialized Security Tools

### 🔍 Parameter Discovery

#### Arjun - HTTP Parameter Discovery
```bash
# Installation
pip3 install arjun

# Basic parameter discovery
arjun -u https://target.com/page.php

# POST parameter discovery
arjun -u https://target.com/login.php -m POST

# Custom wordlist
arjun -u https://target.com -w custom_params.txt

# JSON parameter discovery
arjun -u https://target.com/api/endpoint -m POST --headers "Content-Type: application/json"

# Rate limiting
arjun -u https://target.com --stable --delay 2
```

#### ParamSpider - Parameter Mining
```bash
# Installation
git clone https://github.com/devanshbatham/ParamSpider
cd ParamSpider
pip3 install -r requirements.txt

# Usage
python3 paramspider.py -d target.com -o params.txt
python3 paramspider.py -l domains.txt -o all_params.txt

# Clean and filter parameters
cat params.txt | grep -E '\?.*=' | sort -u > clean_params.txt
```

### 🌐 HTTP Fuzzing

#### Ffuf - Fast Web Fuzzer
```bash
# Directory fuzzing with extensions
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://target.com/FUZZ -e .php,.html,.js,.txt,.asp,.aspx,.jsp

# Parameter fuzzing
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -u https://target.com/page.php?FUZZ=test -fs 1234

# POST data fuzzing
ffuf -w wordlist.txt -X POST -d "username=admin&password=FUZZ" -u https://target.com/login.php -fc 401

# Header fuzzing
ffuf -w wordlist.txt -H "X-Forwarded-For: FUZZ" -u https://target.com/ -fc 403

# Virtual host discovery
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.target.com" -u https://target.com/ -fc 404

# Advanced filtering
ffuf -w wordlist.txt -u https://target.com/FUZZ -fc 404,403 -fs 1234,5678 -fr "not found"
```

#### Wfuzz - Web Application Fuzzer
```bash
# Basic directory fuzzing
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 https://target.com/FUZZ

# Parameter fuzzing
wfuzz -c -z file,params.txt -d "FUZZ=test" --hc 404 https://target.com/login.php

# Cookie fuzzing
wfuzz -c -z file,wordlist.txt -b "session=FUZZ" --hc 404 https://target.com/admin

# Multiple payloads
wfuzz -c -z file,users.txt -z file,passwords.txt -d "username=FUZZ&password=FUZ2Z" --hc 404 https://target.com/login.php
```

## 🤖 Automation and Custom Tool Development

### 🐍 Python Tool Development

#### Reconnaissance Automation Framework
```python
#!/usr/bin/env python3
"""
Bug Bounty Reconnaissance Automation Framework

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import subprocess
import requests
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import argparse
import sys

class BugBountyRecon:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.live_hosts = set()
        self.results = {}
    
    def run_subfinder(self):
        """Run subfinder for passive subdomain enumeration"""
        try:
            cmd = f"subfinder -d {self.domain} -silent"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            subdomains = result.stdout.strip().split('\n')
            self.subdomains.update([s for s in subdomains if s])
            print(f"[+] Subfinder found {len(subdomains)} subdomains")
        except Exception as e:
            print(f"[-] Subfinder error: {e}")
    
    def run_amass(self):
        """Run amass for comprehensive enumeration"""
        try:
            cmd = f"amass enum -passive -d {self.domain} -silent"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            subdomains = result.stdout.strip().split('\n')
            self.subdomains.update([s for s in subdomains if s])
            print(f"[+] Amass found additional subdomains")
        except Exception as e:
            print(f"[-] Amass error: {e}")
    
    def check_alive(self, subdomain):
        """Check if subdomain is alive"""
        try:
            response = requests.get(f"http://{subdomain}", timeout=5)
            if response.status_code:
                self.live_hosts.add(subdomain)
                return True
        except:
            try:
                response = requests.get(f"https://{subdomain}", timeout=5)
                if response.status_code:
                    self.live_hosts.add(subdomain)
                    return True
            except:
                pass
        return False
    
    def validate_subdomains(self):
        """Validate discovered subdomains"""
        print(f"[+] Validating {len(self.subdomains)} subdomains...")
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(self.check_alive, self.subdomains)
        print(f"[+] Found {len(self.live_hosts)} live hosts")
    
    def run_nuclei(self):
        """Run nuclei on live hosts"""
        if not self.live_hosts:
            return
        
        hosts_file = f"{self.domain}_live_hosts.txt"
        with open(hosts_file, 'w') as f:
            for host in self.live_hosts:
                f.write(f"https://{host}\n")
        
        try:
            cmd = f"nuclei -l {hosts_file} -severity critical,high,medium -o {self.domain}_nuclei.txt"
            subprocess.run(cmd, shell=True)
            print(f"[+] Nuclei scan completed")
        except Exception as e:
            print(f"[-] Nuclei error: {e}")
    
    def generate_report(self):
        """Generate comprehensive report"""
        report = {
            'domain': self.domain,
            'total_subdomains': len(self.subdomains),
            'live_hosts': len(self.live_hosts),
            'subdomains': list(self.subdomains),
            'live_hosts_list': list(self.live_hosts)
        }
        
        with open(f"{self.domain}_report.json", 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to {self.domain}_report.json")
    
    def run_full_recon(self):
        """Run complete reconnaissance workflow"""
        print(f"[+] Starting reconnaissance for {self.domain}")
        
        # Subdomain enumeration
        threads = []
        threads.append(threading.Thread(target=self.run_subfinder))
        threads.append(threading.Thread(target=self.run_amass))
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Validation and scanning
        self.validate_subdomains()
        self.run_nuclei()
        self.generate_report()
        
        print(f"[+] Reconnaissance completed for {self.domain}")

def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Reconnaissance Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    args = parser.parse_args()
    
    recon = BugBountyRecon(args.domain)
    recon.run_full_recon()

if __name__ == "__main__":
    main()
```

#### HTTP Request Analysis Tool
```python
#!/usr/bin/env python3
"""
HTTP Request Analysis and Vulnerability Detection Tool

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import requests
import re
import json
from urllib.parse import urlparse, parse_qs
import argparse

class HTTPAnalyzer:
    def __init__(self, url):
        self.url = url
        self.vulnerabilities = []
        self.headers = {}
        self.cookies = {}
        
    def analyze_headers(self, response):
        """Analyze HTTP headers for security issues"""
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-XSS-Protection': 'XSS protection disabled',
            'X-Content-Type-Options': 'MIME sniffing protection missing',
            'Strict-Transport-Security': 'HSTS not implemented',
            'Content-Security-Policy': 'CSP not implemented'
        }
        
        for header, issue in security_headers.items():
            if header not in response.headers:
                self.vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'severity': 'Medium',
                    'description': issue,
                    'header': header
                })
    
    def check_sql_injection(self, url):
        """Basic SQL injection detection"""
        payloads = ["'", "\"", "1'", "1\"", "1' OR '1'='1", "1\" OR \"1\"=\"1"]
        
        for payload in payloads:
            try:
                # Test GET parameters
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    response = requests.get(test_url, timeout=5)
                    
                    # Check for SQL error patterns
                    sql_errors = [
                        'mysql_fetch_array',
                        'ORA-01756',
                        'Microsoft OLE DB Provider',
                        'SQLServer JDBC Driver',
                        'PostgreSQL query failed'
                    ]
                    
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'High',
                                'parameter': param,
                                'payload': payload,
                                'evidence': error
                            })
                            
            except Exception as e:
                continue
    
    def check_xss(self, url):
        """Basic XSS detection"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        for payload in xss_payloads:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    response = requests.get(test_url, timeout=5)
                    
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'reflected': True
                        })
                        
            except Exception as e:
                continue
    
    def analyze_cookies(self, response):
        """Analyze cookies for security issues"""
        for cookie in response.cookies:
            issues = []
            
            if not cookie.secure:
                issues.append("Missing Secure flag")
            
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append("Missing HttpOnly flag")
            
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append("Missing SameSite attribute")
            
            if issues:
                self.vulnerabilities.append({
                    'type': 'Insecure Cookie',
                    'severity': 'Medium',
                    'cookie': cookie.name,
                    'issues': issues
                })
    
    def run_analysis(self):
        """Run complete HTTP analysis"""
        try:
            response = requests.get(self.url, timeout=10)
            
            # Analyze different aspects
            self.analyze_headers(response)
            self.analyze_cookies(response)
            self.check_sql_injection(self.url)
            self.check_xss(self.url)
            
            return {
                'url': self.url,
                'status_code': response.status_code,
                'vulnerabilities': self.vulnerabilities,
                'total_issues': len(self.vulnerabilities)
            }
            
        except Exception as e:
            return {'error': str(e)}

def main():
    parser = argparse.ArgumentParser(description="HTTP Security Analyzer")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    args = parser.parse_args()
    
    analyzer = HTTPAnalyzer(args.url)
    results = analyzer.run_analysis()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
    else:
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
```

### 🔧 Bash Automation Scripts

#### Complete Reconnaissance Pipeline
```bash
#!/bin/bash
#
# Bug Bounty Reconnaissance Pipeline
#
# Author: LakshmiKanthanK(letchupkt)
# Portfolio: https://letchupkt.vgrow.tech
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                Bug Bounty Recon Pipeline                    ║"
echo "║                   by LetchuPKT                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if domain is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}[!] Usage: $0 <domain>${NC}"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR="recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR
cd $OUTPUT_DIR

echo -e "${GREEN}[+] Starting reconnaissance for $DOMAIN${NC}"
echo -e "${BLUE}[*] Output directory: $OUTPUT_DIR${NC}"

# Phase 1: Subdomain Enumeration
echo -e "${YELLOW}[*] Phase 1: Subdomain Enumeration${NC}"

echo -e "${BLUE}[*] Running Subfinder...${NC}"
subfinder -d $DOMAIN -all -recursive -o subfinder.txt 2>/dev/null
SUBFINDER_COUNT=$(wc -l < subfinder.txt)
echo -e "${GREEN}[+] Subfinder found $SUBFINDER_COUNT subdomains${NC}"

echo -e "${BLUE}[*] Running Amass...${NC}"
amass enum -passive -d $DOMAIN -o amass.txt 2>/dev/null
AMASS_COUNT=$(wc -l < amass.txt)
echo -e "${GREEN}[+] Amass found $AMASS_COUNT subdomains${NC}"

echo -e "${BLUE}[*] Running Assetfinder...${NC}"
assetfinder $DOMAIN | tee assetfinder.txt >/dev/null
ASSETFINDER_COUNT=$(wc -l < assetfinder.txt)
echo -e "${GREEN}[+] Assetfinder found $ASSETFINDER_COUNT subdomains${NC}"

# Combine and deduplicate
cat subfinder.txt amass.txt assetfinder.txt | sort -u > all_subdomains.txt
TOTAL_SUBDOMAINS=$(wc -l < all_subdomains.txt)
echo -e "${GREEN}[+] Total unique subdomains: $TOTAL_SUBDOMAINS${NC}"

# Phase 2: Live Host Detection
echo -e "${YELLOW}[*] Phase 2: Live Host Detection${NC}"
echo -e "${BLUE}[*] Checking for live hosts...${NC}"
httpx -l all_subdomains.txt -o live_hosts.txt -silent
LIVE_HOSTS=$(wc -l < live_hosts.txt)
echo -e "${GREEN}[+] Found $LIVE_HOSTS live hosts${NC}"

# Phase 3: Port Scanning
echo -e "${YELLOW}[*] Phase 3: Port Scanning${NC}"
echo -e "${BLUE}[*] Running Nmap on live hosts...${NC}"
nmap -iL <(cat live_hosts.txt | sed 's|https\?://||' | cut -d'/' -f1) -T4 -oA nmap_scan >/dev/null 2>&1
echo -e "${GREEN}[+] Port scan completed${NC}"

# Phase 4: Content Discovery
echo -e "${YELLOW}[*] Phase 4: Content Discovery${NC}"
echo -e "${BLUE}[*] Running directory enumeration...${NC}"
mkdir -p content_discovery

while IFS= read -r url; do
    domain_name=$(echo $url | sed 's|https\?://||' | cut -d'/' -f1)
    echo -e "${BLUE}[*] Enumerating directories for $domain_name${NC}"
    gobuster dir -u $url -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt -o content_discovery/${domain_name}_dirs.txt -q 2>/dev/null &
done < live_hosts.txt

wait # Wait for all background jobs to complete
echo -e "${GREEN}[+] Content discovery completed${NC}"

# Phase 5: Vulnerability Scanning
echo -e "${YELLOW}[*] Phase 5: Vulnerability Scanning${NC}"
echo -e "${BLUE}[*] Running Nuclei...${NC}"
nuclei -l live_hosts.txt -severity critical,high,medium -o nuclei_results.txt -silent
NUCLEI_FINDINGS=$(wc -l < nuclei_results.txt)
echo -e "${GREEN}[+] Nuclei found $NUCLEI_FINDINGS potential vulnerabilities${NC}"

# Phase 6: Technology Detection
echo -e "${YELLOW}[*] Phase 6: Technology Detection${NC}"
echo -e "${BLUE}[*] Detecting technologies...${NC}"
httpx -l live_hosts.txt -tech-detect -o tech_detection.txt -silent
echo -e "${GREEN}[+] Technology detection completed${NC}"

# Phase 7: Screenshot Collection
echo -e "${YELLOW}[*] Phase 7: Screenshot Collection${NC}"
echo -e "${BLUE}[*] Taking screenshots...${NC}"
mkdir -p screenshots
cat live_hosts.txt | aquatone -out screenshots/ >/dev/null 2>&1
echo -e "${GREEN}[+] Screenshots saved to screenshots/ directory${NC}"

# Generate Summary Report
echo -e "${YELLOW}[*] Generating Summary Report${NC}"
cat > summary_report.txt << EOF
Bug Bounty Reconnaissance Report
Domain: $DOMAIN
Date: $(date)
Author: LetchuPKT

=== SUMMARY ===
Total Subdomains Found: $TOTAL_SUBDOMAINS
Live Hosts: $LIVE_HOSTS
Nuclei Findings: $NUCLEI_FINDINGS

=== FILES GENERATED ===
- all_subdomains.txt: All discovered subdomains
- live_hosts.txt: Live hosts with HTTP/HTTPS
- nmap_scan.*: Nmap port scan results
- content_discovery/: Directory enumeration results
- nuclei_results.txt: Vulnerability scan results
- tech_detection.txt: Technology stack information
- screenshots/: Visual reconnaissance
- summary_report.txt: This summary

=== NEXT STEPS ===
1. Review nuclei_results.txt for immediate vulnerabilities
2. Manually test interesting endpoints from content_discovery/
3. Analyze screenshots for interesting applications
4. Perform manual testing on high-value targets
5. Check for business logic vulnerabilities

=== CONTACT ===
Created by: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
Instagram: @letchu_pkt
LinkedIn: lakshmikanthank
Medium: letchupkt.medium.com
EOF

echo -e "${GREEN}[+] Reconnaissance completed!${NC}"
echo -e "${BLUE}[*] Summary report saved to summary_report.txt${NC}"
echo -e "${YELLOW}[*] Review the results and start manual testing${NC}"

# Display quick stats
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    RECONNAISSANCE SUMMARY                   ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║ Domain: $DOMAIN"
echo "║ Subdomains: $TOTAL_SUBDOMAINS"
echo "║ Live Hosts: $LIVE_HOSTS"
echo "║ Vulnerabilities: $NUCLEI_FINDINGS"
echo "║ Output Directory: $OUTPUT_DIR"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
```

## 📊 Phase 4 Assessment

### ✅ Tool Mastery Checklist

Before moving to Phase 5, ensure you can:

#### HTTP Proxies and Analysis
- [ ] Configure and use Burp Suite Professional effectively
- [ ] Create custom Burp extensions for specific testing needs
- [ ] Use OWASP ZAP for automated scanning and custom scripts
- [ ] Analyze HTTP traffic for security vulnerabilities
- [ ] Integrate proxy tools into testing workflows

#### Reconnaissance Automation
- [ ] Perform comprehensive subdomain enumeration
- [ ] Validate and filter discovered assets
- [ ] Use multiple tools in combination for maximum coverage
- [ ] Create custom reconnaissance workflows
- [ ] Scale reconnaissance for large attack surfaces

#### Vulnerability Detection
- [ ] Use Nuclei effectively with custom templates
- [ ] Create and modify vulnerability detection templates
- [ ] Integrate multiple scanners for comprehensive coverage
- [ ] Filter and prioritize vulnerability findings
- [ ] Validate automated scanner results

#### Custom Tool Development
- [ ] Write Python scripts for security testing
- [ ] Create Bash automation workflows
- [ ] Develop custom payloads and wordlists
- [ ] Build tool integration pipelines
- [ ] Optimize tools for performance and accuracy

### 🎯 Practical Assessment

Complete these challenges to validate your Phase 4 knowledge:

1. **[Custom Tool Development](exercises/custom-tool-development.md)**: Build a comprehensive reconnaissance tool
2. **[Advanced Burp Usage](exercises/advanced-burp-usage.md)**: Create custom extensions and advanced testing workflows
3. **[Nuclei Template Creation](exercises/nuclei-template-creation.md)**: Develop custom vulnerability detection templates

### 📈 Progress Tracking

| Tool Category | Basic Usage | Advanced Features | Custom Development | Automation | Your Level |
|---------------|-------------|-------------------|-------------------|------------|------------|
| HTTP Proxies | Manual testing | Extensions & Scripts | Custom extensions | Workflow automation | [ ] |
| Reconnaissance | Single tools | Multi-tool workflows | Custom frameworks | Scalable pipelines | [ ] |
| Vulnerability Scanners | Basic scans | Custom templates | Template development | Integration workflows | [ ] |
| Content Discovery | Directory enum | Advanced fuzzing | Custom wordlists | Automated discovery | [ ] |
| Custom Development | Basic scripts | Advanced tools | Framework development | Tool integration | [ ] |

## 🎉 Phase 4 Completion

Outstanding! You now have mastery over essential bug bounty tools. You should:

- ✅ Be proficient with all major security testing tools
- ✅ Have built custom automation workflows
- ✅ Understand how to scale reconnaissance and testing
- ✅ Be able to develop custom tools for specific needs
- ✅ Have integrated multiple tools into efficient workflows

## 🚀 Next Steps

Ready for Phase 5? Move on to [Phase 5: Advanced Techniques](../phase-05-advanced-techniques/) where you'll learn:

- Advanced exploitation techniques and methodologies
- Emerging attack vectors and cutting-edge vulnerabilities
- Mobile and API security testing at scale
- Business logic vulnerability identification
- Zero-day research and development techniques

---

## 📝 Author & Credits

**Created by: LakshmiKanthanK(letchupkt)**

🔗 **Connect with me:**
- 🌐 **Portfolio**: [letchupkt.vgrow.tech](https://letchupkt.vgrow.tech)
- 📸 **Instagram**: [@letchu_pkt](https://instagram.com/letchu_pkt)
- 💼 **LinkedIn**: [lakshmikanthank](https://linkedin.com/in/lakshmikanthank)
- ✍️ **Medium**: [letchupkt.medium.com](https://letchupkt.medium.com)

---

**⏱️ Estimated Time to Complete**: 4-5 months (20-25 hours/week)
**🎯 Success Rate**: 75% of students who complete all tool mastery move successfully to Phase 5
**📈 Next Phase**: [Phase 5: Advanced Techniques](../phase-05-advanced-techniques/)

*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*