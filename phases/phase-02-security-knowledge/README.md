# 🔒 Phase 2: Core Security Knowledge (Months 3-6)

> **Goal**: Master fundamental security concepts and vulnerability types essential for bug bounty hunting

## 📚 Learning Objectives

By the end of this phase, you will:
- ✅ Master all OWASP Top 10 vulnerabilities (2021-2025)
- ✅ Understand security testing methodologies
- ✅ Know how to identify and exploit common vulnerabilities
- ✅ Be familiar with security frameworks and standards
- ✅ Have read essential bug bounty literature

## 🎯 Phase Overview

| Week | Focus Area | Time Investment | Key Deliverables |
|------|------------|----------------|------------------|
| 1-2 | OWASP Top 10 (A01-A03) | 20-25 hours | Understand Broken Access Control, Crypto Failures, Injection |
| 3-4 | OWASP Top 10 (A04-A06) | 20-25 hours | Master Insecure Design, Misconfig, Vulnerable Components |
| 5-6 | OWASP Top 10 (A07-A10) | 20-25 hours | Learn Auth Failures, Integrity Issues, Logging, SSRF |
| 7-8 | Security Testing Methods | 15-20 hours | Testing methodologies and frameworks |
| 9-10 | Essential Reading | 25-30 hours | Bug bounty books and research papers |
| 11-12 | Vulnerability Research | 20-25 hours | CVE analysis and exploit research |

## 🏆 OWASP Top 10 (2021-2025) - Complete Guide

### 🥇 A01: Broken Access Control

> **Impact**: Highest - Attackers can access unauthorized functionality or data

#### What is Broken Access Control?
Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data.

#### Common Scenarios
- **Vertical Privilege Escalation**: Regular user gains admin access
- **Horizontal Privilege Escalation**: User accesses another user's data
- **IDOR (Insecure Direct Object References)**: Direct access to objects by ID
- **Missing Function Level Access Control**: Unprotected admin functions

#### Real-World Examples
```http
# IDOR Example - Accessing other user's data
GET /api/user/123/profile HTTP/1.1
# Change 123 to 124 to access another user's profile

# Privilege Escalation Example
POST /admin/delete-user HTTP/1.1
# Regular user accessing admin function
```

#### 🛠️ Testing Techniques
1. **Parameter Manipulation**: Change user IDs, role parameters
2. **URL Manipulation**: Access admin URLs directly
3. **HTTP Method Testing**: Try different HTTP methods
4. **Token Analysis**: Analyze JWT tokens for role information

#### 🔧 Tools for Testing
- **Burp Suite**: Parameter manipulation, session analysis
- **OWASP ZAP**: Automated access control testing
- **Custom Scripts**: Automated IDOR testing

#### 📚 Learning Resources
- [PortSwigger Access Control Labs](https://portswigger.net/web-security/access-control)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [TryHackMe IDOR Room](https://tryhackme.com/room/idor)

### 🥈 A02: Cryptographic Failures

> **Impact**: High - Sensitive data exposure due to weak or missing encryption

#### What are Cryptographic Failures?
Previously known as "Sensitive Data Exposure," this category focuses on failures related to cryptography that often lead to sensitive data exposure.

#### Common Scenarios
- **Weak Encryption Algorithms**: MD5, SHA1, DES
- **Missing Encryption**: Sensitive data transmitted in plaintext
- **Poor Key Management**: Hardcoded keys, weak key generation
- **Improper Certificate Validation**: Accepting invalid SSL certificates

#### Real-World Examples
```javascript
// Weak hashing example
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex'); // WEAK!

// Better approach
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12); // STRONG!
```

#### 🛠️ Testing Techniques
1. **Traffic Analysis**: Check for unencrypted sensitive data
2. **Certificate Analysis**: Verify SSL/TLS configuration
3. **Encryption Testing**: Test for weak algorithms
4. **Key Analysis**: Look for hardcoded keys in source code

#### 🔧 Tools for Testing
- **SSLyze**: SSL/TLS configuration analysis
- **testssl.sh**: Comprehensive SSL testing
- **Nmap SSL Scripts**: SSL vulnerability scanning
- **Burp Suite**: Traffic analysis and manipulation

### 🥉 A03: Injection

> **Impact**: High - Complete system compromise possible

#### What is Injection?
Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands.

#### Types of Injection
1. **SQL Injection**: Database queries
2. **Command Injection**: Operating system commands
3. **LDAP Injection**: LDAP queries
4. **XPath Injection**: XML queries
5. **NoSQL Injection**: NoSQL database queries

#### SQL Injection Deep Dive

##### Union-Based SQL Injection
```sql
-- Original query
SELECT * FROM users WHERE id = '1'

-- Malicious input
1' UNION SELECT username,password FROM admin_users--

-- Final query
SELECT * FROM users WHERE id = '1' UNION SELECT username,password FROM admin_users--'
```

##### Boolean-Based Blind SQL Injection
```sql
-- Test for vulnerability
1' AND 1=1-- (returns normal response)
1' AND 1=2-- (returns different response)

-- Extract data
1' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'--
```

##### Time-Based Blind SQL Injection
```sql
-- MySQL example
1'; IF(1=1, SLEEP(5), 0)--

-- PostgreSQL example
1'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 0 END--
```

#### Command Injection Examples
```bash
# Original command
ping -c 1 192.168.1.1

# Malicious input
192.168.1.1; cat /etc/passwd

# Final command
ping -c 1 192.168.1.1; cat /etc/passwd
```

#### 🛠️ Testing Techniques
1. **Input Validation Testing**: Test all input fields
2. **Special Character Testing**: Use SQL/command metacharacters
3. **Blind Testing**: Use time delays and boolean conditions
4. **Error-Based Testing**: Trigger database errors

#### 🔧 Tools for Testing
- **SQLMap**: Automated SQL injection testing
- **Commix**: Command injection testing
- **Burp Suite**: Manual injection testing
- **OWASP ZAP**: Automated injection scanning

### 🏅 A04: Insecure Design

> **Impact**: Medium to High - Fundamental security flaws in application design

#### What is Insecure Design?
Insecure design is a broad category representing different weaknesses, expressed as "missing or ineffective control design." It focuses on risks related to design and architectural flaws.

#### Common Design Flaws
- **Missing Security Controls**: No rate limiting, access controls
- **Insufficient Threat Modeling**: Not considering attack scenarios
- **Business Logic Flaws**: Workflow vulnerabilities
- **Insecure Architecture**: Poor separation of concerns

#### Business Logic Vulnerability Examples
```
# Price Manipulation
1. Add expensive item to cart ($1000)
2. Add cheap item to cart ($10)
3. Modify quantity of expensive item to negative (-1)
4. Total becomes $10 - $1000 = -$990 (credit to account)

# Race Condition
1. User has $100 balance
2. Simultaneously initiate two $100 transfers
3. Both transfers succeed due to race condition
4. User transfers $200 with only $100 balance
```

#### 🛠️ Testing Techniques
1. **Threat Modeling**: Identify potential attack vectors
2. **Business Logic Testing**: Test workflow edge cases
3. **Architecture Review**: Analyze system design
4. **Abuse Case Testing**: Test unintended use cases

### 🔐 A05: Security Misconfiguration

> **Impact**: Medium to High - Unauthorized access to systems and data

#### What is Security Misconfiguration?
Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete configurations, or misconfigured HTTP headers.

#### Common Misconfigurations
- **Default Credentials**: admin/admin, root/root
- **Directory Listing**: Exposed file directories
- **Verbose Error Messages**: Stack traces in production
- **Missing Security Headers**: CSP, HSTS, X-Frame-Options
- **Unnecessary Services**: Unused ports and services

#### Examples
```http
# Missing Security Headers
HTTP/1.1 200 OK
Content-Type: text/html
# Missing: X-Frame-Options, CSP, HSTS

# Should include:
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000
```

#### 🛠️ Testing Techniques
1. **Configuration Review**: Check server configurations
2. **Default Credential Testing**: Test common credentials
3. **Directory Enumeration**: Look for exposed directories
4. **Header Analysis**: Check for missing security headers

#### 🔧 Tools for Testing
- **Nmap**: Port and service scanning
- **Nikto**: Web server misconfiguration scanner
- **DirBuster**: Directory enumeration
- **SecurityHeaders.com**: Header analysis

### 📦 A06: Vulnerable and Outdated Components

> **Impact**: Medium to Critical - Known vulnerabilities in dependencies

#### What are Vulnerable Components?
Applications often use components with known vulnerabilities. This includes libraries, frameworks, and other software modules that run with the same privileges as the application.

#### Common Scenarios
- **Outdated Libraries**: Using old versions with known CVEs
- **Unnecessary Components**: Unused libraries increasing attack surface
- **Unpatched Systems**: Missing security updates
- **Supply Chain Attacks**: Compromised dependencies

#### Examples
```json
// package.json with vulnerable dependencies
{
  "dependencies": {
    "lodash": "4.17.4",  // Vulnerable to prototype pollution
    "jquery": "1.12.4",  // Multiple XSS vulnerabilities
    "express": "3.21.2"  // Directory traversal vulnerability
  }
}
```

#### 🛠️ Testing Techniques
1. **Dependency Scanning**: Identify vulnerable components
2. **Version Analysis**: Check component versions against CVE databases
3. **License Review**: Understand component licenses
4. **Supply Chain Analysis**: Verify component integrity

#### 🔧 Tools for Testing
- **npm audit**: Node.js dependency scanning
- **Snyk**: Multi-language vulnerability scanning
- **OWASP Dependency-Check**: Open source dependency scanner
- **GitHub Security Advisories**: Automated vulnerability alerts

### 🔑 A07: Identification and Authentication Failures

> **Impact**: High - Complete account takeover possible

#### What are Authentication Failures?
Previously known as "Broken Authentication," this category includes weaknesses in authentication and session management that allow attackers to compromise passwords, keys, or session tokens.

#### Common Scenarios
- **Weak Password Policies**: No complexity requirements
- **Credential Stuffing**: Using breached password lists
- **Session Fixation**: Reusing session IDs
- **Missing Multi-Factor Authentication**: Single factor authentication only

#### Attack Examples
```python
# Brute Force Attack
import requests

passwords = ['password', '123456', 'admin', 'letmein']
for password in passwords:
    response = requests.post('https://example.com/login', 
                           data={'username': 'admin', 'password': password})
    if 'Invalid' not in response.text:
        print(f'Password found: {password}')
        break
```

#### 🛠️ Testing Techniques
1. **Brute Force Testing**: Test weak passwords
2. **Session Analysis**: Analyze session token generation
3. **Password Policy Testing**: Test password requirements
4. **Multi-Factor Testing**: Check MFA implementation

#### 🔧 Tools for Testing
- **Hydra**: Network login brute forcer
- **Burp Suite Intruder**: Automated brute force attacks
- **John the Ripper**: Password cracking
- **Hashcat**: Advanced password recovery

### 🔄 A08: Software and Data Integrity Failures

> **Impact**: High - Code execution and data tampering

#### What are Integrity Failures?
This category focuses on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity.

#### Common Scenarios
- **Unsigned Updates**: Software updates without signature verification
- **Insecure Deserialization**: Untrusted data deserialization
- **CI/CD Pipeline Attacks**: Compromised build processes
- **Auto-Update Vulnerabilities**: Insecure update mechanisms

#### Deserialization Attack Example
```python
# Vulnerable Python code
import pickle
import base64

# Attacker payload
class Exploit:
    def __reduce__(self):
        return (os.system, ('rm -rf /',))

# Serialized malicious object
payload = base64.b64encode(pickle.dumps(Exploit()))

# Vulnerable deserialization
pickle.loads(base64.b64decode(payload))  # Executes rm -rf /
```

#### 🛠️ Testing Techniques
1. **Deserialization Testing**: Test serialized data handling
2. **Update Mechanism Analysis**: Check software update security
3. **CI/CD Pipeline Review**: Analyze build processes
4. **Digital Signature Verification**: Check code signing

### 📊 A09: Security Logging and Monitoring Failures

> **Impact**: Medium - Delayed incident detection and response

#### What are Logging Failures?
Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems and maintain persistence.

#### Common Issues
- **Insufficient Logging**: Not logging security events
- **Log Injection**: Unsanitized user input in logs
- **Missing Monitoring**: No real-time threat detection
- **Poor Log Management**: Logs not properly stored or analyzed

#### Log Injection Example
```
# User input: admin' OR '1'='1
# Logged as: User admin' OR '1'='1 logged in successfully
# Could be used to inject malicious content into logs
```

#### 🛠️ Testing Techniques
1. **Log Analysis**: Review application logs
2. **Event Testing**: Trigger security events and check logging
3. **Log Injection Testing**: Test log input sanitization
4. **Monitoring Testing**: Test alerting mechanisms

### 🌐 A10: Server-Side Request Forgery (SSRF)

> **Impact**: High - Internal network access and data exposure

#### What is SSRF?
SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination.

#### Attack Scenarios
- **Internal Network Scanning**: Access internal services
- **Cloud Metadata Access**: AWS/Azure metadata endpoints
- **File System Access**: Read local files via file:// protocol
- **Port Scanning**: Enumerate internal services

#### SSRF Examples
```http
# Basic SSRF
POST /fetch-url HTTP/1.1
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/"}

# Bypassing filters
{"url": "http://127.0.0.1:22"}  # SSH port
{"url": "file:///etc/passwd"}   # Local file access
{"url": "gopher://internal-service:6379/_INFO"}  # Redis access
```

#### 🛠️ Testing Techniques
1. **URL Parameter Testing**: Test all URL parameters
2. **Protocol Testing**: Try different protocols (file://, gopher://)
3. **Bypass Testing**: Test filter bypasses
4. **Internal Service Discovery**: Scan for internal services

#### 🔧 Tools for Testing
- **SSRFmap**: SSRF exploitation tool
- **Gopherus**: Generate gopher payloads
- **Burp Suite**: Manual SSRF testing
- **Custom Scripts**: Automated SSRF detection

## 📚 Essential Bug Bounty Literature

### 🏆 Must-Read Books

#### 1. The Web Application Hacker's Handbook
- **Authors**: Dafydd Stuttard, Marcus Pinto
- **Focus**: Comprehensive web application security testing
- **Key Topics**: All major vulnerability classes, testing methodologies
- **Why Essential**: Industry standard reference for web app security

#### 2. Bug Bounty Bootcamp
- **Author**: Vickie Li
- **Focus**: Modern bug bounty hunting techniques
- **Key Topics**: Reconnaissance, automation, reporting
- **Why Essential**: Written by active bug bounty hunter, practical approach

#### 3. Real-World Bug Hunting
- **Author**: Peter Yaworski
- **Focus**: Case studies and real vulnerability examples
- **Key Topics**: Actual bug bounty reports, hunting strategies
- **Why Essential**: Learn from real-world examples and success stories

#### 4. The Hacker Playbook 3
- **Author**: Peter Kim
- **Focus**: Practical penetration testing
- **Key Topics**: Red team tactics, advanced techniques
- **Why Essential**: Hands-on approach to security testing

### 📖 Reading Schedule

| Week | Book/Resource | Chapters/Sections | Focus Area |
|------|---------------|-------------------|------------|
| 7 | Web App Hacker's Handbook | Chapters 1-4 | Web app fundamentals |
| 8 | Bug Bounty Bootcamp | Chapters 1-6 | Reconnaissance and methodology |
| 9 | Real-World Bug Hunting | Part 1 | XSS and injection vulnerabilities |
| 10 | Real-World Bug Hunting | Part 2 | Access control and logic flaws |
| 11 | The Hacker Playbook 3 | Chapters 1-3 | Advanced techniques |
| 12 | Security Research Papers | Various | Latest research and techniques |

## 🔬 Vulnerability Research and CVE Analysis

### Understanding CVEs (Common Vulnerabilities and Exposures)

#### CVE Structure
```
CVE-YYYY-NNNN
├── CVE: Common Vulnerabilities and Exposures
├── YYYY: Year of publication
└── NNNN: Sequential number
```

#### CVE Analysis Process
1. **Vulnerability Description**: Understand the flaw
2. **Affected Systems**: Identify vulnerable software/versions
3. **CVSS Score**: Assess severity and impact
4. **Exploit Analysis**: Study proof-of-concept exploits
5. **Mitigation Strategies**: Learn remediation techniques

### 🔍 CVE Research Resources

| Resource | Type | Focus | URL |
|----------|------|-------|-----|
| NIST NVD | Database | Official CVE database | https://nvd.nist.gov/ |
| CVE Details | Database | CVE statistics and details | https://www.cvedetails.com/ |
| Exploit-DB | Exploits | Proof-of-concept exploits | https://www.exploit-db.com/ |
| VulDB | Database | Vulnerability intelligence | https://vuldb.com/ |
| Packet Storm | Security | Security advisories | https://packetstormsecurity.com/ |

### 📊 Weekly CVE Analysis Exercise

Each week, analyze 5 recent CVEs:
1. **High-severity web application CVEs**
2. **Document findings in standardized format**
3. **Create proof-of-concept if possible**
4. **Identify similar vulnerabilities in bug bounty scope**

## 🛡️ Security Testing Methodologies

### OWASP Testing Guide (OTG)

#### Testing Categories
1. **Information Gathering** (OTG-INFO)
2. **Configuration and Deployment Management** (OTG-CONFIG)
3. **Identity Management** (OTG-IDENT)
4. **Authentication** (OTG-AUTHN)
5. **Authorization** (OTG-AUTHZ)
6. **Session Management** (OTG-SESS)
7. **Input Validation** (OTG-INPVAL)
8. **Error Handling** (OTG-ERR)
9. **Cryptography** (OTG-CRYPST)
10. **Business Logic** (OTG-BUSLOGIC)
11. **Client Side** (OTG-CLIENT)

### PTES (Penetration Testing Execution Standard)

#### Testing Phases
1. **Pre-engagement Interactions**
2. **Intelligence Gathering**
3. **Threat Modeling**
4. **Vulnerability Analysis**
5. **Exploitation**
6. **Post Exploitation**
7. **Reporting**

### NIST Cybersecurity Framework

#### Core Functions
1. **Identify**: Asset management, risk assessment
2. **Protect**: Access control, data security
3. **Detect**: Continuous monitoring, detection processes
4. **Respond**: Incident response, communications
5. **Recover**: Recovery planning, improvements

## 📊 Phase 2 Assessment

### ✅ Knowledge Checklist

Before moving to Phase 3, ensure you can:

#### OWASP Top 10 Mastery
- [ ] Explain each vulnerability with real-world examples
- [ ] Identify vulnerable code patterns
- [ ] Describe testing techniques for each vulnerability
- [ ] Understand remediation strategies

#### Security Testing
- [ ] Apply systematic testing methodologies
- [ ] Use security frameworks for assessment
- [ ] Perform threat modeling exercises
- [ ] Analyze security architectures

#### Vulnerability Research
- [ ] Analyze CVE reports effectively
- [ ] Understand exploit development basics
- [ ] Research vulnerability trends
- [ ] Identify zero-day potential

### 🎯 Practical Assessment

Complete these challenges to validate your Phase 2 knowledge:

1. **[OWASP Top 10 Challenge](exercises/owasp-top10-challenge.md)**: Identify and exploit all OWASP Top 10 vulnerabilities in a test application
2. **[CVE Analysis Project](exercises/cve-analysis-project.md)**: Analyze 10 recent CVEs and create detailed reports
3. **[Security Testing Plan](exercises/security-testing-plan.md)**: Create a comprehensive testing plan for a web application

### 📈 Progress Tracking

| Vulnerability Type | Understanding | Testing Skills | Exploitation | Your Level |
|-------------------|---------------|----------------|--------------|------------|
| Broken Access Control | Theory | Manual Testing | Automated Tools | [ ] |
| Cryptographic Failures | Concepts | Configuration Review | Weakness Exploitation | [ ] |
| Injection | All Types | Manual/Automated | Advanced Techniques | [ ] |
| Insecure Design | Principles | Architecture Review | Business Logic | [ ] |
| Security Misconfiguration | Common Issues | Systematic Testing | Tool Usage | [ ] |
| Vulnerable Components | Identification | Scanning | Exploitation | [ ] |
| Authentication Failures | Mechanisms | Testing Methods | Bypass Techniques | [ ] |
| Integrity Failures | Concepts | Testing Approaches | Exploitation | [ ] |
| Logging Failures | Requirements | Assessment | Monitoring | [ ] |
| SSRF | Understanding | Detection | Advanced Exploitation | [ ] |

## 🎉 Phase 2 Completion

Congratulations! You now have comprehensive security knowledge. You should:

- ✅ Master all OWASP Top 10 vulnerabilities
- ✅ Understand security testing methodologies
- ✅ Be familiar with vulnerability research processes
- ✅ Have read essential bug bounty literature
- ✅ Be ready for hands-on practice and tool usage

## 🚀 Next Steps

Ready for Phase 3? Move on to [Phase 3: Hands-On Practice](../phase-03-hands-on-practice/) where you'll:

- Practice on intentionally vulnerable applications
- Complete CTF challenges and labs
- Use security testing tools in real scenarios
- Build practical exploitation skills

## 📚 Additional Resources

### Security Blogs and Research
- [PortSwigger Research](https://portswigger.net/research) - Latest web security research
- [Google Project Zero](https://googleprojectzero.blogspot.com/) - Zero-day research
- [Krebs on Security](https://krebsonsecurity.com/) - Security news and analysis
- [Schneier on Security](https://www.schneier.com/) - Security commentary

### Academic Resources
- [SANS Reading Room](https://www.sans.org/reading-room/) - Security whitepapers
- [IEEE Security & Privacy](https://www.computer.org/csdl/magazine/sp) - Academic research
- [ACM Digital Library](https://dl.acm.org/) - Computer science research

### Vulnerability Databases
- [Mitre CVE](https://cve.mitre.org/) - Official CVE database
- [CWE List](https://cwe.mitre.org/) - Common weakness enumeration
- [CAPEC](https://capec.mitre.org/) - Common attack pattern enumeration

---

## 📝 Author & Credits

**Created by: LakshmiKanthanK(letchupkt)**

🔗 **Connect with me:**
- 🌐 **Portfolio**: [letchupkt.vgrow.tech](https://letchupkt.vgrow.tech)
- 📸 **Instagram**: [@letchu_pkt](https://instagram.com/letchu_pkt)
- 💼 **LinkedIn**: [lakshmikanthank](https://linkedin.com/in/lakshmikanthank)
- ✍️ **Medium**: [letchupkt.medium.com](https://letchupkt.medium.com)

---

**⏱️ Estimated Time to Complete**: 3-4 months (15-20 hours/week)
**🎯 Success Rate**: 85% of students who complete all assessments move successfully to Phase 3
**📈 Next Phase**: [Phase 3: Hands-On Practice](../phase-03-hands-on-practice/)

*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*