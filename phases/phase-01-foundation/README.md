# 🏗️ Phase 1: Building Your Foundation (Months 1-3)

> **Goal**: Establish solid technical fundamentals required for bug bounty hunting

## 📚 Learning Objectives

By the end of this phase, you will:
- ✅ Understand computer systems and networking fundamentals
- ✅ Be proficient with command line interfaces (Windows/Linux)
- ✅ Have basic programming skills in Python and JavaScript
- ✅ Understand web application architecture and HTTP protocol
- ✅ Know operating system basics and security concepts

## 🎯 Phase Overview

| Week | Focus Area | Time Investment | Key Deliverables |
|------|------------|----------------|------------------|
| 1-2 | Computer Fundamentals | 15-20 hours | Complete basic computer course |
| 3-4 | Networking Basics | 20-25 hours | Understand TCP/IP, DNS, HTTP |
| 5-6 | Operating Systems | 15-20 hours | Command line proficiency |
| 7-8 | Programming Basics | 25-30 hours | Basic Python/JavaScript skills |
| 9-10 | Web Fundamentals | 20-25 hours | HTTP, HTML, CSS, JavaScript |
| 11-12 | Review & Practice | 15-20 hours | Hands-on exercises |

## 📖 1.1 Computer Fundamentals

### 🎓 Free Learning Resources

| Resource | Type | Duration | Difficulty |
|----------|------|----------|------------|
| [CompTIA A+ Training](https://www.comptia.org/training/by-certification/a) | Course | 40 hours | Beginner |
| [Computer Fundamentals Tutorial](https://www.tutorialspoint.com/computer_fundamentals/index.htm) | Tutorial | 10 hours | Beginner |
| [SWAYAM Computer Course](https://onlinecourses.swayam2.ac.in/cec19_cs06/preview) | Course | 30 hours | Beginner |
| [FreeCodeCamp Fundamentals](https://www.youtube.com/watch?v=tIfRDPekybU) | Video | 8 hours | Beginner |

### 📝 Key Concepts to Master
- Computer hardware components (CPU, RAM, Storage)
- Binary and hexadecimal number systems
- Data representation and encoding
- Basic computer architecture
- Input/Output operations

### ✅ Checkpoint Quiz
Test your knowledge with our [Computer Fundamentals Quiz](exercises/computer-fundamentals-quiz.md)

## 🌐 1.2 Computer Networking

### 🎓 Free Learning Resources

| Resource | Type | Duration | Difficulty |
|----------|------|----------|------------|
| [Networking by Ravindrababu](https://www.youtube.com/watch?v=0AcpUwnc12E&list=PLkW9FMxqUvyZaSQNQslneeODER3bJCb2K) | Video Series | 25 hours | Intermediate |
| [Computer Networking Full Course](https://www.youtube.com/watch?v=qiQR5rTSshw) | Video | 12 hours | Beginner |
| [Gate Smashers Networks](https://www.youtube.com/watch?v=L3ZzkOTDins) | Video | 15 hours | Intermediate |
| [Udacity Networking](https://www.udacity.com/course/computer-networking--ud436) | Course | 20 hours | Intermediate |
| [Google IT Support Certificate](https://www.coursera.org/professional-certificates/google-it-support) | Certificate | 40 hours | Beginner |

### 🔑 Critical Concepts for Bug Bounty

#### TCP/IP Protocol Stack
- **Application Layer**: HTTP, HTTPS, FTP, DNS
- **Transport Layer**: TCP, UDP
- **Network Layer**: IP, ICMP
- **Data Link Layer**: Ethernet, WiFi

#### DNS (Domain Name System)
- DNS resolution process
- DNS record types (A, AAAA, CNAME, MX, TXT)
- DNS enumeration techniques
- Subdomain discovery concepts

#### HTTP/HTTPS Protocols
- Request/Response cycle
- HTTP methods (GET, POST, PUT, DELETE, PATCH)
- HTTP headers and their security implications
- Status codes and their meanings
- HTTPS and TLS/SSL basics

### 🛠️ Practical Exercises
1. [Network Traffic Analysis](exercises/network-analysis.md)
2. [DNS Enumeration Practice](exercises/dns-enumeration.md)
3. [HTTP Request/Response Lab](exercises/http-lab.md)

## 💻 1.3 Operating Systems

### 🎓 Learning Resources

| Resource | Type | Duration | Difficulty |
|----------|------|----------|------------|
| [OS by Neso Academy](https://www.youtube.com/watch?v=z2r-p7xc7c4) | Video Series | 20 hours | Intermediate |
| [Operating Systems Full Course](https://www.youtube.com/watch?v=_tCY-c-sPZc) | Video | 10 hours | Beginner |
| [Coursera OS Power User](https://www.coursera.org/learn/os-power-user) | Course | 25 hours | Beginner |
| [Linux Command Line Tutorial](https://www.youtube.com/watch?v=v_1zB2WNN14) | Video | 8 hours | Beginner |

### 🖥️ Windows Command Line Mastery

#### Essential Commands
```cmd
# File and Directory Operations
dir                    # List directory contents
cd [path]             # Change directory
mkdir [name]          # Create directory
rmdir [name]          # Remove directory
copy [src] [dest]     # Copy files
del [file]            # Delete file
type [file]           # Display file contents

# Network Commands
ipconfig              # Display network configuration
ping [host]           # Test connectivity
netstat -an           # Show network connections
nslookup [domain]     # DNS lookup
tracert [host]        # Trace route to host

# System Information
systeminfo            # Display system information
tasklist              # List running processes
taskkill /PID [id]    # Kill process by ID
```

#### PowerShell Essentials
```powershell
# File Operations
Get-ChildItem         # List files (ls equivalent)
Set-Location          # Change directory (cd equivalent)
Copy-Item             # Copy files
Remove-Item           # Delete files
Get-Content           # Read file contents

# Network Operations
Test-NetConnection    # Advanced ping
Resolve-DnsName       # DNS resolution
Get-NetTCPConnection  # Network connections

# System Operations
Get-Process           # List processes
Stop-Process          # Kill processes
Get-Service           # List services
```

### 🐧 Linux Command Line Mastery

#### File System Navigation
```bash
# Basic Navigation
ls -la                # List files with details
cd /path/to/dir       # Change directory
pwd                   # Print working directory
find / -name "*.txt"  # Find files
locate filename       # Locate files quickly

# File Operations
cat file.txt          # Display file contents
less file.txt         # View file page by page
head -n 10 file.txt   # First 10 lines
tail -f file.txt      # Follow file changes
grep "pattern" file   # Search in files
```

#### Network Commands
```bash
# Network Information
ifconfig              # Network interface config
ip addr show          # Modern network info
netstat -tulpn        # Network connections
ss -tulpn             # Modern netstat
lsof -i :80           # Processes using port 80

# Network Testing
ping google.com       # Test connectivity
traceroute google.com # Trace network path
nslookup google.com   # DNS lookup
dig google.com        # Advanced DNS lookup
curl -I website.com   # HTTP headers
wget file.txt         # Download files
```

### 🛠️ Practical Exercises
1. [Command Line Challenges](exercises/command-line-challenges.md)
2. [File System Navigation](exercises/file-system-nav.md)
3. [Network Troubleshooting](exercises/network-troubleshooting.md)

## 🐍 1.4 Programming Languages

### Python for Bug Bounty (Highly Recommended)

#### Why Python?
- **Automation**: Perfect for reconnaissance scripts
- **Web Scraping**: Beautiful Soup, Scrapy
- **HTTP Requests**: Requests library
- **Data Processing**: Pandas, JSON handling
- **Exploit Development**: Pwntools, socket programming

#### 🎓 Learning Resources

| Resource | Type | Duration | Focus |
|----------|------|----------|-------|
| [Python for Beginners](https://www.youtube.com/watch?v=ZLga4doUdjY&t=30352s) | Video | 12 hours | Complete Basics |
| [Complete Python Tutorial](https://www.youtube.com/watch?v=gfDE2a7MKjA) | Video | 15 hours | Comprehensive |
| [Python Crash Course](https://www.youtube.com/watch?v=eTyI-M50Hu4) | Video | 6 hours | Quick Start |
| [Automate Boring Stuff](https://automatetheboringstuff.com/) | Book/Course | 20 hours | Practical Python |

#### 🔧 Essential Python for Bug Bounty
```python
# HTTP Requests
import requests

# Basic GET request
response = requests.get('https://example.com')
print(response.status_code)
print(response.headers)

# POST request with data
data = {'username': 'admin', 'password': 'test'}
response = requests.post('https://example.com/login', data=data)

# Custom headers
headers = {'User-Agent': 'Custom-Agent/1.0'}
response = requests.get('https://example.com', headers=headers)

# Web Scraping
from bs4 import BeautifulSoup

html = requests.get('https://example.com').text
soup = BeautifulSoup(html, 'html.parser')
links = soup.find_all('a')
for link in links:
    print(link.get('href'))

# File Operations
with open('subdomains.txt', 'r') as f:
    subdomains = f.read().splitlines()

# JSON Handling
import json
data = {'key': 'value'}
json_string = json.dumps(data)
parsed_data = json.loads(json_string)
```

### JavaScript for Web Security (Essential)

#### Why JavaScript?
- **Client-Side Understanding**: How web apps work
- **XSS Exploitation**: Payload development
- **DOM Manipulation**: Understanding web behavior
- **API Interaction**: Modern web applications
- **Node.js**: Server-side JavaScript

#### 🎓 Learning Resources

| Resource | Type | Duration | Focus |
|----------|------|----------|-------|
| [JavaScript Full Course](https://www.youtube.com/watch?v=-lCF2t6iuUc) | Video | 10 hours | Complete JS |
| [JavaScript Tutorial](https://www.youtube.com/watch?v=hKB-YGF14SY&t=1486s) | Video | 8 hours | Fundamentals |
| [JavaScript Basics](https://www.youtube.com/watch?v=jS4aFq5-91M) | Video | 6 hours | Quick Start |
| [MDN JavaScript Guide](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide) | Documentation | Self-paced | Reference |

#### 🔧 Essential JavaScript Concepts
```javascript
// DOM Manipulation
document.getElementById('myElement').innerHTML = 'New Content';
document.querySelector('.class-name').style.display = 'none';

// Event Handling
document.addEventListener('click', function(event) {
    console.log('Clicked:', event.target);
});

// AJAX Requests
fetch('https://api.example.com/data')
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error('Error:', error));

// Local Storage
localStorage.setItem('key', 'value');
const value = localStorage.getItem('key');

// Cookies
document.cookie = "username=admin; path=/";
console.log(document.cookie);
```

### 🛠️ Programming Exercises
1. [Python HTTP Client](exercises/python-http-client.md)
2. [JavaScript DOM Manipulation](exercises/js-dom-manipulation.md)
3. [Web Scraping Challenge](exercises/web-scraping-challenge.md)

## 🌐 1.5 Web Application Fundamentals

### 🎓 Learning Resources

| Resource | Type | Duration | Focus |
|----------|------|----------|-------|
| [How The Web Works (TryHackMe)](https://tryhackme.com/module/how-the-web-works) | Interactive | 5 hours | Web Basics |
| [HTTP in Detail (TryHackMe)](https://tryhackme.com/room/httpindetail) | Interactive | 2 hours | HTTP Protocol |
| [MDN Web Docs - HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Overview) | Documentation | 3 hours | HTTP Reference |
| [Understanding HTTP Protocol](https://www.hackingarticles.in/understanding-http-protocol/) | Article | 1 hour | HTTP Deep Dive |

### 🏗️ Web Architecture Components

#### Client-Server Architecture
```
[Client Browser] ←→ [Web Server] ←→ [Application Server] ←→ [Database]
     ↓                   ↓                    ↓                ↓
  HTML/CSS/JS        HTTP/HTTPS           Business Logic    Data Storage
```

#### HTTP Request/Response Cycle
```
1. User enters URL or clicks link
2. Browser resolves domain name (DNS)
3. Browser establishes connection (TCP/TLS)
4. Browser sends HTTP request
5. Server processes request
6. Server sends HTTP response
7. Browser renders response
```

### 🔍 HTTP Methods Deep Dive

| Method | Purpose | Idempotent | Safe | Common Use |
|--------|---------|------------|------|------------|
| GET | Retrieve data | Yes | Yes | Fetch web pages, API data |
| POST | Submit data | No | No | Form submissions, create resources |
| PUT | Update/create | Yes | No | Update entire resource |
| PATCH | Partial update | No | No | Update part of resource |
| DELETE | Remove resource | Yes | No | Delete resources |
| HEAD | Get headers only | Yes | Yes | Check if resource exists |
| OPTIONS | Get allowed methods | Yes | Yes | CORS preflight requests |

### 📋 HTTP Headers for Security

#### Request Headers
```http
# Authentication
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Cookie: sessionid=abc123; csrftoken=xyz789

# Content Type
Content-Type: application/json
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data

# Security Headers
X-Requested-With: XMLHttpRequest
Origin: https://example.com
Referer: https://example.com/page
```

#### Response Headers
```http
# Security Headers
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000

# CORS Headers
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
```

### 🍪 Session Management

#### Cookies
```javascript
// Setting cookies
document.cookie = "sessionid=abc123; Secure; HttpOnly; SameSite=Strict";

// Cookie attributes
// Secure: Only sent over HTTPS
// HttpOnly: Not accessible via JavaScript
// SameSite: CSRF protection
```

#### Session Storage vs Local Storage
```javascript
// Session Storage (cleared when tab closes)
sessionStorage.setItem('key', 'value');

// Local Storage (persists until cleared)
localStorage.setItem('key', 'value');
```

### 🛠️ Practical Exercises
1. [HTTP Request Analysis](exercises/http-request-analysis.md)
2. [Cookie Manipulation Lab](exercises/cookie-manipulation.md)
3. [Web Architecture Quiz](exercises/web-architecture-quiz.md)

## 📊 Phase 1 Assessment

### ✅ Knowledge Checklist

Before moving to Phase 2, ensure you can:

#### Computer Fundamentals
- [ ] Explain how computers process and store data
- [ ] Convert between binary, decimal, and hexadecimal
- [ ] Understand basic computer architecture

#### Networking
- [ ] Explain the TCP/IP model
- [ ] Perform DNS lookups and understand DNS records
- [ ] Analyze HTTP requests and responses
- [ ] Understand the difference between HTTP and HTTPS

#### Operating Systems
- [ ] Navigate file systems using command line
- [ ] Execute basic network commands
- [ ] Manage processes and services
- [ ] Understand file permissions

#### Programming
- [ ] Write basic Python scripts for HTTP requests
- [ ] Manipulate DOM elements with JavaScript
- [ ] Parse JSON and XML data
- [ ] Handle file operations

#### Web Applications
- [ ] Understand client-server architecture
- [ ] Explain HTTP methods and their purposes
- [ ] Analyze HTTP headers for security implications
- [ ] Understand session management concepts

### 🎯 Practical Assessment

Complete these challenges to validate your Phase 1 knowledge:

1. **[Network Reconnaissance Challenge](exercises/network-recon-challenge.md)**: Use command-line tools to gather information about a target domain
2. **[HTTP Analysis Challenge](exercises/http-analysis-challenge.md)**: Analyze HTTP traffic and identify potential security issues
3. **[Scripting Challenge](exercises/scripting-challenge.md)**: Write a Python script to automate a simple reconnaissance task

### 📈 Progress Tracking

| Skill Area | Beginner | Intermediate | Advanced | Your Level |
|------------|----------|--------------|----------|------------|
| Computer Fundamentals | Basic concepts | Hardware/software interaction | System architecture | [ ] |
| Networking | TCP/IP basics | Protocol analysis | Network security | [ ] |
| Command Line | Basic commands | Scripting | Advanced automation | [ ] |
| Programming | Syntax basics | Problem solving | Tool development | [ ] |
| Web Fundamentals | HTTP basics | Security headers | Architecture patterns | [ ] |

## 🎉 Phase 1 Completion

Congratulations! You've built a solid foundation. You should now:

- ✅ Understand how computers and networks operate
- ✅ Be comfortable with command-line interfaces
- ✅ Have basic programming skills in Python and JavaScript
- ✅ Understand web application architecture and HTTP protocol
- ✅ Be ready to dive into security-specific knowledge

## 🚀 Next Steps

Ready for Phase 2? Move on to [Phase 2: Core Security Knowledge](../phase-02-security-knowledge/) where you'll learn:

- OWASP Top 10 vulnerabilities in detail
- Security testing methodologies
- Vulnerability assessment techniques
- Security tools and frameworks

## 📚 Additional Resources

### Books
- [Computer Networks by Andrew Tanenbaum](https://www.amazon.com/Computer-Networks-5th-Andrew-Tanenbaum/dp/0132126958)
- [HTTP: The Definitive Guide](https://www.amazon.com/HTTP-Definitive-Guide-Guides/dp/1565925092)
- [Python Crash Course](https://www.amazon.com/Python-Crash-Course-Hands-Project-Based/dp/1593276036)

### Practice Platforms
- [Codecademy](https://www.codecademy.com/) - Interactive programming courses
- [HackerRank](https://www.hackerrank.com/) - Programming challenges
- [LeetCode](https://leetcode.com/) - Algorithm practice

### Communities
- [r/learnprogramming](https://www.reddit.com/r/learnprogramming/) - Programming help
- [Stack Overflow](https://stackoverflow.com/) - Technical Q&A
- [GitHub](https://github.com/) - Open source projects

---

## 📝 Author & Credits

**Created by: LakshmiKanthanK(letchupkt)**

🔗 **Connect with me:**
- 🌐 **Portfolio**: [letchupkt.vgrow.tech](https://letchupkt.vgrow.tech)
- 📸 **Instagram**: [@letchu_pkt](https://instagram.com/letchu_pkt)
- 💼 **LinkedIn**: [lakshmikanthank](https://linkedin.com/in/lakshmikanthank)
- ✍️ **Medium**: [letchupkt.medium.com](https://letchupkt.medium.com)

---

**⏱️ Estimated Time to Complete**: 2-3 months (10-15 hours/week)
**🎯 Success Rate**: 95% of students who complete all exercises move successfully to Phase 2
**📈 Next Phase**: [Phase 2: Core Security Knowledge](../phase-02-security-knowledge/)

*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*