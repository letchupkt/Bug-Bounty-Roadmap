# 🛠️ Complete Tool Installation Guide

> **Essential tools for bug bounty hunting - from beginner to advanced**

## 📋 Quick Setup Checklist

### ✅ Phase 1 Tools (Foundation)
- [ ] **Burp Suite Community** - HTTP proxy and testing
- [ ] **OWASP ZAP** - Free security scanner
- [ ] **Firefox/Chrome** - Web browsers with security extensions
- [ ] **Python 3.8+** - Programming and scripting
- [ ] **Git** - Version control and tool management

### ✅ Phase 2 Tools (Security Knowledge)
- [ ] **Nmap** - Network scanning and enumeration
- [ ] **Nikto** - Web server scanner
- [ ] **SQLMap** - SQL injection testing
- [ ] **Gobuster** - Directory and file enumeration
- [ ] **Wireshark** - Network traffic analysis

### ✅ Phase 3 Tools (Hands-On Practice)
- [ ] **Metasploit** - Exploitation framework
- [ ] **John the Ripper** - Password cracking
- [ ] **Hashcat** - Advanced password recovery
- [ ] **Hydra** - Network login brute forcer
- [ ] **Dirb/Dirbuster** - Web content discovery

### ✅ Phase 4 Tools (Advanced)
- [ ] **Subfinder** - Subdomain enumeration
- [ ] **Amass** - Attack surface mapping
- [ ] **Nuclei** - Vulnerability scanner
- [ ] **Ffuf** - Fast web fuzzer
- [ ] **Katana** - Web crawling

## 🖥️ Operating System Setup

### 🐧 Kali Linux (Recommended for Beginners)

#### Installation Options
1. **VirtualBox VM** (Recommended for Windows/Mac users)
2. **VMware** (Better performance)
3. **Dual Boot** (Advanced users)
4. **WSL2** (Windows Subsystem for Linux)

#### Kali Linux VM Setup
```bash
# Download Kali Linux VM
wget https://cdimage.kali.org/kali-2024.1/kali-linux-2024.1-vmware-amd64.7z

# Extract and import to VMware/VirtualBox
# Default credentials: kali/kali

# Update system
sudo apt update && sudo apt upgrade -y

# Install additional tools
sudo apt install -y curl wget git vim nano
```

### 🪟 Windows Setup

#### Windows Subsystem for Linux (WSL2)
```powershell
# Enable WSL2
wsl --install

# Install Kali Linux
wsl --install -d kali-linux

# Update and upgrade
sudo apt update && sudo apt upgrade -y
```

#### Native Windows Tools
```powershell
# Install Chocolatey package manager
Set-ExecutionPolicy Bypass -Scope Process -Force
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install essential tools
choco install -y git python3 nodejs golang
choco install -y firefox googlechrome
choco install -y wireshark nmap
```

### 🍎 macOS Setup

#### Homebrew Installation
```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install essential tools
brew install git python3 node go
brew install nmap gobuster sqlmap
brew install --cask burp-suite firefox google-chrome
```

## 🌐 Web Browsers and Extensions

### 🦊 Firefox Security Extensions

#### Essential Extensions
```
1. FoxyProxy Standard - Proxy management
2. Wappalyzer - Technology detection
3. User-Agent Switcher - UA manipulation
4. Cookie Editor - Cookie manipulation
5. HackBar - Security testing toolbar
```

#### Installation Commands
```bash
# Firefox profiles for security testing
firefox -CreateProfile security-testing
firefox -P security-testing

# Configure proxy settings for Burp Suite
# Proxy: 127.0.0.1:8080
# Import Burp CA certificate
```

### 🔍 Chrome Security Extensions

#### Essential Extensions
```
1. Proxy SwitchyOmega - Proxy management
2. Wappalyzer - Technology stack identification
3. EditThisCookie - Cookie manipulation
4. User-Agent Switcher for Chrome
5. Web Developer - Web development tools
```

## 🔧 Core Security Tools

### 🕷️ Burp Suite

#### Community Edition (Free)
```bash
# Download from PortSwigger website
wget https://portswigger.net/burp/releases/download?product=community&type=linux

# Make executable and run
chmod +x burpsuite_community_linux_*.sh
./burpsuite_community_linux_*.sh
```

#### Professional Edition ($399/year)
```bash
# Features comparison:
# Community: Proxy, Repeater, Decoder, Comparer, Sequencer
# Professional: + Scanner, Intruder, Extensions, Collaborator
```

#### Configuration
```bash
# Proxy settings
Proxy > Options > Proxy Listeners
Interface: 127.0.0.1:8080
Running: ✓

# CA Certificate installation
Proxy > Options > Import/Export CA Certificate
Export Certificate in DER format
Install in browser certificate store
```

### 🛡️ OWASP ZAP

#### Installation
```bash
# Linux (Debian/Ubuntu)
sudo apt install zaproxy

# Windows
choco install zap

# macOS
brew install --cask owasp-zap

# Docker
docker run -u zap -p 8080:8080 -i owasp/zap2docker-stable zap-webswing.sh
```

#### Basic Configuration
```bash
# Command line usage
zap.sh -daemon -port 8080 -config api.disablekey=true

# Automated scanning
zap-baseline.py -t https://example.com
zap-full-scan.py -t https://example.com -r zap_report.html
```

### 🗺️ Nmap

#### Installation
```bash
# Linux
sudo apt install nmap

# Windows
choco install nmap

# macOS
brew install nmap

# Verify installation
nmap --version
```

#### Essential Nmap Commands
```bash
# Basic host discovery
nmap -sn 192.168.1.0/24

# TCP SYN scan
nmap -sS target.com

# Service version detection
nmap -sV target.com

# OS detection
nmap -O target.com

# Comprehensive scan
nmap -sC -sV -O -A target.com

# All ports scan
nmap -p- target.com

# UDP scan (top 1000 ports)
nmap -sU --top-ports 1000 target.com

# Script scanning
nmap --script vuln target.com
nmap --script http-enum target.com
```

### 💉 SQLMap

#### Installation
```bash
# Linux
sudo apt install sqlmap

# From source
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python3 sqlmap.py

# Windows
pip install sqlmap

# Verify installation
sqlmap --version
```

#### Basic Usage
```bash
# Basic SQL injection test
sqlmap -u "http://example.com/page.php?id=1"

# POST request testing
sqlmap -u "http://example.com/login.php" --data="username=admin&password=test"

# Cookie-based testing
sqlmap -u "http://example.com/page.php" --cookie="PHPSESSID=abc123"

# Database enumeration
sqlmap -u "http://example.com/page.php?id=1" --dbs
sqlmap -u "http://example.com/page.php?id=1" -D database_name --tables
sqlmap -u "http://example.com/page.php?id=1" -D database_name -T table_name --columns
sqlmap -u "http://example.com/page.php?id=1" -D database_name -T table_name -C column_name --dump

# Advanced options
sqlmap -u "http://example.com/page.php?id=1" --batch --random-agent --tamper=space2comment
```

### 🔍 Gobuster

#### Installation
```bash
# Linux
sudo apt install gobuster

# From source (Go required)
go install github.com/OJ/gobuster/v3@latest

# Windows
choco install gobuster

# Verify installation
gobuster version
```

#### Directory Enumeration
```bash
# Basic directory enumeration
gobuster dir -u https://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# With file extensions
gobuster dir -u https://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt

# Custom headers and cookies
gobuster dir -u https://example.com -w wordlist.txt -H "Authorization: Bearer token" -c "session=abc123"

# DNS subdomain enumeration
gobuster dns -d example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Virtual host enumeration
gobuster vhost -u https://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

## 🔬 Advanced Reconnaissance Tools

### 🎯 Subfinder

#### Installation
```bash
# Go installation required
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Verify installation
subfinder -version
```

#### Configuration and Usage
```bash
# Create config file
mkdir ~/.config/subfinder
cat > ~/.config/subfinder/provider-config.yaml << EOF
virustotal:
  - "your_virustotal_api_key"
passivetotal:
  - "your_passivetotal_api_key"
securitytrails:
  - "your_securitytrails_api_key"
EOF

# Basic subdomain enumeration
subfinder -d example.com

# Output to file
subfinder -d example.com -o subdomains.txt

# Multiple domains
subfinder -dL domains.txt -o all_subdomains.txt

# Silent mode (only results)
subfinder -d example.com -silent

# Recursive enumeration
subfinder -d example.com -recursive
```

### 🗺️ Amass

#### Installation
```bash
# Linux
sudo apt install amass

# From source
go install -v github.com/OWASP/Amass/v3/...@master

# Verify installation
amass version
```

#### Usage Examples
```bash
# Passive enumeration
amass enum -passive -d example.com -o amass_passive.txt

# Active enumeration
amass enum -active -d example.com -o amass_active.txt

# Brute force enumeration
amass enum -brute -d example.com -o amass_brute.txt

# With configuration file
amass enum -config config.ini -d example.com

# Database operations
amass db -d example.com -enum
amass viz -d3 -d example.com
```

### ⚡ Nuclei

#### Installation
```bash
# Go installation
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Update templates
nuclei -update-templates

# Verify installation
nuclei -version
```

#### Basic Usage
```bash
# Scan single target
nuclei -u https://example.com

# Scan multiple targets
nuclei -l targets.txt

# Specific template categories
nuclei -u https://example.com -t cves/
nuclei -u https://example.com -t vulnerabilities/

# Custom templates
nuclei -u https://example.com -t custom-template.yaml

# Output formats
nuclei -u https://example.com -o results.txt
nuclei -u https://example.com -json -o results.json

# Rate limiting
nuclei -u https://example.com -rate-limit 10
```

### 🚀 Ffuf

#### Installation
```bash
# Go installation
go install github.com/ffuf/ffuf@latest

# Verify installation
ffuf -V
```

#### Usage Examples
```bash
# Directory fuzzing
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://example.com/FUZZ

# File extension fuzzing
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://example.com/FUZZ -e .php,.html,.js,.txt

# Parameter fuzzing
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -u https://example.com/page.php?FUZZ=test

# POST data fuzzing
ffuf -w wordlist.txt -X POST -d "username=admin&password=FUZZ" -u https://example.com/login.php

# Header fuzzing
ffuf -w wordlist.txt -H "X-Forwarded-For: FUZZ" -u https://example.com/

# Filter responses
ffuf -w wordlist.txt -u https://example.com/FUZZ -fc 404,403
ffuf -w wordlist.txt -u https://example.com/FUZZ -fs 1234
```

## 🔐 Password and Hash Tools

### 🔨 John the Ripper

#### Installation
```bash
# Linux
sudo apt install john

# From source (for latest features)
git clone https://github.com/openwall/john.git
cd john/src
make clean && make -s cc

# Verify installation
john --version
```

#### Usage Examples
```bash
# Basic password cracking
john hashes.txt

# With wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Specific hash format
john --format=md5 hashes.txt

# Show cracked passwords
john --show hashes.txt

# Incremental mode
john --incremental hashes.txt

# Rules-based attack
john --rules --wordlist=wordlist.txt hashes.txt
```

### ⚡ Hashcat

#### Installation
```bash
# Linux
sudo apt install hashcat

# Windows
choco install hashcat

# Verify installation
hashcat --version
```

#### Usage Examples
```bash
# MD5 cracking
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# SHA1 cracking
hashcat -m 100 -a 0 hashes.txt wordlist.txt

# NTLM cracking
hashcat -m 1000 -a 0 hashes.txt wordlist.txt

# Brute force attack
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a

# Rule-based attack
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r rules/best64.rule

# Show cracked passwords
hashcat -m 0 hashes.txt --show
```

### 💧 Hydra

#### Installation
```bash
# Linux
sudo apt install hydra

# From source
git clone https://github.com/vanhauser-thc/thc-hydra.git
cd thc-hydra
./configure && make && make install

# Verify installation
hydra -h
```

#### Usage Examples
```bash
# HTTP POST form brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid"

# SSH brute force
hydra -l root -P passwords.txt ssh://192.168.1.100

# FTP brute force
hydra -L users.txt -P passwords.txt ftp://192.168.1.100

# HTTP basic auth
hydra -l admin -P passwords.txt example.com http-get /admin/

# Multiple protocols
hydra -L users.txt -P passwords.txt 192.168.1.100 ssh ftp telnet
```

## 📊 Network Analysis Tools

### 🦈 Wireshark

#### Installation
```bash
# Linux
sudo apt install wireshark

# Add user to wireshark group
sudo usermod -a -G wireshark $USER

# Windows
choco install wireshark

# macOS
brew install --cask wireshark
```

#### Basic Usage
```bash
# Command line version (tshark)
tshark -i eth0 -f "tcp port 80"
tshark -r capture.pcap -Y "http.request.method == POST"

# Common filters
tcp.port == 80
http.request.method == "POST"
ip.addr == 192.168.1.100
dns.qry.name contains "example.com"
```

### 📡 Tcpdump

#### Installation and Usage
```bash
# Usually pre-installed on Linux
tcpdump --version

# Basic packet capture
sudo tcpdump -i eth0

# Capture HTTP traffic
sudo tcpdump -i eth0 port 80

# Save to file
sudo tcpdump -i eth0 -w capture.pcap

# Read from file
tcpdump -r capture.pcap

# Advanced filters
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0'
```

## 🐍 Python Environment Setup

### 📦 Virtual Environment
```bash
# Create virtual environment
python3 -m venv bug-bounty-env

# Activate environment
source bug-bounty-env/bin/activate  # Linux/Mac
bug-bounty-env\Scripts\activate     # Windows

# Install essential packages
pip install requests beautifulsoup4 lxml
pip install urllib3 certifi
pip install colorama termcolor
pip install python-nmap
pip install dnspython
```

### 🔧 Essential Python Libraries
```bash
# HTTP requests and web scraping
pip install requests requests-oauthlib
pip install beautifulsoup4 lxml html5lib
pip install selenium webdriver-manager

# Network and security
pip install scapy netaddr
pip install python-nmap
pip install impacket

# Data processing
pip install pandas numpy
pip install json5 pyyaml
pip install click argparse

# Cryptography
pip install cryptography pycryptodome
pip install hashlib bcrypt

# API testing
pip install httpx aiohttp
pip install graphql-core
```

## 🔧 Custom Tool Installation

### 📝 Installation Script
```bash
#!/bin/bash
# Bug Bounty Tools Installation Script

echo "Installing Bug Bounty Tools..."

# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y curl wget git vim nano python3 python3-pip golang-go

# Install core tools
sudo apt install -y nmap nikto sqlmap gobuster hydra john wireshark

# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Install Python tools
pip3 install sqlmap dirsearch

# Create directories
mkdir -p ~/tools ~/wordlists ~/scripts

# Download wordlists
cd ~/wordlists
wget https://github.com/danielmiessler/SecLists/archive/master.zip
unzip master.zip && rm master.zip

echo "Installation complete!"
```

## 🔍 Tool Verification

### ✅ Verification Script
```bash
#!/bin/bash
# Verify tool installation

echo "Verifying tool installation..."

tools=(
    "nmap --version"
    "gobuster version"
    "sqlmap --version"
    "subfinder -version"
    "nuclei -version"
    "ffuf -V"
    "hydra -h | head -1"
    "john --version"
    "hashcat --version"
)

for tool in "${tools[@]}"; do
    echo -n "Testing $tool: "
    if eval $tool >/dev/null 2>&1; then
        echo "✅ OK"
    else
        echo "❌ FAILED"
    fi
done
```

## 🚀 Performance Optimization

### ⚡ System Optimization
```bash
# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize network settings
echo "net.core.rmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max = 134217728" | sudo tee -a /etc/sysctl.conf

# Apply changes
sudo sysctl -p
```

### 🔧 Tool Configuration
```bash
# Burp Suite memory optimization
export JAVA_OPTS="-Xmx4g -Xms1g"

# Nuclei configuration
mkdir -p ~/.config/nuclei
echo "rate-limit: 150" > ~/.config/nuclei/config.yaml
echo "bulk-size: 25" >> ~/.config/nuclei/config.yaml

# Subfinder API keys
mkdir -p ~/.config/subfinder
# Add API keys to provider-config.yaml
```

## 📚 Additional Resources

### 🔗 Tool Documentation
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [OWASP ZAP User Guide](https://www.zaproxy.org/docs/)
- [Nmap Reference Guide](https://nmap.org/book/)
- [SQLMap User Manual](https://github.com/sqlmapproject/sqlmap/wiki)

### 🎥 Video Tutorials
- [Burp Suite Tutorial Series](https://www.youtube.com/playlist?list=PLq9n8iqQJFDrwFe9AEDBlR1uSHEN7egQA)
- [Nmap Tutorial](https://www.youtube.com/watch?v=4t4kBkMsDbQ)
- [OWASP ZAP Tutorial](https://www.youtube.com/watch?v=ztfgip-UhWw)

### 📖 Cheat Sheets
- [Nmap Cheat Sheet](https://www.stationx.net/nmap-cheat-sheet/)
- [Burp Suite Cheat Sheet](https://portswigger.net/web-security/reference)
- [SQLMap Cheat Sheet](https://www.security-sleuth.com/sleuth-blog/2017/1/3/sqlmap-cheat-sheet)

---

## 📝 Author & Credits

**Created by: LakshmiKanthanK(letchupkt)**

🔗 **Connect with me:**
- 🌐 **Portfolio**: [letchupkt.vgrow.tech](https://letchupkt.vgrow.tech)
- 📸 **Instagram**: [@letchu_pkt](https://instagram.com/letchu_pkt)
- 💼 **LinkedIn**: [lakshmikanthank](https://linkedin.com/in/lakshmikanthank)
- ✍️ **Medium**: [letchupkt.medium.com](https://letchupkt.medium.com)

---

**🔄 Keep Tools Updated**: Run `sudo apt update && sudo apt upgrade` regularly
**📊 Monitor Performance**: Use `htop` and `iotop` to monitor system resources
**🔒 Security First**: Always test tools in isolated environments first

*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*