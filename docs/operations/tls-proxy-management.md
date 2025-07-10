---
title: "TLS & Proxy Management"
parent: "Operations Guide"
nav_order: 14
---

# TLS & Proxy Management

This guide addresses the critical challenges of managing TLS traffic and API proxies in Model Context Protocol (MCP) environments. Since most MCP traffic is encrypted with TLS and uninspectable at the network level, **proper TLS and proxy management is essential** for maintaining security visibility and control.

## Community Discussion

💬 **[TLS & Proxy Management Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Share your TLS management strategies, proxy configurations, and solutions to encrypted traffic challenges.

## The TLS Inspection Challenge

### Why TLS Makes MCP Security Difficult
**Most MCP traffic is encrypted and uninspectable:**
- **HTTPS Everywhere** - All modern APIs use HTTPS, making content inspection impossible
- **End-to-End Encryption** - TLS encrypts the entire HTTP payload, including headers and body
- **Network Security Blindness** - Traditional firewalls and IDS/IPS cannot see encrypted content
- **Compliance Gaps** - Regulatory requirements for data inspection cannot be met at network level

### The API Proxy Solution
**API proxies provide the only practical solution for TLS traffic inspection:**
- **TLS Termination** - Proxy terminates TLS connection and inspects plaintext content
- **Policy Enforcement** - Apply security policies to decrypted traffic
- **Content Filtering** - Block malicious content before it reaches external services
- **Audit Logging** - Log all API interactions for compliance and security monitoring

## TLS Termination Strategies

### Forward Proxy with TLS Termination
```nginx
# nginx.conf - Forward proxy with TLS termination
events {
    worker_connections 1024;
}

http {
    # Define upstream for external services
    upstream external_api {
        server api.external-service.com:443;
        keepalive 32;
    }
    
    # Forward proxy server
    server {
        listen 8080;
        
        # TLS termination and re-encryption
        location / {
            # Extract target host from request
            set $target_host $http_host;
            
            # Proxy to external service with TLS re-encryption
            proxy_pass https://external_api;
            proxy_ssl_verify on;
            proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
            proxy_ssl_protocols TLSv1.2 TLSv1.3;
            
            # Preserve original host header
            proxy_set_header Host $target_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            
            # Security headers
            add_header X-Content-Type-Options nosniff;
            add_header X-Frame-Options DENY;
            add_header X-XSS-Protection "1; mode=block";
            
            # Content inspection and logging
            access_log /var/log/nginx/proxy_access.log;
            error_log /var/log/nginx/proxy_error.log;
        }
    }
}
```

### Squid Proxy with SSL Bump
```conf
# squid.conf - SSL bump configuration for TLS inspection
http_port 3128 ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert=/etc/squid/ssl/squid.pem key=/etc/squid/ssl/squid.key

# SSL bump configuration
ssl_bump bump all
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/spool/squid/ssl_db -M 4MB

# Access control
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16

# Allow local network
http_access allow localnet
http_access deny all

# Content filtering
acl malicious_content rep_header Content-Type -i "application/malware"
http_reply_access deny malicious_content

# Logging
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log
```

## Certificate Management

### Self-Signed Certificate Authority
```bash
#!/bin/bash
# Create self-signed CA for TLS termination

# Generate CA private key
openssl genrsa -out ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 365 -key ca-key.pem -out ca-cert.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=MCP-Proxy-CA"

# Generate server private key
openssl genrsa -out server-key.pem 4096

# Generate server certificate signing request
openssl req -new -key server-key.pem -out server-csr.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=api-gateway"

# Generate server certificate
openssl x509 -req -days 365 -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem

# Set proper permissions
chmod 600 *-key.pem
chmod 644 *-cert.pem
```

### Certificate Distribution
```dockerfile
# Dockerfile - Include custom CA certificate
FROM python:3.11-slim

# Copy custom CA certificate
COPY ca-cert.pem /usr/local/share/ca-certificates/mcp-proxy-ca.crt

# Update CA certificates
RUN update-ca-certificates

# Set environment variable for requests library
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# Install MCP server
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt

CMD ["python", "mcp_server.py"]
```

## Proxy Configuration for MCP Servers

### Python Proxy Configuration
```python
import os
import requests
from requests.adapters import HTTPAdapter
import urllib3

class TLSProxyClient:
    """HTTP client configured for TLS proxy"""
    
    def __init__(self, proxy_url=None, ca_cert_path=None):
        self.session = requests.Session()
        
        # Configure proxy
        self.proxy_url = proxy_url or os.environ.get('HTTPS_PROXY')
        if self.proxy_url:
            self.session.proxies.update({
                'http': self.proxy_url,
                'https': self.proxy_url
            })
        
        # Configure custom CA certificate
        if ca_cert_path:
            self.session.verify = ca_cert_path
        elif os.environ.get('REQUESTS_CA_BUNDLE'):
            self.session.verify = os.environ.get('REQUESTS_CA_BUNDLE')
        
        # Configure SSL/TLS settings
        adapter = HTTPAdapter()
        self.session.mount('https://', adapter)
        
        # Disable SSL warnings if using self-signed certificates
        if ca_cert_path:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def request(self, method, url, **kwargs):
        """Make request through TLS proxy"""
        try:
            response = self.session.request(method, url, **kwargs)
            return response
        except requests.exceptions.SSLError as e:
            print(f"SSL Error: {e}")
            print("Check proxy certificate configuration")
            raise
        except requests.exceptions.ProxyError as e:
            print(f"Proxy Error: {e}")
            print("Check proxy connectivity and authentication")
            raise
```

### Node.js Proxy Configuration
```javascript
const https = require('https');
const HttpsProxyAgent = require('https-proxy-agent');
const fs = require('fs');

class TLSProxyClient {
    constructor(options = {}) {
        this.proxyUrl = options.proxyUrl || process.env.HTTPS_PROXY;
        this.caCertPath = options.caCertPath || process.env.REQUESTS_CA_BUNDLE;
        
        // Configure HTTPS agent
        const agentOptions = {
            keepAlive: true,
            rejectUnauthorized: true
        };
        
        // Add custom CA certificate if specified
        if (this.caCertPath && fs.existsSync(this.caCertPath)) {
            agentOptions.ca = fs.readFileSync(this.caCertPath);
        }
        
        // Create proxy agent
        this.agent = this.proxyUrl ? 
            new HttpsProxyAgent(this.proxyUrl, agentOptions) : 
            new https.Agent(agentOptions);
    }
    
    async request(url, options = {}) {
        return new Promise((resolve, reject) => {
            const req = https.request(url, {
                ...options,
                agent: this.agent
            }, (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => resolve({
                    status: res.statusCode,
                    headers: res.headers,
                    data: data
                }));
            });
            
            req.on('error', (err) => {
                console.error('Request error:', err);
                reject(err);
            });
            
            if (options.data) {
                req.write(options.data);
            }
            
            req.end();
        });
    }
}
```

## Content Inspection and Filtering

### Request Content Inspection
```python
import json
import re
from typing import Dict, List, Any

class ContentInspector:
    """Inspect and filter HTTP content"""
    
    def __init__(self):
        self.blocked_patterns = [
            r'<script[^>]*>.*?</script>',  # Block JavaScript
            r'(password|token|key)\s*[:=]\s*["\']([^"\']+)["\']',  # Block credentials
            r'(eval|exec|system|shell_exec)\s*\(',  # Block dangerous functions
        ]
        
        self.suspicious_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Originating-IP'
        ]
    
    def inspect_request(self, method: str, url: str, headers: Dict, body: str) -> Dict[str, Any]:
        """Inspect HTTP request for security issues"""
        issues = []
        
        # Check for suspicious headers
        for header in self.suspicious_headers:
            if header in headers:
                issues.append(f"Suspicious header: {header}")
        
        # Check request body for blocked patterns
        if body:
            for pattern in self.blocked_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    issues.append(f"Blocked content pattern found: {pattern}")
        
        # Check for SQL injection patterns
        if self._check_sql_injection(body):
            issues.append("Potential SQL injection detected")
        
        # Check for XXE attacks
        if self._check_xxe_attack(body):
            issues.append("Potential XXE attack detected")
        
        return {
            'allowed': len(issues) == 0,
            'issues': issues,
            'risk_score': len(issues) * 10
        }
    
    def _check_sql_injection(self, content: str) -> bool:
        """Check for SQL injection patterns"""
        if not content:
            return False
        
        sql_patterns = [
            r"('|(\\'))|(--|#|\\/\\*)",
            r"(union|select|insert|update|delete|drop|create|alter|exec|execute)"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _check_xxe_attack(self, content: str) -> bool:
        """Check for XXE attack patterns"""
        if not content:
            return False
        
        xxe_patterns = [
            r"<!DOCTYPE.*?ENTITY",
            r"SYSTEM\s+[\"'][^\"']+[\"']",
            r"PUBLIC\s+[\"'][^\"']+[\"']"
        ]
        
        for pattern in xxe_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
```

### Response Content Filtering
```python
class ResponseFilter:
    """Filter HTTP responses for security"""
    
    def __init__(self):
        self.sensitive_patterns = [
            r'(api[_-]?key|token|password|secret)\s*[:=]\s*["\']([^"\']+)["\']',
            r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
            r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64 encoded data
        ]
        
        self.blocked_content_types = [
            'application/x-executable',
            'application/x-msdownload',
            'application/octet-stream'
        ]
    
    def filter_response(self, headers: Dict, body: str) -> Dict[str, Any]:
        """Filter HTTP response for security"""
        issues = []
        
        # Check content type
        content_type = headers.get('Content-Type', '').lower()
        for blocked_type in self.blocked_content_types:
            if blocked_type in content_type:
                issues.append(f"Blocked content type: {blocked_type}")
        
        # Check for sensitive information in response
        if body:
            for pattern in self.sensitive_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    issues.append("Sensitive information detected in response")
        
        # Check response size
        if len(body) > 10 * 1024 * 1024:  # 10MB limit
            issues.append("Response size exceeds limit")
        
        return {
            'allowed': len(issues) == 0,
            'issues': issues,
            'filtered_body': self._sanitize_response(body) if issues else body
        }
    
    def _sanitize_response(self, body: str) -> str:
        """Sanitize response body"""
        sanitized = body
        
        # Remove sensitive patterns
        for pattern in self.sensitive_patterns:
            sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE)
        
        return sanitized
```

## Proxy High Availability

### Multiple Proxy Setup
```yaml
# docker-compose.yml - Multiple proxy setup
version: '3.8'
services:
  mcp-server:
    image: mcp-server:latest
    environment:
      - HTTPS_PROXY=http://proxy-lb:8080
    depends_on:
      - proxy-lb
    networks:
      - mcp-network

  proxy-lb:
    image: nginx:alpine
    ports:
      - "8080:8080"
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf
    depends_on:
      - proxy-1
      - proxy-2
    networks:
      - mcp-network

  proxy-1:
    image: squid:latest
    volumes:
      - ./squid.conf:/etc/squid/squid.conf
    networks:
      - mcp-network

  proxy-2:
    image: squid:latest
    volumes:
      - ./squid.conf:/etc/squid/squid.conf
    networks:
      - mcp-network

networks:
  mcp-network:
    driver: bridge
```

### Load Balancer Configuration
```nginx
# nginx-lb.conf - Load balancer for proxies
events {
    worker_connections 1024;
}

http {
    upstream proxy_backend {
        server proxy-1:3128 max_fails=2 fail_timeout=30s;
        server proxy-2:3128 max_fails=2 fail_timeout=30s;
    }
    
    server {
        listen 8080;
        
        location / {
            proxy_pass http://proxy_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_connect_timeout 30s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
        }
    }
}
```

## Monitoring and Alerting

### Proxy Health Monitoring
```python
import requests
import time
from datetime import datetime

class ProxyHealthMonitor:
    """Monitor proxy health and performance"""
    
    def __init__(self, proxy_url, test_url='https://httpbin.org/ip'):
        self.proxy_url = proxy_url
        self.test_url = test_url
        self.session = requests.Session()
        self.session.proxies.update({
            'http': proxy_url,
            'https': proxy_url
        })
    
    def check_proxy_health(self) -> Dict[str, Any]:
        """Check proxy health"""
        start_time = time.time()
        
        try:
            response = self.session.get(self.test_url, timeout=10)
            response_time = time.time() - start_time
            
            return {
                'healthy': True,
                'response_time': response_time,
                'status_code': response.status_code,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                'healthy': False,
                'error': str(e),
                'response_time': time.time() - start_time,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def monitor_continuously(self, interval=60):
        """Monitor proxy continuously"""
        while True:
            health_status = self.check_proxy_health()
            
            if not health_status['healthy']:
                print(f"ALERT: Proxy unhealthy - {health_status['error']}")
                # Send alert to monitoring system
            
            if health_status.get('response_time', 0) > 5:
                print(f"WARNING: High response time - {health_status['response_time']:.2f}s")
            
            time.sleep(interval)
```

### TLS Certificate Monitoring
```bash
#!/bin/bash
# Monitor TLS certificate expiration

PROXY_HOST="api-gateway"
PROXY_PORT="8080"
CERT_WARNING_DAYS=30

# Check certificate expiration
check_cert_expiry() {
    local host=$1
    local port=$2
    
    # Get certificate expiration date
    expiry_date=$(echo | openssl s_client -connect $host:$port 2>/dev/null | \
                  openssl x509 -noout -enddate | cut -d= -f2)
    
    # Convert to epoch time
    expiry_epoch=$(date -d "$expiry_date" +%s)
    current_epoch=$(date +%s)
    
    # Calculate days until expiry
    days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    if [ $days_until_expiry -lt $CERT_WARNING_DAYS ]; then
        echo "WARNING: Certificate for $host:$port expires in $days_until_expiry days"
        return 1
    else
        echo "OK: Certificate for $host:$port expires in $days_until_expiry days"
        return 0
    fi
}

# Monitor certificate
check_cert_expiry $PROXY_HOST $PROXY_PORT
```

## Troubleshooting TLS Issues

### Common TLS Problems
```python
import ssl
import socket

class TLSTroubleshooter:
    """Troubleshoot TLS connection issues"""
    
    def diagnose_tls_connection(self, hostname, port=443):
        """Diagnose TLS connection issues"""
        results = {}
        
        try:
            # Test basic TCP connection
            sock = socket.create_connection((hostname, port), timeout=10)
            results['tcp_connection'] = 'OK'
            
            # Test TLS handshake
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                results['tls_handshake'] = 'OK'
                results['tls_version'] = ssock.version()
                results['cipher'] = ssock.cipher()
                results['certificate'] = ssock.getpeercert()
                
        except socket.timeout:
            results['tcp_connection'] = 'TIMEOUT'
        except socket.gaierror as e:
            results['tcp_connection'] = f'DNS_ERROR: {e}'
        except ssl.SSLError as e:
            results['tls_handshake'] = f'SSL_ERROR: {e}'
        except Exception as e:
            results['error'] = str(e)
        
        return results
```

### Debug Commands
```bash
#!/bin/bash
# Debug TLS proxy issues

# Test proxy connectivity
echo "Testing proxy connectivity..."
curl -x http://api-gateway:8080 -v https://httpbin.org/ip

# Test TLS handshake
echo "Testing TLS handshake..."
openssl s_client -connect api-gateway:8080 -servername api-gateway

# Test certificate chain
echo "Testing certificate chain..."
openssl s_client -connect api-gateway:8080 -showcerts

# Test proxy authentication
echo "Testing proxy authentication..."
curl -x http://username:password@api-gateway:8080 -v https://httpbin.org/ip
```

## Contributing

Help improve our TLS and proxy management guidance by sharing:
- **Proxy Configurations** - Working proxy configurations for TLS termination
- **Certificate Management** - Best practices for certificate lifecycle management
- **Content Inspection** - Effective content filtering and inspection techniques
- **Troubleshooting Guides** - Solutions to common TLS and proxy issues

*This page is being developed with community input. Share your TLS and proxy experience in our [discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions).*
