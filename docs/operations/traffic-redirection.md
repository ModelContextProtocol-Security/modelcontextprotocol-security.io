---
title: "Traffic Redirection"
parent: "Operations Guide"
nav_order: 15
---

# Traffic Redirection

This guide provides comprehensive guidance for implementing traffic redirection in Model Context Protocol (MCP) servers to route network traffic through security controls. Traffic redirection is often more effective than network-level controls for ensuring all MCP traffic flows through security inspection points.

## Community Discussion

💬 **[Traffic Redirection Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Share your traffic redirection techniques, code examples, and implementation strategies with the community.

## Why Traffic Redirection Is Essential

### Code-Level vs. Network-Level Control
**Code-level traffic redirection is often more reliable than network-level controls:**
- **Guaranteed Routing** - All HTTP/HTTPS requests go through designated security controls
- **Environment Portability** - Works across different network configurations
- **Debugging Capability** - Easier to troubleshoot and verify traffic routing
- **Application Integration** - Better integration with application logging and monitoring

### Common Redirection Scenarios
- **API Gateway Routing** - Route all external API calls through security gateways
- **Proxy Server Integration** - Direct traffic through corporate proxy servers
- **Load Balancer Failover** - Redirect traffic when primary services are unavailable
- **Security Inspection** - Route traffic through security scanning and analysis tools

## HTTP Client Wrapping Techniques

### Python HTTP Client Wrapping
```python
import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging

class SecureHTTPClient:
    """Wrapper for HTTP client with security controls"""
    
    def __init__(self, base_url=None, proxy_url=None):
        self.base_url = base_url
        self.session = requests.Session()
        
        # Configure proxy settings
        self.proxy_url = proxy_url or os.environ.get('HTTPS_PROXY') or os.environ.get('HTTP_PROXY')
        if self.proxy_url:
            self.session.proxies.update({
                'http': self.proxy_url,
                'https': self.proxy_url
            })
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set up logging
        self.logger = logging.getLogger(__name__)
        
    def request(self, method, url, **kwargs):
        """Make HTTP request with security controls"""
        # Ensure URL goes through security controls
        if self.base_url and not url.startswith(('http://', 'https://')):
            url = f"{self.base_url.rstrip('/')}/{url.lstrip('/')}"
        
        # Add security headers
        headers = kwargs.get('headers', {})
        headers.update({
            'User-Agent': 'MCP-Server/1.0',
            'X-MCP-Client': 'secure-client'
        })
        kwargs['headers'] = headers
        
        # Log request for security monitoring
        self.logger.info(f"HTTP Request: {method} {url}")
        
        try:
            response = self.session.request(method, url, **kwargs)
            
            # Log response for security monitoring
            self.logger.info(f"HTTP Response: {response.status_code} {url}")
            
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"HTTP Request failed: {method} {url} - {str(e)}")
            raise

# Usage in MCP server
class MCPServer:
    def __init__(self):
        # Use secure HTTP client with API gateway
        self.http_client = SecureHTTPClient(
            base_url='http://api-gateway:8080',
            proxy_url=None  # Will use environment variables
        )
    
    def call_external_api(self, endpoint, data=None):
        """Call external API through security controls"""
        response = self.http_client.request('POST', f'/external-api/{endpoint}', json=data)
        return response.json()
```

### Node.js HTTP Client Wrapping
```javascript
const axios = require('axios');
const HttpsProxyAgent = require('https-proxy-agent');

class SecureHTTPClient {
    constructor(options = {}) {
        this.baseURL = options.baseURL;
        this.proxyUrl = options.proxyUrl || process.env.HTTPS_PROXY || process.env.HTTP_PROXY;
        
        // Configure axios instance
        this.client = axios.create({
            baseURL: this.baseURL,
            timeout: 30000,
            httpsAgent: this.proxyUrl ? new HttpsProxyAgent(this.proxyUrl) : undefined
        });
        
        // Add request interceptor for security
        this.client.interceptors.request.use(
            (config) => {
                // Add security headers
                config.headers = {
                    ...config.headers,
                    'User-Agent': 'MCP-Server/1.0',
                    'X-MCP-Client': 'secure-client'
                };
                
                // Log request for security monitoring
                console.log(`HTTP Request: ${config.method.toUpperCase()} ${config.url}`);
                
                return config;
            },
            (error) => {
                console.error('Request interceptor error:', error);
                return Promise.reject(error);
            }
        );
        
        // Add response interceptor for security
        this.client.interceptors.response.use(
            (response) => {
                // Log response for security monitoring
                console.log(`HTTP Response: ${response.status} ${response.config.url}`);
                return response;
            },
            (error) => {
                console.error('Response interceptor error:', error);
                return Promise.reject(error);
            }
        );
    }
    
    async request(method, url, data = null, config = {}) {
        try {
            const response = await this.client.request({
                method,
                url,
                data,
                ...config
            });
            return response.data;
        } catch (error) {
            console.error(`HTTP Request failed: ${method} ${url} - ${error.message}`);
            throw error;
        }
    }
}

// Usage in MCP server
class MCPServer {
    constructor() {
        // Use secure HTTP client with API gateway
        this.httpClient = new SecureHTTPClient({
            baseURL: 'http://api-gateway:8080'
        });
    }
    
    async callExternalAPI(endpoint, data = null) {
        return await this.httpClient.request('POST', `/external-api/${endpoint}`, data);
    }
}
```

## Environment Variable Configuration

### Proxy Environment Variables
```bash
# Set proxy environment variables for traffic redirection
export HTTP_PROXY=http://api-gateway:8080
export HTTPS_PROXY=http://api-gateway:8080
export NO_PROXY=localhost,127.0.0.1,.local

# For corporate environments
export HTTP_PROXY=http://corporate-proxy:3128
export HTTPS_PROXY=http://corporate-proxy:3128
export NO_PROXY=localhost,127.0.0.1,.corp.local
```

### Docker Environment Configuration
```yaml
# docker-compose.yml
version: '3.8'
services:
  mcp-server:
    image: mcp-server:latest
    environment:
      - HTTP_PROXY=http://api-gateway:8080
      - HTTPS_PROXY=http://api-gateway:8080
      - NO_PROXY=localhost,127.0.0.1
      - REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
    depends_on:
      - api-gateway
    networks:
      - mcp-network

  api-gateway:
    image: kong:latest
    ports:
      - "8080:8000"
    networks:
      - mcp-network
      - external

networks:
  mcp-network:
    driver: bridge
  external:
    driver: bridge
```

## Advanced Traffic Redirection Patterns

### Conditional Redirection
```python
import re
from urllib.parse import urlparse

class ConditionalRedirectClient:
    """HTTP client with conditional traffic redirection"""
    
    def __init__(self):
        self.session = requests.Session()
        
        # Define redirection rules
        self.redirection_rules = [
            {
                'pattern': r'api\.external-service\.com',
                'proxy': 'http://api-gateway:8080',
                'headers': {'X-Route': 'external-api'}
            },
            {
                'pattern': r'.*\.openai\.com',
                'proxy': 'http://ai-gateway:8080',
                'headers': {'X-Route': 'ai-api'}
            },
            {
                'pattern': r'.*\.amazonaws\.com',
                'proxy': 'http://aws-gateway:8080',
                'headers': {'X-Route': 'aws-api'}
            }
        ]
    
    def request(self, method, url, **kwargs):
        """Make request with conditional redirection"""
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        
        # Find matching redirection rule
        for rule in self.redirection_rules:
            if re.match(rule['pattern'], hostname):
                # Update session with proxy
                self.session.proxies.update({
                    'http': rule['proxy'],
                    'https': rule['proxy']
                })
                
                # Add rule-specific headers
                headers = kwargs.get('headers', {})
                headers.update(rule['headers'])
                kwargs['headers'] = headers
                
                print(f"Redirecting {hostname} through {rule['proxy']}")
                break
        
        return self.session.request(method, url, **kwargs)
```

### Service Discovery Integration
```python
import consul
import random

class ServiceDiscoveryClient:
    """HTTP client with service discovery-based redirection"""
    
    def __init__(self, consul_host='localhost', consul_port=8500):
        self.consul = consul.Consul(host=consul_host, port=consul_port)
        self.session = requests.Session()
    
    def get_service_endpoint(self, service_name):
        """Get service endpoint from service discovery"""
        try:
            _, services = self.consul.health.service(service_name, passing=True)
            if services:
                # Simple load balancing - pick random healthy service
                service = random.choice(services)
                return f"http://{service['Service']['Address']}:{service['Service']['Port']}"
            else:
                raise Exception(f"No healthy instances of {service_name}")
        except Exception as e:
            print(f"Service discovery error: {e}")
            return None
    
    def request(self, method, url, service_name=None, **kwargs):
        """Make request with service discovery"""
        if service_name:
            endpoint = self.get_service_endpoint(service_name)
            if endpoint:
                # Redirect to discovered service
                parsed_url = urlparse(url)
                url = url.replace(f"{parsed_url.scheme}://{parsed_url.netloc}", endpoint)
                print(f"Redirecting to discovered service: {endpoint}")
        
        return self.session.request(method, url, **kwargs)
```

## Load Balancing and Failover

### Client-Side Load Balancing
```python
import random
import time

class LoadBalancedClient:
    """HTTP client with load balancing and failover"""
    
    def __init__(self, endpoints):
        self.endpoints = endpoints
        self.session = requests.Session()
        self.failed_endpoints = set()
        self.last_failure_check = time.time()
    
    def get_healthy_endpoint(self):
        """Get healthy endpoint for request"""
        # Reset failed endpoints periodically
        if time.time() - self.last_failure_check > 300:  # 5 minutes
            self.failed_endpoints.clear()
            self.last_failure_check = time.time()
        
        # Get healthy endpoints
        healthy_endpoints = [ep for ep in self.endpoints if ep not in self.failed_endpoints]
        
        if not healthy_endpoints:
            # All endpoints failed, reset and try again
            self.failed_endpoints.clear()
            healthy_endpoints = self.endpoints
        
        return random.choice(healthy_endpoints)
    
    def request(self, method, path, **kwargs):
        """Make request with load balancing"""
        last_error = None
        
        for attempt in range(len(self.endpoints)):
            endpoint = self.get_healthy_endpoint()
            url = f"{endpoint.rstrip('/')}/{path.lstrip('/')}"
            
            try:
                response = self.session.request(method, url, **kwargs)
                
                # Remove from failed endpoints if successful
                if endpoint in self.failed_endpoints:
                    self.failed_endpoints.remove(endpoint)
                
                return response
                
            except requests.exceptions.RequestException as e:
                print(f"Request failed for {endpoint}: {e}")
                self.failed_endpoints.add(endpoint)
                last_error = e
                
                if attempt < len(self.endpoints) - 1:
                    time.sleep(0.5)  # Brief delay before retry
        
        # All endpoints failed
        raise last_error
```

## Security Monitoring Integration

### Request/Response Logging
```python
import json
import hashlib
from datetime import datetime

class SecurityLoggedClient:
    """HTTP client with comprehensive security logging"""
    
    def __init__(self, log_file='/var/log/mcp-requests.log'):
        self.session = requests.Session()
        self.log_file = log_file
    
    def log_request(self, method, url, headers, data=None):
        """Log request for security monitoring"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'type': 'request',
            'method': method,
            'url': url,
            'headers': dict(headers),
            'data_hash': hashlib.sha256(str(data).encode()).hexdigest() if data else None
        }
        
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def log_response(self, response):
        """Log response for security monitoring"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'type': 'response',
            'status_code': response.status_code,
            'url': response.url,
            'headers': dict(response.headers),
            'response_time': response.elapsed.total_seconds()
        }
        
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def request(self, method, url, **kwargs):
        """Make request with security logging"""
        # Log request
        self.log_request(method, url, kwargs.get('headers', {}), kwargs.get('data'))
        
        # Make request
        response = self.session.request(method, url, **kwargs)
        
        # Log response
        self.log_response(response)
        
        return response
```

## Testing and Validation

### Traffic Redirection Testing
```python
import unittest
from unittest.mock import patch, MagicMock

class TestTrafficRedirection(unittest.TestCase):
    """Test traffic redirection functionality"""
    
    def setUp(self):
        self.client = SecureHTTPClient(proxy_url='http://test-proxy:8080')
    
    @patch('requests.Session.request')
    def test_proxy_configuration(self, mock_request):
        """Test that proxy is properly configured"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        
        self.client.request('GET', 'https://api.example.com/test')
        
        # Verify proxy was used
        self.assertEqual(self.client.session.proxies['https'], 'http://test-proxy:8080')
    
    @patch('requests.Session.request')
    def test_security_headers(self, mock_request):
        """Test that security headers are added"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        
        self.client.request('GET', 'https://api.example.com/test')
        
        # Check that security headers were added
        call_args = mock_request.call_args
        headers = call_args[1]['headers']
        self.assertEqual(headers['User-Agent'], 'MCP-Server/1.0')
        self.assertEqual(headers['X-MCP-Client'], 'secure-client')
```

### Network Connectivity Testing
```bash
#!/bin/bash
# Test traffic redirection configuration

# Test proxy connectivity
echo "Testing proxy connectivity..."
curl -x http://api-gateway:8080 -v https://httpbin.org/ip

# Test environment variable configuration
echo "Testing environment variables..."
export HTTP_PROXY=http://api-gateway:8080
export HTTPS_PROXY=http://api-gateway:8080
curl -v https://httpbin.org/ip

# Test MCP server connectivity
echo "Testing MCP server connectivity..."
docker exec mcp-server curl -v https://httpbin.org/ip
```

## Performance Optimization

### Connection Pooling
```python
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

class PooledSecureClient:
    """HTTP client with connection pooling"""
    
    def __init__(self, pool_size=10, max_retries=3):
        self.session = requests.Session()
        
        # Configure connection pooling
        adapter = HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size,
            max_retries=max_retries
        )
        
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
```

### Caching Integration
```python
import requests_cache

class CachedSecureClient:
    """HTTP client with response caching"""
    
    def __init__(self, cache_name='mcp_cache', expire_after=300):
        # Create cached session
        self.session = requests_cache.CachedSession(
            cache_name=cache_name,
            expire_after=expire_after
        )
        
        # Configure proxy
        proxy_url = os.environ.get('HTTPS_PROXY')
        if proxy_url:
            self.session.proxies.update({
                'http': proxy_url,
                'https': proxy_url
            })
```

## Contributing

Help improve our traffic redirection guidance by sharing:
- **Client Wrappers** - HTTP client wrapper implementations for different languages
- **Redirection Patterns** - Advanced traffic redirection strategies
- **Testing Scripts** - Validation and testing procedures for traffic redirection
- **Performance Optimizations** - Techniques for optimizing redirected traffic

*This page is being developed with community input. Share your traffic redirection experience in our [discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions).*
