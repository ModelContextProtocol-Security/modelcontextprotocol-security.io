# API Gateway Operations

This guide provides comprehensive guidance for operating API gateways to secure Model Context Protocol (MCP) server traffic. Since most MCP traffic is TLS-encrypted and uninspectable at the network level, **API gateways are essential** for gaining visibility and control over MCP server communications.

## Community Discussion

💬 **[API Gateway Operations Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Share your API gateway configurations, traffic policies, and operational experiences with the community.

## Why API Gateways Are Critical for MCP Security

### The TLS Inspection Problem
**Most MCP traffic is encrypted and uninspectable:**
- **HTTPS Everywhere** - MCP servers communicate with external services via HTTPS
- **Network Monitoring Blind Spots** - Traditional network security tools can't inspect encrypted payloads
- **Agent Communication** - AI agents make API calls to multiple external services simultaneously
- **No Traffic Visibility** - Without an API gateway, you can't see what data is being sent/received

### API Gateway Solutions
**API gateways provide essential security capabilities:**
- **Traffic Decryption** - Decrypt incoming traffic for inspection, then re-encrypt for external services
- **Policy Enforcement** - Apply security policies to API calls before they reach external services
- **Audit Logging** - Log all API interactions for security monitoring and compliance
- **Rate Limiting** - Control API usage to prevent abuse and resource exhaustion
- **Access Control** - Authenticate and authorize API calls based on policies

## API Gateway Architecture Patterns

### MCP Server → API Gateway → External Services
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ MCP Server  │───▶│ API Gateway │───▶│ External    │
│             │    │             │    │ Services    │
└─────────────┘    └─────────────┘    └─────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │ Security    │
                   │ Logging &   │
                   │ Monitoring  │
                   └─────────────┘
```

### Benefits of This Architecture
- **Complete Visibility** - All external API calls are logged and monitored
- **Policy Enforcement** - Security policies applied to all outbound traffic
- **Centralized Security** - Single point for security controls and monitoring
- **Compliance** - Audit trail of all external API interactions

## Popular API Gateway Solutions

### Kong Gateway
```yaml
# docker-compose.yml
version: '3.8'
services:
  kong:
    image: kong:latest
    environment:
      - KONG_DATABASE=off
      - KONG_DECLARATIVE_CONFIG=/kong/declarative/kong.yml
      - KONG_PROXY_ACCESS_LOG=/dev/stdout
      - KONG_ADMIN_ACCESS_LOG=/dev/stdout
      - KONG_PROXY_ERROR_LOG=/dev/stderr
      - KONG_ADMIN_ERROR_LOG=/dev/stderr
    ports:
      - "8000:8000"  # Proxy port
      - "8001:8001"  # Admin API
    volumes:
      - ./kong.yml:/kong/declarative/kong.yml
```

### Kong Configuration Example
```yaml
# kong.yml
_format_version: "3.0"
_transform: true

services:
  - name: external-api-service
    url: https://api.external-service.com
    plugins:
      - name: rate-limiting
        config:
          minute: 100
          hour: 1000
      - name: request-size-limiting
        config:
          allowed_payload_size: 10
      - name: response-size-limiting
        config:
          allowed_payload_size: 50

routes:
  - name: external-api-route
    service: external-api-service
    paths:
      - /external-api
```

### Nginx with OpenResty
```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    # Logging for security monitoring
    log_format mcp_access '$remote_addr - $remote_user [$time_local] '
                         '"$request" $status $body_bytes_sent '
                         '"$http_referer" "$http_user_agent" '
                         '"$upstream_addr" "$upstream_response_time"';

    access_log /var/log/nginx/mcp_access.log mcp_access;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

    upstream external_service {
        server api.external-service.com:443;
    }

    server {
        listen 8080;
        
        # Apply rate limiting
        limit_req zone=api_limit burst=20 nodelay;
        
        location /api/ {
            # Security headers
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Proxy to external service
            proxy_pass https://external_service/;
            proxy_ssl_verify on;
            proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
            
            # Request/response size limits
            client_max_body_size 10M;
            proxy_buffering on;
            proxy_buffer_size 4k;
            proxy_buffers 8 4k;
        }
    }
}
```

## Configuring MCP Servers to Use API Gateways

### Environment Variable Configuration
```bash
# Set proxy environment variables
export HTTP_PROXY=http://api-gateway:8080
export HTTPS_PROXY=http://api-gateway:8080
export NO_PROXY=localhost,127.0.0.1,.local
```

### Python MCP Server Configuration
```python
import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class MCPServer:
    def __init__(self):
        self.session = requests.Session()
        
        # Configure proxy settings
        proxies = {
            'http': os.environ.get('HTTP_PROXY'),
            'https': os.environ.get('HTTPS_PROXY')
        }
        
        if proxies['http'] or proxies['https']:
            self.session.proxies.update(proxies)
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def make_api_call(self, url, data=None):
        """Make API call through gateway"""
        try:
            response = self.session.post(url, json=data, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            # Log error for security monitoring
            print(f"API call failed: {e}")
            raise
```

### Node.js MCP Server Configuration
```javascript
const axios = require('axios');
const HttpsProxyAgent = require('https-proxy-agent');

class MCPServer {
    constructor() {
        const proxyUrl = process.env.HTTPS_PROXY || process.env.HTTP_PROXY;
        
        this.httpClient = axios.create({
            timeout: 30000,
            httpsAgent: proxyUrl ? new HttpsProxyAgent(proxyUrl) : undefined
        });
        
        // Add request interceptor for logging
        this.httpClient.interceptors.request.use(
            (config) => {
                console.log(`API Request: ${config.method.toUpperCase()} ${config.url}`);
                return config;
            },
            (error) => {
                console.error('Request error:', error);
                return Promise.reject(error);
            }
        );
    }
    
    async makeApiCall(url, data = null) {
        try {
            const response = await this.httpClient.post(url, data);
            return response.data;
        } catch (error) {
            console.error('API call failed:', error.message);
            throw error;
        }
    }
}
```

## Security Policies and Rules

### Rate Limiting Policies
```yaml
# Kong plugin configuration
plugins:
  - name: rate-limiting
    config:
      minute: 100
      hour: 1000
      policy: local
      hide_client_headers: false
      fault_tolerant: true
```

### Request/Response Size Limits
```yaml
# Kong plugin configuration
plugins:
  - name: request-size-limiting
    config:
      allowed_payload_size: 10  # 10MB
  - name: response-size-limiting
    config:
      allowed_payload_size: 50  # 50MB
```

### IP Whitelisting
```yaml
# Kong plugin configuration
plugins:
  - name: ip-restriction
    config:
      allow:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
```

## Monitoring and Alerting

### Security Monitoring
```bash
# Monitor API gateway logs for security events
tail -f /var/log/kong/access.log | grep -E "(40[0-9]|50[0-9])" | \
while read line; do
    echo "Security Alert: $line"
    # Send to security monitoring system
done
```

### Prometheus Metrics
```yaml
# Kong Prometheus plugin
plugins:
  - name: prometheus
    config:
      per_consumer: true
      status_code_metrics: true
      latency_metrics: true
      bandwidth_metrics: true
```

### Log Analysis
```bash
# Analyze API gateway logs for suspicious patterns
awk '
    /429/ { rate_limit_exceeded++ }
    /401|403/ { auth_failures++ }
    /50[0-9]/ { server_errors++ }
    END {
        print "Rate limit violations:", rate_limit_exceeded
        print "Authentication failures:", auth_failures
        print "Server errors:", server_errors
    }
' /var/log/kong/access.log
```

## Traffic Inspection and Analysis

### Request/Response Logging
```yaml
# Kong plugin for detailed logging
plugins:
  - name: file-log
    config:
      path: /var/log/kong/requests.log
      custom_fields_by_lua:
        request_body: "return kong.request.get_raw_body()"
        response_body: "return kong.response.get_raw_body()"
```

### Content Filtering
```lua
-- Kong custom plugin for content filtering
local ContentFilter = {
    VERSION = "1.0.0",
    PRIORITY = 1000,
}

function ContentFilter:access(conf)
    local body = kong.request.get_raw_body()
    
    -- Check for suspicious content
    if body and string.find(body, "malicious_pattern") then
        return kong.response.exit(400, {
            message = "Request blocked by content filter"
        })
    end
end

return ContentFilter
```

## Performance Optimization

### Caching Strategies
```yaml
# Kong caching plugin
plugins:
  - name: proxy-cache
    config:
      response_code:
        - 200
        - 301
        - 302
      request_method:
        - GET
        - HEAD
      content_type:
        - text/plain
        - application/json
      cache_ttl: 300  # 5 minutes
```

### Load Balancing
```yaml
# Kong upstream configuration
upstreams:
  - name: external-service-upstream
    algorithm: round-robin
    healthchecks:
      active:
        healthy:
          interval: 30
          successes: 2
        unhealthy:
          interval: 30
          http_failures: 3
    targets:
      - target: api1.external-service.com:443
        weight: 100
      - target: api2.external-service.com:443
        weight: 100
```

## Troubleshooting Common Issues

### Connectivity Problems
```bash
# Test API gateway connectivity
curl -v http://api-gateway:8000/health

# Check proxy configuration
docker exec mcp-server env | grep -i proxy

# Test external service connectivity through gateway
curl -v -H "Host: api.external-service.com" http://api-gateway:8000/api/test
```

### Performance Issues
```bash
# Monitor API gateway performance
docker stats kong

# Check response times
curl -o /dev/null -s -w "Connect: %{time_connect} Start Transfer: %{time_starttransfer} Total: %{time_total}\n" http://api-gateway:8000/api/test
```

## Contributing

Help improve our API gateway operations guidance by sharing:
- **Gateway Configurations** - Working configurations for different API gateway solutions
- **Security Policies** - Effective security policies and rules
- **Monitoring Setups** - Comprehensive monitoring and alerting configurations
- **Performance Optimizations** - Techniques for optimizing API gateway performance

*This page is being developed with community input. Share your API gateway experience in our [discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions).*
