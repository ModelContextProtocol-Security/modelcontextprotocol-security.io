---
layout: default
title: "OAuth Security Patterns"
permalink: /build/oauth-security/
nav_order: 1
parent: "Build Security"
---

# OAuth Security Patterns

**Overview**: Secure OAuth implementations for MCP tool authorization and invocation.

OAuth provides a robust framework for secure authorization in MCP systems. This guide covers secure OAuth patterns, implementation best practices, and security considerations for MCP deployments.

## OAuth Flow Security

### Authorization Code Flow with PKCE

The most secure OAuth flow for MCP implementations:

```python
# Secure OAuth implementation with PKCE
import hashlib
import base64
import secrets
from urllib.parse import urlencode

class SecureOAuthClient:
    def __init__(self, client_id, authorization_endpoint, token_endpoint):
        self.client_id = client_id
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        
    def generate_pkce_challenge(self):
        """Generate PKCE code verifier and challenge"""
        # Generate cryptographically secure random code verifier
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        # Generate SHA256 challenge
        challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    def build_authorization_url(self, scope, redirect_uri, state=None):
        """Build secure authorization URL"""
        if not state:
            state = secrets.token_urlsafe(32)
        
        code_verifier, code_challenge = self.generate_pkce_challenge()
        
        # Store code_verifier securely for token exchange
        self.store_code_verifier(state, code_verifier)
        
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        return f"{self.authorization_endpoint}?{urlencode(params)}"
    
    def exchange_code_for_token(self, code, redirect_uri, state):
        """Exchange authorization code for access token"""
        code_verifier = self.retrieve_code_verifier(state)
        
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'code': code,
            'redirect_uri': redirect_uri,
            'code_verifier': code_verifier
        }
        
        # Make secure token request
        response = self.make_token_request(token_data)
        
        # Validate and return token
        return self.validate_token_response(response)
```

## Scope Minimization

### Principle of Least Privilege

Implement minimal necessary scopes for MCP tools:

```python
# Secure scope management
class MCPScopeManager:
    def __init__(self):
        self.tool_scopes = {
            'file_reader': ['read:files'],
            'database_connector': ['read:database'],
            'api_client': ['read:api', 'write:api'],
            'admin_tool': ['admin:system']
        }
        
        self.scope_hierarchy = {
            'read:files': ['read:files'],
            'write:files': ['read:files', 'write:files'],
            'admin:system': ['read:files', 'write:files', 'admin:system']
        }
    
    def get_minimal_scopes(self, tool_name, requested_actions):
        """Get minimal scopes for tool actions"""
        tool_scopes = self.tool_scopes.get(tool_name, [])
        minimal_scopes = set()
        
        for action in requested_actions:
            required_scope = self.map_action_to_scope(action)
            if required_scope in tool_scopes:
                minimal_scopes.add(required_scope)
        
        return list(minimal_scopes)
    
    def validate_scope_access(self, token_scopes, required_scope):
        """Validate token has required scope"""
        for token_scope in token_scopes:
            if required_scope in self.scope_hierarchy.get(token_scope, []):
                return True
        return False
```

## Redirect URI Validation

### Secure Redirect Handling

```python
# Secure redirect URI validation
import re
from urllib.parse import urlparse

class RedirectURIValidator:
    def __init__(self):
        self.allowed_schemes = ['https']
        self.allowed_hosts = ['localhost', 'mcp-client.example.com']
        self.blocked_patterns = [
            r'.*\.evil\.com',
            r'javascript:',
            r'data:',
            r'file:'
        ]
    
    def validate_redirect_uri(self, redirect_uri, registered_uris):
        """Validate redirect URI security"""
        
        # Check if URI is in registered URIs
        if redirect_uri not in registered_uris:
            return False, "Redirect URI not registered"
        
        # Parse URI
        parsed = urlparse(redirect_uri)
        
        # Validate scheme
        if parsed.scheme not in self.allowed_schemes:
            return False, "Invalid scheme"
        
        # Validate host
        if parsed.hostname not in self.allowed_hosts:
            return False, "Invalid host"
        
        # Check blocked patterns
        for pattern in self.blocked_patterns:
            if re.match(pattern, redirect_uri):
                return False, "Blocked URI pattern"
        
        # Additional security checks
        if self.contains_suspicious_content(redirect_uri):
            return False, "Suspicious content detected"
        
        return True, "Valid redirect URI"
    
    def contains_suspicious_content(self, uri):
        """Check for suspicious content in URI"""
        suspicious_patterns = [
            'javascript:',
            'data:',
            'vbscript:',
            '<script',
            'onload=',
            'onerror='
        ]
        
        return any(pattern in uri.lower() for pattern in suspicious_patterns)
```

## Token Management

### Secure Token Storage and Handling

```python
# Secure token management
import jwt
import time
from cryptography.fernet import Fernet

class SecureTokenManager:
    def __init__(self, encryption_key):
        self.cipher = Fernet(encryption_key)
        self.token_storage = {}
        
    def store_token(self, user_id, token_data):
        """Securely store access token"""
        # Encrypt token data
        encrypted_token = self.cipher.encrypt(
            json.dumps(token_data).encode('utf-8')
        )
        
        # Store with expiration
        self.token_storage[user_id] = {
            'token': encrypted_token,
            'expires_at': time.time() + token_data.get('expires_in', 3600),
            'created_at': time.time()
        }
    
    def retrieve_token(self, user_id):
        """Retrieve and decrypt access token"""
        if user_id not in self.token_storage:
            return None
        
        token_entry = self.token_storage[user_id]
        
        # Check expiration
        if time.time() > token_entry['expires_at']:
            del self.token_storage[user_id]
            return None
        
        # Decrypt token
        encrypted_token = token_entry['token']
        token_data = json.loads(
            self.cipher.decrypt(encrypted_token).decode('utf-8')
        )
        
        return token_data
    
    def refresh_token(self, user_id, refresh_token):
        """Refresh expired access token"""
        refresh_data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.client_id
        }
        
        response = self.make_token_request(refresh_data)
        
        if response.get('access_token'):
            self.store_token(user_id, response)
            return response
        
        return None
```

## Security Best Practices

### OAuth Security Checklist

```python
# OAuth security validation
class OAuthSecurityValidator:
    def __init__(self):
        self.security_checks = [
            'pkce_enabled',
            'https_only',
            'state_validation',
            'redirect_uri_validation',
            'scope_minimization',
            'token_expiration',
            'refresh_token_rotation'
        ]
    
    def validate_oauth_implementation(self, config):
        """Validate OAuth implementation security"""
        results = {}
        
        # Check PKCE support
        results['pkce_enabled'] = self.check_pkce_support(config)
        
        # Check HTTPS enforcement
        results['https_only'] = self.check_https_enforcement(config)
        
        # Check state parameter usage
        results['state_validation'] = self.check_state_validation(config)
        
        # Check redirect URI validation
        results['redirect_uri_validation'] = self.check_redirect_validation(config)
        
        # Check scope minimization
        results['scope_minimization'] = self.check_scope_minimization(config)
        
        # Check token expiration
        results['token_expiration'] = self.check_token_expiration(config)
        
        # Check refresh token rotation
        results['refresh_token_rotation'] = self.check_refresh_rotation(config)
        
        return results
    
    def generate_security_report(self, results):
        """Generate OAuth security assessment report"""
        passed = sum(1 for result in results.values() if result)
        total = len(results)
        
        report = {
            'score': f"{passed}/{total}",
            'percentage': (passed / total) * 100,
            'recommendations': self.generate_recommendations(results)
        }
        
        return report
```

## Common OAuth Vulnerabilities

### Vulnerability Prevention

```python
# OAuth vulnerability prevention
class OAuthVulnerabilityPrevention:
    def __init__(self):
        self.common_vulnerabilities = {
            'authorization_code_interception': self.prevent_code_interception,
            'csrf_attacks': self.prevent_csrf_attacks,
            'redirect_uri_manipulation': self.prevent_redirect_manipulation,
            'scope_elevation': self.prevent_scope_elevation,
            'token_leakage': self.prevent_token_leakage
        }
    
    def prevent_code_interception(self, config):
        """Prevent authorization code interception"""
        return {
            'pkce_required': True,
            'https_only': True,
            'short_code_lifetime': 600,  # 10 minutes
            'one_time_use': True
        }
    
    def prevent_csrf_attacks(self, config):
        """Prevent CSRF attacks"""
        return {
            'state_parameter_required': True,
            'state_entropy': 32,  # bytes
            'state_validation': True,
            'state_timeout': 300  # 5 minutes
        }
    
    def prevent_redirect_manipulation(self, config):
        """Prevent redirect URI manipulation"""
        return {
            'exact_uri_matching': True,
            'uri_registration_required': True,
            'localhost_restrictions': True,
            'scheme_validation': True
        }
```

## Integration with MCP

### MCP-Specific OAuth Patterns

```python
# MCP OAuth integration
class MCPOAuthIntegration:
    def __init__(self, oauth_client):
        self.oauth_client = oauth_client
        
    def authorize_tool_access(self, tool_name, user_id, requested_scopes):
        """Authorize MCP tool access via OAuth"""
        
        # Validate tool registration
        if not self.is_tool_registered(tool_name):
            raise ValueError("Tool not registered")
        
        # Get minimal required scopes
        minimal_scopes = self.get_minimal_scopes(tool_name, requested_scopes)
        
        # Generate authorization URL
        auth_url = self.oauth_client.build_authorization_url(
            scope=' '.join(minimal_scopes),
            redirect_uri=self.get_tool_redirect_uri(tool_name),
            state=self.generate_tool_state(tool_name, user_id)
        )
        
        return auth_url
    
    def handle_tool_callback(self, code, state):
        """Handle OAuth callback for tool authorization"""
        
        # Validate state
        tool_name, user_id = self.validate_tool_state(state)
        
        # Exchange code for token
        token_data = self.oauth_client.exchange_code_for_token(
            code, 
            self.get_tool_redirect_uri(tool_name),
            state
        )
        
        # Store token for tool usage
        self.store_tool_token(tool_name, user_id, token_data)
        
        return token_data
```

## References and Resources

### Standards and Specifications
- **[RFC 6749: OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)**
- **[RFC 7636: PKCE for OAuth 2.0](https://tools.ietf.org/html/rfc7636)**
- **[OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)**

### Security Guidelines
- **[OAuth 2.0 Threat Model](https://tools.ietf.org/html/rfc6819)**
- **[OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252)**
- **[OAuth 2.0 Device Authorization Grant](https://tools.ietf.org/html/rfc8628)**

---

*OAuth Security Patterns provide a robust foundation for secure authorization in MCP systems while maintaining usability and interoperability.*