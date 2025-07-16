---
layout: default
title: "Authentication Strategies"
permalink: /build/authentication-strategies/
nav_order: 2
parent: "Build Security"
---

# Authentication Strategies

**Overview**: Alternative authentication schemes and patterns for MCP implementations.

While OAuth provides robust authorization, various authentication strategies may be appropriate for different MCP deployment scenarios. This guide covers secure authentication patterns, implementation approaches, and security considerations.

## API Key Authentication

### Secure API Key Implementation

```python
# Secure API key authentication
import hmac
import hashlib
import secrets
import time
from typing import Optional, Dict, Any

class SecureAPIKeyManager:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.api_keys = {}
        self.key_policies = {}
        
    def generate_api_key(self, user_id: str, scopes: list, expires_in: int = 86400) -> Dict[str, Any]:
        """Generate secure API key with scope and expiration"""
        
        # Generate cryptographically secure key
        key_id = secrets.token_urlsafe(16)
        key_secret = secrets.token_urlsafe(32)
        
        # Create key metadata
        key_data = {
            'key_id': key_id,
            'key_secret': key_secret,
            'user_id': user_id,
            'scopes': scopes,
            'created_at': time.time(),
            'expires_at': time.time() + expires_in,
            'active': True
        }
        
        # Store securely
        self.api_keys[key_id] = key_data
        self.key_policies[key_id] = {
            'rate_limit': 1000,  # requests per hour
            'ip_whitelist': [],
            'allowed_endpoints': self.map_scopes_to_endpoints(scopes)
        }
        
        return {
            'key_id': key_id,
            'key_secret': key_secret,
            'expires_in': expires_in
        }
    
    def validate_api_key(self, key_id: str, key_secret: str, request_context: Dict) -> Optional[Dict]:
        """Validate API key and return user context"""
        
        # Check if key exists
        if key_id not in self.api_keys:
            return None
        
        key_data = self.api_keys[key_id]
        
        # Check if key is active
        if not key_data['active']:
            return None
        
        # Check expiration
        if time.time() > key_data['expires_at']:
            return None
        
        # Validate key secret
        if not hmac.compare_digest(key_data['key_secret'], key_secret):
            return None
        
        # Validate request context
        if not self.validate_request_context(key_id, request_context):
            return None
        
        return {
            'user_id': key_data['user_id'],
            'scopes': key_data['scopes'],
            'key_id': key_id
        }
    
    def validate_request_context(self, key_id: str, context: Dict) -> bool:
        """Validate request context against key policies"""
        
        policy = self.key_policies.get(key_id)
        if not policy:
            return False
        
        # Check IP whitelist
        if policy['ip_whitelist'] and context.get('ip') not in policy['ip_whitelist']:
            return False
        
        # Check endpoint access
        endpoint = context.get('endpoint')
        if endpoint not in policy['allowed_endpoints']:
            return False
        
        # Check rate limits
        if not self.check_rate_limit(key_id, context):
            return False
        
        return True
```

### API Key Policy Management

```python
# API key policy enforcement
class APIKeyPolicyManager:
    def __init__(self):
        self.policies = {}
        self.usage_tracking = {}
        
    def create_policy(self, key_id: str, policy_config: Dict) -> None:
        """Create API key policy"""
        
        policy = {
            'scopes': policy_config.get('scopes', []),
            'rate_limits': {
                'requests_per_minute': policy_config.get('rpm', 100),
                'requests_per_hour': policy_config.get('rph', 1000),
                'requests_per_day': policy_config.get('rpd', 10000)
            },
            'ip_restrictions': {
                'whitelist': policy_config.get('ip_whitelist', []),
                'blacklist': policy_config.get('ip_blacklist', [])
            },
            'time_restrictions': {
                'allowed_hours': policy_config.get('allowed_hours', list(range(24))),
                'timezone': policy_config.get('timezone', 'UTC')
            },
            'endpoint_restrictions': {
                'allowed_endpoints': policy_config.get('allowed_endpoints', []),
                'blocked_endpoints': policy_config.get('blocked_endpoints', [])
            }
        }
        
        self.policies[key_id] = policy
        self.usage_tracking[key_id] = {
            'requests_this_minute': 0,
            'requests_this_hour': 0,
            'requests_this_day': 0,
            'last_request_time': 0
        }
    
    def enforce_policy(self, key_id: str, request_context: Dict) -> bool:
        """Enforce API key policy"""
        
        policy = self.policies.get(key_id)
        if not policy:
            return False
        
        # Check rate limits
        if not self.check_rate_limits(key_id, policy):
            return False
        
        # Check IP restrictions
        if not self.check_ip_restrictions(key_id, request_context['ip'], policy):
            return False
        
        # Check time restrictions
        if not self.check_time_restrictions(policy):
            return False
        
        # Check endpoint restrictions
        if not self.check_endpoint_restrictions(request_context['endpoint'], policy):
            return False
        
        # Update usage tracking
        self.update_usage_tracking(key_id)
        
        return True
```

## Mutual TLS Authentication

### mTLS Implementation

```python
# Mutual TLS authentication
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class MTLSAuthenticator:
    def __init__(self, ca_cert_path: str, server_cert_path: str, server_key_path: str):
        self.ca_cert_path = ca_cert_path
        self.server_cert_path = server_cert_path
        self.server_key_path = server_key_path
        self.trusted_certificates = {}
        
    def setup_mtls_context(self) -> ssl.SSLContext:
        """Setup mutual TLS context"""
        
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(self.server_cert_path, self.server_key_path)
        context.load_verify_locations(self.ca_cert_path)
        
        # Additional security settings
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        
        return context
    
    def validate_client_certificate(self, cert_der: bytes) -> Dict[str, Any]:
        """Validate client certificate"""
        
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Check certificate validity
            current_time = datetime.utcnow()
            if current_time < cert.not_valid_before or current_time > cert.not_valid_after:
                return {'valid': False, 'reason': 'Certificate expired or not yet valid'}
            
            # Extract subject information
            subject = cert.subject
            common_name = None
            organization = None
            
            for attribute in subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    common_name = attribute.value
                elif attribute.oid == x509.NameOID.ORGANIZATION_NAME:
                    organization = attribute.value
            
            # Check against trusted certificates
            cert_fingerprint = cert.fingerprint(hashlib.sha256()).hex()
            if cert_fingerprint not in self.trusted_certificates:
                return {'valid': False, 'reason': 'Certificate not trusted'}
            
            return {
                'valid': True,
                'common_name': common_name,
                'organization': organization,
                'fingerprint': cert_fingerprint,
                'user_id': self.trusted_certificates[cert_fingerprint]['user_id']
            }
            
        except Exception as e:
            return {'valid': False, 'reason': f'Certificate validation error: {str(e)}'}
    
    def register_trusted_certificate(self, cert_path: str, user_id: str, scopes: list) -> None:
        """Register trusted client certificate"""
        
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            fingerprint = cert.fingerprint(hashlib.sha256()).hex()
            
            self.trusted_certificates[fingerprint] = {
                'user_id': user_id,
                'scopes': scopes,
                'registered_at': time.time()
            }
```

## Signed Tool Definitions (ETDI)

### Enhanced Tool Definition Integrity

```python
# Signed tool definitions implementation
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class SignedToolDefinition:
    def __init__(self, private_key_path: str, public_key_path: str):
        self.private_key = self.load_private_key(private_key_path)
        self.public_key = self.load_public_key(public_key_path)
        
    def load_private_key(self, key_path: str):
        """Load private key for signing"""
        with open(key_path, 'rb') as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    
    def load_public_key(self, key_path: str):
        """Load public key for verification"""
        with open(key_path, 'rb') as key_file:
            return serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    
    def sign_tool_definition(self, tool_definition: Dict) -> Dict:
        """Sign tool definition with ETDI"""
        
        # Normalize tool definition
        normalized_def = self.normalize_definition(tool_definition)
        
        # Create signature payload
        payload = {
            'tool_definition': normalized_def,
            'timestamp': time.time(),
            'version': '1.0'
        }
        
        # Sign payload
        payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
        signature = self.private_key.sign(
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Create signed definition
        signed_definition = {
            'payload': payload,
            'signature': base64.b64encode(signature).decode('utf-8'),
            'algorithm': 'RS256',
            'key_id': self.get_key_id()
        }
        
        return signed_definition
    
    def verify_tool_definition(self, signed_definition: Dict) -> bool:
        """Verify signed tool definition"""
        
        try:
            # Extract components
            payload = signed_definition['payload']
            signature = base64.b64decode(signed_definition['signature'])
            algorithm = signed_definition['algorithm']
            
            # Verify algorithm
            if algorithm != 'RS256':
                return False
            
            # Verify signature
            payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
            self.public_key.verify(
                signature,
                payload_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Verify timestamp (not too old)
            current_time = time.time()
            signature_time = payload['timestamp']
            if current_time - signature_time > 86400:  # 24 hours
                return False
            
            return True
            
        except Exception:
            return False
    
    def normalize_definition(self, definition: Dict) -> Dict:
        """Normalize tool definition for consistent signing"""
        
        normalized = {
            'name': definition['name'],
            'description': definition['description'],
            'version': definition.get('version', '1.0'),
            'author': definition.get('author', 'unknown'),
            'capabilities': sorted(definition.get('capabilities', [])),
            'parameters': definition.get('parameters', {}),
            'security_requirements': definition.get('security_requirements', {})
        }
        
        return normalized
```

## Bearer Token Authentication

### JWT-Based Bearer Tokens

```python
# JWT bearer token authentication
import jwt
import time
from typing import Optional, Dict, Any

class JWTBearerTokenManager:
    def __init__(self, secret_key: str, algorithm: str = 'HS256'):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.token_blacklist = set()
        
    def generate_token(self, user_id: str, scopes: list, expires_in: int = 3600) -> str:
        """Generate JWT bearer token"""
        
        current_time = time.time()
        
        payload = {
            'user_id': user_id,
            'scopes': scopes,
            'iat': current_time,
            'exp': current_time + expires_in,
            'jti': secrets.token_urlsafe(16)  # JWT ID for blacklisting
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        return token
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT bearer token"""
        
        try:
            # Decode token
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check if token is blacklisted
            jti = payload.get('jti')
            if jti in self.token_blacklist:
                return None
            
            # Check expiration
            if time.time() > payload['exp']:
                return None
            
            return {
                'user_id': payload['user_id'],
                'scopes': payload['scopes'],
                'jti': jti
            }
            
        except jwt.InvalidTokenError:
            return None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke JWT token"""
        
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            jti = payload.get('jti')
            
            if jti:
                self.token_blacklist.add(jti)
                return True
                
        except jwt.InvalidTokenError:
            pass
        
        return False
    
    def create_policy_bound_token(self, user_id: str, policy: Dict) -> str:
        """Create token bound to specific policy"""
        
        current_time = time.time()
        
        payload = {
            'user_id': user_id,
            'scopes': policy['scopes'],
            'policy': {
                'allowed_endpoints': policy['allowed_endpoints'],
                'rate_limits': policy['rate_limits'],
                'ip_restrictions': policy.get('ip_restrictions', [])
            },
            'iat': current_time,
            'exp': current_time + policy.get('expires_in', 3600),
            'jti': secrets.token_urlsafe(16)
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        return token
```

## Authentication Strategy Selection

### Decision Framework

```python
# Authentication strategy selector
class AuthenticationStrategySelector:
    def __init__(self):
        self.strategies = {
            'oauth2': {
                'security_level': 'high',
                'complexity': 'high',
                'use_cases': ['web_applications', 'mobile_apps', 'third_party_integrations']
            },
            'api_key': {
                'security_level': 'medium',
                'complexity': 'low',
                'use_cases': ['server_to_server', 'automated_systems', 'simple_integrations']
            },
            'mtls': {
                'security_level': 'very_high',
                'complexity': 'high',
                'use_cases': ['high_security_environments', 'government', 'financial_services']
            },
            'jwt_bearer': {
                'security_level': 'high',
                'complexity': 'medium',
                'use_cases': ['microservices', 'apis', 'stateless_applications']
            }
        }
    
    def recommend_strategy(self, requirements: Dict) -> str:
        """Recommend authentication strategy based on requirements"""
        
        security_level = requirements.get('security_level', 'medium')
        complexity_tolerance = requirements.get('complexity_tolerance', 'medium')
        use_case = requirements.get('use_case', 'general')
        
        scores = {}
        
        for strategy, config in self.strategies.items():
            score = 0
            
            # Security level match
            if self.matches_security_level(config['security_level'], security_level):
                score += 3
            
            # Complexity tolerance
            if self.matches_complexity(config['complexity'], complexity_tolerance):
                score += 2
            
            # Use case match
            if use_case in config['use_cases']:
                score += 5
            
            scores[strategy] = score
        
        # Return highest scoring strategy
        return max(scores, key=scores.get)
    
    def matches_security_level(self, strategy_level: str, required_level: str) -> bool:
        """Check if strategy meets security level requirements"""
        
        levels = {'low': 1, 'medium': 2, 'high': 3, 'very_high': 4}
        
        return levels[strategy_level] >= levels[required_level]
    
    def matches_complexity(self, strategy_complexity: str, tolerance: str) -> bool:
        """Check if strategy complexity matches tolerance"""
        
        complexity_levels = {'low': 1, 'medium': 2, 'high': 3}
        
        return complexity_levels[strategy_complexity] <= complexity_levels[tolerance]
```

## Security Considerations

### Common Authentication Vulnerabilities

- **Credential Exposure**: Secure storage and transmission of credentials
- **Token Leakage**: Proper token handling and lifecycle management
- **Replay Attacks**: Time-based validation and nonce usage
- **Brute Force**: Rate limiting and account lockout mechanisms
- **Session Fixation**: Proper session management and rotation

### Best Practices

1. **Use Strong Cryptography**: Implement proper encryption and hashing
2. **Implement Rate Limiting**: Protect against brute force attacks
3. **Validate All Inputs**: Prevent injection and manipulation attacks
4. **Use Secure Defaults**: Configure systems with security in mind
5. **Monitor Authentication**: Track and alert on authentication anomalies

---

*Authentication Strategies provide flexible security options for different MCP deployment scenarios while maintaining strong security posture.*