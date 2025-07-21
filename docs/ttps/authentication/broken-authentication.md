---
layout: default
title: "Broken Authentication"
permalink: /ttps/authentication/broken-authentication/
nav_order: 2
parent: "Authentication & Authorization"
grand_parent: "MCP Security TTPs"
---

# Broken Authentication

**Category**: Authentication & Authorization  
**Severity**: Critical  

## Description

Flawed authentication implementations allowing unauthorized access through weak, bypassed, or compromised authentication mechanisms in MCP systems.

## Technical Details

### Attack Vector
- Weak authentication mechanisms
- Authentication logic flaws
- Credential validation failures
- Authentication bypass vulnerabilities

### Common Techniques
- Weak password policies
- Authentication timing attacks
- Credential stuffing
- Authentication logic bypasses

## Impact

- **Account Takeover**: Unauthorized access to user accounts
- **Identity Theft**: Impersonation of legitimate users
- **System Compromise**: Access to protected MCP resources
- **Privilege Escalation**: Higher-level access through compromised authentication

## Detection Methods

### Authentication Monitoring
- Monitor authentication attempts
- Track authentication failures
- Detect brute force attacks
- Analyze authentication patterns

### Credential Analysis
- Monitor credential usage
- Track password changes
- Detect credential reuse
- Analyze authentication methods

## Mitigation Strategies

### Authentication Strengthening
- Implement strong password policies
- Use multi-factor authentication
- Deploy authentication validation
- Monitor authentication events

### Security Controls
- Implement rate limiting
- Use account lockout policies
- Deploy authentication logging
- Monitor authentication patterns

## Real-World Examples

### Example 1: Weak Password Validation
```python
def authenticate_user(username, password):
    user = get_user(username)
    
    # Weak password validation
    if user and user.password == password:
        return True
    return False
    
    # Should use: secure_password_hash_compare()
```

### Example 2: Authentication Timing Attack
```python
def validate_credentials(username, password):
    users = get_all_users()
    
    # Timing attack vulnerability
    for user in users:
        if user.username == username:
            if user.password == password:
                return True
            return False
    return False
    
    # Should use: constant_time_compare()
```

### Example 3: Authentication Logic Bypass
```python
def login(username, password, remember_me=False):
    # Authentication bypass through parameter
    if remember_me and username in remembered_users:
        return create_session(username)
    
    # Normal authentication
    if authenticate_user(username, password):
        return create_session(username)
    
    return None
```

## References & Sources

- **Philippe Bogaerts** - "The Security Risks of Model Context Protocol (MCP)"
- **Red Hat** - "Model Context Protocol (MCP): Understanding security risks and controls"

## Related TTPs

- [Unauthenticated Access](unauthenticated-access.md)
- [Session Management Issues](session-management-issues.md)
- [Identity Subversion](identity-subversion.md)

---

*Broken authentication represents a critical vulnerability that undermines the entire security foundation of MCP systems.*