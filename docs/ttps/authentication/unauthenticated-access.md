---
layout: default
title: "Unauthenticated Access"
permalink: /ttps/authentication/unauthenticated-access/
nav_order: 1
parent: "Authentication & Authorization"
grand_parent: "MCP Security TTPs"
---

# Unauthenticated Access

**Category**: Authentication & Authorization  
**Severity**: Critical  
**MITRE ATT&CK Mapping**: T1190 (Exploit Public-Facing Application)

## Description

MCP endpoints exposed without proper authentication mechanisms, allowing attackers to access protected resources and functionality without providing valid credentials.

## Technical Details

### Attack Vector
- Exposed MCP endpoints without authentication
- Missing authentication checks
- Bypassed authentication requirements
- Open access to protected resources

### Common Techniques
- Direct endpoint access
- Authentication bypass
- Missing authentication validation
- Default open access

## Impact

- **Unauthorized Access**: Access to protected MCP resources
- **Data Exposure**: Sensitive information accessible without authentication
- **System Compromise**: Control over MCP functionality
- **Service Abuse**: Misuse of MCP services without authorization

## Detection Methods

### Access Monitoring
- Monitor endpoint access patterns
- Track unauthenticated requests
- Detect unauthorized access attempts
- Analyze access logs

### Authentication Analysis
- Monitor authentication failures
- Track missing authentication
- Detect authentication bypass attempts
- Analyze authentication patterns

## Mitigation Strategies

### Authentication Implementation
- Implement strong authentication
- Use multi-factor authentication
- Deploy authentication validation
- Monitor authentication events

### Access Controls
- Implement authorization checks
- Use role-based access control
- Deploy access validation
- Monitor access attempts

## Real-World Examples

### Example 1: Open MCP Endpoint
```python
@app.route('/mcp/tools', methods=['GET'])
def get_tools():
    # No authentication check
    return jsonify(get_all_tools())
    
    # Should include: require_authentication()
```

### Example 2: Missing Authentication Validation
```python
def execute_tool(tool_name, parameters):
    # No authentication validation
    tool = get_tool(tool_name)
    return tool.execute(parameters)
    
    # Should include: validate_user_authentication()
```

### Example 3: Bypassed Authentication
```python
def admin_action(action):
    # Authentication bypass through parameter
    if action == "emergency_access":
        return perform_admin_action()
    
    # Normal authentication only for non-emergency
    if not authenticate_user():
        return "Unauthorized"
    
    return perform_admin_action()
```

## References & Sources

- **AppSecEngineer** - "5 Critical MCP Vulnerabilities Every Security Team Should Know"
- **Equixly** - "MCP Servers: The New Security Nightmare"
- **Red Hat** - "Model Context Protocol (MCP): Understanding security risks and controls"

## Related TTPs

- [Broken Authentication](broken-authentication.md)
- [Authorization Bypass](authorization-bypass.md)
- [Auth Bypass & Rogue Server Registration](auth-bypass-rogue-server.md)

---

*Unauthenticated access represents a fundamental security failure that can lead to complete system compromise.*