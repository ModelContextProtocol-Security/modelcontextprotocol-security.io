---
layout: default
title: "Cross-Context Access"
permalink: /ttps/privilege-access-control/cross-context-access/
nav_order: 5
parent: "Privilege & Access Control"
grand_parent: "MCP Security TTPs"
---

# Cross-Context Access

**Category**: Privilege & Access Control  
**Severity**: High  
**MITRE ATT&CK Mapping**: T1021 (Remote Services)

## Description

Unauthorized access across different security contexts, sessions, or user boundaries in MCP systems, enabling attackers to access resources from other users or contexts.

## Technical Details

### Attack Vector
- Context isolation failures
- Session boundary violations
- User context switching
- Security context bypass

### Common Techniques
- Context confusion attacks
- Session hijacking
- User impersonation
- Security boundary violations

## Impact

- **Data Access**: Access to data from other users or contexts
- **Privacy Violation**: Unauthorized access to user information
- **Context Compromise**: Compromise of security contexts
- **System Integrity**: Violation of system security boundaries

## Detection Methods

### Context Monitoring
- Monitor context switching
- Track cross-context access
- Detect context violations
- Analyze context integrity

### Session Monitoring
- Monitor session boundaries
- Track session access
- Detect session hijacking
- Analyze session integrity

## Mitigation Strategies

### Context Isolation
- Implement strong context isolation
- Use secure session management
- Deploy context monitoring
- Regular context audits

### Access Control
- Implement context-aware access control
- Use session-based permissions
- Deploy access monitoring
- Monitor context boundaries

## Real-World Examples

### Example 1: Session Context Mixing
```python
# Vulnerable session management
class MCPSessionManager:
    def __init__(self):
        self.sessions = {}
        self.current_user = None
    
    def get_user_data(self, session_id):
        # Vulnerable: uses current_user instead of session user
        if session_id in self.sessions:
            return self.get_data_for_user(self.current_user)
        
        # Attacker accesses another user's data
        # session_id = "victim_session"
        # current_user = "attacker"
```

### Example 2: Context Boundary Violation
```python
# Vulnerable context isolation
class MCPContextManager:
    def __init__(self):
        self.contexts = {}
        self.shared_resources = {}
    
    def access_resource(self, context_id, resource_id):
        # Insufficient context validation
        if context_id in self.contexts:
            # Should validate resource belongs to context
            return self.shared_resources.get(resource_id)
        
        # Attacker accesses resources from other contexts
        # context_id = "user_context"
        # resource_id = "admin_resource"
```

### Example 3: User Context Switching
```python
# Vulnerable user context switching
class MCPUserContext:
    def __init__(self):
        self.current_user = None
        self.user_data = {}
    
    def switch_user(self, new_user):
        # Insufficient validation
        self.current_user = new_user
    
    def get_user_files(self):
        # Returns files for current user
        return self.user_data.get(self.current_user, [])
    
    def process_request(self, request):
        # Vulnerable: user switching without validation
        if request.get('switch_user'):
            self.switch_user(request['switch_user'])
        
        # Attacker switches to another user context
        # request = {"switch_user": "admin", "action": "get_files"}
```

## References & Sources

- **Equixly** - "MCP Servers: The New Security Nightmare"
- **Red Hat** - "Model Context Protocol (MCP): Understanding security risks and controls"

## Related TTPs

- [Unauthorized Privilege Escalation](unauthorized-privilege-escalation.md)
- [Resource Access Control Bypass](resource-access-control-bypass.md)
- [Session Management Issues](../authentication/session-management-issues.md)

---

*Cross-context access vulnerabilities can lead to serious privacy violations and unauthorized access to sensitive user data and system resources.*