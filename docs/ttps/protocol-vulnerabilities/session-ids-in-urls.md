---
layout: default
title: "Session IDs in URLs"
permalink: /ttps/protocol-vulnerabilities/session-ids-in-urls/
nav_order: 1
parent: "Protocol Vulnerabilities"
grand_parent: "MCP Security TTPs"
---

# Session IDs in URLs

**Category**: Protocol Vulnerabilities  
**Severity**: Medium  

## Description

Exposure of sensitive session identifiers in URL parameters, violating security best practices and enabling session hijacking through URL exposure.

## Technical Details

### Attack Vector
- Session IDs in URL parameters
- URL-based session exposure
- Session token leakage
- Referer header exposure

### Common Techniques
- URL parameter extraction
- Log file analysis
- Referer header harvesting
- Browser history exploitation

## Impact

- **Session Hijacking**: Unauthorized access to user sessions
- **Session Exposure**: Session tokens visible in logs and history
- **Privacy Violation**: User sessions exposed to unauthorized parties
- **Authentication Bypass**: Unauthorized access through exposed session IDs

## Detection Methods

### URL Analysis
- Monitor URL patterns for session IDs
- Analyze URL parameters
- Detect session token exposure
- Monitor URL logging

### Session Monitoring
- Track session ID usage
- Monitor session exposure
- Detect session hijacking
- Analyze session patterns

## Mitigation Strategies

### Session Security
- Use secure session management
- Implement session cookies
- Deploy session protection
- Monitor session usage

### URL Security
- Avoid session IDs in URLs
- Use POST requests for sensitive data
- Implement URL filtering
- Monitor URL patterns

## Real-World Examples

### Example 1: Session ID in URL Parameter
```
# Vulnerable URL with session ID
https://mcp-server.com/api/tools?session_id=abc123def456

# Secure alternative using cookie
https://mcp-server.com/api/tools
Cookie: session_id=abc123def456
```

### Example 2: Session Exposure in Logs
```bash
# Web server logs expose session IDs
192.168.1.100 - - [15/Jan/2024:10:30:15] "GET /api/tools?session_id=abc123def456 HTTP/1.1" 200 1234

# Session ID now visible in server logs
```

### Example 3: Referer Header Leakage
```http
# User clicks external link, session ID leaked in referer
GET https://external-site.com/page
Referer: https://mcp-server.com/dashboard?session_id=abc123def456

# Session ID exposed to external site
```

## References & Sources

- **Equixly** - "MCP Servers: The New Security Nightmare"

## Related TTPs

- [Session Management Issues](../authentication/session-management-issues.md)
- [Insecure Communication](insecure-communication.md)
- [Missing Integrity Controls](missing-integrity-controls.md)

---

*Session IDs in URLs represent a fundamental security flaw that can lead to session hijacking and unauthorized access.*