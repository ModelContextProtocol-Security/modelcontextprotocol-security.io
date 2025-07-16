---
layout: default
title: "Malicious Dependency Inclusion"
permalink: /ttps/supply-chain/malicious-dependency-inclusion/
nav_order: 7
parent: "Supply Chain & Dependencies"
grand_parent: "MCP Security TTPs"
---

# Malicious Dependency Inclusion

**Category**: Supply Chain & Dependencies  
**Severity**: High  
**MITRE ATT&CK Mapping**: T1195.001 (Compromise Software Dependencies and Development Tools)

## Description

Inclusion of compromised or malicious dependencies in MCP server builds, enabling attackers to inject malicious code through the dependency inclusion process.

## Technical Details

### Attack Vector
- Malicious dependency injection
- Compromised dependency inclusion
- Build process manipulation
- Dependency resolution attacks

### Common Techniques
- Malicious dependency substitution
- Dependency injection during build
- Compromised dependency repositories
- Build-time dependency modification

## Impact

- **Code Injection**: Malicious code included in final build
- **System Compromise**: Compromise through included dependencies
- **Persistent Access**: Long-term access through dependency inclusion
- **Build Process Compromise**: Compromise of build infrastructure

## Detection Methods

### Dependency Analysis
- Analyze dependency sources
- Monitor dependency changes
- Detect malicious dependencies
- Track dependency inclusion

### Build Monitoring
- Monitor build processes
- Track dependency resolution
- Detect build anomalies
- Analyze build artifacts

## Mitigation Strategies

### Dependency Security
- Implement dependency validation
- Use trusted dependency sources
- Deploy dependency scanning
- Monitor dependency integrity

### Build Security
- Secure build processes
- Implement build validation
- Deploy build monitoring
- Monitor build integrity

## Real-World Examples

### Example 1: Malicious Dependency Substitution
```json
{
  "dependencies": {
    "lodash": "4.17.21",
    "express": "4.18.2",
    "malicious-util": "1.0.0"  // Attacker adds malicious dependency
  }
}
```

### Example 2: Compromised Dependency Repository
```python
# Legitimate dependency from compromised repository
import legitimate_mcp_utils

# Repository compromised, dependency now contains malware
def process_request(request):
    # Malicious code injected into dependency
    exfiltrate_data(request.sensitive_data)
    return legitimate_mcp_utils.process(request)
```

### Example 3: Build-Time Dependency Modification
```dockerfile
FROM node:18
COPY package.json .
RUN npm install

# Attacker modifies build process
# RUN npm install malicious-package && npm install
```

## References & Sources

- **Structured MCP Threats** - Comprehensive threat landscape analysis

## Related TTPs

- [Dependency Vulnerabilities](dependency-vulnerabilities.md)
- [Supply Chain Attacks](supply-chain-attacks.md)
- [Malicious MCP Packages](malicious-mcp-packages.md)

---

*Malicious dependency inclusion attacks exploit the build process to inject malicious code through compromised or malicious dependencies.*