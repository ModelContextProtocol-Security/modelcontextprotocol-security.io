---
layout: default
title: "Supply Chain & Dependencies"
permalink: /ttps/supply-chain/
nav_order: 6
parent: "MCP Security TTPs"
has_children: true
---

# Supply Chain & Dependencies

Compromising MCP through malicious packages, dependency attacks, and supply chain infiltration, targeting the development and distribution infrastructure.

## Overview

Supply chain attacks exploit the distributed nature of MCP development by compromising the tools, libraries, and distribution channels used to build and deploy MCP servers.

## Attack Techniques

### [Malicious MCP Packages](malicious-mcp-packages.md)
Trojanized or malicious MCP servers distributed through official or unofficial channels.

### [Supply Chain Attacks](supply-chain-attacks.md)
Compromise of MCP development or distribution infrastructure.

### [Dependency Vulnerabilities](dependency-vulnerabilities.md)
Security flaws in third-party libraries and dependencies used by MCP servers.

### [Installer Spoofing](installer-spoofing.md)
Fake or malicious MCP installers that compromise systems during installation.

### [Typosquatting](typosquatting.md)
Malicious MCP servers with names similar to legitimate ones to deceive users.

### [Drift from Upstream](drift-from-upstream.md)
Unnoticed changes in tool behavior or code from upstream sources over time.

### [Malicious Dependency Inclusion](malicious-dependency-inclusion.md)
Inclusion of compromised or malicious dependencies in MCP server builds.

## Impact Assessment

- **Severity**: High to Critical
- **Likelihood**: Medium
- **Detection Difficulty**: High

## Common Indicators

- Unexpected package installations
- Unusual dependency changes
- Suspicious installer behavior
- Modified upstream sources
- Compromised build processes

## General Mitigation Strategies

1. **Package Verification**: Verify package integrity and authenticity
2. **Dependency Scanning**: Regular vulnerability scanning of dependencies
3. **Supply Chain Monitoring**: Monitor supply chain integrity
4. **Secure Development**: Implement secure development practices
5. **Distribution Security**: Secure package distribution channels

## Detection Methods

- Package integrity monitoring
- Dependency vulnerability scanning
- Supply chain analysis
- Build process monitoring

## Related Resources

- [Top 10 MCP Security Risks - Supply Chain](/top10/server/#supply-chain-attacks)
- [Hardening Guide - Provenance & Selection](/hardening/provenance-selection/)
- [Audit Tools - Security Assessment](/audit/)

---

*This category contains 7 distinct attack techniques focused on compromising MCP systems through supply chain vulnerabilities.*