---
layout: default
title: "Typosquatting"
permalink: /ttps/supply-chain/typosquatting/
nav_order: 5
parent: "Supply Chain & Dependencies"
grand_parent: "MCP Security TTPs"
---

# Typosquatting

**Category**: Supply Chain & Dependencies  
**Severity**: Medium  

## Description

Malicious MCP servers with names similar to legitimate ones to deceive users, enabling attackers to trick users into installing malicious packages through name confusion.

## Technical Details

### Attack Vector
- Similar package names
- Typo-based naming
- Character substitution
- Domain/namespace confusion

### Common Techniques
- Character substitution
- Letter omission/addition
- Character transposition
- Similar-looking characters

## Impact

- **Accidental Installation**: Users install malicious packages by mistake
- **System Compromise**: Malicious code execution through typosquatted packages
- **Trust Exploitation**: Abuse of trust in legitimate package names
- **Ecosystem Pollution**: Confusion in package ecosystem

## Detection Methods

### Name Analysis
- Analyze package names for similarities
- Detect typosquatting patterns
- Monitor package registrations
- Track naming conflicts

### Installation Monitoring
- Monitor package installations
- Track package usage patterns
- Detect suspicious installations
- Analyze installation sources

## Mitigation Strategies

### Name Protection
- Reserve similar package names
- Implement name validation
- Monitor package registrations
- Deploy name similarity detection

### User Education
- Educate users about typosquatting
- Provide package verification guidance
- Implement installation warnings
- Monitor installation patterns

## Real-World Examples

### Example 1: Character Substitution
```
Legitimate: "mcp-database-connector"
Typosquatted: "mcp-database-conecter" (n → c)
Typosquatted: "mcp-databse-connector" (as → bs)
```

### Example 2: Similar Characters
```
Legitimate: "mcp-file-manager"
Typosquatted: "mcp-fi1e-manager" (l → 1)
Typosquatted: "mcp-file-manag3r" (e → 3)
```

### Example 3: Domain Confusion
```
Legitimate: "github.com/mcp-tools/file-reader"
Typosquatted: "github.com/mcp-t00ls/file-reader" (o → 0)
Typosquatted: "github.com/mcp-tools/file-readr" (e missing)
```

## References & Sources

- **Palo Alto Networks** - "Model Context Protocol (MCP): A Security Overview"

## Related TTPs

- [Malicious MCP Packages](malicious-mcp-packages.md)
- [Tool Name Conflict](../tool-poisoning/tool-name-conflict.md)
- [Installer Spoofing](installer-spoofing.md)

---

*Typosquatting attacks exploit human error and trust to trick users into installing malicious packages with similar names to legitimate ones.*