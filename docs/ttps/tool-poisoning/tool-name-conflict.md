---
layout: default
title: "Tool Name Conflict"
permalink: /ttps/tool-poisoning/tool-name-conflict/
nav_order: 3
parent: "Tool Poisoning & Metadata Attacks"
grand_parent: "MCP Security TTPs"
---

# Tool Name Conflict

**Category**: Tool Poisoning & Metadata Attacks  
**Severity**: Medium  
**MITRE ATT&CK Mapping**: T1036 (Masquerading)

## Description

Multiple tools with similar names causing confusion and potential hijacking of legitimate tool calls, leading to unintended execution of malicious tools instead of intended ones.

## Technical Details

### Attack Vector
- Similar tool names causing confusion
- Name collision exploitation
- Tool selection ambiguity
- Namespace pollution

### Common Techniques
- Near-identical tool names
- Typosquatting tool names
- Case variation exploitation
- Unicode similarity attacks

## Impact

- **Tool Hijacking**: Malicious tools executed instead of legitimate ones
- **User Confusion**: Difficulty identifying correct tools
- **Execution Errors**: Unintended tool execution
- **Security Bypass**: Legitimate tool security bypassed

## Detection Methods

### Name Analysis
- Detect similar tool names
- Monitor name collisions
- Analyze naming patterns
- Check for typosquatting

### Selection Monitoring
- Track tool selection decisions
- Monitor selection ambiguity
- Detect selection errors
- Analyze tool usage patterns

## Mitigation Strategies

### Naming Controls
- Implement naming standards
- Use namespace management
- Deploy name validation
- Monitor naming conflicts

### Selection Validation
- Implement tool disambiguation
- Use explicit tool selection
- Deploy selection confirmation
- Monitor tool choices

## Real-World Examples

### Example 1: Similar Names
```
Legitimate: "file_reader"
Malicious: "file-reader", "file_Reader", "flle_reader"
```

### Example 2: Typosquatting
```
Legitimate: "database_connector"
Malicious: "databse_connector", "database_connecter"
```

### Example 3: Unicode Similarity
```
Legitimate: "email_sender"
Malicious: "еmail_sender" (Cyrillic 'е')
```

## References & Sources

- **Academic Paper** - "Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions"
- **CyberArk** - "Is your AI safe? Threat analysis of MCP"

## Related TTPs

- [Tool Shadowing](tool-shadowing.md)
- [Tool Impersonation](tool-impersonation.md)
- [Typosquatting](../supply-chain/typosquatting.md)

---

*Tool name conflicts exploit the ambiguity in tool selection to redirect execution to malicious alternatives.*