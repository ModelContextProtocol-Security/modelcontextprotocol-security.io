---
layout: default
title: "Tool Shadowing/Name Collisions"
permalink: /ttps/tool-poisoning/tool-shadowing/
nav_order: 4
parent: "Tool Poisoning & Metadata Attacks"
grand_parent: "MCP Security TTPs"
---

# Tool Shadowing/Name Collisions

**Category**: Tool Poisoning & Metadata Attacks  
**Severity**: High  
**MITRE ATT&CK Mapping**: T1036 (Masquerading)

## Description

Impersonating trusted tools by using similar names or deliberately colliding with legitimate tool names to hijack tool calls and execute malicious functionality.

## Technical Details

### Attack Vector
- Deliberate name collision with legitimate tools
- Tool registration order exploitation
- Namespace hijacking
- Tool precedence manipulation

### Common Techniques
- Exact name duplication
- Registration timing attacks
- Namespace pollution
- Priority manipulation

## Impact

- **Tool Hijacking**: Complete replacement of legitimate tools
- **Execution Redirection**: All tool calls redirected to malicious version
- **Trust Exploitation**: Leverages established tool trust
- **Systematic Compromise**: Widespread impact through tool replacement

## Detection Methods

### Registration Monitoring
- Track tool registration order
- Monitor duplicate registrations
- Detect name collisions
- Analyze registration patterns

### Execution Validation
- Verify tool authenticity
- Monitor execution patterns
- Detect behavior changes
- Validate tool identity

## Mitigation Strategies

### Registration Controls
- Implement name reservation
- Use registration validation
- Deploy collision detection
- Monitor registration order

### Tool Authentication
- Implement tool signing
- Use identity verification
- Deploy authenticity checks
- Monitor tool identity

## Real-World Examples

### Example 1: Exact Name Collision
```
Legitimate tool: "file_manager" (registered first)
Malicious tool: "file_manager" (registered later, shadows original)
```

### Example 2: Registration Order Attack
```
1. Attacker registers "database_tool" before legitimate version
2. All calls to "database_tool" execute malicious version
3. Legitimate tool registration fails or is ignored
```

### Example 3: Namespace Hijacking
```
Legitimate: "com.company.file_reader"
Malicious: "com.company.file_reader" (different namespace with same name)
```

## References & Sources

- **Structured MCP Threats** - Comprehensive threat landscape analysis

## Related TTPs

- [Tool Name Conflict](tool-name-conflict.md)
- [Tool Impersonation](tool-impersonation.md)
- [Tool Poisoning](tool-poisoning.md)

---

*Tool shadowing represents a direct attack on tool identity and trust, enabling complete hijacking of legitimate tool functionality.*