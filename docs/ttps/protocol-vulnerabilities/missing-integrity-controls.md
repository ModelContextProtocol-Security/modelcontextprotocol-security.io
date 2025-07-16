---
layout: default
title: "Missing Integrity Controls"
permalink: /ttps/protocol-vulnerabilities/missing-integrity-controls/
nav_order: 3
parent: "Protocol Vulnerabilities"
grand_parent: "MCP Security TTPs"
---

# Missing Integrity Controls

**Category**: Protocol Vulnerabilities  
**Severity**: High  
**MITRE ATT&CK Mapping**: T1565 (Data Manipulation)

## Description

Lack of message signing or verification mechanisms allowing message tampering, enabling attackers to modify MCP messages in transit without detection.

## Technical Details

### Attack Vector
- Message tampering attacks
- Man-in-the-middle attacks
- Protocol message modification
- Communication integrity bypass

### Common Techniques
- Message interception and modification
- Protocol message injection
- Communication tampering
- Integrity bypass

## Impact

- **Message Tampering**: Unauthorized modification of MCP messages
- **Data Integrity Loss**: Compromised message integrity
- **Communication Compromise**: Compromised communication channels
- **Trust Erosion**: Loss of trust in communication integrity

## Detection Methods

### Message Analysis
- Monitor message integrity
- Detect message modifications
- Analyze message patterns
- Monitor communication integrity

### Protocol Monitoring
- Monitor protocol communications
- Track message integrity
- Detect protocol tampering
- Analyze protocol security

## Mitigation Strategies

### Integrity Protection
- Implement message signing
- Use message authentication codes
- Deploy integrity verification
- Monitor message integrity

### Communication Security
- Implement secure communications
- Use encrypted channels
- Deploy integrity controls
- Monitor communication security

## Real-World Examples

### Example 1: Message Tampering
```python
# Original message
message = {
    "type": "tool_call",
    "tool": "file_reader",
    "params": {"file": "document.txt"}
}

# Tampered message (no integrity check)
message = {
    "type": "tool_call",
    "tool": "file_reader",
    "params": {"file": "/etc/passwd"}  # Modified parameter
}
```

### Example 2: Protocol Message Injection
```python
# Legitimate message flow
def send_message(message):
    # No integrity protection
    transmit_message(message)

# Attacker injects malicious message
malicious_message = {
    "type": "admin_command",
    "command": "delete_all_users"
}
send_message(malicious_message)  # Injected without detection
```

### Example 3: Communication Tampering
```python
# Vulnerable communication without integrity
def communicate(data):
    # No message signing or verification
    response = send_to_server(data)
    return response

# Attacker intercepts and modifies response
# No way to detect tampering
```

## References & Sources

- **Equixly** - "MCP Servers: The New Security Nightmare"
- **Red Hat** - "Model Context Protocol (MCP): Understanding security risks and controls"

## Related TTPs

- [Insecure Communication](insecure-communication.md)
- [Protocol Implementation Flaws](protocol-implementation-flaws.md)
- [Data Manipulation](../context-manipulation/context-manipulation.md)

---

*Missing integrity controls enable message tampering attacks that can compromise the entire MCP communication system.*