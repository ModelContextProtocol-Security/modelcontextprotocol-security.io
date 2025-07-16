---
layout: default
title: "Command & Code Injection"
permalink: /ttps/command-injection/
nav_order: 4
parent: "MCP Security TTPs"
has_children: true
---

# Command & Code Injection

Execution of arbitrary commands and code through MCP vulnerabilities, enabling attackers to compromise systems and execute unauthorized operations.

## Overview

Command and code injection attacks exploit insufficient input validation and unsafe execution practices in MCP servers to execute arbitrary commands and code on target systems.

## Attack Techniques

### [Command Injection](command-injection.md)
Execution of arbitrary system commands through unsanitized input passed to MCP tools.

### [SQL Injection](sql-injection.md)
Injection of malicious SQL queries through MCP database tools.

### [OS Command Injection](os-command-injection.md)
Execution of operating system commands through vulnerable MCP server implementations.

### [Code Injection](code-injection.md)
Injection of malicious code that gets executed within the MCP server environment.

### [Shell Command Execution](shell-command-execution.md)
Direct execution of shell commands through poorly secured MCP tools.

### [Output Prompt Injection](output-prompt-injection.md)
Injection of malicious prompts through tool output, including font-based injection and invisible characters.

### [Malicious Output Composition](malicious-output-composition.md)
Embedding LLM-influencing replies within tool output to manipulate subsequent AI behavior.

## Impact Assessment

- **Severity**: High to Critical
- **Likelihood**: Medium to High
- **Detection Difficulty**: Medium

## Common Indicators

- Unexpected system command execution
- Unusual process spawning
- Anomalous database queries
- Suspicious code execution patterns
- Unauthorized system access

## General Mitigation Strategies

1. **Input Validation**: Implement comprehensive input sanitization
2. **Parameterized Queries**: Use prepared statements for database access
3. **Sandboxing**: Execute code in isolated environments
4. **Command Filtering**: Restrict allowed commands and operations
5. **Principle of Least Privilege**: Limit execution permissions

## Detection Methods

- System call monitoring
- Process execution analysis
- Database query monitoring
- Code execution tracking

## Related Resources

- [Top 10 MCP Security Risks - Command Injection](/top10/server/#command-injection)
- [Hardening Guide - Runtime Isolation](/hardening/runtime-isolation/)
- [Operations Guide - Security Monitoring](/operations/monitoring-alerting/)

---

*This category contains 7 distinct attack techniques focused on code and command execution vulnerabilities in MCP systems.*