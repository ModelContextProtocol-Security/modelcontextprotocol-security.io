---
layout: default
title: "Code Injection"
permalink: /ttps/command-injection/code-injection/
nav_order: 4
parent: "Command & Code Injection"
grand_parent: "MCP Security TTPs"
---

# Code Injection

**Category**: Command & Code Injection  
**Severity**: Critical  
**MITRE ATT&CK Mapping**: T1059 (Command and Scripting Interpreter)

## Description

Injection of malicious code that gets executed within the MCP server environment, enabling attackers to execute arbitrary code and compromise the application runtime.

## Technical Details

### Attack Vector
- Dynamic code execution vulnerabilities
- Script injection attacks
- Runtime code manipulation
- Interpreter exploitation

### Common Techniques
- Dynamic code evaluation
- Script injection
- Template injection
- Serialization attacks

## Impact

- **Application Compromise**: Control over application execution
- **Runtime Manipulation**: Modification of application behavior
- **Data Access**: Access to application data and memory
- **System Access**: Potential system-level access through application

## Detection Methods

### Code Analysis
- Monitor dynamic code execution
- Track script evaluation
- Detect code injection patterns
- Analyze code execution flow

### Runtime Monitoring
- Monitor application behavior
- Track execution patterns
- Detect runtime anomalies
- Analyze code execution context

## Mitigation Strategies

### Code Security
- Avoid dynamic code execution
- Use safe evaluation methods
- Implement code validation
- Deploy code sandboxing

### Runtime Protection
- Use runtime security controls
- Implement execution monitoring
- Deploy code integrity checks
- Monitor application behavior

## Real-World Examples

### Example 1: Dynamic Code Evaluation
```python
def execute_formula(formula):
    # Vulnerable dynamic code execution
    result = eval(formula)
    
    # Attack: formula = "__import__('os').system('rm -rf /')"
    # Executed: __import__('os').system('rm -rf /')
```

### Example 2: Template Injection
```python
def generate_report(template, data):
    # Vulnerable template processing
    template_str = f"Result: {template}"
    result = eval(template_str)
    
    # Attack: template = "{{config.__class__.__init__.__globals__['os'].system('whoami')}}"
    # Executed: Template injection leading to code execution
```

### Example 3: Serialization Attack
```python
def process_data(serialized_data):
    # Vulnerable deserialization
    data = pickle.loads(serialized_data)
    
    # Attack: serialized_data contains malicious pickled object
    # Executed: Code execution during deserialization
```

## References & Sources

- **Philippe Bogaerts** - "The Security Risks of Model Context Protocol (MCP)"
- **Strobes Security** - "MCP and Its Critical Vulnerabilities"
- **Structured MCP Threats** - Comprehensive threat landscape analysis

## Related TTPs

- [Command Injection](command-injection.md)
- [OS Command Injection](os-command-injection.md)
- [Shell Command Execution](shell-command-execution.md)

---

*Code injection attacks target the application runtime itself, enabling sophisticated attacks that can compromise the entire MCP server environment.*