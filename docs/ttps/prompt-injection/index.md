---
layout: default
title: "Prompt Injection & Manipulation"
permalink: /ttps/prompt-injection/
nav_order: 1
parent: "MCP Security TTPs"
has_children: true
---

# Prompt Injection & Manipulation

Techniques for manipulating AI behavior through malicious prompts and instructions embedded in user input, data sources, or tool descriptions.

## Overview

Prompt injection attacks represent one of the most critical security threats to MCP systems. These attacks exploit the natural language processing capabilities of AI models to bypass security controls and manipulate system behavior.

## Attack Techniques

### [Direct Prompt Injection](direct-prompt-injection.md)
Malicious instructions embedded directly in user input to manipulate AI behavior and bypass security filters.

### [Indirect Prompt Injection](indirect-prompt-injection.md)
Malicious instructions embedded in external data sources that the AI processes, causing unintended actions.

### [Tool Description Poisoning](tool-description-poisoning.md)
Attackers embed malicious instructions in MCP tool descriptions that are visible to the LLM but hidden from users.

### [Context Shadowing](context-shadowing.md)
Attackers manipulate context data to influence AI reasoning without direct prompt injection.

### [Prompt-State Manipulation](prompt-state-manipulation.md)
Manipulation of the AI's internal state through crafted prompts to alter behavior persistently.

### [ANSI Escape Code Injection](ansi-escape-injection.md)
Using terminal escape codes to hide malicious instructions in tool descriptions.

### [Hidden Instructions](hidden-instructions.md)
Embedding covert commands in seemingly innocent content that trigger unauthorized actions.

## Impact Assessment

- **Severity**: High to Critical
- **Likelihood**: High
- **Detection Difficulty**: Medium to High

## Common Indicators

- Unusual AI responses or behavior
- Unexpected tool executions
- Anomalous context processing
- Suspicious prompt patterns in logs

## General Mitigation Strategies

1. **Input Validation**: Implement comprehensive input sanitization
2. **Prompt Filtering**: Deploy prompt injection detection systems
3. **Context Isolation**: Separate user input from system prompts
4. **Behavioral Monitoring**: Monitor AI decision-making patterns
5. **Tool Description Security**: Secure tool metadata and descriptions

## Detection Methods

- Pattern-based prompt analysis
- Behavioral anomaly detection
- Context integrity checking
- Response validation systems

## Related Resources

- [Top 10 MCP Security Risks - Prompt Injection](/top10/server/#mcp-01-prompt-injection)
- [Hardening Guide - Policy & Guardrails](/hardening/policy-guardrails/)
- [Audit Tools - Security Assessment](/audit/)

---

*This category contains 7 distinct attack techniques with comprehensive technical details, detection methods, and mitigation strategies.*