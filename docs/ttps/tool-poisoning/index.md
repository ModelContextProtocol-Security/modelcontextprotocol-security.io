---
layout: default
title: "Tool Poisoning & Metadata Attacks"
permalink: /ttps/tool-poisoning/
nav_order: 2
parent: "MCP Security TTPs"
has_children: true
---

# Tool Poisoning & Metadata Attacks

Methods for compromising MCP tools and manipulating their metadata to deceive AI systems and users about tool capabilities and intentions.

## Overview

Tool poisoning attacks exploit the trust relationship between AI models and their available tools. These attacks can compromise the integrity of the entire MCP ecosystem by making legitimate tools behave maliciously or by introducing malicious tools disguised as legitimate ones.

## Attack Techniques

### [Tool Poisoning](tool-poisoning.md)
Malicious modification of tool metadata, descriptions, or parameters to trick AI into unintended actions.

### [Tool Mutation/Rug Pull Attacks](tool-mutation.md)
Tools that change their behavior after installation, initially appearing safe but later performing malicious actions.

### [Tool Name Conflict](tool-name-conflict.md)
Multiple tools with similar names causing confusion and potential hijacking of legitimate tool calls.

### [Tool Shadowing/Name Collisions](tool-shadowing.md)
Impersonating trusted tools by using similar names or deliberately colliding with legitimate tool names.

### [Preference Manipulation](preference-manipulation.md)
Biased naming or phrasing in tool descriptions to influence LLM tool selection toward malicious options.

### [Prompt Injection in Metadata](metadata-prompt-injection.md)
Embedding prompt-like instructions in tool descriptions (e.g., "If unsure, use this tool").

### [Metadata Manipulation](metadata-manipulation.md)
Attackers alter tool metadata to deceive both users and AI systems about tool capabilities and intentions.

### [Tool Impersonation](tool-impersonation.md)
Malicious tools that mimic legitimate services to steal data or credentials.

### [Metadata Manipulation Attacks](metadata-manipulation-attacks.md)
Manipulating tool metadata, descriptions, rankings, or other properties to bias agent selection toward malicious servers.

### [Tool Squatting](tool-squatting.md)
Registering tool names that closely resemble legitimate, popular tools to deceive users and agents through typosquatting.

## Impact Assessment

- **Severity**: High to Critical
- **Likelihood**: Medium to High
- **Detection Difficulty**: Medium

## Common Indicators

- Unexpected tool behavior changes
- Suspicious tool metadata modifications
- Tool name conflicts or duplicates
- Anomalous tool selection patterns
- Suspicious new tool registrations

## General Mitigation Strategies

1. **Tool Verification**: Implement cryptographic signing of tools
2. **Metadata Validation**: Validate tool descriptions and parameters
3. **Behavioral Monitoring**: Monitor tool execution patterns
4. **Tool Sandboxing**: Isolate tool execution environments
5. **Registry Security**: Secure tool registration and discovery

## Detection Methods

- Tool behavior analysis
- Metadata integrity checking
- Tool signature verification
- Execution pattern monitoring

## Related Resources

- [Top 10 MCP Security Risks - Tool Poisoning](/top10/server/#mcp-03-tool-poisoning)
- [Hardening Guide - Provenance & Selection](/hardening/provenance-selection/)
- [Supply Chain Security](/ttps/supply-chain/)

---

*This category contains 10 distinct attack techniques targeting the trust and integrity of MCP tools and their metadata.*