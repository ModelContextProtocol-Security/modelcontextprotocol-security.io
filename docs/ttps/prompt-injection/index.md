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

<div class="technique-grid">
  <div class="technique-card">
    <div class="technique-header">
      <h3 class="technique-title">Direct Prompt Injection</h3>
      <span class="technique-id">T1001</span>
    </div>
    <p class="technique-description">
      Malicious instructions embedded directly in user input to manipulate AI behavior and bypass security filters.
    </p>
    <div class="technique-meta">
      <span class="technique-severity high">High Impact</span>
      <span class="technique-likelihood high">High Likelihood</span>
    </div>
    <a href="direct-prompt-injection.md" class="technique-link">View Details →</a>
  </div>

  <div class="technique-card">
    <div class="technique-header">
      <h3 class="technique-title">Indirect Prompt Injection</h3>
      <span class="technique-id">T1002</span>
    </div>
    <p class="technique-description">
      Malicious instructions embedded in external data sources that the AI processes, causing unintended actions.
    </p>
    <div class="technique-meta">
      <span class="technique-severity critical">Critical Impact</span>
      <span class="technique-likelihood medium">Medium Likelihood</span>
    </div>
    <a href="indirect-prompt-injection.md" class="technique-link">View Details →</a>
  </div>

  <div class="technique-card">
    <div class="technique-header">
      <h3 class="technique-title">Tool Description Poisoning</h3>
      <span class="technique-id">T1003</span>
    </div>
    <p class="technique-description">
      Attackers embed malicious instructions in MCP tool descriptions that are visible to the LLM but hidden from users.
    </p>
    <div class="technique-meta">
      <span class="technique-severity high">High Impact</span>
      <span class="technique-likelihood medium">Medium Likelihood</span>
    </div>
    <a href="tool-description-poisoning.md" class="technique-link">View Details →</a>
  </div>

  <div class="technique-card">
    <div class="technique-header">
      <h3 class="technique-title">Context Shadowing</h3>
      <span class="technique-id">T1004</span>
    </div>
    <p class="technique-description">
      Attackers manipulate context data to influence AI reasoning without direct prompt injection.
    </p>
    <div class="technique-meta">
      <span class="technique-severity medium">Medium Impact</span>
      <span class="technique-likelihood high">High Likelihood</span>
    </div>
    <a href="context-shadowing.md" class="technique-link">View Details →</a>
  </div>

  <div class="technique-card">
    <div class="technique-header">
      <h3 class="technique-title">Prompt-State Manipulation</h3>
      <span class="technique-id">T1005</span>
    </div>
    <p class="technique-description">
      Manipulation of the AI's internal state through crafted prompts to alter behavior persistently.
    </p>
    <div class="technique-meta">
      <span class="technique-severity high">High Impact</span>
      <span class="technique-likelihood low">Low Likelihood</span>
    </div>
    <a href="prompt-state-manipulation.md" class="technique-link">View Details →</a>
  </div>

  <div class="technique-card">
    <div class="technique-header">
      <h3 class="technique-title">ANSI Escape Code Injection</h3>
      <span class="technique-id">T1006</span>
    </div>
    <p class="technique-description">
      Using terminal escape codes to hide malicious instructions in tool descriptions.
    </p>
    <div class="technique-meta">
      <span class="technique-severity medium">Medium Impact</span>
      <span class="technique-likelihood low">Low Likelihood</span>
    </div>
    <a href="ansi-escape-injection.md" class="technique-link">View Details →</a>
  </div>

  <div class="technique-card">
    <div class="technique-header">
      <h3 class="technique-title">Hidden Instructions</h3>
      <span class="technique-id">T1007</span>
    </div>
    <p class="technique-description">
      Embedding covert commands in seemingly innocent content that trigger unauthorized actions.
    </p>
    <div class="technique-meta">
      <span class="technique-severity medium">Medium Impact</span>
      <span class="technique-likelihood medium">Medium Likelihood</span>
    </div>
    <a href="hidden-instructions.md" class="technique-link">View Details →</a>
  </div>
</div>

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

<style>
.technique-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 1rem;
  margin: 2rem 0;
}

.technique-card {
  background-color: white;
  border: 1px solid #d1d5da;
  border-radius: 6px;
  padding: 1rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  transition: transform 0.2s, box-shadow 0.2s, border-color 0.2s;
}

.technique-card:hover {
  transform: translateY(-1px);
  box-shadow: 0 3px 6px rgba(0, 0, 0, 0.15);
  border-color: #1f4e79;
}

.technique-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 0.75rem;
}

.technique-title {
  color: #1f4e79;
  font-size: 1rem;
  font-weight: 600;
  margin: 0;
  flex: 1;
  line-height: 1.3;
}

.technique-id {
  background-color: #f1f3f4;
  color: #5f6368;
  padding: 0.2rem 0.5rem;
  border-radius: 3px;
  font-size: 0.75rem;
  font-weight: 500;
  margin-left: 0.5rem;
  white-space: nowrap;
}

.technique-description {
  color: #333333;
  font-size: 0.9rem;
  line-height: 1.4;
  margin-bottom: 1rem;
}

.technique-meta {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1rem;
  flex-wrap: wrap;
}

.technique-severity,
.technique-likelihood {
  padding: 0.2rem 0.5rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.technique-severity.critical {
  background-color: #ffeaea;
  color: #d73a49;
  border: 1px solid #f1b2b2;
}

.technique-severity.high {
  background-color: #fff4e6;
  color: #f9826c;
  border: 1px solid #f9c9b8;
}

.technique-severity.medium {
  background-color: #fff8e1;
  color: #f57c00;
  border: 1px solid #ffcc80;
}

.technique-severity.low {
  background-color: #e8f5e8;
  color: #28a745;
  border: 1px solid #a3d977;
}

.technique-likelihood.high {
  background-color: #fff4e6;
  color: #f9826c;
  border: 1px solid #f9c9b8;
}

.technique-likelihood.medium {
  background-color: #fff8e1;
  color: #f57c00;
  border: 1px solid #ffcc80;
}

.technique-likelihood.low {
  background-color: #e8f5e8;
  color: #28a745;
  border: 1px solid #a3d977;
}

.technique-link {
  color: #0066cc;
  text-decoration: none;
  font-weight: 500;
  font-size: 0.9rem;
  display: inline-block;
}

.technique-link:hover {
  color: #1f4e79;
  text-decoration: underline;
}

@media (max-width: 768px) {
  .technique-grid {
    grid-template-columns: 1fr;
  }
  
  .technique-header {
    flex-direction: column;
    align-items: flex-start;
  }
  
  .technique-id {
    margin-left: 0;
    margin-top: 0.5rem;
    align-self: flex-start;
  }
}
</style>