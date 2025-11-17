---
layout: default
title: "MCP Security TTPs"
permalink: /ttps/
nav_order: 4
has_children: true
custom_css: /assets/css/ttp-cards.css
---

<link rel="stylesheet" href="{{ '/assets/css/ttp-cards.css' | relative_url }}">

# MCP Security Tactics, Techniques, and Procedures (TTPs)

A comprehensive database of security tactics, techniques, and procedures specific to Model Context Protocol (MCP) implementations. This resource provides detailed technical information about attack vectors, detection methods, and mitigation strategies for MCP security threats.

## Viewing Options

<div class="view-options">
  <div class="view-option-card">
    <h3>Category View</h3>
    <p>Browse TTPs organized by security categories with detailed descriptions and guidance.</p>
    <span class="current-view">You are here</span>
  </div>
  
  <div class="view-option-card">
    <h3>Matrix View</h3>
    <p>Interactive matrix showing all techniques in a unified scrollable interface.</p>
    <a href="/ttps-view/" class="view-link">Open Matrix View →</a>
  </div>
</div>

## About This Framework

This TTP framework is designed to evolve into a comprehensive resource specifically for MCP security. It organizes security threats by category and provides actionable intelligence for defenders, developers, and security professionals.

## TTP Categories

<div class="ttp-categories">
  <div class="ttp-category">
    <div class="ttp-category-header">
      <h3>Prompt Injection & Manipulation</h3>
      <span class="ttp-count">7 techniques</span>
    </div>
    <p class="ttp-description">
      Techniques for manipulating AI behavior through malicious prompts and instructions
    </p>
    <a href="/ttps/prompt-injection/" class="ttp-link">Explore Techniques →</a>
  </div>

  <div class="ttp-category">
    <div class="ttp-category-header">
      <h3>Tool Poisoning & Metadata Attacks</h3>
      <span class="ttp-count">8 techniques</span>
    </div>
    <p class="ttp-description">
      Methods for compromising MCP tools and manipulating their metadata
    </p>
    <a href="/ttps/tool-poisoning/" class="ttp-link">Explore Techniques →</a>
  </div>

  <div class="ttp-category">
    <div class="ttp-category-header">
      <h3>Data Exfiltration & Credential Theft</h3>
      <span class="ttp-count">6 techniques</span>
    </div>
    <p class="ttp-description">
      Unauthorized extraction of sensitive data and credentials from MCP systems
    </p>
    <a href="/ttps/data-exfiltration/" class="ttp-link">Explore Techniques →</a>
  </div>

  <div class="ttp-category">
    <div class="ttp-category-header">
      <h3>Command & Code Injection</h3>
      <span class="ttp-count">7 techniques</span>
    </div>
    <p class="ttp-description">
      Execution of arbitrary commands and code through MCP vulnerabilities
    </p>
    <a href="/ttps/command-injection/" class="ttp-link">Explore Techniques →</a>
  </div>

  <div class="ttp-category">
    <div class="ttp-category-header">
      <h3>Authentication & Authorization</h3>
      <span class="ttp-count">8 techniques</span>
    </div>
    <p class="ttp-description">
      Bypassing authentication and authorization controls in MCP systems
    </p>
    <a href="/ttps/authentication/" class="ttp-link">Explore Techniques →</a>
  </div>

  <div class="ttp-category">
    <div class="ttp-category-header">
      <h3>Supply Chain & Dependencies</h3>
      <span class="ttp-count">7 techniques</span>
    </div>
    <p class="ttp-description">
      Compromising MCP through malicious packages and dependency attacks
    </p>
    <a href="/ttps/supply-chain/" class="ttp-link">Explore Techniques →</a>
  </div>

  <div class="ttp-category">
    <div class="ttp-category-header">
      <h3>Context Manipulation</h3>
      <span class="ttp-count">5 techniques</span>
    </div>
    <p class="ttp-description">
      Manipulating context data to influence AI behavior and decision-making
    </p>
    <a href="/ttps/context-manipulation/" class="ttp-link">Explore Techniques →</a>
  </div>

  <div class="ttp-category">
    <div class="ttp-category-header">
      <h3>Protocol Vulnerabilities</h3>
      <span class="ttp-count">5 techniques</span>
    </div>
    <p class="ttp-description">
      Exploiting flaws in MCP protocol implementation and communication
    </p>
    <a href="/ttps/protocol-vulnerabilities/" class="ttp-link">Explore Techniques →</a>
  </div>

  <div class="ttp-category">
    <div class="ttp-category-header">
      <h3>Privilege & Access Control</h3>
      <span class="ttp-count">6 techniques</span>
    </div>
    <p class="ttp-description">
      Escalating privileges and bypassing access controls in MCP deployments
    </p>
    <a href="/ttps/privilege-access-control/" class="ttp-link">Explore Techniques →</a>
  </div>

  <div class="ttp-category">
    <div class="ttp-category-header">
      <h3>Economic & Infrastructure Abuse</h3>
      <span class="ttp-count">3 techniques</span>
    </div>
    <p class="ttp-description">
      Abusing MCP systems for economic damage and infrastructure disruption
    </p>
    <a href="/ttps/economic-infrastructure-abuse/" class="ttp-link">Explore Techniques →</a>
  </div>

  <div class="ttp-category">
    <div class="ttp-category-header">
      <h3>Monitoring & Operational Security</h3>
      <span class="ttp-count">5 techniques</span>
    </div>
    <p class="ttp-description">
      Exploiting gaps in monitoring and operational security practices
    </p>
    <a href="/ttps/monitoring-operational-security/" class="ttp-link">Explore Techniques →</a>
  </div>

  <div class="ttp-category">
    <div class="ttp-category-header">
      <h3>AI-Specific Vulnerabilities</h3>
      <span class="ttp-count">4 techniques</span>
    </div>
    <p class="ttp-description">
      Vulnerabilities specific to AI reasoning and model behavior
    </p>
    <a href="/ttps/ai-specific-vulnerabilities/" class="ttp-link">Explore Techniques →</a>
  </div>
</div>

## How to Use This Framework

### For Security Teams
- **Threat Hunting**: Use TTPs to identify potential attack vectors in your environment
- **Risk Assessment**: Evaluate which TTPs are most relevant to your MCP deployment
- **Detection Rules**: Develop monitoring and alerting based on specific TTP indicators
- **Incident Response**: Reference TTPs during security incident investigation

### For Developers
- **Secure Development**: Understand attack techniques to build more secure MCP applications
- **Code Review**: Use TTPs as a checklist during security code reviews
- **Testing**: Validate security controls against known attack techniques
- **Threat Modeling**: Incorporate TTPs into application threat modeling exercises

### For Auditors
- **Security Assessment**: Evaluate MCP implementations against known attack techniques
- **Compliance Testing**: Verify security controls address relevant TTPs
- **Penetration Testing**: Use TTPs to guide security testing activities
- **Risk Evaluation**: Assess organizational exposure to specific attack techniques

## TTP Structure

Each TTP entry includes:

- **Description**: Clear explanation of the attack technique
- **Impact**: Potential consequences of successful exploitation
- **Detection Methods**: Ways to identify the technique being used
- **Mitigation Strategies**: Defensive measures and countermeasures
- **Real-World Examples**: Documented cases and demonstrations
- **Sources & References**: Research and industry reports

## Contributing to the TTP Framework

### How to Contribute
- **[GitHub Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Suggest new TTPs or improvements
- **Research Contributions** - Share findings from security research
- **Field Experience** - Document real-world attack observations
- **Detection Methods** - Contribute monitoring and detection approaches

### Community Development
This framework is community-driven and evolves based on:
- **Emerging Threats**: New attack techniques and vulnerabilities
- **Research Findings**: Academic and industry security research
- **Field Experience**: Real-world incident reports and observations
- **Technology Evolution**: Changes in MCP specifications and implementations

## Related Resources

### Implementation Guidance
- **[Top 10 Security Risks](/top10/)** - Prioritized list of critical MCP security risks
- **[Hardening Guide](/hardening/)** - Comprehensive security implementation framework
- **[Audit Tools](/audit/)** - Security assessment tools and procedures

### Community Resources
- **[Vulnerability Database](/vulnerability-db/)** - Known security issues and CVEs
- **[Security Tools](/tools/)** - Defensive tools and automation
- **[Community Guidelines](/community/)** - How to contribute to MCP security

---

*This TTP framework represents the collective knowledge of the MCP security community and is continuously updated based on emerging threats and research findings.*

<style>
.ttp-categories {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
  gap: 1.5rem;
  margin: 2rem 0;
}

.ttp-category {
  background-color: white;
  border: 1px solid #e1e4e8;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  transition: transform 0.2s, box-shadow 0.2s;
}

.ttp-category:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
}

.ttp-category-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}

.ttp-category-header h3 {
  color: #1f4e79;
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0;
}

.ttp-count {
  background-color: #f8f9fa;
  color: #6c757d;
  padding: 0.25rem 0.5rem;
  border-radius: 12px;
  font-size: 0.8rem;
  font-weight: 500;
}

.ttp-description {
  color: #333333;
  margin-bottom: 1rem;
  line-height: 1.5;
  font-size: 0.95rem;
}

.ttp-link {
  color: #0066cc;
  text-decoration: none;
  font-weight: 500;
  font-size: 0.9rem;
}

.ttp-link:hover {
  color: #1f4e79;
  text-decoration: underline;
}

@media (max-width: 768px) {
  .ttp-categories {
    grid-template-columns: 1fr;
  }
}
</style>
