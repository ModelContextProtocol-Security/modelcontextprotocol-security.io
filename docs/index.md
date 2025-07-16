---
layout: home
title: "Model Context Protocol Security"
description: "A Cloud Security Alliance Community Project - Secure Autonomy: Hardening Model-Context-Protocol Servers & Agents"
nav_order: 1
---

{: .hero-description }
This comprehensive resource provides security guidance, best practices, and tools for safely deploying Model Context Protocol (MCP) servers and AI agents. MCP has become the de-facto adapter layer that lets autonomous agents interact with APIs, services, and systems - but this power comes with significant security responsibilities.

---

## Quick Start
{: .quick-start-title }

<div class="quick-start">
  <div class="quick-start-item">
    <strong>New to MCP Security?</strong> Start with our <a href="/why/">Why MCP Security?</a> overview
  </div>
  <div class="quick-start-item">
    <strong>Critical Risks?</strong> Review the <a href="/top10/">MCP Top 10 Security Risks</a>
  </div>
  <div class="quick-start-item">
    <strong>Ready to Secure?</strong> Jump to the <a href="/hardening/">Hardening Guide</a>
  </div>
  <div class="quick-start-item">
    <strong>Operating MCP Servers?</strong> Check our <a href="/operations/">Operations Guide</a>
  </div>
  <div class="quick-start-item">
    <strong>Need to Audit?</strong> Use our <a href="/audit/">MCP Audit Tools</a>
  </div>
  <div class="quick-start-item">
    <strong>Want to Contribute?</strong> Share your knowledge in our <a href="/community/">Community</a>
  </div>
</div>

---

## Security Guides

<div class="cards-container">
  <div class="card">
    <div class="card-title">🔍 Why MCP Security?</div>
    <div class="card-description">
      Executive brief on MCP security risks and value proposition. Perfect for decision-makers and security teams.
    </div>
    <a href="/why/" class="card-link">Learn More →</a>
  </div>

  <div class="card">
    <div class="card-title">⚠️ MCP Top 10 Security Risks</div>
    <div class="card-description">
      Comprehensive Top 10 lists covering the most critical security risks in both MCP server and client implementations.
    </div>
    <a href="/top10/" class="card-link">Review Risks →</a>
  </div>

  <div class="card">
    <div class="card-title">🎯 Security TTPs</div>
    <div class="card-description">
      Comprehensive database of MCP security tactics, techniques, and procedures for defenders and developers.
    </div>
    <a href="/ttps/" class="card-link">Explore TTPs →</a>
  </div>

  <div class="card">
    <div class="card-title">🚨 Known Vulnerabilities</div>
    <div class="card-description">
      Documented security vulnerabilities in MCP implementations, including CVEs, security advisories, and incident reports.
    </div>
    <a href="/known-vulnerabilities/" class="card-link">View Vulnerabilities →</a>
  </div>

  <div class="card">
    <div class="card-title">🛡️ Hardening Guide</div>
    <div class="card-description">
      Comprehensive security framework covering provenance, isolation, traffic mediation, and more.
    </div>
    <a href="/hardening/" class="card-link">Start Hardening →</a>
  </div>

  <div class="card">
    <div class="card-title">⚙️ Operations Guide</div>
    <div class="card-description">
      Production-ready guidance for securely operating MCP servers with containers, network controls, and monitoring.
    </div>
    <a href="/operations/" class="card-link">View Operations →</a>
  </div>

  <div class="card">
    <div class="card-title">🏗️ Reference Patterns</div>
    <div class="card-description">
      Architecture patterns and deployment guides for common MCP security scenarios.
    </div>
    <a href="/patterns/" class="card-link">View Patterns →</a>
  </div>

  <div class="card">
    <div class="card-title">🔎 Audit Tools</div>
    <div class="card-description">
      Security evaluation tools, scorecards, and step-by-step audit procedures for MCP deployments.
    </div>
    <a href="/audit/" class="card-link">Start Auditing →</a>
  </div>

  <div class="card">
    <div class="card-title">🛠️ Tools & Scripts</div>
    <div class="card-description">
      Security automation tools, utilities, and scripts for MCP security operations.
    </div>
    <a href="/tools/" class="card-link">View Tools →</a>
  </div>
</div>

---

## Community Resources

### Discussion & Collaboration
- **[GitHub Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Ask questions, share insights, propose improvements
- **[Main Organization](https://github.com/ModelContextProtocol-Security)** - All project repositories and resources
- **Working Group Meetings** - Bi-weekly technical discussions and planning sessions

### Community Databases
- **[Audit Database](https://github.com/ModelContextProtocol-Security/audit-db)** - Community-maintained MCP security audit results
- **[Vulnerability Database](/vulnerability-db/)** - Known security issues and CVEs

### How to Contribute

We welcome contributions to strengthen AI agent infrastructure security:

1. **Start a Discussion** - Share ideas in our [GitHub Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)
2. **Join Working Group** - Participate in bi-weekly meetings
3. **Document Security Patterns** - Share deployment architectures and lessons learned
4. **Contribute Audit Findings** - Help build the community security database
5. **Improve Hardening Guides** - Add practical examples and real-world scenarios
6. **Develop Security Tools** - Build automation scripts and utilities

*Every contribution helps strengthen the security of AI agent infrastructure for everyone.*

---

<div class="footer-csa">
  <p><em>This project is sponsored by the <a href="https://cloudsecurityalliance.org">Cloud Security Alliance</a> and maintained by the Model Context Protocol Security Working Group.</em></p>
</div>

<style>
.cards-container {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 1.5rem;
  margin: 2rem 0;
}

.card {
  background-color: white;
  border: 1px solid #e1e4e8;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  transition: transform 0.2s, box-shadow 0.2s;
}

.card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
}

.card-title {
  color: #1f4e79;
  font-size: 1.25rem;
  font-weight: 600;
  margin-bottom: 0.75rem;
}

.card-description {
  color: #333333;
  margin-bottom: 1rem;
  line-height: 1.5;
}

.card-link {
  color: #0066cc;
  text-decoration: none;
  font-weight: 500;
}

.card-link:hover {
  color: #1f4e79;
  text-decoration: underline;
}

.quick-start {
  background-color: #f8f9fa;
  padding: 2rem;
  border-radius: 8px;
  margin: 2rem 0;
}

.quick-start-title {
  color: #1f4e79;
  font-size: 1.5rem;
  font-weight: 600;
  margin-bottom: 1rem;
}

.quick-start-item {
  margin-bottom: 0.75rem;
  padding: 0.5rem 0;
}

.quick-start-item strong {
  color: #1f4e79;
}

.footer-csa {
  text-align: center;
  margin-top: 3rem;
  padding: 2rem;
  background-color: #f8f9fa;
  border-radius: 8px;
}

.footer-csa a {
  color: #1f4e79;
  text-decoration: none;
  font-weight: 500;
}

.footer-csa a:hover {
  color: #0066cc;
  text-decoration: underline;
}

@media (max-width: 768px) {
  .cards-container {
    grid-template-columns: 1fr;
  }
  
  .quick-start {
    padding: 1.5rem;
  }
}
</style>
