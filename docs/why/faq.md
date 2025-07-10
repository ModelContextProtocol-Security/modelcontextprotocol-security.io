---
title: "FAQ"
parent: "Why MCP Security?"
nav_order: 2
---

# Frequently Asked Questions

## General Questions

### What is MCP Security?
MCP Security is a Cloud Security Alliance community project focused on providing security guidance, best practices, and tools for safely deploying Model Context Protocol (MCP) servers and AI agents.

### Who should use this guidance?
- **Security Teams** implementing AI agent infrastructure
- **DevOps Engineers** deploying MCP servers
- **Developers** building secure AI applications
- **IT Managers** overseeing AI implementations
- **Compliance Officers** ensuring regulatory adherence

### Is this project affiliated with the official MCP project?
No, this is an independent community project sponsored by the Cloud Security Alliance. We provide security-focused guidance complementary to the official MCP documentation.

## Technical Questions

### What security risks does MCP introduce?
MCP servers can introduce several security risks:
- **Privilege escalation** through overly permissive configurations
- **Data exposure** via insufficient access controls
- **Supply chain risks** from untrusted MCP servers
- **Operational risks** from inadequate monitoring

### Do I need to implement all hardening measures?
Our [Hardening Guide](../hardening/) provides a comprehensive framework, but you should implement controls based on your specific risk profile and requirements. Use our [Security Checklist](../hardening/checklist.md) to assess your needs.

### Can I use these practices with any MCP server?
Yes, our guidance is designed to be implementation-agnostic. The security principles apply regardless of the specific MCP server technology you're using.

## Implementation Questions

### How do I get started?
1. **Read** our [Why MCP Security?](index.md) overview
2. **Assess** your current deployment risk
3. **Follow** our [Hardening Guide](../hardening/)
4. **Implement** appropriate [Reference Patterns](../patterns/)
5. **Monitor** using our [Operations Guide](../operations/)

### What if I'm already running MCP servers in production?
Start with our [Audit Tools](../audit/) to assess your current security posture, then prioritize improvements based on your risk assessment.

### How often should I audit my MCP deployment?
We recommend:
- **Monthly** automated security scans
- **Quarterly** comprehensive audits
- **Annual** full security assessments
- **Immediate** audits after any significant changes

## Community Questions

### How can I contribute?
- **Share experiences** in [GitHub Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)
- **Contribute documentation** via pull requests
- **Report vulnerabilities** to our [Vulnerability Database](../vulnerability-db/)
- **Join working group meetings** - see [Events](../events/)

### How do I report a security vulnerability?
Please report security vulnerabilities through our [responsible disclosure process](../community/security-reporting.md).

### Is there commercial support available?
This is a community project with volunteer support. For commercial support, consult with security firms familiar with AI infrastructure.

## Questions Not Answered Here?

Join our [GitHub Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions) or check our [Community Guidelines](../community/) for more ways to get help.
