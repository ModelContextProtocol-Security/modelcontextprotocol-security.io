---
title: "Hardening Guide"
nav_order: 4
has_children: true
---

# Hardening Guide

This comprehensive guide provides detailed security guidance for Model Context Protocol (MCP) servers and AI agent infrastructure. Our security framework covers all aspects of MCP security, from initial server selection through ongoing operational security, organized in a logical narrative that builds from foundational concepts to advanced implementations.

## Community Discussion

**[Join the Hardening Discussion](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Share your hardening experiences, ask questions about implementation, and collaborate with other security professionals on MCP security best practices.

## Security Framework

Our security framework is organized as a logical progression that builds from foundational security concepts to advanced operational practices:

### Foundational Security
Start with the basics - understanding and verifying what you're deploying:

**[Provenance & Selection](provenance-selection.md)** - Verifying and tracking MCP server origins and trustworthiness  
**[Code Integrity & Auditing](code-integrity-auditing.md)** - Validating MCP server code quality and security

### Deployment Security
Secure your MCP deployment architecture and communications:

**[Runtime Isolation](runtime-isolation.md)** - Containerization, sandboxing, and process isolation  
**[Traffic Mediation](traffic-mediation.md)** - API gateways, network controls, and traffic monitoring

### Operational Security
Manage ongoing security operations and data protection:

**[Secrets & Credential Management](secrets-management.md)** - Secure handling of API keys, tokens, and credentials  
**[Observability & Logging](observability-logging.md)** - Monitoring, alerting, and incident response  
**[Backup & Versioning](backup-versioning.md)** - Data protection, recovery, and configuration management

### Advanced Security
Implement sophisticated security controls and specialized features:

**[Policy & Guardrails](policy-guardrails.md)** - Automated policy enforcement and risk management  
**[Payments & Wallet Security](payments-wallets.md)** - Financial controls for AI agents with payment capabilities  
**[Lifecycle Management](lifecycle-management.md)** - Update strategies, maintenance, and retirement planning

## Quick Reference

### [Security Checklist](checklist.md)
Printable checklist covering all security areas for rapid security assessment and implementation tracking.

## Contributing to the Hardening Guide

### Share Your Experience
We encourage the community to contribute practical knowledge and real-world examples:

#### Implementation Examples
- **Configuration Samples** - Share working configurations and deployment scripts
- **Deployment Patterns** - Document successful hardening implementations
- **Lessons Learned** - Share what worked (and what didn't) in your environment
- **Case Studies** - Detailed analysis of security implementations and their outcomes

#### Improvement Suggestions
- **Gap Analysis** - Identify areas where our guidance could be more comprehensive
- **New Techniques** - Propose additional security measures and best practices
- **Tool Recommendations** - Suggest security tools and utilities that work well with MCP
- **Methodology Improvements** - Help us refine our approach based on field experience

### How to Contribute

1. **[Start a Discussion](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Share your ideas and experiences
2. **Provide Feedback** - Comment on existing documentation with suggestions
3. **Submit Examples** - Contribute real-world configuration samples and deployment guides
4. **Document Edge Cases** - Help us address complex or unusual security scenarios

## Getting Started with Hardening

### For Security Teams
1. **Assess Current State** - Use our [checklist](checklist.md) to evaluate existing MCP deployments
2. **Prioritize Areas** - Focus on the most critical security gaps in your environment
3. **Implement Gradually** - Start with foundational security and build up controls progressively
4. **Share Results** - Document your implementation experience for the community

### For Developers
1. **Understand the Risks** - Learn why each area matters for MCP security
2. **Integrate Early** - Build security into your MCP development process from the start
3. **Test Thoroughly** - Validate that your security controls work as expected
4. **Contribute Fixes** - Help improve security in open-source MCP servers

### For Organizations
1. **Develop Policy** - Create organizational standards based on our security framework
2. **Train Teams** - Educate developers and operators on MCP security best practices
3. **Measure Progress** - Track security improvements and compliance with recommendations
4. **Share Expertise** - Contribute enterprise-scale implementation guidance

## Community Support

### Getting Help
- **[GitHub Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Ask questions about implementation challenges
- **Working Group Meetings** - Participate in bi-weekly technical discussions
- **Peer Review** - Get feedback on your hardening plans and implementations

### Providing Help
- **Answer Questions** - Share your expertise with others facing similar challenges
- **Review Contributions** - Help validate and improve community-contributed content
- **Mentor Others** - Guide newcomers through their first MCP security implementations

## Framework Evolution

Our security framework is a living resource that evolves based on:
- **Community Feedback** - Suggestions and improvements from practitioners
- **Threat Evolution** - New attack vectors and security challenges
- **Technology Changes** - Updates to MCP specifications and implementations
- **Industry Best Practices** - Emerging security standards and methodologies

## Recognition

We recognize valuable contributions to the hardening guide:
- **Contributor Acknowledgment** - Featured recognition for significant improvements
- **Speaking Opportunities** - Present your hardening experience at conferences
- **Advisory Role** - Help shape the future direction of MCP security guidance

*The effectiveness of our hardening guide depends on real-world validation and community input. Join our discussions and help make MCP infrastructure more secure for everyone.*
