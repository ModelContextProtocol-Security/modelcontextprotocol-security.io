# Model Context Protocol Security

**A Cloud Security Alliance Community Project**

Secure Autonomy: Hardening Model-Context-Protocol Servers & Agents

This comprehensive resource provides security guidance, best practices, and tools for safely deploying Model Context Protocol (MCP) servers and AI agents. MCP has become the de-facto adapter layer that lets autonomous agents interact with APIs, services, and systems - but this power comes with significant security responsibilities.

## Community Hub

**[Join the Discussion](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Our primary community forum for MCP security discussions, questions, and collaboration

## Quick Start

**New to MCP Security?** Start with our [Why MCP Security?](why/) overview  
**Ready to Secure?** Jump to the [Hardening Guide](hardening/)  
**Operating MCP Servers?** Check our [Operations Guide](operations/)  
**Need to Audit?** Use our [MCP Audit Tools](audit/)  
**Want to Contribute?** Share your knowledge in our [Community](community/)

## Site Navigation

### [Why MCP Security?](why/)
- [Overview](why/index.md) - Executive brief on MCP security risks and value proposition
- [FAQ](why/faq.md) - Frequently asked questions about MCP security

### [Hardening Guide](hardening/)
- [Overview](hardening/index.md) - Introduction to our comprehensive security framework
- [Provenance & Selection](hardening/provenance-selection.md) - Verifying and tracking MCP server origins
- [Code Integrity & Auditing](hardening/code-integrity-auditing.md) - Auditing and validating MCP code
- [Runtime Isolation](hardening/runtime-isolation.md) - Containerization and sandboxing
- [Traffic Mediation](hardening/traffic-mediation.md) - API gateways and network controls
- [Secrets & Credential Management](hardening/secrets-management.md) - Secure credential handling
- [Observability & Logging](hardening/observability-logging.md) - Monitoring and incident response
- [Backup & Versioning](hardening/backup-versioning.md) - Data protection and recovery
- [Policy & Guardrails](hardening/policy-guardrails.md) - Automated policy enforcement
- [Payments & Wallet Security](hardening/payments-wallets.md) - Financial security for AI agents
- [Lifecycle Management](hardening/lifecycle-management.md) - Updates and retirement strategies
- [Security Checklist](hardening/checklist.md) - Printable security assessment checklist

### [Operations Guide](operations/)
- [Overview](operations/index.md) - Securely operating MCP servers in production
- [Container Operations](operations/container-operations.md) - Dockerizing and containerizing MCP servers
- [Remote Deployment](operations/remote-deployment.md) - Secure remote infrastructure deployment
- [Network Controls](operations/network-controls.md) - iptables, network redirection, and traffic control
- [API Gateway Operations](operations/api-gateway-operations.md) - Operating API gateways for traffic mediation
- [Traffic Redirection](operations/traffic-redirection.md) - Wrapping code to redirect network traffic
- [TLS & Proxy Management](operations/tls-proxy-management.md) - Managing TLS traffic and API proxies
- [Security Monitoring & Alerting](operations/monitoring-alerting.md) - Production monitoring and alerting
- [Incident Response](operations/incident-response.md) - MCP-specific incident response procedures
- [Operational Maintenance](operations/operational-maintenance.md) - Regular security maintenance tasks
- [Security Operations Workflows](operations/security-workflows.md) - Standardized operational procedures
- [Performance & Security Optimization](operations/performance-security.md) - Balancing security and performance
- [Change Management](operations/change-management.md) - Security-focused change management
- [Security Troubleshooting](operations/security-troubleshooting.md) - Diagnosing security issues
- [Forensics & Investigation](operations/forensics-investigation.md) - Security incident investigation
- [Operational Runbooks](operations/operational-runbooks.md) - Step-by-step operational procedures

### [Reference Patterns](patterns/)
- [Overview](patterns/index.md) - Architecture patterns and deployment guides
- [Local Dev Container](patterns/local-dev-container.md) - Secure development environment setup
- [LLM Heaven VPS](patterns/llm-heaven-vps.md) - Isolated cloud deployment pattern
- [Enterprise Gateway](patterns/enterprise-gateway.md) - Corporate-grade MCP security architecture

### [Tools & Scripts](tools/)
- [Overview](tools/index.md) - Security tools and automation scripts

### [Vulnerability Database](vulnerability-db/)
- [Overview](vulnerability-db/index.md) - Security vulnerabilities and community-maintained advisory database

### [Audit an MCP](audit/)
- [Overview](audit/index.md) - How to audit MCP server security
- [Selection Scorecard](audit/scorecard.md) - Interactive MCP evaluation criteria
- [Step-by-Step Guide](audit/step-by-step-guide.md) - Manual security audit process
- [MCP Inspector](audit/mcp-inspector.md) - Automated security scanning tool (Coming Soon)

### [Blog](blog/)
- [Latest Posts](blog/index.md) - Security insights and community updates

### [Events](events/)
- [Upcoming Events](events/index.md) - Workshops, webinars, and working group meetings

### [Community](community/)
- [Getting Started](community/index.md) - How to contribute and get involved
- [Code of Conduct](community/code-of-conduct.md) - Community behavior guidelines
- [Project Charter](community/charter.md) - Governance and decision-making process

## Community Resources & Contributing

### Discussion & Collaboration
- **[GitHub Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Ask questions, share insights, propose improvements
- **[Main Organization](https://github.com/ModelContextProtocol-Security)** - All project repositories and resources
- **Working Group Meetings** - Bi-weekly technical discussions and planning sessions

### Community Databases
- **[Audit Database](https://github.com/ModelContextProtocol-Security/audit-db)** - Community-maintained MCP security audit results
- **[Vulnerability Database](https://github.com/ModelContextProtocol-Security/vulnerability-db)** - Known security issues and CVEs

### Development & Tools
- **[Security Tools](https://github.com/ModelContextProtocol-Security/security-tools)** - Open-source security utilities and scripts
- **[Documentation Site](https://github.com/ModelContextProtocol-Security/modelcontextprotocol-security.io)** - This website's source code

### Knowledge Contributions
We welcome and encourage contributions to our collective knowledge base:
- **Document Security Patterns** - Share your deployment architectures and lessons learned
- **Contribute Audit Findings** - Help build the community security database
- **Improve Hardening Guides** - Add practical examples and real-world scenarios
- **Share Operations Experience** - Document operational security procedures and technical setups
- **Create Educational Content** - Write blog posts, tutorials, and case studies
- **Develop Security Tools** - Build and share automation scripts and utilities

### How to Contribute
1. **Start a Discussion** - Share your ideas and questions in our [GitHub Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)
2. **Join Working Group** - Participate in our bi-weekly meetings and planning sessions
3. **Submit Documentation** - Improve guides, add examples, or create new content
4. **Share Audit Results** - Contribute to our security databases and findings
5. **Share Technical Operations** - Document your containerization, network controls, and proxy setups
6. **Build Tools** - Develop utilities that help the community secure MCP deployments

*Every contribution, whether large or small, helps strengthen the security of AI agent infrastructure for everyone.*

---

*This project is sponsored by the [Cloud Security Alliance](https://cloudsecurityalliance.org) and maintained by the Blockchain Working Group.*
