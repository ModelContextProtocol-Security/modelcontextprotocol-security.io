# Model Context Protocol Security

**Website: [modelcontextprotocol-security.io](https://modelcontextprotocol-security.io)**

A comprehensive security resource for Model Context Protocol (MCP) deployments, providing hardening guidance, operational best practices, and security tools for organizations using MCP servers and AI agents.

## About This Project

This is a **Cloud Security Alliance (CSA) Community Project** focused exclusively on the security aspects of Model Context Protocol implementations. While the main [modelcontextprotocol.io](https://modelcontextprotocol.io) site provides technical documentation and implementation guidance, this security-focused companion site addresses the critical security challenges that arise when deploying MCP in production environments.

### Key Distinctions

| **Main MCP Site** | **MCP Security Site** |
|-------------------|------------------------|
| Technical documentation & specs | Security hardening & risk management |
| Developers & implementers | Security teams & enterprise adopters |
| Getting started & tutorials | Production deployment security |
| Anthropic & MCP community | Cloud Security Alliance community |

## What's Included

### **Security Guidance**
- **[Why MCP Security?](/why/)** - Executive briefings on MCP security risks and business value
- **[Hardening Guide](/hardening/)** - 10-part comprehensive security framework
- **[Operations Guide](/operations/)** - Production deployment best practices
- **[Reference Patterns](/patterns/)** - Proven secure architecture templates

### **Threat Intelligence & Assessment**
- **[Security TTPs](/ttps/)** - Comprehensive database of MCP security tactics, techniques, and procedures
- **[TTP Matrix View](/ttps-view/)** - Interactive matrix interface for browsing all security techniques
- **[Known Vulnerabilities](/known-vulnerabilities/)** - CVE database and security advisories
- **[Audit Tools](/audit/)** - Security assessment utilities and procedures

### **Community Projects & Tools**
- **[Community Projects](/projects/)** - Open-source MCP security tool ecosystem
- **[Tools & Scripts](/tools/)** - Security automation and monitoring utilities

### **Community Resources**
- **[GitHub Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Security discussions and Q&A
- **[Working Group Meetings](/events/)** - Bi-weekly technical sessions
- **[Community Guidelines](/community/)** - How to contribute and collaborate

## MCP Security Ecosystem

This documentation hub is part of a comprehensive security ecosystem:

### **Documentation & Website**
- **[modelcontextprotocol-security.io](https://github.com/ModelContextProtocol-Security/modelcontextprotocol-security.io)** - This website and documentation hub

### **Security Tools**
- **[mcpserver-audit](https://github.com/ModelContextProtocol-Security/mcpserver-audit)** - MCP Security Expert for risk assessment and security evaluation
- **[mcpserver-finder](https://github.com/ModelContextProtocol-Security/mcpserver-finder)** - MCP Discovery Expert for finding and evaluating servers
- **[mcpserver-builder](https://github.com/ModelContextProtocol-Security/mcpserver-builder)** - MCP Development Expert for secure server development
- **[mcpserver-operator](https://github.com/ModelContextProtocol-Security/mcpserver-operator)** - MCP Operations Expert for secure deployment

### **Community Databases**
- **[vulnerability-db](https://github.com/ModelContextProtocol-Security/vulnerability-db)** - Comprehensive vulnerability database with CVE tracking
- **[audit-db](https://github.com/ModelContextProtocol-Security/audit-db)** - Community audit results and security assessments

*All projects are actively maintained and available under open-source licenses.*

## Why MCP Security Matters

Model Context Protocol enables AI agents to interact with external systems, APIs, and data sources. This powerful capability introduces significant security challenges:

- **Privilege Escalation**: AI agents may gain unintended access to sensitive systems
- **Data Exposure**: Sensitive information can be compromised through inadequate controls
- **Supply Chain Risks**: Third-party MCP servers may introduce vulnerabilities
- **Operational Security**: Production deployments require robust security measures

Recent security research has highlighted critical vulnerabilities in MCP tools, making security guidance essential for safe production deployment.

## Getting Started

### **For Security Teams**
1. **Understand the Risks**: Start with [Why MCP Security?](https://modelcontextprotocol-security.io/why/)
2. **Assess Current Deployments**: Use [MCP Security Expert](https://github.com/ModelContextProtocol-Security/mcpserver-audit) for risk assessment
3. **Review Threat Landscape**: Explore the [TTP Matrix View](https://modelcontextprotocol-security.io/ttps-view/)
4. **Check Vulnerabilities**: Review [Known Vulnerabilities](https://modelcontextprotocol-security.io/known-vulnerabilities/)

### **For Developers**
1. **Secure Development**: Use [MCP Development Expert](https://github.com/ModelContextProtocol-Security/mcpserver-builder)
2. **Follow Best Practices**: Implement controls from our [Hardening Guide](https://modelcontextprotocol-security.io/hardening/)
3. **Use Reference Patterns**: Deploy proven architectures from [Reference Patterns](https://modelcontextprotocol-security.io/patterns/)

### **For Operations Teams**
1. **Secure Deployment**: Use [MCP Operations Expert](https://github.com/ModelContextProtocol-Security/mcpserver-operator)
2. **Operational Security**: Follow our [Operations Guide](https://modelcontextprotocol-security.io/operations/)
3. **Find Secure Servers**: Discover vetted servers with [MCP Discovery Expert](https://github.com/ModelContextProtocol-Security/mcpserver-finder)

## Contributing

We welcome contributions from security professionals, developers, and organizations using MCP:

### Ways to Contribute
- **Join Discussions**: Share experiences in [GitHub Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)
- **Improve Documentation**: Enhance security guides with real-world examples
- **Develop Security Tools**: Contribute to our [open-source tool ecosystem](https://modelcontextprotocol-security.io/projects/)
- **Report Vulnerabilities**: Submit findings to our [vulnerability database](https://github.com/ModelContextProtocol-Security/vulnerability-db)
- **Share Audit Results**: Contribute to the [community audit database](https://github.com/ModelContextProtocol-Security/audit-db)
- **Expand TTPs**: Help document new attack techniques and defenses

### Getting Help
- **Questions**: Use [GitHub Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)
- **Issues**: Report problems via [GitHub Issues](https://github.com/ModelContextProtocol-Security/modelcontextprotocol-security.io/issues)
- **Working Group**: Join our bi-weekly meetings (check [Events](https://modelcontextprotocol-security.io/events/))

## Local Development

This site is built with Jekyll and can be run locally:

```bash
# Navigate to the docs directory
cd docs/

# Run setup (installs dependencies)
./setup.sh

# Start development server
./serve.sh

# Visit http://localhost:4000
```

See [docs/README.md](docs/README.md) for detailed development instructions.

## License

This documentation website is released under CC0-1.0 (Creative Commons). Individual tools in the MCP Security ecosystem use Apache-2.0 licenses. See individual repository README files for specific licensing details.

## Sponsorship

This project is sponsored by the **[Cloud Security Alliance (CSA)](https://cloudsecurityalliance.org)** and maintained by the **Model Context Protocol Security Working Group**.

---

**Start securing your MCP deployment today at [modelcontextprotocol-security.io](https://modelcontextprotocol-security.io)**
