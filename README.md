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

### **Security Tools & Resources**
- **[Audit Tools](/audit/)** - Security assessment utilities and procedures
- **[Tools & Scripts](/tools/)** - Security automation and monitoring utilities
- **[Vulnerability Database](/vulnerability-db/)** - Community-maintained security advisories

### **Community Resources**
- **[GitHub Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Security discussions and Q&A
- **[Working Group Meetings](/events/)** - Bi-weekly technical sessions
- **[Community Guidelines](/community/)** - How to contribute and collaborate

## Related Repositories

This project is part of the larger MCP Security ecosystem:

- **[vulnerability-db](https://github.com/ModelContextProtocol-Security/vulnerability-db)** - Community-maintained database of MCP security vulnerabilities and advisories
- **[audit-db](https://github.com/ModelContextProtocol-Security/audit-db)** - Community-maintained database of MCP security audit results and findings

## Why MCP Security Matters

Model Context Protocol enables AI agents to interact with external systems, APIs, and data sources. This powerful capability introduces significant security challenges:

- **Privilege Escalation**: AI agents may gain unintended access to sensitive systems
- **Data Exposure**: Sensitive information can be compromised through inadequate controls
- **Supply Chain Risks**: Third-party MCP servers may introduce vulnerabilities
- **Operational Security**: Production deployments require robust security measures

Recent security research has highlighted critical vulnerabilities in MCP tools, making security guidance essential for safe production deployment.

## Getting Started

1. **Read the Overview**: Start with [Why MCP Security?](https://modelcontextprotocol-security.io/why/)
2. **Follow the Hardening Guide**: Implement security controls with our [Hardening Guide](https://modelcontextprotocol-security.io/hardening/)
3. **Use Reference Patterns**: Deploy proven architectures from our [Reference Patterns](https://modelcontextprotocol-security.io/patterns/)
4. **Audit Your Deployment**: Assess security posture with our [Audit Tools](https://modelcontextprotocol-security.io/audit/)

## Contributing

We welcome contributions from security professionals, developers, and organizations using MCP:

### Ways to Contribute
- **Join Discussions**: Share experiences in [GitHub Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)
- **Improve Documentation**: Enhance security guides with real-world examples
- **Contribute Tools**: Develop security automation and monitoring utilities
- **Report Vulnerabilities**: Help identify and address security issues
- **Share Audit Results**: Contribute to the community audit database

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

This project is open source and available under the same terms as the broader MCP Security project.

## Sponsorship

This project is sponsored by the **[Cloud Security Alliance (CSA)](https://cloudsecurityalliance.org)** and maintained by the **Model Context Protocol Security Working Group**.

---

**Start securing your MCP deployment today at [modelcontextprotocol-security.io](https://modelcontextprotocol-security.io)**
