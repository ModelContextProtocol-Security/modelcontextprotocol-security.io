---
title: "Selection Scorecard"
parent: "Audit Tools"
nav_order: 2
---

# MCP Selection Scorecard

This interactive evaluation framework helps you assess the security posture of Model Context Protocol servers before deployment. The scorecard criteria are based on industry best practices and community-validated security indicators.

## Using the Scorecard

The scorecard evaluates MCP servers across multiple security dimensions. For pre-computed scores and detailed audit results, check our [audit database](https://github.com/ModelContextProtocol-Security/audit-db).

## Evaluation Criteria

### Repository Health (25%)
- **Maintenance Activity**: Recent commits, issue response times
- **Code Quality**: Test coverage, documentation completeness
- **Security Practices**: Signed commits, dependency management
- **Community Trust**: Contributor count, star ratings, fork activity

### Security Implementation (35%)
- **Input Validation**: Proper sanitization and error handling
- **Access Control**: Minimal permissions, credential management
- **Logging & Monitoring**: Audit trails, security event tracking
- **Dependency Security**: Vulnerability scanning, supply chain integrity

### Operational Security (25%)
- **Deployment Patterns**: Containerization, isolation capabilities
- **Configuration Security**: Secure defaults, hardening guidance
- **Update Mechanisms**: Controlled updates, rollback capabilities
- **Documentation**: Security guides, incident response procedures

### Community & Governance (15%)
- **Maintainer Reputation**: Track record, organizational backing
- **Issue Resolution**: Security bug handling, disclosure practices
- **License Compliance**: Open source licensing, legal clarity
- **Longevity Indicators**: Project roadmap, sustainability metrics

## Scoring Guide

Each criterion is scored on a scale of 0-4:
- **4 - Excellent**: Exceeds security best practices
- **3 - Good**: Meets most security requirements
- **2 - Adequate**: Basic security measures in place
- **1 - Poor**: Significant security gaps identified
- **0 - Critical**: Major security vulnerabilities present

## Automated Scoring

Our upcoming MCP Inspector tool will automatically generate scorecard ratings and submit results to the audit database. Manual assessments can be contributed using our [step-by-step guide](step-by-step-guide.md).

## Community Scores

Visit the [audit database](https://github.com/ModelContextProtocol-Security/audit-db) to view:
- Pre-computed scorecards for popular MCP servers
- Community-contributed audit results
- Historical security trend analysis
- Comparative security rankings

*Help improve our scoring methodology by contributing feedback and audit results to the community database.*
