# Pillar 1: Provenance & Selection

This pillar focuses on verifying the origin and integrity of MCP servers before deployment. Proper provenance tracking prevents supply chain attacks and ensures you're deploying trusted code.

## Key Practices

- Prefer official or actively maintained repositories
- Fork and clone repositories before use to ensure availability
- Record repository URL and commit hash in deployment manifests
- Verify signed commits and attestations where available
- Assess maintainer activity and community health

## Implementation Guide

This section will provide detailed steps for:
- Evaluating MCP server repositories
- Setting up repository forking workflows
- Implementing commit signature verification
- Creating provenance tracking systems
- Establishing vendor assessment criteria

## Risk Mitigation

Addresses threats including abandoned repositories, repository hijacking, and malicious code injection through compromised maintainer accounts.
