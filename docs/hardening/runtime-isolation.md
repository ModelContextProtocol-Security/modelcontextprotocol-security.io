---
title: "Runtime Isolation"
parent: "Hardening Guide"
nav_order: 3
---

# Runtime Isolation

This section establishes secure execution environments for MCP servers using containerization, virtualization, and system-level isolation techniques to limit the impact of compromised or malicious code.

## Key Practices

- Default to Docker containers or lightweight VMs for MCP execution
- Use dedicated VPS environments for high-risk workloads
- Implement capability dropping and seccomp profiles
- Apply principle of least privilege to file system access
- Isolate network communications and restrict outbound connections

## Implementation Guide

This section will cover:
- Docker security best practices for MCP containers
- VPS and VM isolation configurations
- Linux security modules (AppArmor, SELinux) setup
- Network isolation and firewall rules
- Resource limits and monitoring

## Risk Mitigation

Addresses threats including system compromise, lateral movement, privilege escalation, and resource exhaustion attacks that could impact the host system or other workloads.
