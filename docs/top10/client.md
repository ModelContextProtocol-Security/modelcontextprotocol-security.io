---
layout: default
title: "MCP Client Top 10 Security Risks"
permalink: /top10/client/
nav_order: 2
parent: "MCP Top 10 Security Risks"
---

# MCP Client Top 10 Security Risks

While MCP servers provide the backend functionality, MCP clients (such as Claude Desktop, Cursor, VS Code with MCP extensions, and other AI applications) represent the critical human interface to the MCP ecosystem. Clients handle user interactions, manage server connections, and serve as the trust boundary between users and the broader MCP infrastructure.

Client-side security risks are particularly important because compromised clients can undermine the security of entire MCP deployments from the user's perspective. Unlike server-side risks that focus on backend security, client risks center on user interaction, local data protection, trust relationships, and the unique challenges of securing AI-integrated applications.

## The Top 10 MCP Client Security Risks

### MCP-C01: Malicious Server Connection
**Connecting to compromised or malicious MCP servers**

Malicious server connection occurs when clients connect to compromised or malicious MCP servers without proper validation. This includes fake servers, DNS poisoning, server impersonation, and connection hijacking. The distributed nature of MCP server deployment makes it easy for attackers to create malicious servers that appear legitimate to unsuspecting clients.

*Impact: Data theft, malicious code execution, credential compromise*

---

### MCP-C02: Insecure Credential Storage
**Improper storage of MCP server credentials on the client**

Insecure credential storage involves improper storage of MCP server credentials, API keys, and authentication tokens on the client system. This includes plaintext credentials, weak encryption, accessible credential files, and inadequate protection of sensitive authentication data. Client-side credential storage is particularly vulnerable to local attacks and system compromise.

*Impact: Credential theft, unauthorized server access, account takeover*

---

### MCP-C03: UI/UX Deception
**Misleading users about MCP server actions or permissions**

UI/UX deception involves misleading users about MCP server actions, permissions, or capabilities through the client interface. This includes hidden tool calls, misleading permission dialogs, unclear action descriptions, and interfaces that don't clearly communicate what actions are being performed. Users may unknowingly authorize dangerous operations.

*Impact: Unintended actions, data exposure, user manipulation*

---

### MCP-C04: Insufficient Server Validation
**Inadequate validation of MCP server authenticity and integrity**

Insufficient server validation occurs when clients fail to properly validate MCP server authenticity and integrity before establishing connections. This includes no certificate validation, missing server verification, weak trust models, and inadequate verification of server identity. Without proper validation, clients may connect to malicious servers.

*Impact: Connection to malicious servers, man-in-the-middle attacks*

---

### MCP-C05: Client-Side Data Leakage
**Sensitive data leaking through client logs, caches, or storage**

Client-side data leakage involves sensitive data leaking through client logs, caches, temporary files, or local storage mechanisms. This includes credentials in logs, cached sensitive responses, temporary file exposure, and inadequate cleanup of sensitive data. Client systems often store more data than users realize, creating multiple leakage vectors.

*Impact: Data breaches, credential exposure, privacy violations*

---

### MCP-C06: Excessive Permission Granting
**Clients granting excessive permissions to MCP servers**

Excessive permission granting occurs when clients grant more permissions to MCP servers than necessary for their intended function. This includes overprivileged server access, permission escalation, unnecessary scopes, and inadequate permission review processes. Users may grant broad permissions without understanding the implications.

*Impact: Increased attack surface, potential for greater damage*

---

### MCP-C07: Client-Side Code Execution
**Malicious responses from MCP servers executing code on the client**

Client-side code execution involves malicious responses from MCP servers that execute code on the client system. This includes script injection, code execution via responses, client-side attacks through crafted responses, and exploitation of client-side interpreters. Clients that process server responses unsafely are vulnerable to code execution attacks.

*Impact: Client compromise, malware installation, system takeover*

---

### MCP-C08: Insecure Communication Handling
**Poor implementation of secure communication protocols**

Insecure communication handling involves poor implementation of secure communication protocols between clients and servers. This includes weak TLS implementation, certificate bypass vulnerabilities, protocol downgrade attacks, and inadequate encryption of sensitive communications. Clients must properly implement secure communication to protect data in transit.

*Impact: Data interception, credential theft, communication tampering*

---

### MCP-C09: Session and State Management Failures
**Inadequate management of client sessions and application state**

Session and state management failures involve inadequate management of client sessions, authentication state, and application state. This includes session hijacking, state manipulation, authentication bypass, and inadequate session termination. Poor session management can lead to unauthorized access and privilege escalation.

*Impact: Unauthorized access, privilege escalation, data manipulation*

---

### MCP-C10: Update and Patch Management
**Insecure update mechanisms or delayed security patches**

Update and patch management issues involve insecure update mechanisms or delayed application of security patches. This includes unverified updates, delayed patches, insecure update channels, and inadequate update verification. Clients with poor update mechanisms remain vulnerable to known security issues.

*Impact: Persistent vulnerabilities, malware distribution, system compromise*

---

## Honourable Mentions

While not in the top 10, these additional client-side security concerns are important for comprehensive MCP client security:

### Local Storage Vulnerabilities
Sensitive data stored insecurely on client filesystem, including accessible configuration files and unencrypted local databases that can be accessed by other applications or users.

### Client-Side Prompt Injection
Malicious prompts manipulating client behavior and UI manipulation through crafted responses designed to trick users into performing unintended actions.

### Dependency Vulnerabilities
Vulnerable third-party libraries in client applications and supply chain attacks targeting client dependencies, particularly relevant for applications built with multiple open source components.

### Privacy and Data Handling
Inadequate user privacy protections and unauthorized data collection and transmission, including telemetry and usage data that may expose sensitive information.

### Cross-Platform Security Issues
Platform-specific vulnerabilities and inconsistent security implementations across different operating systems, creating security gaps in multi-platform deployments.

### Configuration Security
Insecure client configuration management, including exposed configuration files and weak default settings that leave clients vulnerable to attack.

### Network Security
Inadequate network security controls, including poor firewall integration and network-based attack vulnerabilities specific to client environments.

---

## Client vs Server Risk Differences

**Client risks focus on:**
- **User interaction** and deception through interfaces
- **Local data protection** and storage security
- **Trust relationships** with remote servers
- **UI/UX security** implications and user awareness
- **Client-side execution** environments and local attacks

**Server risks focus on:**
- **Service provision** and backend API security
- **Infrastructure** security and system hardening
- **Multi-tenancy** and isolation between users
- **Protocol implementation** and specification compliance
- **Backend system** integration and data processing

## Using This Guide

This Client Top 10 list serves as a foundation for understanding MCP client security risks. Each risk will be expanded into detailed guidance covering:

- **Detailed attack scenarios** and real-world examples
- **Technical implementation** of client-side attacks and defenses
- **Prevention strategies** and secure development practices
- **Detection and monitoring** approaches for client security
- **User education** and awareness strategies

Organizations should use this list to assess their MCP client implementations, train users on security best practices, and develop comprehensive security strategies for AI-integrated client applications.

---


