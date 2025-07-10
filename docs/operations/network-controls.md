---
title: "Network Controls"
parent: "Operations Guide"
nav_order: 2
---

# Network Controls

This guide provides comprehensive guidance for implementing network-level security controls for Model Context Protocol (MCP) servers using iptables, network namespaces, and traffic redirection techniques. These controls provide defense-in-depth security for MCP deployments.

## Community Discussion

💬 **[Network Controls Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Share your network security configurations, iptables rules, and network isolation strategies with the community.

## Network Security Challenges for MCP

### Unique MCP Network Characteristics
- **Multiple External Connections** - MCP servers connect to various external APIs and services
- **Dynamic Service Discovery** - AI agents may discover and connect to new services at runtime
- **Encrypted Traffic** - Most traffic is HTTPS, making content inspection challenging
- **High Connection Volume** - AI agents can make many concurrent API calls

### Network Security Objectives
- **Traffic Isolation** - Separate MCP traffic from other network traffic
- **Egress Control** - Control and monitor outbound connections
- **Traffic Redirection** - Route traffic through security controls
- **Network Segmentation** - Isolate MCP servers from other systems

## iptables Rules for MCP Security

### Basic Firewall Rules
```bash
#!/bin/bash
# Basic iptables rules for MCP server security

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow SSH (adjust port as needed)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT

# Allow MCP server to connect to API gateway
iptables -A OUTPUT -d 10.0.0.100 -p tcp --dport 8080 -j ACCEPT

# Allow API gateway to connect to external services
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "INPUT DROP: "
iptables -A OUTPUT -j LOG --log-prefix "OUTPUT DROP: "
```

### Traffic Redirection Rules
```bash
#!/bin/bash
# Redirect all HTTP/HTTPS traffic through API gateway

# Create custom chain for MCP traffic
iptables -t nat -N MCP_REDIRECT

# Redirect HTTP traffic to API gateway
iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080

# Redirect HTTPS traffic to API gateway (requires TLS termination)
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080

# Redirect specific destinations to API gateway
iptables -t nat -A OUTPUT -d api.external-service.com -p tcp --dport 443 -j REDIRECT --to-port 8080
```

### Port-Based Traffic Control
```bash
#!/bin/bash
# Control traffic by port and protocol

# Allow only specific outbound ports
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT   # HTTP
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT  # HTTPS
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT   # DNS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT   # DNS

# Block all other outbound traffic
iptables -A OUTPUT -j DROP

# Rate limit connections to prevent abuse
iptables -A OUTPUT -p tcp --dport 443 -m limit --limit 25/min --limit-burst 50 -j ACCEPT
```

## Network Namespaces for Isolation

### Create Isolated Network Namespace
```bash
#!/bin/bash
# Create isolated network namespace for MCP server

# Create namespace
ip netns add mcp-namespace

# Create veth pair
ip link add veth-mcp type veth peer name veth-host

# Move one end to namespace
ip link set veth-mcp netns mcp-namespace

# Configure host side
ip addr add 10.0.0.1/24 dev veth-host
ip link set veth-host up

# Configure namespace side
ip netns exec mcp-namespace ip addr add 10.0.0.2/24 dev veth-mcp
ip netns exec mcp-namespace ip link set veth-mcp up
ip netns exec mcp-namespace ip link set lo up

# Set up routing
ip netns exec mcp-namespace ip route add default via 10.0.0.1
```

### Network Namespace with API Gateway
```bash
#!/bin/bash
# Set up network namespace with API gateway routing

# Create namespace
ip netns add mcp-secure

# Create bridge for secure network
ip link add name mcp-bridge type bridge
ip link set mcp-bridge up
ip addr add 172.16.0.1/24 dev mcp-bridge

# Create veth pair for MCP server
ip link add mcp-veth type veth peer name mcp-veth-ns
ip link set mcp-veth-ns netns mcp-secure
ip link set mcp-veth master mcp-bridge
ip link set mcp-veth up

# Configure namespace network
ip netns exec mcp-secure ip addr add 172.16.0.10/24 dev mcp-veth-ns
ip netns exec mcp-secure ip link set mcp-veth-ns up
ip netns exec mcp-secure ip link set lo up
ip netns exec mcp-secure ip route add default via 172.16.0.1

# Set up NAT for outbound traffic through API gateway
iptables -t nat -A POSTROUTING -s 172.16.0.0/24 -j MASQUERADE
iptables -A FORWARD -i mcp-bridge -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o mcp-bridge -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

## Traffic Redirection Techniques

### Transparent Proxy with iptables
```bash
#!/bin/bash
# Set up transparent proxy for MCP traffic

# Create custom chain for transparent proxy
iptables -t nat -N TRANSPARENT_PROXY

# Exclude local traffic
iptables -t nat -A TRANSPARENT_PROXY -d 127.0.0.0/8 -j RETURN
iptables -t nat -A TRANSPARENT_PROXY -d 10.0.0.0/8 -j RETURN

# Redirect HTTP traffic to transparent proxy
iptables -t nat -A TRANSPARENT_PROXY -p tcp --dport 80 -j REDIRECT --to-port 8080

# Redirect HTTPS traffic to transparent proxy
iptables -t nat -A TRANSPARENT_PROXY -p tcp --dport 443 -j REDIRECT --to-port 8080

# Apply to OUTPUT chain
iptables -t nat -A OUTPUT -p tcp -j TRANSPARENT_PROXY
```

### User-Based Traffic Control
```bash
#!/bin/bash
# Control traffic based on user/group

# Create MCP user
useradd -r -s /bin/false mcp-user

# Allow MCP user to access API gateway only
iptables -A OUTPUT -m owner --uid-owner mcp-user -d 10.0.0.100 -p tcp --dport 8080 -j ACCEPT

# Block all other traffic from MCP user
iptables -A OUTPUT -m owner --uid-owner mcp-user -j DROP
```

## Container Network Controls

### Docker Network Security
```bash
#!/bin/bash
# Create secure Docker network for MCP

# Create custom bridge network
docker network create \
  --driver bridge \
  --subnet=172.20.0.0/16 \
  --ip-range=172.20.240.0/20 \
  --gateway=172.20.0.1 \
  --opt com.docker.network.bridge.name=mcp-bridge \
  mcp-secure-network

# Run MCP server in secure network
docker run -d \
  --name mcp-server \
  --network mcp-secure-network \
  --ip 172.20.240.10 \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  mcp-server:latest
```

### Container iptables Rules
```bash
#!/bin/bash
# iptables rules for container security

# Create chain for container traffic
iptables -N DOCKER-MCP

# Allow container to connect to API gateway
iptables -A DOCKER-MCP -s 172.20.240.10 -d 172.20.240.100 -p tcp --dport 8080 -j ACCEPT

# Block direct external access
iptables -A DOCKER-MCP -s 172.20.240.10 -d 0.0.0.0/0 -j DROP

# Apply to FORWARD chain
iptables -A FORWARD -i mcp-bridge -j DOCKER-MCP
```

## Network Monitoring and Logging

### Connection Monitoring
```bash
#!/bin/bash
# Monitor network connections from MCP server

# Log all outbound connections
iptables -A OUTPUT -p tcp --dport 443 -j LOG --log-prefix "HTTPS-OUT: "
iptables -A OUTPUT -p tcp --dport 80 -j LOG --log-prefix "HTTP-OUT: "

# Monitor connection counts
netstat -an | grep :443 | grep ESTABLISHED | wc -l
```

### Traffic Analysis
```bash
#!/bin/bash
# Analyze network traffic patterns

# Monitor bandwidth usage
iftop -i eth0 -P

# Log network statistics
ss -tuln > /var/log/mcp-connections.log

# Monitor DNS queries
tcpdump -i eth0 port 53 -n | tee /var/log/mcp-dns.log
```

### Real-time Monitoring
```bash
#!/bin/bash
# Real-time network monitoring script

while true; do
    # Count active connections
    HTTPS_CONNECTIONS=$(netstat -an | grep :443 | grep ESTABLISHED | wc -l)
    HTTP_CONNECTIONS=$(netstat -an | grep :80 | grep ESTABLISHED | wc -l)
    
    # Check for suspicious activity
    if [ $HTTPS_CONNECTIONS -gt 50 ]; then
        echo "ALERT: High HTTPS connection count: $HTTPS_CONNECTIONS"
    fi
    
    if [ $HTTP_CONNECTIONS -gt 10 ]; then
        echo "ALERT: HTTP connections detected: $HTTP_CONNECTIONS"
    fi
    
    sleep 30
done
```

## Advanced Network Security

### Network Segmentation
```bash
#!/bin/bash
# Implement network segmentation for MCP deployment

# Create separate VLANs for different components
ip link add link eth0 name eth0.100 type vlan id 100  # MCP servers
ip link add link eth0 name eth0.200 type vlan id 200  # API gateways
ip link add link eth0 name eth0.300 type vlan id 300  # Monitoring

# Configure VLAN interfaces
ip addr add 10.1.0.1/24 dev eth0.100
ip addr add 10.2.0.1/24 dev eth0.200
ip addr add 10.3.0.1/24 dev eth0.300

# Set up inter-VLAN routing rules
iptables -A FORWARD -i eth0.100 -o eth0.200 -j ACCEPT  # MCP to Gateway
iptables -A FORWARD -i eth0.200 -o eth0.100 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth0.300 -j ACCEPT  # Monitoring can access all
```

### DDoS Protection
```bash
#!/bin/bash
# Implement DDoS protection for MCP servers

# Rate limit incoming connections
iptables -A INPUT -p tcp --dport 8080 -m limit --limit 25/min --limit-burst 50 -j ACCEPT

# Limit concurrent connections
iptables -A INPUT -p tcp --dport 8080 -m connlimit --connlimit-above 20 -j DROP

# Block IP addresses with too many connections
iptables -A INPUT -p tcp --dport 8080 -m recent --set --name mcp_clients
iptables -A INPUT -p tcp --dport 8080 -m recent --update --seconds 60 --hitcount 10 --name mcp_clients -j DROP
```

## Troubleshooting Network Issues

### Connectivity Testing
```bash
#!/bin/bash
# Test network connectivity

# Test basic connectivity
ping -c 3 8.8.8.8

# Test DNS resolution
nslookup api.external-service.com

# Test HTTP connectivity
curl -v http://api-gateway:8080/health

# Test HTTPS connectivity
curl -v https://api.external-service.com/health
```

### Debug iptables Rules
```bash
#!/bin/bash
# Debug iptables configuration

# List all rules with line numbers
iptables -L -n --line-numbers

# Check NAT table
iptables -t nat -L -n --line-numbers

# Monitor packet counters
watch -n 5 'iptables -L -n -v'

# Trace packet flow
iptables -t raw -A PREROUTING -p tcp --dport 443 -j TRACE
iptables -t raw -A OUTPUT -p tcp --dport 443 -j TRACE
```

## Contributing

Help improve our network controls guidance by sharing:
- **iptables Configurations** - Working iptables rulesets for different scenarios
- **Network Namespace Setups** - Advanced network isolation configurations
- **Monitoring Scripts** - Network monitoring and alerting automation
- **Troubleshooting Procedures** - Solutions to common network configuration issues

*This page is being developed with community input. Share your network security experience in our [discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions).*
