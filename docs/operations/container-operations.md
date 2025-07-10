---
title: "Container Operations"
parent: "Operations Guide"
nav_order: 1
---

# Container Operations

This guide provides comprehensive guidance for securely operating Model Context Protocol (MCP) servers in Docker containers. Containerization provides essential isolation and security benefits for MCP deployments, but requires specific operational security practices.

## Community Discussion

💬 **[Container Operations Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Share your container configurations, Docker security setups, and containerization strategies with the community.

## Why Containerize MCP Servers?

### Security Benefits
- **Process Isolation** - MCP servers run in isolated environments with limited system access
- **Resource Control** - Prevent resource exhaustion attacks through container limits
- **Consistent Deployment** - Identical security configurations across all environments
- **Simplified Cleanup** - Easy containment and cleanup of compromised containers

### Operational Advantages
- **Deployment Standardization** - Consistent deployment across development, staging, and production
- **Dependency Management** - All MCP server dependencies packaged in the container
- **Scalability** - Easy horizontal scaling of MCP server instances
- **Version Control** - Immutable container images with version tracking

## Secure Container Configuration

### Base Image Selection
```dockerfile
# Use minimal, security-focused base images
FROM python:3.11-slim-bullseye

# Or use distroless images for even better security
FROM gcr.io/distroless/python3
```

### Non-Root User Setup
```dockerfile
# Create non-root user for MCP server
RUN groupadd -r mcpuser && useradd -r -g mcpuser mcpuser

# Set up application directory with proper permissions
RUN mkdir -p /app && chown mcpuser:mcpuser /app
WORKDIR /app

# Switch to non-root user
USER mcpuser
```

### Security Hardening
```dockerfile
# Remove unnecessary packages and files
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set security-focused environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
```

## Runtime Security Controls

### Container Resource Limits
```yaml
# docker-compose.yml
version: '3.8'
services:
  mcp-server:
    image: mcp-server:latest
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
```

### Security Options
```yaml
# docker-compose.yml
services:
  mcp-server:
    image: mcp-server:latest
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Only if needed for port 80/443
    read_only: true
    tmpfs:
      - /tmp
      - /var/tmp
```

### Network Security
```yaml
# docker-compose.yml
services:
  mcp-server:
    image: mcp-server:latest
    networks:
      - mcp-network
    ports:
      - "127.0.0.1:8080:8080"  # Bind to localhost only

networks:
  mcp-network:
    driver: bridge
    internal: true  # No external access
```

## Container Networking for Security

### API Gateway Integration
```yaml
# docker-compose.yml
services:
  mcp-server:
    image: mcp-server:latest
    environment:
      - HTTP_PROXY=http://api-gateway:3128
      - HTTPS_PROXY=http://api-gateway:3128
      - NO_PROXY=localhost,127.0.0.1
    depends_on:
      - api-gateway
    networks:
      - mcp-internal

  api-gateway:
    image: kong:latest
    ports:
      - "8000:8000"
    networks:
      - mcp-internal
      - external

networks:
  mcp-internal:
    driver: bridge
    internal: true
  external:
    driver: bridge
```

### Traffic Routing Through Security Controls
```dockerfile
# Dockerfile - Install proxy tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Copy traffic redirection script
COPY redirect-traffic.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/redirect-traffic.sh
```

## Operational Procedures

### Container Health Monitoring
```yaml
# docker-compose.yml
services:
  mcp-server:
    image: mcp-server:latest
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

### Log Management
```yaml
# docker-compose.yml
services:
  mcp-server:
    image: mcp-server:latest
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    volumes:
      - ./logs:/app/logs:rw
```

### Secret Management
```yaml
# docker-compose.yml
services:
  mcp-server:
    image: mcp-server:latest
    secrets:
      - api_key
      - database_password
    environment:
      - API_KEY_FILE=/run/secrets/api_key
      - DB_PASSWORD_FILE=/run/secrets/database_password

secrets:
  api_key:
    file: ./secrets/api_key.txt
  database_password:
    file: ./secrets/db_password.txt
```

## Container Security Scanning

### Build-Time Scanning
```bash
# Scan container images for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image mcp-server:latest

# Scan for secrets in images
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  trufflesecurity/trufflehog:latest docker --image mcp-server:latest
```

### Runtime Security
```bash
# Monitor container runtime security
docker run -d --name falco \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /dev:/host/dev \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  falcosecurity/falco:latest
```

## Production Deployment Patterns

### Multi-Stage Builds
```dockerfile
# Multi-stage build for security
FROM python:3.11-slim as builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim as runtime
RUN groupadd -r mcpuser && useradd -r -g mcpuser mcpuser
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --chown=mcpuser:mcpuser . .
USER mcpuser
CMD ["python", "mcp_server.py"]
```

### Container Orchestration
```yaml
# Kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-server
  template:
    metadata:
      labels:
        app: mcp-server
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
      containers:
      - name: mcp-server
        image: mcp-server:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "250m"
```

## Troubleshooting Container Security

### Common Issues
- **Permission Denied Errors** - Ensure proper user permissions and volume mounts
- **Network Connectivity** - Check container networking and proxy configurations
- **Resource Limits** - Monitor container resource usage and adjust limits
- **Secret Access** - Verify secret mounting and environment variable configuration

### Debugging Commands
```bash
# Inspect container security configuration
docker inspect mcp-server | jq '.[]| {SecurityOpt, ReadonlyRootfs, Privileged}'

# Check container resource usage
docker stats mcp-server

# Access container for debugging
docker exec -it mcp-server /bin/sh

# View container logs
docker logs mcp-server --tail 100 -f
```

## Contributing

Help improve our container operations guidance by sharing:
- **Docker Configurations** - Secure Dockerfile and docker-compose examples
- **Security Scanning Results** - Vulnerability assessment findings and remediation
- **Orchestration Templates** - Kubernetes, Docker Swarm, or other orchestration configs
- **Operational Procedures** - Container maintenance and troubleshooting procedures

*This page is being developed with community input. Share your container operations experience in our [discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions).*
