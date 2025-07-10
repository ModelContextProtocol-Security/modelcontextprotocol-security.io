---
title: "Remote Deployment"
parent: "Operations Guide"
nav_order: 3
---

# Remote Deployment

This guide provides comprehensive guidance for securely deploying and operating Model Context Protocol (MCP) servers on remote infrastructure. Remote deployments require specific security considerations to ensure safe operation while maintaining performance and reliability.

## Community Discussion

💬 **[Remote Deployment Discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions)** - Share your remote deployment strategies, infrastructure configurations, and operational experiences with the community.

## Why Remote Deployment?

### Benefits of Remote MCP Deployment
- **Resource Isolation** - Separate MCP servers from development and production systems
- **Scalability** - Easy horizontal scaling of MCP server instances
- **Cost Efficiency** - Use cloud resources only when needed
- **Security Boundaries** - Isolate AI agent operations from corporate networks
- **Compliance** - Meet regulatory requirements for data processing locations

### Remote Deployment Challenges
- **Network Security** - Secure communication over public networks
- **Access Control** - Manage remote access and authentication
- **Monitoring** - Comprehensive monitoring of remote systems
- **Incident Response** - Responding to security incidents on remote infrastructure

## VPS Security Hardening

### Initial VPS Setup
```bash
#!/bin/bash
# Secure VPS setup for MCP deployment

# Update system
apt update && apt upgrade -y

# Create non-root user for MCP
useradd -m -s /bin/bash mcp-user
usermod -aG sudo mcp-user

# Configure SSH security
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
echo "AllowUsers mcp-user" >> /etc/ssh/sshd_config
systemctl reload ssh

# Install security tools
apt install -y fail2ban ufw unattended-upgrades

# Configure firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 8080/tcp  # MCP server port
ufw --force enable

# Configure fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -i 's/bantime = 10m/bantime = 1h/' /etc/fail2ban/jail.local
sed -i 's/maxretry = 5/maxretry = 3/' /etc/fail2ban/jail.local
systemctl enable fail2ban
systemctl start fail2ban

# Enable automatic security updates
dpkg-reconfigure -plow unattended-upgrades
```

### File System Security
```bash
#!/bin/bash
# Secure file system configuration

# Create secure directory structure
mkdir -p /opt/mcp/{config,logs,data}
chown -R mcp-user:mcp-user /opt/mcp
chmod 750 /opt/mcp/config
chmod 755 /opt/mcp/logs
chmod 700 /opt/mcp/data

# Set up secure temporary directory
mkdir -p /opt/mcp/tmp
chmod 700 /opt/mcp/tmp
echo "export TMPDIR=/opt/mcp/tmp" >> /home/mcp-user/.bashrc

# Configure log rotation
cat > /etc/logrotate.d/mcp << EOF
/opt/mcp/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 mcp-user mcp-user
}
EOF
```

## Container Deployment on Remote Systems

### Docker Compose for Remote Deployment
```yaml
# docker-compose.yml - Remote MCP deployment
version: '3.8'
services:
  mcp-server:
    image: mcp-server:latest
    container_name: mcp-server
    restart: unless-stopped
    user: "1000:1000"  # Non-root user
    networks:
      - mcp-network
    ports:
      - "127.0.0.1:8080:8080"  # Bind to localhost only
    environment:
      - MCP_ENV=production
      - MCP_LOG_LEVEL=info
      - HTTPS_PROXY=http://api-gateway:8080
    volumes:
      - ./config:/app/config:ro
      - ./logs:/app/logs:rw
      - ./data:/app/data:rw
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
    tmpfs:
      - /tmp
      - /var/tmp

  api-gateway:
    image: kong:latest
    container_name: api-gateway
    restart: unless-stopped
    networks:
      - mcp-network
    ports:
      - "8080:8000"
    environment:
      - KONG_DATABASE=off
      - KONG_DECLARATIVE_CONFIG=/kong/declarative/kong.yml
      - KONG_PROXY_ACCESS_LOG=/dev/stdout
      - KONG_ADMIN_ACCESS_LOG=/dev/stdout
    volumes:
      - ./kong.yml:/kong/declarative/kong.yml:ro

  monitoring:
    image: prom/prometheus:latest
    container_name: monitoring
    restart: unless-stopped
    networks:
      - mcp-network
    ports:
      - "127.0.0.1:9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

networks:
  mcp-network:
    driver: bridge
    internal: false

volumes:
  prometheus_data:
```

### Kubernetes Deployment
```yaml
# k8s-deployment.yaml - Kubernetes deployment for MCP
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server
  namespace: mcp-system
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
        fsGroup: 1000
      containers:
      - name: mcp-server
        image: mcp-server:latest
        ports:
        - containerPort: 8080
        env:
        - name: MCP_ENV
          value: "production"
        - name: HTTPS_PROXY
          value: "http://api-gateway:8080"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
        - name: logs
          mountPath: /app/logs
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: config
        configMap:
          name: mcp-config
      - name: logs
        emptyDir: {}
      - name: tmp
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-server
  namespace: mcp-system
spec:
  selector:
    app: mcp-server
  ports:
  - port: 8080
    targetPort: 8080
  type: ClusterIP
```

## Cloud Provider Security

### AWS Security Configuration
```bash
#!/bin/bash
# AWS security configuration for MCP deployment

# Create security group
aws ec2 create-security-group \
    --group-name mcp-security-group \
    --description "Security group for MCP server" \
    --vpc-id vpc-12345678

# Allow SSH from specific IP
aws ec2 authorize-security-group-ingress \
    --group-id sg-12345678 \
    --protocol tcp \
    --port 22 \
    --cidr YOUR_IP/32

# Allow MCP server port from load balancer
aws ec2 authorize-security-group-ingress \
    --group-id sg-12345678 \
    --protocol tcp \
    --port 8080 \
    --source-group sg-87654321

# Create IAM role for MCP server
aws iam create-role \
    --role-name mcp-server-role \
    --assume-role-policy-document file://trust-policy.json

# Attach minimal permissions policy
aws iam attach-role-policy \
    --role-name mcp-server-role \
    --policy-arn arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy

# Create instance profile
aws iam create-instance-profile \
    --instance-profile-name mcp-server-profile

aws iam add-role-to-instance-profile \
    --instance-profile-name mcp-server-profile \
    --role-name mcp-server-role
```

### GCP Security Configuration
```bash
#!/bin/bash
# GCP security configuration for MCP deployment

# Create firewall rules
gcloud compute firewall-rules create mcp-allow-ssh \
    --allow tcp:22 \
    --source-ranges YOUR_IP/32 \
    --target-tags mcp-server

gcloud compute firewall-rules create mcp-allow-http \
    --allow tcp:8080 \
    --source-tags load-balancer \
    --target-tags mcp-server

# Create service account
gcloud iam service-accounts create mcp-server-sa \
    --display-name "MCP Server Service Account"

# Grant minimal permissions
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member "serviceAccount:mcp-server-sa@PROJECT_ID.iam.gserviceaccount.com" \
    --role "roles/monitoring.metricWriter"

# Create instance template
gcloud compute instance-templates create mcp-server-template \
    --image-family ubuntu-2004-lts \
    --image-project ubuntu-os-cloud \
    --machine-type n1-standard-1 \
    --service-account mcp-server-sa@PROJECT_ID.iam.gserviceaccount.com \
    --scopes https://www.googleapis.com/auth/monitoring.write \
    --tags mcp-server
```

## Network Security for Remote Deployments

### VPN Configuration
```bash
#!/bin/bash
# WireGuard VPN setup for secure remote access

# Install WireGuard
apt install -y wireguard

# Generate keys
wg genkey | tee /etc/wireguard/privatekey | wg pubkey | tee /etc/wireguard/publickey

# Create server configuration
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $(cat /etc/wireguard/privatekey)
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = CLIENT_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32
EOF

# Enable and start WireGuard
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Configure firewall
ufw allow 51820/udp
```

### SSH Hardening
```bash
#!/bin/bash
# SSH hardening for remote access

# Generate SSH keys
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""

# Configure SSH
cat > /etc/ssh/sshd_config << EOF
Port 2222
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Authentication
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM no

# Security settings
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Restrict users
AllowUsers mcp-user

# Disable dangerous features
X11Forwarding no
AllowTcpForwarding no
PermitTunnel no
EOF

systemctl reload ssh
```

## Monitoring and Alerting

### Prometheus Configuration
```yaml
# prometheus.yml - Monitoring configuration
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

scrape_configs:
  - job_name: 'mcp-server'
    static_configs:
      - targets: ['mcp-server:8080']
    metrics_path: '/metrics'
    scrape_interval: 5s
    
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
    
  - job_name: 'api-gateway'
    static_configs:
      - targets: ['api-gateway:8001']
    metrics_path: '/metrics'

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Alert Rules
```yaml
# alert_rules.yml - Alert rules for MCP deployment
groups:
- name: mcp-server
  rules:
  - alert: MCPServerDown
    expr: up{job="mcp-server"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "MCP Server is down"
      description: "MCP Server has been down for more than 1 minute"
      
  - alert: HighCPUUsage
    expr: rate(process_cpu_seconds_total{job="mcp-server"}[5m]) > 0.8
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage on MCP Server"
      description: "CPU usage is above 80% for more than 5 minutes"
      
  - alert: HighMemoryUsage
    expr: process_resident_memory_bytes{job="mcp-server"} > 1073741824
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage on MCP Server"
      description: "Memory usage is above 1GB for more than 5 minutes"
```

## Security Monitoring

### Log Aggregation
```bash
#!/bin/bash
# Set up centralized logging

# Install rsyslog
apt install -y rsyslog

# Configure remote logging
cat >> /etc/rsyslog.conf << EOF
# Remote logging configuration
*.* @@log-server:514
EOF

# Configure log rotation
cat > /etc/logrotate.d/mcp-remote << EOF
/var/log/mcp-remote/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 syslog adm
}
EOF

systemctl restart rsyslog
```

### Intrusion Detection
```bash
#!/bin/bash
# Install and configure AIDE for file integrity monitoring

# Install AIDE
apt install -y aide

# Initialize AIDE database
aideinit

# Configure AIDE rules
cat > /etc/aide/aide.conf << EOF
# AIDE configuration for MCP server
@@define DBDIR /var/lib/aide
@@define LOGDIR /var/log/aide

database=file:@@{DBDIR}/aide.db
database_out=file:@@{DBDIR}/aide.db.new
gzip_dbout=yes

# Rules
/opt/mcp/config R
/opt/mcp/data R
/etc R
/usr/bin R
/usr/sbin R
EOF

# Set up daily checks
cat > /etc/cron.daily/aide << EOF
#!/bin/bash
/usr/bin/aide --check
EOF

chmod +x /etc/cron.daily/aide
```

## Backup and Recovery

### Automated Backup Script
```bash
#!/bin/bash
# Automated backup script for MCP deployment

BACKUP_DIR="/opt/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="mcp_backup_${DATE}.tar.gz"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup MCP configuration and data
tar -czf $BACKUP_DIR/$BACKUP_FILE \
    /opt/mcp/config \
    /opt/mcp/data \
    /etc/nginx \
    /etc/docker \
    /home/mcp-user/.ssh

# Upload to cloud storage (AWS S3 example)
aws s3 cp $BACKUP_DIR/$BACKUP_FILE s3://mcp-backups/

# Keep only last 7 days of local backups
find $BACKUP_DIR -name "mcp_backup_*.tar.gz" -mtime +7 -delete

# Log backup completion
echo "$(date): Backup completed - $BACKUP_FILE" >> /var/log/mcp-backup.log
```

### Disaster Recovery Plan
```bash
#!/bin/bash
# Disaster recovery script for MCP deployment

# Stop services
docker-compose down

# Restore from backup
BACKUP_FILE=$1
if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

# Extract backup
tar -xzf $BACKUP_FILE -C /

# Restore file permissions
chown -R mcp-user:mcp-user /opt/mcp
chmod 750 /opt/mcp/config
chmod 700 /opt/mcp/data

# Restart services
docker-compose up -d

# Verify services
sleep 30
curl -f http://localhost:8080/health || echo "Health check failed"
```

## Contributing

Help improve our remote deployment guidance by sharing:
- **Infrastructure Templates** - Terraform, CloudFormation, and other IaC templates
- **Security Configurations** - Hardening scripts and security configurations
- **Monitoring Setups** - Comprehensive monitoring and alerting configurations
- **Operational Procedures** - Deployment, backup, and recovery procedures

*This page is being developed with community input. Share your remote deployment experience in our [discussions](https://github.com/orgs/ModelContextProtocol-Security/discussions).*
