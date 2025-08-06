---
title: Production Environment Setup
description: Enterprise production server deployment with PostgreSQL, WSGI, and reverse proxy
hide:
  - navigation
---

# Production Environment Setup

This guide provides comprehensive instructions for deploying the Intrudex Server in a production environment with enterprise-grade security, performance optimizations, and scalability features.

---

## Production Environment Overview

!!! info "Production Configuration"
    The production environment uses PostgreSQL database for reliability, WSGI servers for performance, reverse proxy for security, and comprehensive monitoring for operational excellence.

### Production Features

- **PostgreSQL Database**: Enterprise-grade reliability and performance
- **WSGI Server**: High-performance application server (Gunicorn/Waitress)
- **Reverse Proxy**: Nginx/Apache for SSL termination and load balancing
- **Security Hardening**: Production security configurations
- **Service Management**: System service integration
- **Monitoring & Logging**: Comprehensive operational monitoring

```mermaid
graph TB
    subgraph "Server Layer"
        Server[Intrudex Servers]
    end
    
    subgraph "Load Balancer Layer"
        LB[Load Balancer]
    end
    
    subgraph "Reverse Proxy Layer"
        NGINX[Nginx/Apache]
        SSL[SSL/TLS Termination]
    end
    
    subgraph "Application Layer"
        WSGI1[WSGI Server 1]
        WSGI2[WSGI Server 2]
        APP[Flask Application]
    end
    
    subgraph "Database Layer"
        POSTGRES[(PostgreSQL)]
        REDIS[(Redis Cache)]
    end
    
    subgraph "Infrastructure Layer"
        LOGS[Log Management]
        MONITOR[Monitoring]
        BACKUP[Backup System]
    end
    
    Server --> LB
    LB --> NGINX
    NGINX --> SSL
    SSL --> WSGI1
    SSL --> WSGI2
    WSGI1 --> APP
    WSGI2 --> APP
    APP --> POSTGRES
    APP --> REDIS
    
    LOGS --> APP
    MONITOR --> APP
    BACKUP --> POSTGRES
    
    style POSTGRES fill:#336791
    style NGINX fill:#27ae60
    style WSGI1 fill:#2d4a87
    style WSGI2 fill:#2d4a87
```

---

## System Requirements

### Minimum Production Specifications
- **Operating System**: Ubuntu 20.04 LTS, CentOS 8+, RHEL 8+, or Windows Server 2019+
- **CPU**: 4 cores minimum (8+ cores recommended)
- **Memory**: 8 GB RAM minimum (16+ GB recommended)
- **Storage**: 100 GB SSD storage (500+ GB for high-volume environments)
- **Network**: Gigabit network interface
- **SSL Certificates**: Valid SSL certificates for production domains

### High Availability Specifications
- **CPU**: 8+ cores per server
- **Memory**: 32+ GB RAM per server
- **Storage**: 1+ TB SSD with RAID configuration
- **Network**: Redundant network interfaces
- **Load Balancer**: Hardware or software load balancer
- **Database**: PostgreSQL cluster with replication

---

## Prerequisites Installation

### System Updates and Dependencies

=== "Ubuntu/Debian"
    ```bash
    # Update system packages
    sudo apt update && sudo apt upgrade -y
    
    # Install essential packages
    sudo apt install -y python3 python3-pip python3-venv python3-dev \
                        postgresql postgresql-contrib postgresql-client \
                        nginx redis-server git curl wget \
                        build-essential libpq-dev libssl-dev libffi-dev
    
    # Install Node.js (for frontend builds)
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt install -y nodejs
    ```

=== "CentOS/RHEL"
    ```bash
    # Update system packages
    sudo dnf update -y
    
    # Install EPEL repository
    sudo dnf install -y epel-release
    
    # Install essential packages
    sudo dnf install -y python3 python3-pip python3-devel \
                        postgresql postgresql-server postgresql-contrib \
                        nginx redis git curl wget \
                        gcc gcc-c++ make libpq-devel openssl-devel libffi-devel
    
    # Install Node.js
    curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
    sudo dnf install -y nodejs
    ```

=== "Windows Server"
    ```powershell
    # Install Chocolatey package manager
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    
    # Install required packages
    choco install -y python nodejs postgresql redis-64 git
    
    # Install IIS and URL Rewrite (for reverse proxy)
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole, IIS-WebServer
    choco install -y urlrewrite
    ```

---

## Database Setup (PostgreSQL)

### PostgreSQL Installation and Configuration

=== "Ubuntu/Debian"
    ```bash
    # Start and enable PostgreSQL
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
    
    # Create production database and user
    sudo -u postgres psql << EOF
    CREATE DATABASE intrudex_production;
    CREATE USER intrudex_user WITH PASSWORD 'secure_production_password';
    GRANT ALL PRIVILEGES ON DATABASE intrudex_production TO intrudex_user;
    ALTER USER intrudex_user CREATEDB;
    \q
    EOF
    
    # Configure PostgreSQL for production
    sudo nano /etc/postgresql/*/main/postgresql.conf
    # Edit the following settings:
    # listen_addresses = '*'
    # max_connections = 200
    # shared_buffers = 256MB
    # effective_cache_size = 1GB
    # work_mem = 4MB
    # maintenance_work_mem = 64MB
    
    # Configure authentication
    sudo nano /etc/postgresql/*/main/pg_hba.conf
    # Add: host intrudex_production intrudex_user 127.0.0.1/32 md5
    
    # Restart PostgreSQL
    sudo systemctl restart postgresql
    ```

=== "CentOS/RHEL"
    ```bash
    # Initialize PostgreSQL database
    sudo postgresql-setup --initdb
    
    # Start and enable PostgreSQL
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
    
    # Create production database and user
    sudo -u postgres psql << EOF
    CREATE DATABASE intrudex_production;
    CREATE USER intrudex_user WITH PASSWORD 'secure_production_password';
    GRANT ALL PRIVILEGES ON DATABASE intrudex_production TO intrudex_user;
    ALTER USER intrudex_user CREATEDB;
    \q
    EOF
    
    # Configure PostgreSQL (similar to Ubuntu instructions above)
    sudo systemctl restart postgresql
    ```

=== "Windows Server"
    ```powershell
    # PostgreSQL is installed via Chocolatey
    # Configure via PostgreSQL GUI or command line
    
    # Create database using psql
    psql -U postgres -c "CREATE DATABASE intrudex_production;"
    psql -U postgres -c "CREATE USER intrudex_user WITH PASSWORD 'secure_production_password';"
    psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE intrudex_production TO intrudex_user;"
    ```

### Database Performance Tuning

```sql
-- Connect to PostgreSQL and apply performance settings
-- For systems with 8GB+ RAM

ALTER SYSTEM SET shared_buffers = '2GB';
ALTER SYSTEM SET effective_cache_size = '6GB';
ALTER SYSTEM SET maintenance_work_mem = '512MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;

-- Reload configuration
SELECT pg_reload_conf();
```

---

## Application Deployment

### Step 1: Application Setup

```bash
# Create production user
sudo useradd -m -s /bin/bash intrudex
sudo usermod -aG sudo intrudex

# Switch to production user
sudo su - intrudex

# Clone repository
git clone https://github.com/ToolsHive/Intrudex.git
cd Intrudex/Intrudex-Server

# Create production virtual environment
python3 -m venv venv-production
source venv-production/bin/activate

# Install production dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install production WSGI server
pip install gunicorn  # Linux/macOS
# pip install waitress  # Windows alternative
```

### Step 2: Production Environment Configuration

Create production environment configuration:

```bash
# Create production .env file
cat > .env << 'EOF'
# Production Server Configuration
FLASK_RUN_PORT=80
FLASK_RUN_HOST=0.0.0.0
FLASK_ENV=production
FLASK_DEBUG=0

# Security Configuration
SECRET_KEY=your-cryptographically-secure-production-key-min-32-chars
WTF_CSRF_ENABLED=True
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax

# Production Database Configuration
DATABASE_URL=postgresql://intrudex_user:secure_production_password@localhost/intrudex_production
SQLALCHEMY_TRACK_MODIFICATIONS=False
SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True, "pool_recycle": 300}

# Redis Configuration (optional)
REDIS_URL=redis://localhost:6379/0

# Production Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/intrudex/intrudex.log

# Security Headers
SECURITY_HEADERS=True
SSL_DISABLE=False
EOF

# Secure the environment file
chmod 600 .env
```

### Step 3: Frontend Assets Build

```bash
# Install Node.js dependencies
npm install

# Build production assets
npm run build

```

### Step 4: Database Migration

```bash
# Ensure virtual environment is activated
source venv-production/bin/activate

# Initialize database schema
flask db init
flask db migrate -m "Initial production migration"
flask db upgrade

# Create production admin user
flask create-admin
# Enter secure credentials when prompted
```

---

## WSGI Server Configuration

### Gunicorn Configuration (Linux/macOS)

Create Gunicorn configuration file:

```bash
# Create Gunicorn configuration
cat > gunicorn.conf.py << 'EOF'
# Gunicorn production configuration

# Server socket
bind = "0.0.0.0:8000"
backlog = 2048

# Worker processes
workers = 4  # 2 * CPU cores
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Restart workers after this many requests
max_requests = 1000
max_requests_jitter = 50

# Logging
loglevel = "info"
accesslog = "/var/log/intrudex/gunicorn-access.log"
errorlog = "/var/log/intrudex/gunicorn-error.log"
capture_output = True

# Process naming
proc_name = "intrudex-server"

# Server mechanics
daemon = False
pidfile = "/var/run/intrudex/gunicorn.pid"
user = "intrudex"
group = "intrudex"
tmp_upload_dir = None

# SSL (if terminating SSL at application level)
# keyfile = "/path/to/private.key"
# certfile = "/path/to/certificate.crt"
EOF
```

Test Gunicorn configuration:

```bash
# Test Gunicorn startup
gunicorn --config gunicorn.conf.py wsgi:app

# Test with configuration check
gunicorn --check-config --config gunicorn.conf.py wsgi:app
```

### Waitress Configuration (Windows)

For Windows production deployments:

```python
# Create waitress_config.py
"""
Waitress production configuration for Windows
"""

import os
from waitress import serve
from wsgi import app

if __name__ == '__main__':
    # Production configuration
    serve(
        app,
        host='0.0.0.0',
        port=8000,
        threads=6,
        connection_limit=1000,
        cleanup_interval=30,
        channel_timeout=120,
        log_untrusted_proxy_headers=True,
        clear_untrusted_proxy_headers=True,
        trusted_proxy_headers=['x-forwarded-for', 'x-forwarded-proto'],
        trusted_proxy_count=1
    )
```

---

## Reverse Proxy Configuration

### Nginx Configuration

Create Nginx server configuration:

```bash
# Create Nginx configuration
sudo tee /etc/nginx/sites-available/intrudex << 'EOF'
# Intrudex Server Production Configuration

upstream intrudex_backend {
    server 127.0.0.1:8000;
    # Add more servers for load balancing
    # server 127.0.0.1:8001;
    # server 127.0.0.1:8002;
}

# Rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

# SSL Configuration
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
ssl_prefer_server_ciphers on;

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name your-domain.com www.your-domain.com;

    # SSL Configuration
    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';" always;

    # Gzip Compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/javascript
        application/xml+rss
        application/json;

    # API Routes with rate limiting
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://intrudex_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # Login endpoint with stricter rate limiting
    location /api/auth/login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://intrudex_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Static files with caching
    location /static/ {
        alias /home/intrudex/Intrudex/Intrudex-Server/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Main application
    location / {
        proxy_pass http://intrudex_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://intrudex_backend;
        proxy_set_header Host $host;
    }
}
EOF

# Enable the site
sudo ln -s /etc/nginx/sites-available/intrudex /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Apache Configuration (Alternative)

```apache
# /etc/apache2/sites-available/intrudex.conf

<VirtualHost *:80>
    ServerName your-domain.com
    Redirect permanent / https://your-domain.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName your-domain.com
    
    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /path/to/your/certificate.crt
    SSLCertificateKeyFile /path/to/your/private.key
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    
    # Security Headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    
    # Reverse Proxy Configuration
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8000/
    ProxyPassReverse / http://127.0.0.1:8000/
    
    # Static files
    Alias /static /home/intrudex/Intrudex/Intrudex-Server/static
    <Directory "/home/intrudex/Intrudex/Intrudex-Server/static">
        Require all granted
    </Directory>
</VirtualHost>
```

---

## System Service Configuration

### Systemd Service (Linux)

Create systemd service file:

```bash
# Create systemd service
sudo tee /etc/systemd/system/intrudex.service << 'EOF'
[Unit]
Description=Intrudex Security Monitoring Server
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=exec
User=intrudex
Group=intrudex
WorkingDirectory=/home/intrudex/Intrudex/Intrudex-Server
Environment=PATH=/home/intrudex/Intrudex/Intrudex-Server/venv-production/bin
ExecStart=/home/intrudex/Intrudex/Intrudex-Server/venv-production/bin/gunicorn --config gunicorn.conf.py wsgi:app
ExecReload=/bin/kill -s HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=intrudex

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/intrudex /var/run/intrudex

[Install]
WantedBy=multi-user.target
EOF

# Create necessary directories
sudo mkdir -p /var/log/intrudex /var/run/intrudex
sudo chown intrudex:intrudex /var/log/intrudex /var/run/intrudex

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable intrudex
sudo systemctl start intrudex
sudo systemctl status intrudex
```

### Windows Service

For Windows Server deployments using NSSM:

```powershell
# Download and install NSSM
Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile "nssm.zip"
Expand-Archive -Path "nssm.zip" -DestinationPath "C:\Program Files\"

# Install Intrudex as Windows service
C:\Program Files\nssm-2.24\win64\nssm.exe install IntrudexServer
C:\Program Files\nssm-2.24\win64\nssm.exe set IntrudexServer Application "C:\Python\python.exe"
C:\Program Files\nssm-2.24\win64\nssm.exe set IntrudexServer AppParameters "C:\Intrudex\Intrudex-Server\waitress_config.py"
C:\Program Files\nssm-2.24\win64\nssm.exe set IntrudexServer AppDirectory "C:\Intrudex\Intrudex-Server"
C:\Program Files\nssm-2.24\win64\nssm.exe set IntrudexServer DisplayName "Intrudex Security Monitoring Server"
C:\Program Files\nssm-2.24\win64\nssm.exe set IntrudexServer Description "Enterprise security monitoring and threat detection server"
C:\Program Files\nssm-2.24\win64\nssm.exe set IntrudexServer Start SERVICE_AUTO_START

# Start the service
C:\Program Files\nssm-2.24\win64\nssm.exe start IntrudexServer
```

---

## Security Hardening

### Firewall Configuration

=== "Ubuntu/Debian (UFW)"
    ```bash
    # Enable firewall
    sudo ufw enable
    
    # Allow SSH (adjust port if needed)
    sudo ufw allow 22/tcp
    
    # Allow HTTP and HTTPS
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    
    # Allow PostgreSQL (local only)
    sudo ufw allow from 127.0.0.1 to any port 5432
    
    # Allow Redis (local only)
    sudo ufw allow from 127.0.0.1 to any port 6379
    
    # Check status
    sudo ufw status
    ```

=== "CentOS/RHEL (firewalld)"
    ```bash
    # Enable firewall
    sudo systemctl enable firewalld
    sudo systemctl start firewalld
    
    # Allow HTTP and HTTPS
    sudo firewall-cmd --permanent --add-service=http
    sudo firewall-cmd --permanent --add-service=https
    
    # Allow SSH
    sudo firewall-cmd --permanent --add-service=ssh
    
    # Reload firewall
    sudo firewall-cmd --reload
    ```

### SSL/TLS Certificate Setup

#### Using Let's Encrypt (Recommended)

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx  # Ubuntu/Debian
# sudo dnf install certbot python3-certbot-nginx  # CentOS/RHEL

# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Set up automatic renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

#### Using Custom Certificate

```bash
# Copy your certificate files
sudo cp your-certificate.crt /etc/ssl/certs/intrudex.crt
sudo cp your-private.key /etc/ssl/private/intrudex.key

# Set proper permissions
sudo chmod 644 /etc/ssl/certs/intrudex.crt
sudo chmod 600 /etc/ssl/private/intrudex.key
sudo chown root:root /etc/ssl/certs/intrudex.crt /etc/ssl/private/intrudex.key
```

---

## Monitoring and Logging

### Log Management

Configure comprehensive logging:

```bash
# Create log rotation configuration
sudo tee /etc/logrotate.d/intrudex << 'EOF'
/var/log/intrudex/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 intrudex intrudex
    postrotate
        systemctl reload intrudex
    endscript
}
EOF
```

---

## Backup and Recovery

### Database Backup

```bash
#!/bin/bash
# /usr/local/bin/intrudex-backup.sh

BACKUP_DIR="/var/backups/intrudex"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="intrudex_production"
DB_USER="intrudex_user"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Database backup
pg_dump -U "$DB_USER" -h localhost "$DB_NAME" | gzip > "$BACKUP_DIR/db_backup_$DATE.sql.gz"

# Application backup
tar -czf "$BACKUP_DIR/app_backup_$DATE.tar.gz" -C /home/intrudex Intrudex/

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

### Automated Backup Setup

```bash
# Make backup script executable
chmod +x /usr/local/bin/intrudex-backup.sh

# Add to cron for daily backups
echo "0 2 * * * /usr/local/bin/intrudex-backup.sh >> /var/log/intrudex/backup.log 2>&1" | sudo crontab -
```

---

## Troubleshooting

### Common Production Issues

!!! failure "High CPU Usage"
    **Symptom**: Server experiencing high CPU utilization
    
    **Resolution**:
    1. Check Gunicorn worker processes: `ps aux | grep gunicorn`
    2. Optimize worker count in `gunicorn.conf.py`
    3. Review database queries for optimization
    4. Check for memory leaks

!!! failure "Database Connection Errors"
    **Symptom**: Application cannot connect to PostgreSQL
    
    **Resolution**:
    1. Verify PostgreSQL service: `sudo systemctl status postgresql`
    2. Check connection limits: `SELECT * FROM pg_stat_activity;`
    3. Review `pg_hba.conf` authentication settings
    4. Verify network connectivity

!!! failure "SSL Certificate Issues"
    **Symptom**: SSL warnings or connection errors
    
    **Resolution**:
    1. Verify certificate validity: `openssl x509 -in cert.crt -text -noout`
    2. Check certificate chain completeness
    3. Verify domain name matches certificate
    4. Test with SSL Labs: https://www.ssllabs.com/ssltest/

---