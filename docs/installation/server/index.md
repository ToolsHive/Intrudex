---
title: Server Installation Overview
description: Cross-platform server deployment options and environment configurations
hide:
  - navigation
---

# Intrudex Server Installation Guide

The Intrudex Server functions as the central enterprise command and control hub, providing a robust Python Flask-based REST API architecture, sophisticated administrative dashboard interface, and comprehensive centralized alert management system.

---

## Server Architecture Overview

!!! info "Enterprise Server Architecture"
    The Intrudex Server supports enterprise deployment across Windows, macOS, Linux, and containerized cloud environments with full high-availability support and scalable architecture.

### Enterprise Technology Stack Architecture

```mermaid
flowchart TD
    %% Frontend Layer
    subgraph Frontend["Frontend Presentation Layer"]
        UI[<b>Admin Web Dashboard</b>]
        API[<b>REST API Gateway</b>]
    end

    %% Application Logic Layer
    subgraph Logic["Application Business Logic Layer"]
        FLASK[<b>Flask Core</b>]
        AUTH[Authentication<br>& Authorization]
        ALERTS[Alert Management<br>Engine]
    end

    %% Data Layer
    subgraph Data["Data Persistence Layer"]
        SQLITE[(SQLite<br><i>Development</i>)]
        POSTGRES[(PostgreSQL<br><i>Production</i>)]
        CACHE[(Redis<br>Caching)]
    end

    %% Infrastructure Layer
    subgraph Infra["Infrastructure & Security Layer"]
        DOCKER[Docker<br>Containerization]
        NGINX[Nginx<br>Reverse Proxy]
        SSL[TLS/SSL<br>Security]
    end

    %% Connections
    UI -- "User Actions" --> FLASK
    API -- "Client Requests" --> FLASK
    FLASK -- "Business Logic" --> AUTH
    FLASK -- "Alert Ops" --> ALERTS
    ALERTS -- "Store Alerts" --> SQLITE
    ALERTS -- "Store Alerts" --> POSTGRES
    FLASK -- "Cache Ops" --> CACHE

    %% Infra Connections
    FLASK -.-> DOCKER
    FLASK -.-> NGINX
    NGINX -.-> SSL

    %% Styles
    style UI fill:#3498db,color:#fff
    style API fill:#2980b9,color:#fff
    style FLASK fill:#2d4a87,color:#fff
    style AUTH fill:#6c3483,color:#fff
    style ALERTS fill:#af601a,color:#fff
    style SQLITE fill:#b2babb
    style POSTGRES fill:#336791,color:#fff
    style CACHE fill:#27ae60,color:#fff
    style DOCKER fill:#0db7ed,color:#fff
    style NGINX fill:#229954,color:#fff
    style SSL fill:#f1c40f
```

---

## System Requirements

### Minimum Technical Specifications
- **Operating System**: Windows 10+, macOS 10.15+, Ubuntu 18.04 LTS+, or compatible Linux distribution
- **Python Runtime**: Version 3.8+ (Python 3.10+ recommended for optimal performance)
- **Memory Allocation**: 2 GB RAM minimum (4+ GB recommended for production)
- **Storage Requirements**: 10 GB available space (database growth dependent)
- **Network Infrastructure**: Inbound HTTPS connectivity for client communications

### Enterprise Production Recommendations
- **Processing Power**: Multi-core processor architecture (4+ cores recommended)
- **Memory Configuration**: 8 GB RAM minimum for high-volume environments
- **Storage Infrastructure**: SSD with 50+ GB available space
- **Database Backend**: PostgreSQL for enterprise production deployments
- **High Availability**: Load balancer configuration for enterprise requirements

---

## Deployment Options

Choose your deployment strategy based on your environment and requirements:

```mermaid
flowchart TB
    %% Main Node
    A([<b style="font-size:1.8em;">Server Deployment Options</b>])

    %% Deployment Options
    B([<b style="font-size:1.17em;">Development<br>Environment</b>])
    C([<b style="font-size:1.17em;">Production<br>Environment</b>])
    D([<b style="font-size:1.17em;">Docker<br>Development</b>])
    E([<b style="font-size:1.17em;">Docker<br>Production</b>])

    %% Details for Development
    B1([SQLite<br><i>Database</i>])
    B2([Dev Server<br><i>Debug Mode</i>])
    B3([Quick<br>Setup])

    %% Details for Production
    C1([PostgreSQL<br><i>Database</i>])
    C2([Prod<br>Optimizations])
    C3([Security<br>Hardening])

    %% Details for Docker Dev
    D1([Docker Compose])
    D2([Dev<br>Containers])
    D3([Volume<br>Mapping])

    %% Details for Docker Prod
    E1([Prod<br>Containers])
    E2([Orchestration<br>Ready])
    E3([Scalable<br>Arch.])

    %% Connections
    A --> B
    A --> C
    A --> D
    A --> E

    B --> B1
    B --> B2
    B --> B3

    C --> C1
    C --> C2
    C --> C3

    D --> D1
    D --> D2
    D --> D3

    E --> E1
    E --> E2
    E --> E3

    %% Styling
    style A fill:#222f3e,color:#fff,stroke:#222f3e,stroke-width:4px
    style B fill:#3498db,color:#fff,stroke:#2980b9,stroke-width:3px
    style C fill:#27ae60,color:#fff,stroke:#229954,stroke-width:3px
    style D fill:#f39c12,color:#fff,stroke:#e67e22,stroke-width:3px
    style E fill:#e74c3c,color:#fff,stroke:#c0392b,stroke-width:3px

    style B1 fill:#d6eaf8,color:#222
    style B2 fill:#d6eaf8,color:#222
    style B3 fill:#d6eaf8,color:#222

    style C1 fill:#d5f5e3,color:#222
    style C2 fill:#d5f5e3,color:#222
    style C3 fill:#d5f5e3,color:#222

    style D1 fill:#f9e79f,color:#222
    style D2 fill:#f9e79f,color:#222
    style D3 fill:#f9e79f,color:#222

    style E1 fill:#f5b7b1,color:#222
    style E2 fill:#f5b7b1,color:#222
    style E3 fill:#f5b7b1,color:#222

    %% Layout tweaks for better spacing
    linkStyle default stroke-width:2px
    classDef bigNode font-size:30px;
    class A,B,C,D,E bigNode;
```

### Deployment Comparison

| Feature | [Development](development.md) | [Production](production.md) | [Docker Dev](docker-dev.md) | [Docker Prod](docker-prod.md) |
|---------|-----|-----|-----|-----|
| **Setup Speed** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Production Ready** | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Scalability** | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Security** | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Maintenance** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |

---

## Installation Methods

<div class="grid cards" markdown>

-   :fontawesome-solid-laptop-code:{ .lg .middle } **Development Environment**

    ---

    **Perfect for Testing & Development**
    
    Quick setup with SQLite database for development and testing
    
    - SQLite database (no external dependencies)
    - Development server with debug mode
    - Rapid deployment (15 minutes)
    - Local testing environment

    **[Setup Development Environment →](development.md)**

-   :fontawesome-solid-server:{ .lg .middle } **Production Environment**

    ---

    **Enterprise Production Deployment**
    
    Full production setup with PostgreSQL and security hardening
    
    - PostgreSQL database backend
    - Production optimizations
    - Security hardening configurations
    - System service integration

    **[Setup Production Environment →](production.md)**

-   :fontawesome-brands-docker:{ .lg .middle } **Docker Development**

    ---

    **Containerized Development**
    
    Consistent development environment using Docker containers
    
    - Docker Compose orchestration
    - Development container setup
    - Volume mapping for development
    - Easy environment cleanup

    **[Setup Docker Development →](docker-dev.md)**

-   :fontawesome-solid-industry:{ .lg .middle } **Docker Production**

    ---

    **Enterprise Container Deployment**
    
    Production-ready containerized deployment with orchestration
    
    - Production container optimization
    - Security-hardened containers
    - Kubernetes/Swarm ready
    - Scalable microservice architecture

    **[Setup Docker Production →](docker-prod.md)**

</div>

---

## Prerequisites

### Common Prerequisites

Before installation, ensure these components are available:

#### Python Environment
- **Python 3.10+** (3.12+ recommended)
- **pip** package manager
- **virtualenv** for environment isolation

#### Node.js Environment
- **Node.js 16+** for frontend asset compilation
- **npm** package manager

#### Network Requirements
- **Inbound connectivity** on configured port (default: 80)
- **Outbound connectivity** for package downloads
- **DNS resolution** for domain names

### Environment-Specific Prerequisites

=== "Development"
    - Git for source code management
    - Text editor or IDE
    - Local development tools

=== "Production"
    - Production database (PostgreSQL recommended)
    - Reverse proxy (Nginx/Apache)
    - TLS certificates
    - System service management

=== "Docker"
    - Docker Engine 20.10+
    - Docker Compose 2.0+
    - Container orchestration (optional)

---

## Quick Start Guide

### 5-Minute Development Setup

=== "macOS / Linux"
    ```bash
    # Clone repository
    git clone https://github.com/ToolsHive/Intrudex.git
    cd Intrudex/Intrudex-Server

    # Setup Python environment
    python3 -m venv venv
    source venv/bin/activate

    # Install dependencies
    pip install -r requirements.txt
    npm install && npm run build

    # Configure environment
    cp .env.example .env

    # Initialize database
    flask db init
    flask db migrate -m "Initial migration"
    flask db upgrade
    flask create-admin

    # Start server
    flask run
    ```

=== "Windows"
    ```powershell
    # Clone repository
    git clone https://github.com/ToolsHive/Intrudex.git
    cd Intrudex/Intrudex-Server

    # Setup Python environment
    python -m venv venv
    .\venv\Scripts\activate

    # Install dependencies
    pip install -r requirements.txt
    npm install
    npm run build

    # Configure environment
    copy .env.example .env

    # Initialize database
    flask db init
    flask db migrate -m "Initial migration"
    flask db upgrade
    flask create-admin

    # Start server
    flask run
    ```

Access the dashboard at: `http://localhost:80`

---

## Configuration Overview

Key configuration parameters:

### Example `.env` Configuration

=== "Required"
    ```bash
    ##################### Required Settings #####################
    FLASK_RUN_PORT=80
    FLASK_RUN_HOST=0.0.0.0
    FLASK_DEBUG=0  # Production: 0, Development: 1

    SECRET_KEY=your-cryptographically-secure-secret-key

    DATABASE_URL=sqlite:///intrudex.sqlite3  # Development
    # DATABASE_URL=postgresql://user:pass@host/db  # Production

    SQLALCHEMY_TRACK_MODIFICATIONS=False

    Mode=development  # or production
    ```

=== "API Keys"
    ```bash
    ##################### API Keys for different services #####################
    SYSMON_API_KEY=<YOUR-API-KEY>
    APPLICATION_API_KEY=<YOUR-API-KEY>
    SECURITY_API_KEY=<YOUR-API-KEY>
    SYSTEM_API_KEY=<YOUR-API-KEY>
    ```

=== "API Enable/Disable"
    ```bash
    ##################### Enable or disable APIs #####################
    SYSMON_API_ENABLED=1
    APPLICATION_API_ENABLED=1
    SECURITY_API_ENABLED=1
    SYSTEM_API_ENABLED=1
    ```

=== "Security Headers"
    ```bash
    ##################### Additional Security Headers #####################
    ALLOWED_CLIENT_IDS=<ALLOWED-CLIENTS-LIST>
    REQUIRED_HEADERS=<REQUIRED-HEADERS>
    ```

---

### Database Options

=== "SQLite (Development)"
    ```bash
    DATABASE_URL=sqlite:///intrudex.sqlite3
    ```
    - No external dependencies
    - Perfect for development
    - Single file database

=== "PostgreSQL (Production)"
    ```bash
    DATABASE_URL=postgresql://username:password@localhost/intrudex
    ```
    - Enterprise-grade reliability
    - Better performance at scale
    - Advanced features support

---

## Security Considerations

### Development Security
- Use development certificates
- Enable debug mode for troubleshooting
- Local network access only

### Production Security
- Use trusted TLS certificates
- Disable debug mode
- Implement proper authentication
- Configure firewall rules
- Regular security updates

---