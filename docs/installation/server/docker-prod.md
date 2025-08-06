---
title: Docker Production Deployment
description: Enterprise Docker deployment with orchestration, security, and high availability
hide:
  - navigation
---

# Docker Production Deployment

This guide provides comprehensive instructions for deploying the Intrudex Server in production using Docker containers with enterprise-grade orchestration, security hardening, and high availability configurations.

---

## Production Docker Overview

!!! info "Production Container Features"
    The production Docker deployment includes multi-stage builds, security hardening, health checks, auto-scaling, load balancing, and comprehensive monitoring with Docker Swarm or Kubernetes orchestration.

### Production Container Architecture

```mermaid
graph TB
    subgraph "Load Balancer Layer"
        LB[Load Balancer]
        SSL[SSL Termination]
    end
    
    subgraph "Container Orchestration"
        subgraph "Web Tier"
            WEB1[Web Container 1]
            WEB2[Web Container 2]
            WEB3[Web Container 3]
        end
        
        subgraph "Database Tier"
            DB_PRIMARY[(PostgreSQL Primary)]
            DB_REPLICA[(PostgreSQL Replica)]
        end
        
        subgraph "Cache Tier"
            REDIS_MASTER[(Redis Master)]
            REDIS_REPLICA[(Redis Replica)]
        end
    end
    
    subgraph "Infrastructure Services"
        MONITOR[Monitoring]
        LOGS[Log Aggregation]
        BACKUP[Backup Service]
        REGISTRY[Container Registry]
    end
    
    LB --> SSL
    SSL --> WEB1
    SSL --> WEB2
    SSL --> WEB3
    WEB1 --> DB_PRIMARY
    WEB2 --> DB_PRIMARY
    WEB3 --> DB_PRIMARY
    DB_PRIMARY --> DB_REPLICA
    WEB1 --> REDIS_MASTER
    WEB2 --> REDIS_MASTER
    WEB3 --> REDIS_MASTER
    REDIS_MASTER --> REDIS_REPLICA
    
    MONITOR --> WEB1
    MONITOR --> WEB2
    MONITOR --> WEB3
    LOGS --> WEB1
    LOGS --> WEB2
    LOGS --> WEB3
    BACKUP --> DB_PRIMARY
    REGISTRY --> WEB1
    REGISTRY --> WEB2
    REGISTRY --> WEB3
    
    style DB_PRIMARY fill:#336791
    style REDIS_MASTER fill:#dc382d
    style WEB1 fill:#3498db
    style WEB2 fill:#3498db
    style WEB3 fill:#3498db
```

---

## Production Images

### Docker Hub Images

The official Intrudex Docker images are available on Docker Hub:

```bash
# Server Application - Development
docker pull armoghan/intrudex-server:1.0.0-dev

# Server Application - Production
docker pull armoghan/intrudex-server:1.0.0-prod

```

### GitHub Container Registry

Alternative images from GitHub Container Registry:

```bash
# Server Application - Development
docker pull ghcr.io/toolshive/intrudex:1.0.0-dev

# Server Application - Production
docker pull ghcr.io/toolshive/intrudex:1.0.0-prod

# Authentication required for private repositories
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
```

---

## Running the Containers

After pulling the images, run the production container with:

```bash
docker run -d --name intrudex-server-prod \
  -p 8080:8080 \
  -e DATABASE_URL=postgres://user:password@dbhost:5432/intrudex \
  -e REDIS_URL=redis://redishost:6379/0 \
  armoghan/intrudex-server:1.0.0-prod
```

For GitHub Container Registry image:

```bash
docker run -d --name intrudex-server-prod \
  -p 8080:8080 \
  -e DATABASE_URL=postgres://user:password@dbhost:5432/intrudex \
  -e REDIS_URL=redis://redishost:6379/0 \
  ghcr.io/toolshive/intrudex:1.0.0-prod
```

Adjust environment variables and ports as needed for your setup.

---
