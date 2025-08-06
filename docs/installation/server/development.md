---
title: Development Environment Setup
description: Quick development server setup with SQLite database
hide:
  - navigation
---

# Development Environment Setup

This guide provides step-by-step instructions for setting up a development environment of the Intrudex Server. This configuration is ideal for development, testing, and proof-of-concept deployments.

---

## Development Environment Overview

!!! info "Development Configuration"
    The development environment uses SQLite database for simplicity, enables debug mode for detailed logging, and runs on the Flask development server for quick iteration and testing.

### Development Features

- **SQLite Database**: No external database dependencies
- **Debug Mode**: Detailed error messages and auto-reload
- **Hot Reload**: Automatic server restart on code changes  
- **Development Server**: Built-in Flask development server
- **Quick Setup**: Minimal configuration required

---

## Prerequisites

### System Requirements

#### Minimum Specifications
- **Operating System**: Windows 10+, macOS 10.15+, Ubuntu 18.04+
- **Python**: Version 3.8+ (3.10+ recommended)
- **Memory**: 1 GB RAM minimum (2+ GB recommended)
- **Storage**: 5 GB available space
- **Network**: Port 80 available (configurable)

### Required Software

Before beginning, ensure these components are installed:

=== "Windows"
    ```powershell
    # Download Python from python.org
    python --version
    pip --version
    
    # Install Node.js from nodejs.org or via Chocolatey
    choco install nodejs
    node --version
    npm --version
    
    # Install Git
    choco install git
    git --version
    ```

=== "macOS"
    ```bash
    # Install via Homebrew (recommended)
    brew install python@3.13 node git
    
    # Verify installations
    python3 --version
    pip3 --version
    node --version
    npm --version
    git --version
    ```

=== "Ubuntu/Debian"
    ```bash
    # Update package repository
    sudo apt update
    
    # Install required packages
    sudo apt install python3 python3-pip python3-venv nodejs npm git
    
    # Verify installations
    python3 --version
    pip3 --version
    node --version
    npm --version
    git --version
    ```

---

## Installation Process

### Step 1: Repository Acquisition

Clone the Intrudex repository and navigate to the server directory:

```bash
# Clone the repository
git clone https://github.com/ToolsHive/Intrudex.git

# Navigate to server directory
cd Intrudex/Intrudex-Server
```

### Step 2: Python Environment Setup

Create and activate a virtual environment to isolate dependencies:

=== "Linux/macOS"
    ```bash
    # Create virtual environment
    python3 -m venv intrudex-dev-env
    
    # Activate virtual environment
    source intrudex-dev-env/bin/activate
    
    # Verify activation
    which python
    # Should show: /path/to/intrudex-dev-env/bin/python
    ```

=== "Windows"
    ```powershell
    # Create virtual environment
    python -m venv intrudex-dev-env
    
    # Activate virtual environment
    ./intrudex-dev-env\Scripts\activate
    
    # Verify activation
    where python
    # Should show: C:\path\to\intrudex-dev-env\Scripts\python.exe
    ```

### Step 3: Python Dependencies Installation

Install all required Python packages:

```bash
# Ensure virtual environment is activated
pip install --upgrade pip

# Install project dependencies
pip install -r requirements.txt

# Verify key packages
pip show flask flask-migrate flask-sqlalchemy
```

### Step 4: Frontend Dependencies and Build

Install Node.js dependencies and build frontend assets:

```bash
# Install Node.js dependencies
npm install

# Build Tailwind CSS styles for development
npm run build
```

### Step 5: Environment Configuration

Create and configure the development environment file:

```bash
# Create environment configuration file
touch .env  # Linux/macOS
# type nul > .env  # Windows
```

Add the following development configuration to `.env`:

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

### Step 6: Database Initialization

Initialize the SQLite database schema using Flask-Migrate:

```bash
# Initialize migration repository (one-time only)
flask db init

# Generate initial database migration
flask db migrate -m "Initial database schema for development"

# Apply migrations to create database schema
flask db upgrade

# Verify database creation
ls -la *.sqlite3  # Should show intrudex.sqlite3
```

### Step 7: Administrative User Creation

Create an administrative user for dashboard access:

```bash
# Create admin user interactively
flask create-admin

# Follow prompts to set:
# - Admin username
# - Admin password
```

Example output:
```
Admin Username: admin
Admin Password: [hidden]
Confirm Password: [hidden]
Admin user created successfully!
```

### Step 8: Development Server Launch

Start the Flask development server:

```bash
# Start development server
flask run

# Alternative: Use Python directly
# python run.py
```

Expected output:
```
 * Environment: development
 * Debug mode: on
 * Running on http://127.0.0.1:80
 * Restarting with stat
 * Debugger is active!
```

---

## Verification and Testing

### Health Check Verification

Verify the server is running correctly:

```bash
# Test server health endpoint
curl http://localhost:80/

```

### Dashboard Access

1. Open your web browser
2. Navigate to: `http://localhost:80`
3. Login with the admin credentials you created
4. Verify dashboard loads correctly

### API Endpoint Testing

Test key API endpoints:

```bash
# Test authentication endpoint
curl -X POST http://localhost:80/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}'

# Test Logs endpoint
curl http://localhost:80/api/logs
```

---

## Development Workflow

### Daily Development Process

```bash
# 1. Activate virtual environment
source intrudex-dev-env/bin/activate  # Linux/macOS
# intrudex-dev-env\Scripts\activate   # Windows

# 2. Start development server
flask run

# 3. Make code changes - server will auto-reload

# 4. Test changes via browser or API calls
```

### Database Management

```bash
# View current database schema
flask db current

# Create new migration after model changes
flask db migrate -m "Description of changes"

# Apply migrations
flask db upgrade

# Rollback migrations (if needed)
flask db downgrade
```

### Frontend Development

```bash
# Build CSS after changes
npm run build

# Development build (unminified)
npm run dev
```

---

## Troubleshooting

### Common Development Issues

!!! failure "Port Already in Use"
    **Symptom**: `Address already in use` error
    
    **Resolution**:
    ```bash
    # Find process using port 80
    lsof -i :80  # Linux/macOS
    netstat -ano | findstr :80  # Windows
    
    # Kill process or change port in .env
    FLASK_RUN_PORT=8080
    ```

!!! failure "Module Import Errors"
    **Symptom**: `ModuleNotFoundError` when starting server
    
    **Resolution**:
    ```bash
    # Ensure virtual environment is activated
    which python  # Should show venv path
    
    # Reinstall dependencies
    pip install -r requirements.txt
    ```

!!! failure "Database Migration Errors"
    **Symptom**: Migration fails or database locked
    
    **Resolution**:
    ```bash
    # Remove migration files and database
    rm -rf migrations/
    rm intrudex.sqlite3
    
    # Reinitialize
    flask db init
    flask db migrate -m "Initial migration"
    flask db upgrade
    ```

!!! failure "Frontend Build Errors"  
    **Symptom**: CSS not loading or npm build fails
    
    **Resolution**:
    ```bash
    # Clear npm cache and reinstall
    rm -rf node_modules/
    rm package-lock.json
    npm install
    npm run build
    ```

### Development Tips

1. **Auto-reload**: The development server automatically restarts when Python files change
2. **Debug Mode**: Detailed error pages help identify issues quickly  
3. **SQLite Browser**: Use tools like DB Browser for SQLite to inspect the database
4. **API Testing**: Use tools like Postman or curl for API endpoint testing
5. **Logging**: Check console output for detailed debug information

---