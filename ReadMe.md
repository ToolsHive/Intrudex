<h1 align="center">🛡️ Intrudex</h1>

<div align="center">
 
 [![Python](https://img.shields.io/badge/PYTHON-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org)
 [![C++](https://img.shields.io/badge/C++-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)](https://isocpp.org)
 [![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows11&logoColor=white)](https://www.microsoft.com/windows)
 
 [![Stars](https://img.shields.io/github/stars/ToolsHive/Intrudex?style=for-the-badge&logo=github&color=yellow)](https://github.com/ToolsHive/Intrudex/stargazers)
 [![Issues](https://img.shields.io/github/issues/ToolsHive/Intrudex?style=for-the-badge&logo=github&color=red)](https://github.com/ToolsHive/Intrudex/issues)
 
 [![License](https://img.shields.io/badge/License-MIT-A855F7?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](https://github.com/ToolsHive/Intrudex/blob/main/LICENSE)
 [![Last Commit](https://img.shields.io/github/last-commit/ToolsHive/Intrudex?style=for-the-badge&logo=github&logoColor=white)](https://github.com/ToolsHive/Intrudex/commits/main)
 
 [![Repo Size](https://img.shields.io/github/repo-size/ToolsHive/Intrudex?style=for-the-badge&logo=github&logoColor=white)](https://github.com/ToolsHive/Intrudex)
 
 
 **Made with ❤️ by [ToolsHive](https://github.com/ToolsHive)**
 
 </div>
 

<h4 align="center">🚀 A cutting-edge, real-time security monitoring system designed to revolutionize your network's defense.</h4>

---

## 📚 Table of Contents
- [📚 Table of Contents](#-table-of-contents)
- [🎯 Introduction](#-introduction)
- [🖼️ Architecture Overview](#️-architecture-overview)
- [🎯 Motivation \& Problem Statement](#-motivation--problem-statement)
- [⭐ Key Features (Expanded)](#-key-features-expanded)
- [🛠️ How It Works](#️-how-it-works)
- [🚀 Demo Scenarios](#-demo-scenarios)
- [🧩 How to Extend](#-how-to-extend)
- [🔒 Security \& Privacy](#-security--privacy)
- [🚧 Known Limitations \& Future Work](#-known-limitations--future-work)
- [🛠️ Technologies Used](#️-technologies-used)
- [🛡️ INTRUDEX Server](#️-intrudex-server)
  - [⚙️ Prerequisites](#️-prerequisites)
  - [📦 Setup Instructions](#-setup-instructions)
    - [1. Clone the Repository](#1-clone-the-repository)
    - [2. Create a Virtual Environment](#2-create-a-virtual-environment)
    - [3. Install Dependencies](#3-install-dependencies)
    - [4. Environment Configuration](#4-environment-configuration)
    - [5. Build Styles](#5-build-styles)
    - [6. Initialize the Database](#6-initialize-the-database)
    - [7. Run the Server](#7-run-the-server)
    - [8. Admin Panel](#8-admin-panel)
- [📜 Code of Conduct](#-code-of-conduct)
- [⚖️ License](#️-license)

---

## 🎯 Introduction
Intrudex is a **state-of-the-art, Sigma-based Intrusion Detection and Prevention System (IPS/IDS)**, specifically designed for **Windows environments**. It features a **hybrid architecture**, combining the efficiency of a **C++ Windows client** for real-time log monitoring with a **Python Flask-based server** for centralized management and a **web dashboard**.

Intrudex leverages **Sigma rules** to detect threats in **Windows Event Logs**, providing **real-time security alerts** and **automatic threat response mechanisms**.

---

## 🖼️ Architecture Overview

```mermaid
flowchart TB
    %% Client Layer
    subgraph "Client Layer" 
        direction TB
        EL["Windows Event Logs"]:::infra
        SM["SysmonManager"]:::client
        SC["SysmonCollector"]:::client
        SE["Sigma Rule Engine"]:::client
        AL["Alert"]:::client
        HC["HttpClient"]:::client
        RE["Response Engine"]:::client
        CFG["Client Config & Rules"]:::doc
        EL -->|collects events| SC
        SC -->|apply rules| SE
        SE -->|generate| AL
        AL -->|send alert| HC
        HC -->|secure REST| API
        SM -->|self-healing| WR
        SM -->|self-healing| TS
    end

    %% External infra for client
    WR["Windows Registry"]:::infra
    TS["Task Scheduler"]:::infra

    %% API Layer inside Docker
    subgraph "Docker Container" 
        direction TB
        subgraph "REST API Layer"
            direction TB
            API["Flask REST API"]:::api
            API -->|"POST /auth"| AuthAPI
            API -->|"POST /logs"| LogsAPI
            API -->|"GET /main"| MainAPI
            API -->|"error handlers"| ErrorsAPI
        end

        %% Server Layer
        subgraph "Server Layer"
            direction TB
            SI["App Init"]:::server
            DBS["DB Setup & Migrations"]:::server
            subgraph "Models"
                AUTHM["User Model"]:::server
                LOGM["Log Model"]:::server
            end
            subgraph "Routes"
                AuthAPI["/auth endpoints"]:::server
                LogsAPI["/logs endpoints"]:::server
                MainAPI["/main/dashboard"]:::server
                ErrorsAPI["Error Handlers"]:::server
            end
            subgraph "Views & Assets"
                TPL["Jinja2 Templates"]:::view
                STA["Static Assets (TailwindCSS)"]:::view
            end
            CLI["Admin CLI"]:::server
            SI -->|loads config| DBS
            DBS -->|uses models| AUTHM
            DBS -->|uses models| LOGM
            AuthAPI -->|CRUD| AUTHM
            LogsAPI -->|CRUD| LOGM
            MainAPI -->|render| TPL
            TPL -->|styles| STA
            CLI -->|migrations| DBS
        end

        %% Database
        DB["SQLAlchemy DB"]:::db
        DBS -->|connect| DB
        API -->|DB ops| DB
    end

    %% Styles
    classDef client fill:#AEDFF7,stroke:#0366D6,color:#000
    classDef server fill:#FFDDAA,stroke:#D2691E,color:#000
    classDef infra fill:#E2E2E2,stroke:#999,color:#000
    classDef api fill:#C8E6C9,stroke:#388E3C,color:#000
    classDef db fill:#F3E5F5,stroke:#7B1FA2,color:#000
    classDef view fill:#FFF9C4,stroke:#FBC02D,color:#000
    classDef doc fill:#D7CCC8,stroke:#5D4037,color:#000
```

---

## 🎯 Motivation & Problem Statement

Modern Windows environments are under constant threat from malware, insider attacks, and misconfigurations. Traditional antivirus solutions often miss advanced threats. **Intrudex** provides a real-time, Sigma rule-based detection and response system, empowering defenders with instant visibility and automated response.

---

## ⭐ Key Features (Expanded)

- **Real-Time Log Collection:**
  Collects Windows Event Logs and Sysmon logs with minimal performance impact.

- **Sigma Rule Engine:**
  Converts human-readable Sigma rules into actionable detections.  
  *Add your own rules in YAML format—no code required!*

- **LOLBins & Suspicious Tool Detection:**
  Instantly detects use of common living-off-the-land binaries (LOLBins) and admin tools, even if attackers try to blend in.

- **Native Windows Notifications:**
  Alerts appear instantly on the desktop, showing event details, rule names, and more.

- **Centralized Web Dashboard:**
  View all alerts, logs, and rule matches in a modern Flask-based dashboard.

- **Self-Healing & Tamper Protection:**
  Uses registry and scheduled tasks to ensure the agent cannot be easily disabled.

- **Easy Integration:**
  REST API for log shipping, remote commands, and integration with SIEM/SOAR platforms.

---

## 🛠️ How It Works

1. **Log Collection:**
   The C++ client subscribes to Windows Event Logs and Sysmon.

2. **Rule Matching:**
   Each event is checked against all loaded Sigma rules and a list of suspicious tools (LOLBins).

3. **Alerting:**
   On a match, the client:
   - Shows a Windows notification
   - Sends the event to the Flask server
   - Optionally takes automated response actions

4. **Dashboard:**
   The Flask server displays all alerts, allows rule management, and provides analytics.

---

## 🚀 Demo Scenarios

- **Test 1: PowerShell Detection**  
  Open PowerShell and run any command.  
  > You’ll see a Windows notification:  
  > “Shell Command Detected: PowerShell or CMD process detected by Sigma rules.”

- **Test 2: LOLBin Detection**  
  Run `certutil.exe` or `wmic.exe` from CMD.  
  > Notification:  
  > “Suspicious Tool Detected: certutil.exe”

- **Test 3: Sigma Rule Match**  
  Trigger an event that matches a Sigma rule (e.g., failed logon).  
  > Notification shows EventID and RuleName.

- **Test 4: Dashboard**  
  Open the web dashboard to view all alerts and logs in real time.

---

## 🧩 How to Extend

- **Add New Sigma Rules:**  
  Place new YAML files in the rules directory and restart the client.

- **Add New Collectors:**  
  Implement a new collector class and register it in `main.cpp`.

- **Integrate with SIEM:**  
  Use the REST API to forward alerts to your SIEM or SOAR platform.

---

## 🔒 Security & Privacy

- All communication between client and server is authenticated and encrypted.
- No sensitive data is stored unencrypted.
- Only authorized users can access the dashboard and API.

---

## 🚧 Known Limitations & Future Work

- Currently supports only Windows Event Logs and Sysmon.
- Linux/Mac support planned for future versions.
- More advanced response actions (e.g., network isolation) are in development.

---

## 🛠️ Technologies Used

| Component           | Technology Used          |
|---------------------|--------------------------|
| **Windows Client**  | C++ (WinAPI, Sigma)      |
| **Threat Detection**| Sigma Rules (YAML)       |
| **Web Dashboard**   | Python (Flask, TailwindCSS) |
| **Database**        | SQLite                   |
| **Remote Communication** | REST API (Flask)    |
| **Self-Healing**    | Windows Registry, Task Scheduler |
| **Installer**       | NSIS / INNO                    |

---

## 🛡️ INTRUDEX Server

The **INTRUDEX Server** is the server-side component of the Intrusion Detection and Prevention System. It provides a Flask-based REST API and centralized dashboard for monitoring threats, managing Sigma rules, and logging events from Windows clients.

---

### ⚙️ Prerequisites
- Python 3.8+
- Git
- NodeJs , NPM
- (Optional) PostgreSQL (if not using SQLite)

---

### 📦 Setup Instructions

#### 1. Clone the Repository
```bash
git clone https://github.com/ToolsHive/Intrudex.git
cd Intrudex/Intrudex-Server
```

#### 2. Create a Virtual Environment
```bash
python -m venv .venv
./.venv/Scripts/activate    # On Windows
# or
source .venv/bin/activate   # On Linux/macOS
```

#### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

#### 4. Environment Configuration
Create a `.env` file in the root of the project:

``` .env
FLASK_RUN_PORT=80
FLASK_RUN_HOST=127.0.0.1
FLASK_DEBUG=1
SECRET_KEY=your-super-secret-key
DATABASE_URL=sqlite:///intrudex.sqlite3
SQLALCHEMY_TRACK_MODIFICATIONS=False
```

To switch to PostgreSQL, update the `DATABASE_URL`:

``` .env
DATABASE_URL=postgresql://username:password@localhost/intrudex
```

---

#### 5. Build Styles 

Build the tailwind Css for the project

```bash
npm run build
```

---

#### 6. Initialize the Database
Use **Flask-Migrate** to initialize and apply database migrations:

```bash
flask db init         # Run only once to create the migrations folder
flask db migrate -m "Initial migration"
flask db upgrade      # Apply the migration to your database
flask create-admin
```

You will be prompted to enter:
- Admin username
- Admin password (hidden input)
- Confirm password

---

#### 7. Run the Server
Ensure your `.env` file is ready, then run:

```bash
flask run
```
or

```bash
python run.py
```

---

#### 8. Admin Panel
- **URL**: [http://localhost](http://localhost)  
- **Access**: Use the credentials set during Migration.

---

## 📜 Code of Conduct
We follow the [Contributor Covenant](https://contributor-covenant.org).

---

## ⚖️ License
Intrudex is released under the [MIT LICENSE](LICENSE).

---

**Intrudex** – Defend. Detect. Respond.  
*Empowering your Windows security with real-time intelligence.*