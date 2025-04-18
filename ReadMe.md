<h1 align="center">🛡️ Intrudex</h1>

<div align="center">
 
 [![Python](https://img.shields.io/badge/PYTHON-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org)
 [![C++](https://img.shields.io/badge/C++-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)](https://isocpp.org)
 [![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows11&logoColor=white)](https://www.microsoft.com/windows)
 [![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com)
 
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
- [⭐ Features](#-features)
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

## ⭐ Features
- **Windows Log Monitoring** – Uses **Sysmon** and **Windows Event Logs** for security monitoring.  
- **Sigma Rule-Based Detection** – Converts Sigma rules into **real-time security alerts**.  
- **Standalone & Server Mode** – Can function **independently** or connect to a **Flask-based server**.  
- **Windows Notifications** – Displays **security alerts** natively on Windows.  
- **Automatic Threat Response (IPS)** – Blocks IPs, kills processes, and disables accounts upon threat detection.  
- **Remote Command Execution** – Allows **remote security commands** from the web dashboard.  
- **Self-Healing System** – Uses **registry entries and scheduled tasks** to prevent tampering.  
- **Web Dashboard (Flask)** – Provides **log visualization, rule management, and remote control**.  
- **Public/Private Key Authentication** – Ensures **secure client-server communication**.  
- **Log Backup & Report Generator** – Stores logs in a **database** with export functionality.  

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
| **Installer**       | NSIS                     |

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

```
FLASK_RUN_PORT=80
FLASK_RUN_HOST=127.0.0.1
FLASK_DEBUG=1
SECRET_KEY=your-super-secret-key
DATABASE_URL=sqlite:///intrudex.sqlite3
SQLALCHEMY_TRACK_MODIFICATIONS=False
```

To switch to PostgreSQL, update the `DATABASE_URL`:

```
DATABASE_URL=postgresql://username:password@localhost/intrudex
```

---

#### 5. Build Styles 

Build the tailwind Css for the project

```bash
npm run buils
```

---

#### 6. Initialize the Database
Run the following script to create the database and an admin user:

```bash
python init_db.py
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
- **Access**: Use the credentials set during `init_db.py`.

---

## 📜 Code of Conduct
We follow the [Contributor Covenant](https://contributor-covenant.org).

---

## ⚖️ License
Intrudex is released under the [MIT LICENSE](LICENSE).

---