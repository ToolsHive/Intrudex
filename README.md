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

<h4 align="center">🚀 A cutting edge, real time security monitoring system, designed to revolutionize your network's defense.</h4>

### 📚 Table of Contents
- [🎯 Introduction](#-introduction)
- [⭐ Features](#-features)
- [🔧 Installation](#-installation)
  - [📋 Prerequisites](#-prerequisites)
  - [💻 Client Setup](#-client-setup)
  - [🖥️ Server Setup](#️-server-setup)
  - [🚀 Running the System](#-running-the-system)
- [📘 Usage](#-usage)
- [🏗️ System Architecture](#️-system-architecture)
- [🔄 Client-Server Communication](#-client-server-communication)
- [🛠️ Technologies Used](#️-technologies-used)
- [🔍 Sigma Rule Integration](#-sigma-rule-integration)
- [🎯 Sigma: The Backbone of Detection](#-sigma-the-backbone-of-detection)
  - [What is Sigma?](#what-is-sigma)
  - [Why Sigma in Intrudex?](#why-sigma-in-intrudex)
  - [How Intrudex Uses Sigma Rules](#how-intrudex-uses-sigma-rules)
  - [Sigma Compatibility Table](#sigma-compatibility-table)
- [❓ FAQ](#-faq)
- [🔧 Troubleshooting](#-troubleshooting)
- [📜 Code of Conduct](#-code-of-conduct)
- [⚖️ License](#️-license)

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

## 🔧 Installation 

### 📋 Prerequisites
Before you begin, make sure your system meets the following requirements:
- **Python**
- **C++ compiler** (for Windows Client)
- **NSIS/Inno Setup** for creating the installer
- **SQLite/PostgreSQL** for the database
  
### 💻 Client Setup

### 🖥️ Server Setup

### 🚀 Running the System

---

## 📘 Usage

Once the system is running, you can:
- **View logs and alerts** in the web dashboard.
- **Trigger a remote command** from the dashboard to block an IP or kill a malicious process.

---

## 🏗️ System Architecture

Intrudex is based on a **client-server model** with a web-based dashboard for centralized management.

```mermaid 
graph TD
    A[] --> B[]
```

---

## 🔄 Client-Server Communication
This flowchart demonstrates how the client communicates with the server for log storage and report generation.

```mermaid 
graph TD
    A[] --> B[]
```

---

## 🛠️ Technologies Used

| Component | Technology Used |
| --- | --- |
| Windows Client | C++ (WinAPI, Windows Event Log, Sigma) |
| Threat Detection | Sigma Rules (YAML) |
| Web Dashboard | Python (Flask, Bootstrap) |
| Database | SQLite / PostgreSQL |
| Remote Communication | REST API (Flask) |
| Self-Healing | Windows Registry, Task Scheduler |
| Installer | NSIS / Inno Setup |

---

## 🔍 Sigma Rule Integration

- Intrudex parses Sigma rules to detect anomalies and security threats in logs.
- Uses YAML-based Sigma rules to match event logs.
- Example of a Sigma rule for detecting failed logins:
```yml
title: Failed Windows Login Attempts
logsource:
  category: authentication
  product: windows
detection:
  selection:
    EventID: 4625
condition: selection
```

```mermaid 
graph TD
    A[] --> B[]
```

---

## 🎯 Sigma: The Backbone of Detection

### What is Sigma?

Sigma is an open-source, generic signature format for log event detection. Think of it as "Snort/YARA for logs" – it allows security teams to write detection rules that work across diverse log sources (Windows Event Logs, Sysmon, etc.).

### Why Sigma in Intrudex?

- Standardized Threat Detection: Write rules once, apply anywhere – avoids vendor lock-in.
- Community-Driven: Leverage thousands of pre-existing rules from the SigmaHQ repository.
- Flexibility: Customize rules for your environment without reinventing the wheel.

### How Intrudex Uses Sigma Rules
1. Rule Conversion:
Intrudex converts Sigma YAML rules into real-time detection logic for Windows Event Logs.

2. Detection Workflow:

```mermaid 
graph TD
    A[] --> B[]
```

3. Key Features:
    - Automatic Rule Updates: Pull the latest Sigma rules from the community repository.
    - Custom Rules: Add your own Sigma YAML files to sigma_rules/custom/ for tailored detection.
    - Testing: Validate rules against historical logs for accuracy.

### Sigma Compatibility Table

| Sigma Feature | Intrudex Support | Notes |
| --- | --- | --- |
| Windows Event Logs |  Full | Optimized for Sysmon/EventID parsing. |
| Logsource Types | Partial | Supports process_creation, network, etc. |
| Rule Aggregation | Yes | Combine multiple rules for complex threats. |
| Rule Testing |  Basic | Use Sigma CLI for advanced validation. |

---

## ❓ FAQ  
**Q**: Can I use custom Sigma rules?  
**A**: Yes.  

---

## 🔧 Troubleshooting  
**Issue**: Client fails to connect to the server.  
**Solution**:  
- Verify the server IP in `config.json`.  
- Check firewall rules for port `5000`. 

---

## 📜 Code of Conduct  
We follow the [Contributor Covenant](https://contributor-covenant.org).  

---

## ⚖️ License
Intrudex is released under the MIT License.

---
