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
- [🛠️ Technologies Used](#️-technologies-used)
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

## 🛠️ Technologies Used

| Component | Technology Used |
| --- | --- |
| Windows Client | C++ (WinAPI, Windows Event Log, Sigma) |
| Threat Detection | Sigma Rules (YAML) |
| Web Dashboard | Python (Flask, TailwindCss) |
| Database | SQLite / PostgreSQL |
| Remote Communication | REST API (Flask) |
| Self-Healing | Windows Registry, Task Scheduler |
| Installer | NSIS |

---

## 📜 Code of Conduct  
We follow the [Contributor Covenant](https://contributor-covenant.org).  

---

## ⚖️ License
Intrudex is released under the MIT License.

---
