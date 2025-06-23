# 🛡️ DxdCyberShell v2.0

![Version](https://img.shields.io/badge/Version-2.0-blue?style=for-the-badge)
![Language](https://img.shields.io/badge/Built%20With-Bash-green?style=for-the-badge&logo=gnubash)
![Purpose](https://img.shields.io/badge/Purpose-System%20Recon%20%7C%20Phishing%20Detection%20%7C%20SQLi-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

> A **modular terminal toolkit** for cybersecurity tasks: system monitoring, OSINT, phishing detection, and SQL injection scanning — all in one badass Bash-powered interface.  
> **Made by Chief Dhruvil, for educational and ethical research use.**

---

## 🧰 Features

| Module             | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| 🖥️ **System Monitor**     | Live resource tracking: CPU, memory, ports, uptime, network stats       |
| 🌐 **Info Gathering**     | WHOIS, DNS, traceroute, subdomain/email enumeration using `theHarvester` |
| 🧪 **Phishing Detection** | Scan and classify suspicious URLs with a Python ML script               |
| 💉 **SQL Injection**      | Auto exploit using `sqlmap`, tamper scripts, database dumps, etc.      |
| 🎨 **Color-coded UI**     | Interactive, clean terminal menu with keyboard input navigation        |

---

## 🧱 Tech Stack

- **Bash** – core logic and UI
- **Python** – phishing detection script (`phishingdetection.py`)
- **sqlmap** – powerful SQL injection automation
- **Linux Tools** – whois, dig, nslookup, traceroute, ss, netstat, etc.

---

## 📦 Dependencies

Make sure the following tools are installed:

```bash
sudo apt update
sudo apt install -y whois net-tools dnsutils traceroute \
  python3 python3-pip sqlmap
pip3 install tldextract requests
