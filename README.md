# 🔍 Sentinel: Suspicious URL Threat Detector

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/Database-Supabase-green.svg)](https://supabase.com/)

## 🌌 The Sentinel Series (Phase 2)
This project is the **second module** of the **Sentinel Cyber AI** architecture. While Phase 1 handled "Identity" (Passwords), this module acts as the "Eyes" of the system, scanning network traffic and URLs for malicious patterns.

1.  ✅ Password Strength & Security Logic 
2.  👉 **Suspicious URL Detector** (Current)
3.  📧 Phishing Email Analyzer (Planned)
4.  🤖 AI Chatbot for Cyber Awareness (Planned)

---

## 📝 Project Overview
This microservice extracts mathematical and structural features from a given URL and passes them through a heuristic scoring engine to detect phishing attempts, brand impersonation, and malicious routing.

### Key Features
*   **Feature Extraction:** Dissects URLs to count subdomains, measure length, and detect anomalies (like raw IPs or `@` symbols).
*   **Heuristic Engine:** Calculates a risk score out of 100 based on common attacker techniques.
*   **Flask API:** Runs on port 5001 to prevent collisions with other Sentinel microservices.
*   **Supabase Logging:** Automatically logs detected threats and red flags to a PostgreSQL database for audit trails.

---

## 🚀 Getting Started

### Installation
1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/sentinel-url-threat-detector.git](https://github.com/YOUR_USERNAME/sentinel-url-threat-detector.git)
   cd sentinel-url-threat-detector