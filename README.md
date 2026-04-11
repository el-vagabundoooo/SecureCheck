# SecureCheck

Personal Security Audit & Phishing Email Analyzer

Built by Juan Lacia — 2026

## What It Does

**Module 1 — Security Audit**
Scans your own machine and local network for:
- Open ports and running services (nmap)
- SMB exposure (ransomware risk)
- Windows Firewall status
- Nearby Wi-Fi networks with weak security (WEP/Open)

**Module 2 — Phishing Email Analyzer**
Analyses raw email text for:
- Sender/Reply-To/Return-Path mismatches
- SPF/DKIM/DMARC authentication failures
- Urgency and fear language patterns
- Suspicious URLs, IP addresses, brand impersonation
- URL redirect chains
- Suspicious TLDs and domain patterns

Outputs a professional HTML report with risk ratings.

## Requirements

- Python 3.8+
- nmap 7.x (installed separately from nmap.org)
- Windows 10/11

## Installation