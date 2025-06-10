# CyberSec Intel MCP Tool

Welcome to **CyberSec Intel MCP Tool** — a fully functional, agent-ready MCP server and client that provides real-time vulnerability intelligence and CWE enrichment, built for the Hugging Face Agents & MCP Hackathon 2025.


## Project Summary

This project demonstrates:

- Real-time Threat Intelligence using CISA Known Exploited Vulnerabilities (KEV) Catalog
- CVE Enrichment using CVE-AWG API (CVSS scores, CWE IDs)
- CWE Enrichment via MITRE CWE Web Scraping (consequences, mitigations, etc.)
- MCP-Compliant Server using Gradio with MCP Protocol enabled
- Multi-tool architecture with support for querying latest CVEs and CWE information

## 🌐 MCP Tools

### Tool 1 — `get_latest_threats`(app.py)
- Fetches latest CVEs from CISA KEV.
- Enriches with CVSS scores (CVE-AWG).
- Further enriches with CWE descriptions, mitigations, and consequences.

### Tool 2 — `get_cwe_details` - This is exposed in a seperate mcp server (python file mcp_server_cwe.py).
- Fetches full CWE information using CWE scraper based on given CWE-ID.

Future work involve extending the tool to automatically map CVEs to ATT&CK techniques
