# CyberSec Intel MCP Tool

Welcome to **CyberSec Intel MCP Tool** — a fully functional, agent-ready MCP server and client that provides real-time vulnerability intelligence and CWE enrichment, built for the Hugging Face Agents & MCP Hackathon 2025.


## Project Summary

This project demonstrates:

- Real-time Threat Intelligence using CISA Known Exploited Vulnerabilities (KEV) Catalog
- CVE Enrichment using CVE-AWG API (CVSS scores, CWE IDs)
- CWE Enrichment via MITRE CWE Web Scraping (consequences, mitigations, etc.)
- MCP-Compliant Server using Gradio with MCP Protocol enabled
- Multi-tool architecture with support for querying latest CVEs and CWE information

## MCP Tools

### Tool 1 — `get_latest_threats`(app.py)
- Fetches latest CVEs from CISA KEV.
- Enriches with CVSS scores (CVE-AWG).
- Further enriches with CWE descriptions, mitigations, and consequences.

### Tool 2 — `get_cwe_details` - This is exposed in a seperate mcp server (python file mcp_server_cwe.py).
- Fetches full CWE information using CWE scraper based on given CWE-ID.

Future work involve extending the tool to automatically map CVEs to ATT&CK techniques

# `client.py` — CyberSec Intel Tool (MCP Client)
The client.py file is a Model Context Protocol (MCP) client built to interact with the CyberSec Intel MCP Tool hosted on Hugging Face Spaces. It enables natural language interaction with cybersecurity tools using OpenAI’s GPT-4 model.

## What This Client Does
Connects to the running MCP server (/gradio_api/mcp/sse endpoint).

Dynamically loads available tools via the MCPClient.

Uses OpenAI GPT-4 (OpenAIServerModel) as the core reasoning engine.

Wraps the model and tools into a CodeAgent from the smolagents framework.

Launches a Gradio-based chat interface where users can ask questions like:

      - "Show me latest threats after 2025-06-01"
      
      - "What is CWE-306 and what are its consequences?"

Returns summarized responses or invokes tools when needed.
