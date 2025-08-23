# ShodanGUI — Professional Edition  

🚀 **ShodanGUI** is an advanced **Tkinter-based GUI for the Shodan API**, built to streamline reconnaissance, asset intelligence, and vulnerability-centric hunting. Designed for **bug bounty hunters**, **security researchers**, and **security engineers**, it brings powerful Shodan features into a clean, interactive desktop interface.  

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" />
  <img src="https://img.shields.io/badge/UI-Tkinter-orange.svg" />
  <img src="https://img.shields.io/badge/API-Shodan-red.svg" />
</p>  

---

## ✨ Features  

- **🔍 Advanced Search Builder**  
  - Keywords, port, country, city, org/ISP, OS, hostname, CIDR, product, version  
  - One-click toggles: `has_vuln:true` and `has_screenshot:true`  

- **👁 Host Intelligence**  
  - Live host lookup & historical banner data  
  - Exposure details: open ports, vulns, org, OS  

- **⚡ InternetDB Quick Lookup** *(No API key required)*  
  - Open ports, hostnames, CPEs, CVEs  

- **🌐 Domain Intelligence**  
  - Subdomains and DNS records via Shodan DNS DB  

- **🛡 Vulnerability Hunting**  
  - CVE-driven queries with automatic `has_vuln:true` filter  

- **🌍 Community Queries**  
  - Fetch and reuse popular Shodan searches  

- **📡 On-Demand Scans**  
  - Submit new scans for IP / CIDR (subject to API quota)  

- **🚨 Alerts Management**  
  - List, create, and delete network alerts directly  

- **📤 Export**  
  - Save results in JSON or CSV for reporting and pipelines  

- **💡 Smooth UX**  
  - Threaded operations with Abort, buffered console, colorized logs, status bar  

---

## ⚙️ Prerequisites  

- Python **3.8+**  
- A **Shodan account & API key** (required for most features; InternetDB works without a key)  

---

## 🔧 Installation  
- `git clone https://github.com/Mr-rakeshnaik/ShodanGUI.git`
- `cd ShodanGUI`
- `python -m venv .venv`
- **Linux/macOS:** `source .venv/bin/activate`
- **Windows:** `.venv\Scripts\activate`
- **Install dependencies:** `pip install shodan`


---

## 🔑 API Key Setup  

Two ways to provide your **Shodan API Key**:  

1. **GUI Method** → Enter/paste directly when prompted in the app  
2. **File Method** → Create a text file in repo root named `shodan_api.key` containing only your API key  

> ⚡ *InternetDB tab works without an API key*  

---

## ▶️ Usage  

- **Run the app:**
`python Shodan_GUI_App.py`

---

### Core Workflows  

- **Advanced Search** → Build filters (e.g. `port:443 country:US org:Cloudflare os:Linux`) and run. View or facet results.  
- **Host Lookup** → Enter IP → fetch live exposure & history.  
- **InternetDB** → Quick IP lookups (no credits).  
- **Domain Intelligence** → Input a domain → get subdomains & DNS data.  
- **Vulnerabilities** → Query CVEs (`vuln:CVE-2024-1234`) or vuln-enriched searches.  
- **Community Queries** → Browse popular Shodan queries & reuse.  
- **Scans** → Trigger IP/CIDR scans (requires API credits).  
- **Alerts** → Manage alerts (list, create, delete).  
- **Export** → Save results as CSV/JSON.  

---

## 🛠 File Overview  

- **`Shodan_GUI_App.py`** – Main application entry point  
  - Implements Tkinter GUI with tabs:  
    - Advanced Search  
    - Host Lookup  
    - InternetDB  
    - Domain Info  
    - Vulnerability Search  
    - Community Queries  
    - On-Demand Scan  
    - Alerts  
  - Threaded execution, abort mechanism  
  - API key loader (`shodan_api.key`)  
  - Export tools (JSON/CSV)  

---

## 📌 Tips & Best Practices  

- Begin with **“Get Stats (Facets)”** to refine scope before running heavy searches.  
- Use **InternetDB** for fast triage without burning credits.  
- **Export CSV** for downstream processing, dashboards, and reporting.  
- Use **Host History** to investigate exposure timelines.  
- Narrow filters to optimize **credits & time**.  

---

## 🐛 Troubleshooting  

- **No/Invalid API Key** → Enter a valid key in GUI or `shodan_api.key`.  
- **Rate/Quota Errors** → Check your Shodan plan. Advanced features may require higher tiers.  
- **Missing Tkinter (Linux)** → `sudo apt-get install python3-tk`  
- **Frozen UI** → Use Abort. Retry with narrower queries and stable network.  

---

## 🔒 Security & Ethics  

- Use this tool **only on targets you are authorized to test**  
- Respect **local laws, Shodan ToS, & provider policies**  
- Handle exported intelligence with care – it may contain sensitive details  

---

## 🤝 Contributing  

Contributions are always welcome!  

1. Fork the project  
2. Create a new feature branch  
3. Ensure code style consistency and add tests where needed  
4. Submit a PR with a clear description & screenshots of UI changes  

---

## 📜 License  

This project is licensed under the **MIT License**.  

---

## 🙏 Acknowledgments  

- Thanks to the **Shodan ecosystem** for building a powerful internet scanning and intelligence platform.  
- The **security research community**, whose shared knowledge inspires improvements in tooling.  
- Open source contributors and Python/Tkinter community for the frameworks that made this possible.  

---

💡 **ShodanGUI makes Shodan research faster, interactive, and more actionable — perfect for hunters, researchers, and engineers.**
