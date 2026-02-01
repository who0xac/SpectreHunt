# 🕵️ SpectreHunt

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Platform-Linux-green.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Maintained-Yes-brightgreen.svg" alt="Maintained">
</p>

**SpectreHunt** is a comprehensive, automated Bug Bounty reconnaissance framework that combines multiple tools to discover and analyze attack surfaces. From subdomain enumeration to vulnerability scanning, SpectreHunt automates the entire recon workflow in a single command.

---

## 🎯 Features

### 📡 **Subdomain Enumeration**
- **8 Integrated Tools**: subfinder, findomain, assetfinder, sublist3r, chaos, crtsh, shodan, puredns
- **Smart Deduplication**: Automatically merges and removes duplicate subdomains
- **DNS Resolution**: Resolves subdomains to IP addresses with dnsx

### 🌐 **Live Domain Discovery**
- **httpx Integration**: Fast HTTP/HTTPS probing with technology detection
- **Optimized Settings**: 50 threads, 150 rate limit, 5s timeout
- **Rich Information**: Status codes, content length, titles, technologies, IPs, CDNs

### 🔗 **URL Discovery**
- **Dual Crawlers**: katana (active) + gau (passive)
- **Massive Coverage**: Discovers thousands of URLs per target
- **Smart Merging**: Deduplicates and consolidates all discovered URLs

### 🔍 **GF Pattern Filtering**
- **23 Attack Patterns**: XSS, SQLi, SSRF, LFI, RCE, IDOR, SSTI, and more
- **Organized Output**: Categorizes URLs by vulnerability type
- **Ready for Testing**: Pre-filtered URLs for immediate exploitation attempts

### 🔐 **Sensitive Data Discovery**
- **11 Detection Categories**:
  - Sensitive Parameters (tokens, API keys)
  - Payment Endpoints
  - Admin Panels
  - Auth Endpoints
  - Database Files
  - Config Files
  - Email Addresses
  - Cloud Storage URLs
  - Internal IPs
  - SSH/FTP URLs
  - Other Sensitive Data
- **API Discovery**: Detects REST, GraphQL, and API endpoints
- **JavaScript Analysis**: Extracts secrets from JS files using secretfinder
- **Sensitive Files**: Finds .env, .config, .sql, .db, backups

### 📸 **Screenshot Capture**
- **gowitness**: Visual reconnaissance of all live domains
- **Full Page Screenshots**: Captures entire page, not just viewport
- **High Quality**: 1920x1080 resolution, JPEG format

### 🚨 **Subdomain Takeover**
- **DNS Reaper**: 61+ takeover signatures
- **Fast Scanning**: 100 parallel checks
- **Accurate Detection**: Low false positive rate

### 💣 **Vulnerability Scanning**
- **Nuclei**: All templates from nuclei-templates
- **High Performance**: 200 concurrency, 200 rate limit
- **Severity Tracking**: Critical, High, Medium, Low, Info

### 🗂️ **Directory Fuzzing**
- **ffuf**: Fast web fuzzing
- **Custom Wordlists**: Use your own directory lists
- **Smart Filtering**: Filters 404s, tracks status codes

### 🛡️ **WAF Detection**
- **wafw00f**: Identifies Web Application Firewalls
- **Strategic Planning**: Know your target's defenses

---

## 📦 Installation

### Required Tools

```
subfinder
findomain
assetfinder
sublist3r
chaos
crtsh
shodan
dnsx
puredns
httpx
katana
gau
gf
secretfinder
nuclei
ffuf
gowitness
docker
wafw00f
```

### Clone Repository
```bash
git clone https://github.com/yourusername/SpectreHunt.git
cd SpectreHunt
chmod +x spectrehunt.sh
```

### Setup

**Edit config.env and add your API keys (optional):**
```bash
nano config.env

export SHODAN_API_KEY="your-shodan-api-key"
export CHAOS_API_KEY="your-chaos-api-key"
```

---

## 🚀 Usage

### Basic Scan
```bash
./spectrehunt.sh -d example.com
```

### Check Installed Tools
```bash
./spectrehunt.sh -c
```

### Help Menu
```bash
./spectrehunt.sh -h
```

## 🤝 Contributing

Contributions are highly encouraged and appreciated.
If you want to improve SpectreHunt, add new features, enhance detection logic, optimize performance, or fix bugs, your contributions are welcome.

By contributing, you help make this framework more powerful, efficient, and valuable for the Bug Bounty and security research community.


## ⚠️ Disclaimer

**For educational and authorized testing only. The author will not be responsible for any kind of damage or misuse caused by this tool.**

---

## 🌟 Star History

If you find SpectreHunt useful, please give it a ⭐ on GitHub!

---

<p align="center">Made with ❤️ for the Bug Bounty Community</p>
<p align="center">Happy Hunting! 🎯</p>
