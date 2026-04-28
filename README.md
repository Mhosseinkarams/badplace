```
██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ 
██╔══██╗██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  
██║  ██║██║  ██║╚██████╔╝██╔╝ ██╗   ██║   
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
```

# RELAY PROXY

> **Forward HTTP traffic through any relay server (Vercel / Google Apps Script)**  
> **Binds to 127.0.0.1 only — Not a VPN — Not an open proxy**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-brightgreen)](https://python.org)
[![Vercel](https://img.shields.io/badge/Vercel-Deploy-black)](https://vercel.com)

**Author:** [v7lthronyx (Aiden Azad)](https://github.com/v74all)  
**GitHub:** [github.com/v74all/badplace](https://github.com/v74all/badplace)

---

## 🇬🇧 English

### What is this?

A **local-only HTTP/HTTPS proxy** that forwards traffic through a relay server.  
It runs on your own machine and routes your HTTP traffic through a relay (Vercel serverless function or Google Apps Script).

**Use cases:**
- Bypass local network restrictions for HTTP traffic
- Route browser traffic through an external relay
- Test how your apps behave behind a proxy
- Access region-restricted HTTP content

### How it works

```
Browser/App → 127.0.0.1:8085 → Relay (Vercel/GAS) → Target Website
```

1. You configure your browser/app to use `127.0.0.1:8085` as HTTP proxy
2. The proxy forwards each request to the relay server via JSON POST
3. The relay fetches the actual URL and returns the response
4. The proxy sends the response back to your browser/app

### Quick Start

```bash
# 1. Clone and enter the project
git clone https://github.com/v74all/badplace.git
cd badplace

# 2. Configure your relay URL
export RELAY_URL='https://your-relay-url.com'

# 3. Run the proxy
./run-local.sh
```

### Prerequisites

- Python 3.9+
- `curl` (for connectivity checks)
- A relay server (Vercel or Google Apps Script)

### Configuration

Edit `config.local.yaml`:

```yaml
mode: vercel              # vercel | apps_script
relay_url: "https://your-project.vercel.app"
bind_host: "127.0.0.1"
bind_port: 8085
mitm_enabled: false       # HTTPS MITM (advanced)
```

Or use environment variables:

```bash
export RELAY_URL='https://your-project.vercel.app'
```

### Deploy Your Own Relay

#### Option 1: Vercel (Recommended)

```bash
# Deploy the relay function to Vercel
npm install -g vercel
vercel deploy

# Or push to GitHub and import on vercel.com
```

The relay function is in `api/relay.js`. After deployment, use the Vercel URL as your `RELAY_URL`.

#### Option 2: Google Apps Script

1. Go to [script.google.com](https://script.google.com)
2. Create a new project
3. Copy the code from `google-apps-script-relay.gs`
4. Deploy as Web App (Execute as: Me, Who has access: Anyone)
5. Use the deployment URL as your `RELAY_URL`

### Browser Setup

**Chromium (isolated profile — recommended):**
```bash
chromium --proxy-server='http://127.0.0.1:8085' \
         --user-data-dir='/tmp/proxy-browser-profile'
```

**Firefox:**
1. `about:preferences` → Network Settings → Manual proxy
2. HTTP Proxy: `127.0.0.1` Port: `8085`
3. Check "Also use this proxy for HTTPS"
4. No Proxy for: `localhost, 127.0.0.1`

**System-wide (CLI tools):**
```bash
export http_proxy='http://127.0.0.1:8085'
export https_proxy='http://127.0.0.1:8085'
export no_proxy='localhost,127.0.0.1'
```

### Health Endpoints

| Endpoint | Description |
|---|---|
| `http://127.0.0.1:8085/health` | Proxy status |
| `http://127.0.0.1:8085/test-google` | Test Google connectivity |
| `http://127.0.0.1:8085/test-relay` | Test relay connection |

### Commands

```bash
./run-local.sh     # Start the proxy
./stop-local.sh    # Stop the proxy
```

### Security

- ✅ Binds to `127.0.0.1` only — no LAN or internet exposure
- ✅ HTTPS MITM disabled by default
- ✅ Cache disabled by default
- ✅ Full URLs, cookies, Authorization headers not logged
- ✅ CA key stored with `chmod 600`
- ❌ **This is NOT a VPN** — only works for apps configured to use the proxy

---

## 🇮🇷 فارسی

### این ابزار چیه؟

یک **پروکسی HTTP/HTTPS محلی** که ترافیک را از طریق یک relay server عبور می‌دهد.  
روی سیستم خودتان اجرا می‌شود و ترافیک HTTP را از طریق Vercel یا Google Apps Script هدایت می‌کند.

**کاربردها:**
- عبور از محدودیت‌های شبکه محلی برای ترافیک HTTP
- هدایت ترافیک مرورگر از طریق یک relay خارجی
- دسترسی به محتوای محدود شده بر اساس منطقه

### نحوه کار

```
مرورگر/برنامه → 127.0.0.1:8085 → Relay (Vercel/GAS) → سایت مقصد
```

### شروع سریع

```bash
# 1. پروژه را clone کنید
git clone https://github.com/v74all/badplace.git
cd badplace

# 2. URL relay خود را تنظیم کنید
export RELAY_URL='https://your-relay-url.com'

# 3. پروکسی را اجرا کنید
./run-local.sh
```

### نصب Relay در Vercel (پیشنهادی)

```bash
# Deploy تابع relay در Vercel
npm install -g vercel
vercel deploy
```

فایل relay در `api/relay.js` قرار دارد. Vercel در ایران فیلتر نیست و سرعت خوبی دارد.

### تنظیمات مرورگر

**Chromium:**
```bash
chromium --proxy-server='http://127.0.0.1:8085' \
         --user-data-dir='/tmp/proxy-browser-profile'
```

**Firefox:**
- `about:preferences` → Network Settings → Manual proxy
- HTTP Proxy: `127.0.0.1` Port: `8085`
- گزینه "Also use this proxy for HTTPS" را فعال کنید

### نکات امنیتی

- ✅ فقط روی `127.0.0.1` اجرا می‌شود
- ✅ HTTPS MITM پیش‌فرض خاموش است
- ✅ Cache پیش‌فرض خاموش است
- ❌ **این یک VPN نیست**

---

## 📁 Project Structure

```
├── proxy.py                  # Main proxy application
├── config.local.yaml         # Local configuration
├── run-local.sh              # Start script
├── stop-local.sh             # Stop script
├── requirements.txt          # Python dependencies
├── api/
│   └── relay.js              # Vercel serverless relay function
├── vercel.json               # Vercel configuration
├── google-apps-script-relay.gs  # Google Apps Script relay
├── .banner                   # ASCII art banner
└── README.md                 # This file
```

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/v74all">v7lthronyx</a></sub>
</p>
