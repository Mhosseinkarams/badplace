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
mode: apps_script         # vercel | apps_script
relay_url: ""
apps_script_url: "https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec"
bind_host: "127.0.0.1"
bind_port: 8085
socks_port: 1081
mitm_enabled: false       # HTTPS MITM (advanced)
doh_enabled: false       # Disable DoH for faster local DNS
```

Or use environment variables:

```bash
export APPS_SCRIPT_URL='https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec'
```

> Note: If your network blocks `script.google.com`, the proxy can still start, but Google Apps Script relay requests will fail. In that case, use Vercel or another relay host.

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

### Troubleshooting & Speed

- If `script.google.com` یا `script.googleusercontent.com` مسدود است، از `Vercel` استفاده کنید.
- `doh_enabled: false` را در `config.local.yaml` قرار دهید تا DNS محلی سریع‌تر شود.
- اگر می‌خواهید پروکسی حتی در صورت شکست چک اتصال اجرا شود، از:
  ```bash
  STRICT_CHECKS=0 ./run-local.sh
  ```
- اگر می‌خواهید اجرای سخت‌گیرانه باشد، از:
  ```bash
  STRICT_CHECKS=1 ./run-local.sh
  ```
- برای تست سرعت:
  ```bash
  curl -x http://127.0.0.1:8085 http://httpbin.org/get
  ```

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

یک **پروکسی HTTP/HTTPS محلی** که ترافیک را از طریق یک سرور relay عبور می‌دهد.  
روی سیستم خودتان اجرا می‌شود و ترافیک HTTP را از طریق Vercel یا Google Apps Script هدایت می‌کند.

**کاربردها:**
- عبور از محدودیت‌های شبکه محلی برای ترافیک HTTP
- هدایت ترافیک مرورگر از طریق یک relay خارجی
- تست رفتار برنامه‌ها پشت پروکسی
- دسترسی به محتوای محدود شده بر اساس منطقه

### نحوه کار

```
مرورگر/برنامه → 127.0.0.1:8085 → Relay (Vercel/GAS) → سایت مقصد
```

1. مرورگر/برنامه خود را برای استفاده از `127.0.0.1:8085` به عنوان پروکسی HTTP تنظیم کنید
2. پروکسی هر درخواست را به صورت JSON POST به سرور relay ارسال می‌کند
3. Relay URL واقعی را fetch کرده و پاسخ را برمی‌گرداند
4. پروکسی پاسخ را به مرورگر/برنامه شما ارسال می‌کند

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

### پیش‌نیازها

- Python 3.9+
- `curl` (برای چک اتصال)
- یک سرور relay (Vercel یا Google Apps Script)

### تنظیمات

فایل `config.local.yaml` را ویرایش کنید:

```yaml
mode: apps_script        # vercel | apps_script
relay_url: ""
apps_script_url: "https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec"
bind_host: "127.0.0.1"
bind_port: 8085
socks_port: 1081         # پورت SOCKS5
doh_enabled: false       # DNS-over-HTTPS غیرفعال برای سرعت بیشتر
mitm_enabled: false      # HTTPS MITM (پیشرفته)
```

یا از متغیرهای محیطی استفاده کنید:

```bash
export APPS_SCRIPT_URL='https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec'
```

> توجه: اگر شبکه‌ی شما `script.google.com` را بلاک کند، پروکسی اجرا می‌شود اما ارسال درخواست به Google Apps Script با خطا مواجه خواهد شد. در این حالت `Vercel` انتخاب بهتری است.

### نصب Relay خودتان

#### گزینه 1: Vercel (پیشنهادی - سریع‌تر)

```bash
# نصب Vercel CLI
npm install -g vercel

# Deploy تابع relay
vercel deploy
```

فایل relay در `api/relay.js` قرار دارد. بعد از deploy، URL Vercel را به عنوان `RELAY_URL` استفاده کنید.

#### گزینه 2: Google Apps Script

1. به [script.google.com](https://script.google.com) بروید
2. یک پروژه جدید ایجاد کنید
3. کد را از `google-apps-script-relay.gs` کپی کنید
4. به عنوان Web App deploy کنید (Execute as: Me, Who has access: Anyone)
5. URL deployment را به عنوان `APPS_SCRIPT_URL` استفاده کنید

### تنظیمات مرورگر

**Chromium (پروفایل ایزوله - توصیه می‌شود):**
```bash
chromium --proxy-server='http://127.0.0.1:8085' \
         --user-data-dir='/tmp/proxy-browser-profile'
```

**Firefox:**
1. `about:preferences` → Network Settings → Manual proxy
2. HTTP Proxy: `127.0.0.1` Port: `8085`
3. تیک "Also use this proxy for HTTPS"
4. No Proxy for: `localhost, 127.0.0.1`

**ابزارهای CLI (سیستم‌گسترده):**
```bash
export http_proxy='http://127.0.0.1:8085'
export https_proxy='http://127.0.0.1:8085'
export no_proxy='localhost,127.0.0.1'
```

### نقاط پایانی سلامت

| نقطه پایانی | توضیح |
|---|---|
| `http://127.0.0.1:8085/health` | وضعیت پروکسی |
| `http://127.0.0.1:8085/test-google` | تست اتصال گوگل |
| `http://127.0.0.1:8085/test-relay` | تست اتصال relay |

### دستورات

```bash
./run-local.sh     # شروع پروکسی
./stop-local.sh    # توقف پروکسی
```

### امنیت

- ✅ فقط به `127.0.0.1` bind می‌شود — هیچ دسترسی LAN یا اینترنت
- ✅ HTTPS MITM به طور پیش‌فرض غیرفعال
- ✅ کش به طور پیش‌فرض غیرفعال
- ✅ URL کامل، کوکی‌ها، هدر Authorization لاگ نمی‌شوند
- ✅ کلید CA با `chmod 600` ذخیره می‌شود
- ❌ **این VPN نیست** — فقط برای برنامه‌هایی که پروکسی را تنظیم کرده‌اند کار می‌کند

### بهینه‌سازی سرعت

برای بهبود سرعت:
- از Vercel به جای Google Apps Script استفاده کنید (سریع‌تر است)
- DoH را غیرفعال کنید (`doh_enabled: false`)
- لاگ‌ها را در Google Script حذف کنید
- تایم‌اوت را کاهش دهید (در کد تغییر دهید)
- اتصال‌های مستقیم HTTPS ممکن است در شبکه‌های محدود شکست بخورند

### تست سرعت

برای تست سرعت پروکسی:

```bash
# تست سلامت پروکسی
curl http://127.0.0.1:8085/health

# تست اتصال گوگل
curl http://127.0.0.1:8085/test-google

# تست relay
curl http://127.0.0.1:8085/test-relay

# تست سرعت با سایت واقعی
time curl -x http://127.0.0.1:8085 http://httpbin.org/get
```

### عیب‌یابی

- **پورت اشغال شده**: پورت‌ها را چک کنید و پروسه‌های قبلی را بکشید
- **اتصال relay شکست خورد**: URL relay را چک کنید یا از Vercel استفاده کنید
- **سرعت کم**: از Vercel استفاده کنید، DoH را غیرفعال کنید
- **HTTPS کار نمی‌کند**: این پروکسی فقط HTTP را relay می‌کند، HTTPS مستقیم است

---bash
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
