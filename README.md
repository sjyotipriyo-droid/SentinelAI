<div align="center">

# 🛡️ SentinelAI — Autonomous Tier-3 SOC Threat Hunter & SIEM Dashboard

**Feed it raw web server logs. Get back the attackers, the MITRE ATT&CK mapping, and the firewall rules to stop them.**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)](https://sentinel-ai-theta-cyan.vercel.app/)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Next.js 16](https://img.shields.io/badge/Next.js-16-000000?style=for-the-badge&logo=nextdotjs&logoColor=white)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Google Gemini](https://img.shields.io/badge/Google%20Gemini-AI-8E75B2?style=for-the-badge&logo=googlegemini&logoColor=white)](https://ai.google.dev/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-E32636?style=for-the-badge)](https://attack.mitre.org/)

[Live Demo](https://sentinel-ai-theta-cyan.vercel.app/) · [Source Code](https://github.com/sjyotipriyo-droid/SentinelAI)

</div>

---

## 🌟 What is SentinelAI?

### The plain-English version

Every time someone visits a website, the web server writes one line in a text file: who asked (their IP address), when, what they asked for, and whether the server said yes or no. That file is the **server access log**. A busy site produces thousands of these lines every hour.

Hidden in those lines are the footprints of attackers: someone trying to trick the database, someone hunting for files they shouldn't see, someone guessing passwords. Finding them by eye is like watching days of security-camera footage to spot one burglar.

That is the daily job of a **SOC (Security Operations Center)**: a team that watches for attacks. They use a **SIEM (Security Information and Event Management)** dashboard to collect and display security data in one place. The trouble is **alert fatigue**: when tools raise too many alerts, analysts drown in noise and real attacks get missed.

**SentinelAI acts as an automated cyber detective and AI incident responder.** It reads your raw logs, picks out the genuine attack patterns, finds out who the attackers are, and writes a ready-to-use incident report with the exact commands to block them.

> ### ⚡ Try It Live
> Open **https://sentinel-ai-theta-cyan.vercel.app/** to see the SIEM dashboard in action.

<details>
<summary><b>New to this? Quick glossary</b></summary>

<br>

| Term | Plain meaning |
|---|---|
| **Access log** | A text file where the web server records every request it receives |
| **SOC** | Security Operations Center: the team that monitors and responds to attacks |
| **SIEM** | A dashboard that gathers security data from many sources in one place |
| **Tier-3 analyst** | The most senior SOC role: threat hunting, deep investigation, and writing the fix |
| **MITRE ATT&CK** | A public catalog of real attacker techniques, each with an ID like `T1190` |
| **IOC** | Indicator of Compromise: a clue such as a malicious IP or a suspicious URL |
| **ASN** | Autonomous System Number: identifies the network (often a hosting provider) behind an IP |
| **WAF** | Web Application Firewall: filters malicious web requests before they reach your app |
| **TLP** | Traffic Light Protocol: a label (RED, AMBER, GREEN, CLEAR) saying how widely a report can be shared |

</details>

<details>
<summary><b>Anatomy of one log line</b></summary>

<br>

````text
203.0.113.45 - - [24/Oct/2026:02:14:07 +0000] "GET /products.php?id=1 HTTP/1.1" 200 5123 "-" "Mozilla/5.0"
|            |   |                             |                                |   |    |   |
|            |   |                             |                                |   |    |   +-- User-Agent (client software)
|            |   |                             |                                |   |    +------ Referrer
|            |   |                             |                                |   +----------- Response size (bytes)
|            |   |                             |                                +--------------- HTTP status code
|            |   |                             +-------------------------------------------- Request (method, path, query)
|            |   +-------------------------------------------------------------------------- Timestamp
|            +------------------------------------------------------------------------------ Identity fields (usually "-")
+------------------------------------------------------------------------------------------ Client IP address
````

</details>

---

## 🏗️ System Architecture & Threat Hunting Workflow

SentinelAI runs as a five-stage pipeline, from raw telemetry to enforceable remediation.

````text
 +---------------------------------+
 |  RAW APACHE / NGINX ACCESS LOGS |
 |  (unstructured text telemetry)  |
 +----------------+----------------+
                  |
                  v
 +------------------------------------------------+
 |  STAGE 1: SIGNATURE & HEURISTIC ENGINE         |
 |  - Regex parsing of the access log format      |
 |  - Attack-pattern signatures per vector        |
 |  - Behavioral heuristics (request frequency,   |
 |    status-code sequences, repeated targets)    |
 +----------------------+-------------------------+
                        |  flagged events
                        v
 +------------------------------------------------+
 |  STAGE 2: LIVE OSINT & MITRE ATT&CK MAPPER     |
 |  - ip-api: geolocation, ISP, ASN per attacker  |
 |  - Maps each vector to a MITRE technique ID    |
 |    (T1190, T1083, T1059.007, T1110)            |
 +----------------------+-------------------------+
                        |  enriched incident data
                        v
 +------------------------------------------------+
 |  STAGE 3: AUTONOMOUS GEMINI TIER-3 SOC ANALYST |
 |  - Correlates events into an incident          |
 |  - Judges impact from status codes and sizes   |
 |  - Writes a TLP-graded IR report in Markdown   |
 +----------------------+-------------------------+
                        |
                        v
 +------------------------------------------------+
 |  STAGE 4: REMEDIATION OUTPUT                   |
 |  +----------------------+ +------------------+ |
 |  | Firewall rules       | | WAF + code fixes | |
 |  | iptables / ufw DROP  | | ModSecurity      | |
 |  |                      | | SecRule patches  | |
 |  +----------------------+ +------------------+ |
 +------------------------------------------------+

 Delivered through two interchangeable front ends:
   [ Python CLI (rich terminal UI) ]   [ Next.js SIEM web dashboard ]
````

---

## 🔍 Deep-Dive: Detected Threat Vectors & MITRE ATT&CK Matrix

| Threat vector | MITRE ATT&CK technique | Tactic focus |
|---|---|---|
| **SQL Injection (SQLi)** | `T1190` Exploit Public-Facing Application | Initial Access |
| **Directory Traversal / LFI** | `T1083` File and Directory Discovery | Discovery |
| **Reflected Cross-Site Scripting (XSS)** | `T1059.007` Command and Scripting Interpreter: JavaScript | Execution |
| **Credential Brute-Force / Stuffing** | `T1110` Brute Force | Credential Access |

### How to read HTTP status codes during triage

| Code | Beginner meaning | What it signals to an analyst |
|---|---|---|
| `200` | "OK, here is what you asked for" | The request succeeded. For an attack, this is the most dangerous outcome and needs a closer look at response size |
| `401` | "You are not authenticated" | A failed login. In volume, this is the signature of brute force |
| `403` | "Forbidden" | The request was blocked by access rules or a WAF. The control worked |
| `500` | "The server broke" | The input caused an unhandled error. Often seen when injection probes hit fragile code |

> Access logs record the **request** and its **status and size**, not the response body. These indicators suggest impact but do not prove it, so SentinelAI reports them as indicators and recommends verification.

### 1. SQL Injection (SQLi) · `T1190`

- **For beginners:** The attacker types database commands into a website's search box or URL to trick it into handing over data it shouldn't, such as usernames and passwords.
- **For advanced engineers:** Look for `UNION SELECT`, `OR 1=1`, `information_schema`, `SLEEP(`, comment terminators (`--`, `#`), and URL-encoded quotes (`%27`) in query strings. Scanner user agents such as `sqlmap` are a strong secondary signal. A `500` often indicates error-based probing, a `403` indicates a block, and a `200` with a response size far larger than the same endpoint normally returns suggests data may have been extracted.

### 2. Directory Traversal / Local File Inclusion · `T1083`

- **For beginners:** The attacker uses `../` (meaning "go up one folder") to climb out of the website's folder and read private files on the server, like password files.
- **For advanced engineers:** Look for `../`, `..%2f`, `%2e%2e%2f`, double-encoded variants, and targets such as `/etc/passwd`, `/etc/shadow`, or `win.ini`. Pay attention to the status: a `200` with a plausible file-sized response to a traversal request should be treated as probable disclosure, while `403` and `404` indicate the request was rejected or the path did not exist.

### 3. Reflected Cross-Site Scripting (XSS) · `T1059.007`

- **For beginners:** The attacker crafts a link containing hidden JavaScript. If a victim clicks it, the site echoes the script back and the victim's browser runs it, which can steal their session.
- **For advanced engineers:** Look for `<script>`, `%3Cscript%3E`, `onerror=`, `onload=`, and `javascript:` in query parameters. Because the payload executes client-side, the access log only shows the delivery attempt. A `200` indicates the page rendered, which is consistent with possible reflection, so verification requires testing the endpoint.

### 4. Credential Brute-Force / Stuffing · `T1110`

- **For beginners:** The attacker tries huge numbers of passwords, or stolen username/password pairs from other breaches, until one logs in.
- **For advanced engineers:** Look for high-frequency `POST` requests from one source to login endpoints (`/login`, `/wp-login.php`, `/admin`), dominated by `401` responses. Rotating usernames from one IP points to credential stuffing. A run of `401`s followed by a `200` from the same IP is the key escalation signal, because it can mean a successful login. Relevant sub-techniques include `T1110.001` (password guessing) and `T1110.004` (credential stuffing).

---

## 🧠 Autonomous AI Incident Response Engine

Once the detection engine has produced enriched incident data, **Google Gemini** takes the role of a **Tier-3 SOC Analyst** and writes a complete, **TLP-graded** incident response report in Markdown.

| Report section | What it contains |
|---|---|
| **Executive Breach Summary** | A short, non-technical summary of what happened, the likely impact, and the urgency, written for management |
| **Attacker Geo / ASN Matrix** | Per attacker IP: country, city, ISP, ASN, and the attack vectors observed, enriched live through `ip-api` |
| **Perimeter Containment** | Copy-paste `ufw` and `iptables` rules that drop traffic from the attacking IPs |
| **Code-Level & WAF Patches** | Secure-coding fixes for the vulnerable endpoint, plus ModSecurity `SecRule` patches that block the pattern at the edge |

> ⚠️ **Review before you apply.** AI-generated firewall and WAF rules are recommendations. Always check them before running them on a production server, so you don't block legitimate users or lock yourself out of your own machine.

---

## 🛠️ Dual-Engine Tech Stack Breakdown

| | **Engine 1: Python CLI Threat Hunter** | **Engine 2: Next.js SIEM Web Dashboard** |
|---|---|---|
| **Files** | `sentinel.py`, `analyzer.py`, `ai_agent.py` | `dashboard/` |
| **Runtime** | Python 3.12 | Next.js 16, TypeScript, Node.js |
| **Detection** | Regex and heuristic log analysis | Same detection logic, delivered through a web UI |
| **OSINT** | `requests` for `ip-api` geolocation and ASN lookups | Server-side API routes |
| **Interface** | `rich` terminal tables and panels | Tailwind CSS SIEM dashboard |
| **AI** | `google-genai` (Gemini) | Google Gemini |
| **Config** | `python-dotenv`, `.env` | `dashboard/.env.local` |
| **Deployment** | Runs locally | Vercel (live) |

````text
SentinelAI/
├── sentinel.py       # CLI entry point
├── analyzer.py       # Signature and heuristic detection engine
├── ai_agent.py       # Gemini Tier-3 SOC analyst
└── dashboard/        # Next.js 16 full-stack SIEM web dashboard
````

---

## 🚀 Complete Step-by-Step Local Installation & Usage

### Prerequisites

- [Git](https://git-scm.com/)
- [Python 3.12](https://www.python.org/downloads/) for the CLI
- [Node.js](https://nodejs.org/) and npm for the dashboard
- A free [Google Gemini API key](https://aistudio.google.com/) for the AI analyst

### Step 1: Clone the repository

````bash
git clone https://github.com/sjyotipriyo-droid/SentinelAI.git
cd SentinelAI
````

### Step 2: Run the Python CLI

````bash
# Install dependencies
pip install requests rich python-dotenv google-genai
````

Create a file named `.env` in the project root:

````env
GEMINI_API_KEY=your_gemini_api_key
````

Run the CLI:

````bash
py sentinel.py              # Windows
python3 sentinel.py         # macOS / Linux
````

Follow the on-screen prompts to provide an access log.

### Step 3: Run the Next.js SIEM Dashboard

````bash
cd dashboard
npm install
````

Create `dashboard/.env.local`:

````env
GEMINI_API_KEY=your_gemini_api_key
````

Start the server:

````bash
npm run dev
````

Open **http://localhost:3000** in your browser.

### Where do I find a real access log?

| Server | Common default location |
|---|---|
| Apache (Debian / Ubuntu) | `/var/log/apache2/access.log` |
| Apache (RHEL / CentOS) | `/var/log/httpd/access_log` |
| Nginx | `/var/log/nginx/access.log` |

<details>
<summary><b>No server? Create a small test log</b></summary>

<br>

````bash
cat > sample_access.log << 'EOF'
203.0.113.45 - - [24/Oct/2026:02:14:07 +0000] "GET /products.php?id=1'%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 5123 "-" "sqlmap/1.7"
203.0.113.45 - - [24/Oct/2026:02:14:19 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 200 1847 "-" "Mozilla/5.0"
198.51.100.23 - - [24/Oct/2026:02:15:02 +0000] "GET /search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1" 200 3320 "-" "Mozilla/5.0"
192.0.2.77 - - [24/Oct/2026:02:16:41 +0000] "POST /wp-login.php HTTP/1.1" 401 1203 "-" "python-requests/2.31"
192.0.2.77 - - [24/Oct/2026:02:16:42 +0000] "POST /wp-login.php HTTP/1.1" 401 1203 "-" "python-requests/2.31"
192.0.2.77 - - [24/Oct/2026:02:16:44 +0000] "POST /wp-login.php HTTP/1.1" 200 4410 "-" "python-requests/2.31"
EOF
````

The IP addresses above come from reserved documentation ranges, so they are safe to use in examples.

</details>

> 🔐 **Never commit `.env` or `dashboard/.env.local`.** Make sure both are listed in `.gitignore`.

---

## 📄 Sample Log Telemetry & Incident Report Preview

> The output below is illustrative. Exact results depend on your logs.

### Input: raw Apache access log

````text
203.0.113.45 - - [24/Oct/2026:02:14:07 +0000] "GET /products.php?id=1'%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 5123 "-" "sqlmap/1.7"
203.0.113.45 - - [24/Oct/2026:02:14:19 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 200 1847 "-" "Mozilla/5.0"
192.0.2.77 - - [24/Oct/2026:02:16:41 +0000] "POST /wp-login.php HTTP/1.1" 401 1203 "-" "python-requests/2.31"
192.0.2.77 - - [24/Oct/2026:02:16:42 +0000] "POST /wp-login.php HTTP/1.1" 401 1203 "-" "python-requests/2.31"
192.0.2.77 - - [24/Oct/2026:02:16:44 +0000] "POST /wp-login.php HTTP/1.1" 200 4410 "-" "python-requests/2.31"
````

### Output: detected incidents

| Source IP | Vector | MITRE ID | Key indicator | Triage |
|---|---|---|---|---|
| `203.0.113.45` | SQL Injection | `T1190` | `UNION SELECT`, `sqlmap` user agent, `200` with 5123 bytes | **Critical**: possible data extraction |
| `203.0.113.45` | Directory Traversal / LFI | `T1083` | `../../../../etc/passwd`, `200` | **Critical**: possible file disclosure |
| `192.0.2.77` | Brute Force | `T1110` | `401`, `401`, then `200` on `/wp-login.php` | **High**: possible account takeover |

### Output: AI incident response report (excerpt)

````markdown
# Incident Response Report
**TLP:AMBER** · Incident ID: SENT-2026-1024-001 · Generated: 2026-10-24 02:20 UTC

## 1. Executive Breach Summary
Two external sources attacked the public web application within three minutes.
One source ran SQL injection and a path traversal request that both returned
HTTP 200 with substantial response sizes, which indicates probable data and file
disclosure. A second source guessed credentials against /wp-login.php and
received a 200 after two failures, consistent with a successful login.
Treat the application and its credentials as potentially compromised.

## 2. Attacker Geo / ASN Matrix
| IP            | Country | City      | ASN      | ISP / Org        | Vectors                |
|---------------|---------|-----------|----------|------------------|------------------------|
| 203.0.113.45  | DE      | Frankfurt | AS64496  | Example Hosting  | SQLi, LFI              |
| 192.0.2.77    | NL      | Amsterdam | AS64497  | Example Cloud    | Credential brute force |

## 3. Perimeter Containment
```bash
# ufw
sudo ufw deny from 203.0.113.45 to any
sudo ufw deny from 192.0.2.77 to any

# iptables
sudo iptables -I INPUT -s 203.0.113.45 -j DROP
sudo iptables -I INPUT -s 192.0.2.77 -j DROP
```

## 4. Code-Level & WAF Patches
**Fix the injection (parameterized query):**
```python
cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
```

**ModSecurity rules:**
```apache
SecRule ARGS|REQUEST_URI "@rx (?i)(?:union\s+select|'\s*or\s+1\s*=\s*1)" \
    "id:1000001,phase:2,t:none,t:urlDecodeUni,deny,status:403,log,\
    msg:'SQL injection attempt (MITRE T1190)',tag:'attack-sqli'"

SecRule REQUEST_URI|ARGS "@rx (?:\.\./|\.\.\\)" \
    "id:1000002,phase:2,t:none,t:urlDecodeUni,deny,status:403,log,\
    msg:'Path traversal attempt (MITRE T1083)',tag:'attack-lfi'"
```

## 5. Recommended Follow-up
Rotate credentials for any account that logged in from 192.0.2.77, review
database and file access logs, and verify whether /etc/passwd was readable.
````

---

## 👨‍💻 Author

**Jyotipriyo Saha**
Cybersecurity builder focused on defensive security and automated threat detection.

[![GitHub](https://img.shields.io/badge/GitHub-@sjyotipriyo--droid-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/sjyotipriyo-droid)

---

<div align="center">

**If SentinelAI helped you spot an attack, consider giving the repo a ⭐**

[Try the Live Dashboard](https://sentinel-ai-theta-cyan.vercel.app/) · [View the Source](https://github.com/sjyotipriyo-droid/SentinelAI)

</div>
