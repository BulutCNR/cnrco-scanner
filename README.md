# CNRCO Security Scanner

> Passive OWASP Top 10:2021 audit agent — powered by a local AI model via Ollama. No API keys. No accounts. No cost.

```
  ██████╗███╗   ██╗██████╗  ██████╗ ██████╗
 ██╔════╝████╗  ██║██╔══██╗██╔════╝██╔═══██╗
 ██║     ██╔██╗ ██║██████╔╝██║     ██║   ██║
 ██║     ██║╚██╗██║██╔══██╗██║     ██║   ██║
 ╚██████╗██║ ╚████║██║  ██║╚██████╗╚██████╔╝
  ╚═════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝
  OWASP Top 10 Security Scanner  ·  v1.0  ·  cnrco.nl
```

Point it at a domain you have authorisation to audit. The scanner fetches real HTTP headers and TLS data, feeds it to a local AI model, and produces a severity-ranked report mapped to the OWASP Top 10:2021 — straight in your terminal.

Everything runs on your machine. No data leaves your computer.

---

## Features

- Real passive recon — fetches actual headers, TLS info, cookies, server fingerprints
- Full OWASP Top 10:2021 coverage (A01–A10)
- CVSS scoring and vectors per finding
- Severity-ranked output: Critical → High → Medium → Low → Info
- Export to Markdown (client-ready) or JSON
- 100% local — no API keys, no accounts, no cost

---

## Requirements

- Node.js 18+
- [Ollama](https://ollama.com) installed and running

---

## Setup

```bash
# 1. Install Ollama
brew install ollama        # macOS
# or visit https://ollama.com for Windows/Linux

# 2. Pull a model (one-time, ~2GB download)
ollama pull llama3.2

# 3. Start Ollama (keep this running in a terminal tab)
ollama serve

# 4. Clone this repo
git clone https://github.com/YOUR_USERNAME/cnrco-scanner.git
cd cnrco-scanner

# 5. Install dependencies
npm install
```

---

## Usage

```bash
# Basic scan
node scan.js https://example.com

# Save a Markdown report
node scan.js https://example.com --output report.md

# Save JSON findings
node scan.js https://example.com --json findings.json

# Use a different model (better results, more RAM needed)
node scan.js https://example.com --model llama3.1:8b

# Quiet mode
node scan.js https://example.com --quiet --output report.md
```

### Options

| Flag | Description |
|---|---|
| `-o, --output <file>` | Save report as Markdown |
| `-j, --json <file>` | Save raw findings as JSON |
| `-m, --model <name>` | Ollama model to use (default: llama3.2) |
| `-q, --quiet` | Suppress banner and spinner |
| `-h, --help` | Show help |

---

## Recommended Models

| Model | RAM needed | Quality |
|---|---|---|
| `llama3.2` | ~4GB | Good — default |
| `llama3.1:8b` | ~6GB | Better JSON reliability |
| `mistral` | ~5GB | Fast, solid output |

Pull any model with `ollama pull <model-name>`.

---

## How It Works

1. The scanner fetches real HTTP headers, TLS status, cookies, and server fingerprints from the target
2. That data is passed to your local Ollama model as a structured prompt
3. The model maps findings to OWASP Top 10:2021 categories with CVSS scores
4. Results are printed to your terminal and optionally saved

This is a **first-pass passive assessment** — designed to run before active testing with Burp Suite, Nikto, or testssl.sh.

---

## Legal & Ethics

This tool performs **passive reconnaissance only**. It makes a single HTTP request to the target (the same as visiting it in a browser) and analyses the response.

**Only scan systems you own or have explicit written authorisation to audit.**

In the Netherlands, unauthorised computer access is a criminal offence under Article 138ab Sr (computervredebreuk). Always obtain a signed scope agreement before scanning client systems.

---

## Built by

[CNRCO](https://cnrco.nl) — Web Application Security for Dutch SMBs
