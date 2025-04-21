# 🔎 Advanced Secret & API Key Detector

This repository contains a powerful, extensible Python tool and a comprehensive collection of regular expressions to detect sensitive information, API keys, tokens, credentials, and configuration leaks in code, text files, git history, and web pages.

## 🚀 Features

- **Massive Pattern Coverage:**
  - 100+ regex patterns for modern and legacy API keys, OAuth tokens, secrets, JWTs, session cookies, cloud credentials, blockchain/web3 keys, AI/ML API keys, mobile and IoT secrets, and more.
  - Supports Google, AWS, Azure, Facebook, Twitter, Discord, Telegram, Stripe, Shopify, GitHub, GitLab, Bitbucket, Cloudflare, Heroku, Vercel, Netlify, Supabase, OpenAI, HuggingFace, and dozens of other services.
- **Web & Code Context Awareness:**
  - Scans source code, config files, directories, git commit history, and entire websites (with subdomain and deep recursive support).
  - Extracts secrets from HTML, JS, JSON, inline scripts, CSS, onclicks, and embedded web configs (window.__env__, meta tags, etc).
  - Ignores common false positives (minified files, images, test data, etc) with smart filtering.
- **Parallel & Recursive Web Scanning:**
  - Multi-threaded domain scanning (configurable thread count) for fast, large-scale web reconnaissance.
  - Recursive/deep crawling with max depth and aggressive EXTREME mode (ignores robots.txt, filetype, domain, etc.).
  - Randomized User-Agent rotation for stealthier and more robust crawling.
- **Flexible Output:**
  - Console and file output, grouped by file or URL, with optional verbose mode for detailed findings.
  - Ready for integration with CI/CD, bug bounty, or security pipelines.
  - Supports saving results to text file for later review.
- **Easy to Extend:**
  - Add new regexes or detection logic with minimal code changes.
  - Modular structure for adding new scanning methods (directory, git, url, website, etc).
- **Developer-Oriented:**
  - Clean, well-documented codebase.
  - Modern Python 3.8+ support.
  - CLI with rich options and argument groups.

## 🛠️ Usage

```bash
python3 secret_detector.py --file app.js
python3 secret_detector.py --dir ./myproject
python3 secret_detector.py --domain example.com
python3 secret_detector.py --list domains.txt
python3 secret_detector.py --domain yahoo.com --crawler --depth 5
python3 secret_detector.py --domain example.com --max-pages 100 --max-workers 20 --verbose
python3 secret_detector.py --git-history /path/to/repo
```

See `python3 secret_detector.py --help` for all options and advanced usage.

## 📦 Requirements
- Python 3.8+
- requests, beautifulsoup4, tqdm, urllib3

Install dependencies:
```bash
pip install -r requirements.txt
```

## 👑 Supported Secret Types (Partial List)
- Google API, OAuth, Maps, Analytics, Firebase, GCP Service Accounts
- AWS Access/Secret Keys, MWS, S3 URLs, Session Tokens
- Azure, Office365, Teams, IBM, Oracle, Alibaba, Salesforce, SAP
- GitHub, GitLab, Bitbucket, Atlassian, Copilot, Runner Tokens
- Facebook, Twitter, LinkedIn, Discord, Telegram, Slack, Zoom
- Stripe, PayPal, Square, Shopify, Mailgun, SendGrid, Mailchimp, Pusher, Algolia, Sentry, Mixpanel
- OpenAI, HuggingFace, Expo, Android/iOS, MQTT, Okta, ServiceNow, Vault, Docker, Kubernetes, Jenkins, CircleCI, TravisCI
- Blockchain/Web3: Ethereum, Infura, Alchemy, etc.
- JWTs, Session Cookies, Bearer/OAuth tokens, CSRF/XSRF tokens
- Generic API keys, secrets, and custom patterns
- SMTP, Redis, RabbitMQ, MongoDB, PostgreSQL, MySQL, Elasticsearch, and more
- PEM, DSA, EC, PGP, SSH private keys, dotenv, and critical config files

## ⚡ Example Output
```
Type: Google API Key
Value: AIzaSyD...abc123
Position: 120-160
URL: https://example.com/app.js
--------------------------------------------------
Type: AWS Secret Key
Value: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Position: 45-85
File: config.py
--------------------------------------------------
```

## 🧩 Advanced Features
- **Aggressive EXTREME Mode:** Ignores all crawling restrictions, file types, and domains for maximum coverage.
- **Subdomain & Deep Crawler:** Automatically discovers and scans subdomains and supports recursive crawling with depth control.
- **Git History Scanning:** Finds secrets in git commit history, not just current files.
- **False Positive Filtering:** Smart filtering for common code, asset, and test data noise.
- **Threaded, Fast, and Scalable:** Designed for both single-file and massive-scale web scanning.
- **Customizable:** Easily add new patterns, scanning methods, or output formats.

## 👨‍💻 Developers
- [![haxshadow's GitHub](https://img.shields.io/badge/-@haxshadow-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/haxshadow)
- [![ibrahimsql's GitHub](https://img.shields.io/badge/-@ibrahimsql-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/ibrahimsql)

---

For bug reports, feature requests, or contributions, open an issue or pull request on GitHub.
