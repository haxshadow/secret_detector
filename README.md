# 🔎 Ultra-Advanced Secret & API Key Detector

This repository contains a powerful, extensible Python tool and a comprehensive collection of regular expressions to detect sensitive information, API keys, tokens, credentials, and configuration leaks in code, text files, and web pages.

## 🚀 Features

- **Massive Pattern Coverage:**
  - 100+ regex patterns for modern and legacy API keys, OAuth tokens, secrets, JWTs, session cookies, cloud credentials, blockchain/web3 keys, AI/ML API keys, mobile and IoT secrets, and more.
  - Supports Google, AWS, Azure, Facebook, Twitter, Discord, Telegram, Stripe, Shopify, GitHub, GitLab, Bitbucket, Cloudflare, Heroku, Vercel, Netlify, Supabase, OpenAI, HuggingFace, and dozens of other services.
- **Web & Code Context Awareness:**
  - Scans source code, config files, directories, and entire websites.
  - Extracts secrets from HTML, JS, JSON, and embedded web configs (window.__env__, meta tags, etc).
  - Ignores common false positives (minified files, images, test data, etc).
- **Parallel Web Scanning:**
  - Multi-threaded domain scanning for fast, large-scale web reconnaissance.
  - Randomized User-Agent rotation for stealthier and more robust crawling.
- **Flexible Output:**
  - Console and file output, grouped by file or URL.
  - Ready for integration with CI/CD, bug bounty, or security pipelines.
- **Easy to Extend:**
  - Add new regexes or detection logic with minimal code changes.

## 🛠️ Usage

```bash
python3 secret_detector.py --file app.js
python3 secret_detector.py --dir ./myproject
python3 secret_detector.py --domain example.com
python3 secret_detector.py --list domains.txt
python3 secret_detector.py --domain yahoo.com --crawler --depth 5
```

See `python3 secret_detector.py --help` for all options.

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

## 👨‍💻 Developers
-[@haxshadow](https://github.com/haxshadow)
-[@ibrahimsql](https://github.com/ibrahimsql)
