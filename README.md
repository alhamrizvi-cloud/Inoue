# Inoue
<img width="1099" height="717" alt="image" src="https://github.com/user-attachments/assets/0dbb322d-781e-42bd-aae4-c3cd793d2df5" />

Fast, open-source tech stack fingerprinting CLI — like Wappalyzer or BuiltWith, but runs in your terminal, free, and hackable.

Built for recon, CTF/HTB, bug bounty, and general web surface analysis.

Maintained by Alham Rizvi.

GitHub: https://github.com/alhamrizvi-cloud/Inoue

## Features

- 🖥 **Advanced web-stack fingerprinting** — identifies servers, CMS, frameworks, CDNs, WAFs, analytics, payment providers, and more
- 🔒 **SSL/TLS inspection** — protocol, cipher, cert issuer, SANs, expiry, and certificate metadata
- 🌐 **DNS intelligence** — A, AAAA, MX, NS, TXT, and CNAME records for broader recon coverage
- 🛡 **Security header audit** — checks for HSTS, CSP, X-Frame-Options, and other protective headers
- ⚡ **Fast parallel scanning** — scan many targets concurrently with configurable worker counts
- 📄 **Structured JSON output** — save results to files or pipe them into other automation workflows
- 🎨 **Rich CLI reporting** — color-coded output with confidence levels, versions, and evidence hints
- 🧠 **Extensible fingerprint engine** — add new detection signatures quickly in the signatures module

## Install

```bash
git clone https://github.com/alhamrizvi-cloud/Inoue.git
cd Inoue
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python inoue.py example.com

# Verbose (SSL, DNS, security headers, all response headers)
python inoue.py -v target.htb

# Show detection evidence for each tech
python inoue.py -e https://target.com

# Full recon mode
python inoue.py -v -e https://target.com

# Scan multiple targets concurrently
python inoue.py site1.com site2.com site3.com

# JSON output
python inoue.py --json target.com
python inoue.py --json -o results.json target.com

# HTB / CTF (fast, no DNS, custom timeout)
python inoue.py --no-dns -t 5 10.10.11.55

# Skip SSL check (for HTTP-only or self-signed targets)
python inoue.py --no-ssl http://target.htb
```

## Options

| Flag | Description |
|------|-------------|
| `-v, --verbose` | Show SSL info, DNS records, security headers, all headers |
| `-e, --evidence` | Show what triggered each detection |
| `--no-dns` | Skip DNS enumeration |
| `--no-ssl` | Skip SSL/TLS inspection |
| `-t, --timeout` | HTTP timeout in seconds (default: 10) |
| `-w, --workers` | Concurrent scan threads (default: 5) |
| `--json` | Output as JSON |
| `-o, --output` | Save JSON to file |
| `--no-banner` | Suppress ASCII banner |
| `--api-key` | Optional API key for enrichment services |

## Categories Detected

| Category | Examples |
|----------|---------|
| Web Server | Apache, Nginx, IIS, LiteSpeed, Caddy |
| Language | PHP, ASP.NET, Node.js, Python |
| Framework | Laravel, Django, Flask, Express, Spring, Next.js, Nuxt |
| CMS | WordPress, Drupal, Joomla, Ghost |
| E-Commerce | Magento, Shopify |
| JS Framework | React, Vue, Angular, Svelte, Next.js |
| CDN | Cloudflare, AWS CloudFront, Fastly, Akamai, Varnish |
| WAF | Cloudflare WAF, AWS WAF, Sucuri, Imperva, ModSecurity |
| Analytics | Google Analytics, GTM, Hotjar, Matomo, Plausible |
| Security Headers | HSTS, CSP, X-Frame-Options, X-XSS-Protection |
| Hosting | Vercel, Netlify, Heroku, GitHub Pages |
| Payment | Stripe, PayPal |

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for setup and PR guidance.

## Adding Signatures

Edit `fingerprints/signatures.py`. Each entry follows this schema:

```python
"TechName": {
    "category": "Framework",
    "headers": {"Header-Name": r"regex(with optional (version) group)"},
    "cookies": [r"cookie_name_pattern"],
    "html":    [r"pattern in response body"],
    "scripts": [r"pattern in <script src=...>"],
    "meta":    {"generator": r"pattern"},
},
```

## Output Example (JSON)

```json
[
  {
    "url": "https://target.com",
    "ip": "1.2.3.4",
    "status_code": 200,
    "response_time_ms": 142.3,
    "server": "nginx",
    "technologies": [
      {"name": "Nginx", "category": "Web Server", "version": "1.24.0", "evidence": "Server: nginx/1.24.0"},
      {"name": "WordPress", "category": "CMS", "version": "6.5", "evidence": "Meta generator: WordPress 6.5"}
    ],
    "ssl": { "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", ... },
    "dns": { "A": ["1.2.3.4"], "MX": ["mail.target.com"] }
  }
]
```

---

## Roadmap

Planned improvements include:
- more fingerprint signatures for modern web stacks
- extra enrichment sources and version heuristics
- broader TLS and header analysis
- better structured reports for recon workflows

## License

MIT — go build something cool.
