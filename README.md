# Inoue

<img width="430" height="63" alt="image" src="https://github.com/user-attachments/assets/3ebec879-7fdb-4ee4-9def-277e95b1c406" />

Inoue is a fast, open-source recon-oriented tech stack fingerprinting CLI. It is designed to identify the technologies exposed by a target website or service from the terminal, with a broad signature catalog that covers servers, runtimes, CMS platforms, ecommerce stacks, frameworks, JavaScript libraries, analytics tools, payment providers, admin panels, cloud/self-hosted management surfaces, VPN portals, and IoT/admin devices.

It is useful for recon, CTF/HTB, bug bounty, internal network review, and general surface analysis.

Maintained by Alham Rizvi.

Repository: https://github.com/alhamrizvi-cloud/Inoue

## Features

- Broad fingerprint coverage for web servers, languages, frameworks, CMS, ecommerce platforms, JS libraries, analytics, payments, CDNs, WAFs, and more
- Detection from HTTP headers, cookies, HTML, script tags, meta tags, and URL paths
- Recon-oriented service hints for exposed admin panels, management consoles, cloud portals, and self-hosted applications
- Version-aware detection where the signature supports it
- SSL/TLS inspection with certificate metadata and handshake details
- DNS intelligence for A, AAAA, MX, NS, TXT, and CNAME records
- Security header auditing for HSTS, CSP, X-Frame-Options, and related protections
- Parallel scanning for multiple targets with configurable worker count
- Structured JSON output for automation and reporting
- Rich CLI output with confidence, version, and evidence hints
- Extensible signature engine for quickly adding new detections

<img width="941" height="684" alt="image" src="https://github.com/user-attachments/assets/a4c579ae-7b00-43e1-a88f-0541f124e33f" />

<img width="929" height="453" alt="image" src="https://github.com/user-attachments/assets/f15c9e8a-5f12-427b-a72f-d084815bbda8" />

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

# Verbose scan with SSL, DNS, headers, and security inspection
python inoue.py -v target.htb

# Show the evidence behind each detection
python inoue.py -e https://target.com

# Full recon-style scan
python inoue.py -v -e https://target.com

# Scan multiple targets concurrently
python inoue.py site1.com site2.com site3.com

# JSON output
python inoue.py --json target.com
python inoue.py --json -o results.json target.com

# Fast HTB/CTF style scan without DNS
python inoue.py --no-dns -t 5 10.10.11.55

# Skip SSL checks for HTTP-only or self-signed targets
python inoue.py --no-ssl http://target.htb
```

For a full command reference, see [COMMANDS.md](COMMANDS.md).

## Options

| Flag | Description |
|------|-------------|
| `-v, --verbose` | Show SSL info, DNS records, security headers, and response headers |
| `-e, --evidence` | Show the evidence that triggered each detection |
| `--no-dns` | Skip DNS enumeration |
| `--no-ssl` | Skip SSL/TLS inspection |
| `-t, --timeout` | HTTP timeout in seconds (default: 10) |
| `-w, --workers` | Concurrent scan threads (default: 5) |
| `--json` | Output results as JSON |
| `-o, --output` | Save JSON to a file |
| `--no-banner` | Suppress the ASCII banner |
| `--api-key` | Optional API key for enrichment services |

## What it can identify

Inoue is built around a large signature catalog and can surface technologies across categories such as:

- Web servers: Apache, Nginx, IIS, LiteSpeed, Caddy, Tomcat, OpenResty
- Languages and runtimes: PHP, ASP.NET, Node.js, Python, Ruby on Rails, Java, Go
- Frameworks: Laravel, Django, Flask, Express.js, Spring, Symfony, FastAPI, Next.js, React, Vue, Angular
- CMS and ecommerce: WordPress, Drupal, Joomla, Magento, Shopify, PrestaShop, OpenCart, Ghost
- Analytics and marketing: Google Analytics, Tag Manager, Hotjar, Matomo, Plausible, Segment, Mixpanel
- Payments: Stripe, PayPal, Braintree, Authorize.Net, Square, Adyen, Paddle
- CDNs and security: Cloudflare, CloudFront, Fastly, Akamai, Varnish, WAF products
- Admin and management panels: phpMyAdmin, Adminer, pgAdmin, Webmin, Portainer, Jenkins, GitLab, Jira, Confluence, Webmin, and more
- Cloud and self-hosted infrastructure: OpenStack, OpenShift, Proxmox, oVirt, CloudStack, Rancher, Harbor, Nextcloud, OwnCloud
- VPN and remote access: OpenVPN, WireGuard, Tailscale, pfSense, OPNsense, FortiGate, UniFi, MikroTik
- IoT and appliance surfaces: Home Assistant, OpenHAB, Synology DSM, QNAP QTS, TrueNAS, routers, cameras, and printer web consoles

## How detection works

The scanner evaluates several signal sources in order:

- HTTP response headers
- Cookies
- HTML body content
- Script tags and referenced assets
- Meta tags
- URL paths and common login/admin routes

Each detection is enriched with a confidence level, version hint when available, and evidence from the matched signal.

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for setup and PR guidance.

## Adding signatures

Edit [fingerprints/signatures.py](fingerprints/signatures.py). Each entry follows this schema:

```python
"TechName": {
    "category": "Framework",
    "headers": {"Header-Name": r"regex(with optional (version) group)"},
    "cookies": [r"cookie_name_pattern"],
    "html": [r"pattern in response body"],
    "scripts": [r"pattern in <script src=...>"],
    "meta": {"generator": r"pattern"},
    "paths": [r"/common/admin/path"],
},
```

## Example JSON output

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
    "ssl": {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
    "dns": {"A": ["1.2.3.4"], "MX": ["mail.target.com"]}
  }
]
```

## Roadmap

Planned improvements include:
- more signature coverage for modern web stacks
- broader version heuristics and enrichment sources
- deeper TLS and header analysis
- better structured reports for recon workflows

## License

MIT.
