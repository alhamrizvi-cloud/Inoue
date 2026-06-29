"""
Tech stack fingerprint signatures.
Each entry maps a technology to detection rules across headers, cookies, HTML, scripts, meta tags, etc.
"""

SIGNATURES = {
    # --- Web Servers ---
    "Apache": {
        "headers": {"Server": r"Apache(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },
    "Nginx": {
        "headers": {"Server": r"nginx(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },
    "IIS": {
        "headers": {"Server": r"Microsoft-IIS(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },
    "LiteSpeed": {
        "headers": {"Server": r"LiteSpeed"},
        "category": "Web Server",
    },
    "Caddy": {
        "headers": {"Server": r"Caddy"},
        "category": "Web Server",
    },
    "OpenResty": {
        "headers": {"Server": r"openresty(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },
    "Gunicorn": {
        "headers": {"Server": r"gunicorn(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },
    "Werkzeug": {
        "headers": {"Server": r"Werkzeug(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },
    "Tornado": {
        "headers": {"Server": r"TornadoServer(?:/(\d+[\d.]+))?"},
        "category": "Web Server",
    },

    # --- Languages / Runtimes ---
    "PHP": {
        "headers": {"X-Powered-By": r"PHP(?:/(\d+[\d.]+))?"},
        "cookies": [r"PHPSESSID"],
        "category": "Language",
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r"(\d+[\d.]+)"},
        "cookies": [r"ASP\.NET_SessionId"],
        "category": "Language",
    },
    "Node.js": {
        "headers": {"X-Powered-By": r"Express"},
        "category": "Language",
    },
    "Ruby on Rails": {
        "headers": {"X-Powered-By": r"Phusion Passenger(?:/(\d+[\d.]+))?"},
        "cookies": [r"_session_id"],
        "html": [r'content="Ruby on Rails'],
        "category": "Framework",
    },
    "Python": {
        "headers": {"X-Powered-By": r"Python(?:/(\d+[\d.]+))?"},
        "category": "Language",
    },

    # --- Frameworks ---
    "Laravel": {
        "cookies": [r"laravel_session", r"XSRF-TOKEN"],
        "html": [r'csrf-token.*laravel', r'Laravel'],
        "category": "Framework",
    },
    "Django": {
        "cookies": [r"csrftoken", r"sessionid"],
        "html": [r"csrfmiddlewaretoken"],
        "category": "Framework",
    },
    "Flask": {
        "cookies": [r"session"],
        "headers": {"Server": r"Werkzeug"},
        "category": "Framework",
    },
    "Express.js": {
        "headers": {"X-Powered-By": r"Express"},
        "category": "Framework",
    },
    "FastAPI": {
        "html": [r"fastapi", r"/openapi\.json", r"/docs"],
        "category": "Framework",
    },
    "Spring": {
        "cookies": [r"JSESSIONID"],
        "headers": {"X-Application-Context": r".+"},
        "category": "Framework",
    },
    "Symfony": {
        "cookies": [r"PHPSESSID"],
        "html": [r"Symfony", r"sf_redirect"],
        "category": "Framework",
    },
    "CodeIgniter": {
        "cookies": [r"ci_session"],
        "html": [r"CodeIgniter"],
        "category": "Framework",
    },

    # --- CMS ---
    "WordPress": {
        "html": [r'/wp-content/', r'/wp-includes/', r'wordpress'],
        "meta": {"generator": r"WordPress(?:\s(\d+[\d.]+))?"},
        "category": "CMS",
    },
    "Drupal": {
        "headers": {"X-Generator": r"Drupal(?:\s(\d+))?"},
        "html": [r'/sites/default/files/', r'Drupal\.settings'],
        "meta": {"generator": r"Drupal(?:\s(\d+[\d.]+))?"},
        "category": "CMS",
    },
    "Joomla": {
        "html": [r'/media/jui/', r'/components/com_'],
        "meta": {"generator": r"Joomla!(?:\s(\d+[\d.]+))?"},
        "category": "CMS",
    },
    "Magento": {
        "cookies": [r"frontend"],
        "html": [r'Mage\.', r'/skin/frontend/', r'var BLANK_URL'],
        "category": "CMS / E-Commerce",
    },
    "Shopify": {
        "html": [r'cdn\.shopify\.com', r'Shopify\.theme'],
        "category": "CMS / E-Commerce",
    },
    "Ghost": {
        "meta": {"generator": r"Ghost(?:\s(\d+[\d.]+))?"},
        "html": [r'ghost\.org', r'content="Ghost'],
        "category": "CMS",
    },
    "Wix": {
        "html": [r'wixsite\.com', r'static\.wixstatic\.com'],
        "category": "Site Builder",
    },
    "Squarespace": {
        "html": [r'squarespace\.com', r'static1\.squarespace\.com'],
        "category": "Site Builder",
    },
    "Webflow": {
        "html": [r'webflow\.com', r'data-wf-'],
        "category": "Site Builder",
    },

    # --- JS Frameworks ---
    "React": {
        "html": [r'__reactFiber', r'__reactProps', r'react\.development\.js', r'react\.production\.min\.js', r'_reactRootContainer'],
        "scripts": [r'react(?:\.min)?\.js', r'react-dom'],
        "category": "JS Framework",
    },
    "Vue.js": {
        "html": [r'__vue__', r'data-v-', r'vue\.min\.js', r'vue\.js'],
        "scripts": [r'vue(?:\.min)?\.js'],
        "category": "JS Framework",
    },
    "Angular": {
        "html": [r'ng-version=', r'ng-app', r'angular\.min\.js'],
        "scripts": [r'angular(?:\.min)?\.js'],
        "category": "JS Framework",
    },
    "Next.js": {
        "html": [r'__NEXT_DATA__', r'/_next/static/'],
        "headers": {"X-Powered-By": r"Next\.js"},
        "category": "JS Framework",
    },
    "Nuxt.js": {
        "html": [r'__NUXT__', r'/_nuxt/'],
        "category": "JS Framework",
    },
    "Svelte": {
        "html": [r'svelte-', r'__svelte'],
        "category": "JS Framework",
    },
    "jQuery": {
        "html": [r'jquery(?:\.min)?\.js', r'jQuery v(\d+[\d.]+)'],
        "scripts": [r'jquery(?:-(\d+[\d.]+))?(?:\.min)?\.js'],
        "category": "JS Library",
    },
    "Bootstrap": {
        "html": [r'bootstrap(?:\.min)?\.css', r'bootstrap(?:\.min)?\.js'],
        "scripts": [r'bootstrap(?:-(\d+[\d.]+))?'],
        "category": "CSS Framework",
    },
    "Tailwind CSS": {
        "html": [r'tailwindcss', r'class="[^"]*(?:flex|grid|text-\w+|bg-\w+|p-\d|m-\d)[^"]*"'],
        "category": "CSS Framework",
    },

    # --- CDN / Cloud ---
    "Cloudflare": {
        "headers": {"CF-Ray": r".+", "Server": r"cloudflare"},
        "category": "CDN / Security",
    },
    "AWS CloudFront": {
        "headers": {"X-Amz-Cf-Id": r".+", "Via": r"CloudFront"},
        "category": "CDN",
    },
    "Fastly": {
        "headers": {"X-Served-By": r"cache-", "Fastly-Debug-Digest": r".+"},
        "category": "CDN",
    },
    "Akamai": {
        "headers": {"X-Check-Cacheable": r".+", "X-Akamai-Transformed": r".+"},
        "category": "CDN",
    },
    "Varnish": {
        "headers": {"X-Varnish": r".+", "Via": r"varnish"},
        "category": "Cache",
    },

    # --- WAF ---
    "AWS WAF": {
        "headers": {"X-AMZ-WAF": r".+"},
        "category": "WAF",
    },
    "Sucuri": {
        "headers": {"X-Sucuri-ID": r".+", "Server": r"Sucuri"},
        "category": "WAF",
    },
    "Imperva": {
        "headers": {"X-Iinfo": r".+"},
        "category": "WAF",
    },
    "ModSecurity": {
        "headers": {"X-Mod-Security": r".+"},
        "category": "WAF",
    },

    # --- Analytics ---
    "Google Analytics": {
        "html": [r'google-analytics\.com/analytics\.js', r'gtag\(', r'UA-\d+-\d+', r'G-[A-Z0-9]+'],
        "scripts": [r'google-analytics\.com', r'googletagmanager\.com'],
        "category": "Analytics",
    },
    "Google Tag Manager": {
        "html": [r'googletagmanager\.com/gtm\.js', r'GTM-[A-Z0-9]+'],
        "category": "Analytics",
    },
    "Hotjar": {
        "html": [r'hotjar\.com', r'hjid:', r'hjsv:'],
        "category": "Analytics",
    },
    "Matomo": {
        "html": [r'matomo\.js', r'piwik\.js', r'_paq\.push'],
        "category": "Analytics",
    },
    "Plausible": {
        "html": [r'plausible\.io/js'],
        "category": "Analytics",
    },

    # --- Security Headers ---
    "HSTS": {
        "headers": {"Strict-Transport-Security": r".+"},
        "category": "Security Header",
    },
    "CSP": {
        "headers": {"Content-Security-Policy": r".+"},
        "category": "Security Header",
    },
    "X-Frame-Options": {
        "headers": {"X-Frame-Options": r".+"},
        "category": "Security Header",
    },
    "X-XSS-Protection": {
        "headers": {"X-XSS-Protection": r".+"},
        "category": "Security Header",
    },

    # --- Databases / Backend hints ---
    "MySQL": {
        "html": [r'mysql_connect', r'MySQL'],
        "category": "Database",
    },
    "MongoDB": {
        "html": [r'mongodb', r'MongoClient'],
        "category": "Database",
    },
    "Elasticsearch": {
        "html": [r'elasticsearch', r'elastic\.co'],
        "category": "Search Engine",
    },

    # --- Hosting ---
    "Vercel": {
        "headers": {"X-Vercel-Id": r".+", "Server": r"Vercel"},
        "category": "Hosting",
    },
    "Netlify": {
        "headers": {"X-Nf-Request-Id": r".+", "Server": r"Netlify"},
        "category": "Hosting",
    },
    "Heroku": {
        "headers": {"Via": r"1\.1 vegur"},
        "category": "Hosting",
    },
    "GitHub Pages": {
        "html": [r'github\.io'],
        "category": "Hosting",
    },

    # --- Payment ---
    "Stripe": {
        "html": [r'js\.stripe\.com', r'Stripe\('],
        "scripts": [r'js\.stripe\.com'],
        "category": "Payment",
    },
    "PayPal": {
        "html": [r'paypal\.com/sdk', r'paypalobjects\.com'],
        "category": "Payment",
    },

    # --- Misc ---
    "Font Awesome": {
        "html": [r'font-awesome', r'fontawesome'],
        "scripts": [r'fontawesome'],
        "category": "UI Library",
    },
    "reCAPTCHA": {
        "html": [r'google\.com/recaptcha', r'grecaptcha'],
        "category": "Security",
    },
    "Intercom": {
        "html": [r'intercom\.io', r'intercomSettings'],
        "category": "CRM / Chat",
    },
    "Zendesk": {
        "html": [r'zendesk\.com', r'zE\('],
        "category": "CRM / Chat",
    },
}
