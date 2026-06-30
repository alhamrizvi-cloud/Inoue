"""
Core scanning engine - fetches target and runs all detections concurrently.
"""

import os
import re
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

try:
    import whois
except ImportError:  # pragma: no cover - optional dependency
    whois = None

import httpx

from fingerprints.signatures import SIGNATURES



@dataclass
class Detection:
    name: str
    category: str
    version: Optional[str] = None
    confidence: str = "high"  # high / medium / low
    evidence: str = ""


@dataclass
class ScanResult:
    url: str
    final_url: str
    status_code: int
    response_time_ms: float
    ip: str = ""
    server: str = ""
    technologies: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    dns_records: dict = field(default_factory=dict)
    ssl_info: dict = field(default_factory=dict)
    whois_info: dict = field(default_factory=dict)
    subdomains: list = field(default_factory=list)
    mail_records: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    extra_intel: dict = field(default_factory=dict)
    error: Optional[str] = None
    enriched: dict = field(default_factory=dict)


def _normalize_version(raw: str) -> Optional[str]:
    value = raw.strip().strip("'\";,:/\\")
    if not value:
        return None
    if value.lower().startswith(("version", "ver", "release", "build", "rev")):
        value = value.split(None, 1)[-1]
    value = value.replace("_", ".").replace("-", ".")
    value = re.sub(r"[^0-9.]+", "", value)
    return value if value.count(".") or value.isdigit() else None


def _extract_version(pattern: str, text: str) -> Optional[str]:
    """Try to pull a version string from a regex match group 1 or from nearby version-like text."""
    if not text:
        return None

    try:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            for idx in range(1, m.lastindex + 1 if m.lastindex else 1):
                value = m.group(idx)
                normalized = _normalize_version(str(value)) if value else None
                if normalized:
                    return normalized
    except re.error:
        pass

    patterns = [
        r'(?i)(?:v|version|ver|release|build|rev(?:ision)?)\s*[:=]?\s*(\d+(?:[._-]?\d+){1,3})',
        r'(?i)(?:^|[^a-z0-9])(?:v|version|ver|release)\s*(\d+(?:[._-]?\d+){1,3})',
        r'(?i)/(?:v|version|ver|release)?(?:[._-])?(\d+(?:[._-]?\d+){1,3})',
    ]
    for regex in patterns:
        try:
            matches = re.findall(regex, text)
            if matches:
                normalized = _normalize_version(matches[0])
                if normalized:
                    return normalized
        except re.error:
            continue

    try:
        version_matches = re.findall(r'(\d+(?:[._-]?\d+){1,3})', text)
        if version_matches:
            for candidate in version_matches:
                normalized = _normalize_version(candidate)
                if normalized and len(normalized.split('.')) >= 2:
                    return normalized
    except re.error:
        pass
    return None


def _match_headers(sig: dict, headers: dict) -> tuple[bool, Optional[str], str]:
    """Returns (matched, version, evidence)."""
    for header_name, pattern in sig.get("headers", {}).items():
        val = headers.get(header_name, "") or headers.get(header_name.lower(), "")
        if val and re.search(pattern, val, re.IGNORECASE):
            version = _extract_version(pattern, val)
            return True, version, f"{header_name}: {val[:80]}"
    return False, None, ""


def _match_cookies(sig: dict, cookies: dict) -> tuple[bool, str]:
    for pattern in sig.get("cookies", []):
        for cookie_name in cookies:
            if re.search(pattern, cookie_name, re.IGNORECASE):
                return True, f"Cookie: {cookie_name}"
    return False, ""


def _match_html(sig: dict, body: str) -> tuple[bool, Optional[str], str]:
    for pattern in sig.get("html", []):
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            snippet = body[max(0, m.start()-20):m.end()+20].strip().replace("\n", " ")
            version = _extract_version(pattern, body[m.start():m.end() + 80])
            return True, version, f"HTML: …{snippet[:60]}…"
    return False, None, ""


def _match_scripts(sig: dict, scripts: list[str]) -> tuple[bool, Optional[str], str]:
    for pattern in sig.get("scripts", []):
        for src in scripts:
            m = re.search(pattern, src, re.IGNORECASE)
            if m:
                version = None
                try:
                    version = m.group(1) if m.lastindex else None
                except IndexError:
                    pass
                if not version:
                    version = _extract_version(pattern, src)
                return True, version, f"Script: {src[:80]}"
    return False, None, ""


def _match_meta(sig: dict, meta: dict) -> tuple[bool, Optional[str], str]:
    for meta_name, pattern in sig.get("meta", {}).items():
        val = meta.get(meta_name, "")
        if val and re.search(pattern, val, re.IGNORECASE):
            version = _extract_version(pattern, val)
            return True, version, f"Meta {meta_name}: {val[:60]}"
    return False, None, ""


def _extract_scripts(body: str) -> list[str]:
    return re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)


def _extract_meta(body: str) -> dict:
    meta = {}
    for m in re.finditer(r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE):
        meta[m.group(1).lower()] = m.group(2)
    for m in re.finditer(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE):
        meta[m.group(2).lower()] = m.group(1)
    return meta


def _get_ssl_info(hostname: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=5), server_hostname=hostname) as s:
            cert = s.getpeercert()
            return {
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "notAfter": cert.get("notAfter", ""),
                "notBefore": cert.get("notBefore", ""),
                "version": cert.get("version", ""),
                "san": [x[1] for x in cert.get("subjectAltName", [])],
                "protocol": s.version(),
                "cipher": s.cipher()[0] if s.cipher() else "",
            }
    except Exception as e:
        return {"error": str(e)}


def _get_dns(hostname: str) -> dict:
    records = {}
    try:
        import dns.resolver
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(hostname, rtype, lifetime=3)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
    except ImportError:
        # fallback: just A record via socket
        try:
            infos = socket.getaddrinfo(hostname, None)
            records["A"] = list({i[4][0] for i in infos if i[0] == socket.AF_INET})
            records["AAAA"] = list({i[4][0] for i in infos if i[0] == socket.AF_INET6})
        except Exception:
            pass
    return records


def _resolve_ip(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return ""


def build_recon_plan(requested: Optional[list[str]] = None) -> dict:
    modules = {
        "headers": True,
        "dns": True,
        "ssl": True,
        "whois": True,
        "subdomains": True,
        "mail": True,
        "tech": True,
        "ports": True,
        "extra": True,
    }
    if not requested:
        return modules

    selected = set()
    for item in requested:
        selected.add(item.lower())

    full_recon = "full-recon" in selected or "full_recon" in selected or "all" in selected
    fast_scan = "fast" in selected or "fast-scan" in selected or "fast_scan" in selected
    for key in modules:
        modules[key] = full_recon or key in selected

    if fast_scan:
        modules.update({
            "headers": True,
            "dns": False,
            "ssl": False,
            "whois": False,
            "subdomains": False,
            "mail": False,
            "tech": True,
            "ports": False,
            "extra": False,
        })

    if "intel" in selected:
        modules["extra"] = True
    if full_recon:
        modules["headers"] = True
        modules["dns"] = True
        modules["ssl"] = True
        modules["whois"] = True
        modules["subdomains"] = True
        modules["mail"] = True
        modules["tech"] = True
        modules["ports"] = True
        modules["extra"] = True
    return modules


def _get_whois(hostname: str) -> dict:
    if not whois:
        return {"error": "python-whois is not installed"}
    try:
        data = whois.whois(hostname)
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if v}
        return {"raw": str(data)}
    except Exception as exc:
        return {"error": str(exc)}


def _get_mail_records(hostname: str) -> list[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(hostname, "MX", lifetime=3)
        return sorted(str(r.exchange).rstrip(".") for r in answers)
    except Exception:
        return []


def _guess_subdomains(hostname: str) -> list[str]:
    common = [
        "www", "mail", "login", "admin", "portal", "api", "dev", "test", "staging",
        "blog", "cpanel", "webmail", "mx", "ns1", "ns2", "ftp", "smtp", "imap",
        "autodiscover", "cloud", "vpn", "remote", "cdn", "assets", "files",
    ]
    found = []
    for prefix in common:
        candidate = f"{prefix}.{hostname}"
        try:
            socket.gethostbyname(candidate)
            found.append(candidate)
        except Exception:
            continue
    return sorted(found)


def _extract_html_intel(body: str) -> dict:
    intel = {}
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(body, "html.parser")
        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        if title:
            intel["title"] = title
        headings = [h.get_text(" ", strip=True) for h in soup.find_all(["h1", "h2", "h3"]) if h.get_text(" ", strip=True)]
        if headings:
            intel["headings"] = headings[:10]
        links = [link.get("href") for link in soup.find_all("a", href=True) if link.get("href")][:20]
        if links:
            intel["links"] = links
        canonical = soup.find("link", rel=lambda value: value and "canonical" in value.lower())
        if canonical and canonical.get("href"):
            intel["canonical"] = canonical.get("href")
        meta_description = soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
        if meta_description and meta_description.get("content"):
            intel["meta_description"] = meta_description.get("content")
    except Exception:
        pass
    return intel


def _fetch_public_intel(hostname: str, body: str = "") -> dict:
    intel = {}
    try:
        with httpx.Client(timeout=5, verify=False) as client:
            for url in [
                f"https://dns.google/resolve?name={hostname}&type=A",
                f"https://dns.google/resolve?name={hostname}&type=TXT",
            ]:
                try:
                    response = client.get(url)
                    if response.status_code == 200:
                        payload = response.json()
                        if isinstance(payload, dict):
                            intel.setdefault("public_dns", []).extend(payload.get("Answer", []))
                except Exception:
                    pass

            try:
                crt = client.get(f"https://crt.sh/?q=%25.{hostname}&output=json", timeout=8)
                if crt.status_code == 200:
                    data = crt.json()
                    if isinstance(data, list):
                        names = []
                        for item in data:
                            if isinstance(item, dict):
                                value = item.get("name_value")
                                if isinstance(value, str):
                                    names.extend([x.strip() for x in value.splitlines() if x.strip()])
                        intel["crt_sh"] = sorted(set(names))[:20]
            except Exception:
                pass
    except Exception:
        pass

    if body:
        intel["page_intel"] = _extract_html_intel(body)
    return intel


def _scan_common_ports(hostname: str, timeout: int = 1) -> list[dict]:
    open_ports = []
    ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 5432, 6379, 8080, 8443, 8888, 9000, 5900, 2375, 2376]
    for port in ports:
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                open_ports.append({"port": port, "service": "unknown"})
        except Exception:
            continue
    return open_ports


def build_service_summary(result: ScanResult) -> list[dict]:
    summary = []
    for tech in result.technologies:
        summary.append({
            "name": tech.name,
            "category": tech.category,
            "version": tech.version or "unknown",
            "confidence": tech.confidence,
            "evidence": tech.evidence,
        })
    return summary


def build_recon_summary(result: ScanResult) -> list[dict]:
    services = []
    for tech in result.technologies:
        hints = []
        if tech.name in {
            "Jenkins", "Nifi", "Tomcat", "Grafana", "Prometheus", "Kibana", "Jira",
            "Confluence", "GitLab", "Rancher", "Portainer", "OpenSSH", "Redis",
            "PostgreSQL", "MongoDB", "Elasticsearch", "RabbitMQ", "phpMyAdmin",
            "Webmin", "Adminer", "Apache Guacamole", "Zabbix", "Cacti", "Rundeck",
            "Plesk", "cPanel", "DirectAdmin"
        }:
            hints.append("Common exposed management or data service")
        if tech.name in {"Apache", "Nginx", "IIS", "Tomcat", "OpenSSH", "Jenkins", "GitLab"}:
            hints.append("Likely entrypoint or foothold service")
        if tech.version:
            hints.append("Version detected")
        services.append({
            "name": tech.name,
            "category": tech.category,
            "version": tech.version or "unknown",
            "confidence": tech.confidence,
            "evidence": tech.evidence,
            "service_hints": hints,
        })
    return services


def _enrich_with_external_services(hostname: str, technology_names: list[str], api_key: Optional[str] = None) -> dict:
    if not api_key:
        return {}

    try:
        endpoint = os.getenv("INOUE_ENRICHMENT_URL", "https://api.technitium.com")
        headers = {"Authorization": f"Bearer {api_key}"}
        with httpx.Client(timeout=5, verify=False) as client:
            response = client.get(f"{endpoint}/services/{hostname}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                return data if isinstance(data, dict) else {}
    except Exception:
        return {}
    return {}


def run_fingerprints(headers: dict, cookies: dict, body: str, url: str = "") -> list[Detection]:
    scripts = _extract_scripts(body)
    meta = _extract_meta(body)
    detections = []
    path = ""
    if url:
        try:
            parsed = urlparse(url)
            path = parsed.path or ""
        except Exception:
            path = ""

    for tech_name, sig in SIGNATURES.items():
        category = sig.get("category", "Other")
        matched = False
        version = None
        evidence = ""
        confidence = "low"
        candidates = []

        h_match, h_ver, h_ev = _match_headers(sig, headers)
        if h_match:
            candidates.append((4, h_ver, h_ev))

        m_match, m_ver, m_ev = _match_meta(sig, meta)
        if m_match:
            candidates.append((3, m_ver, m_ev))

        s_match, s_ver, s_ev = _match_scripts(sig, scripts)
        if s_match:
            candidates.append((2, s_ver, s_ev))

        b_match, b_ver, b_ev = _match_html(sig, body)
        if b_match:
            candidates.append((1, b_ver, b_ev))

        c_match, c_ev = _match_cookies(sig, cookies)
        if c_match:
            candidates.append((0, None, c_ev))

        if path:
            for pattern in sig.get("paths", []):
                if re.search(pattern, path, re.IGNORECASE):
                    candidates.append((0, None, f"Path: {path}"))
                    break

        if candidates:
            matched = True
            best_rank, best_version, best_evidence = max(candidates, key=lambda item: item[0])
            version = best_version
            evidence = best_evidence
            for rank, candidate_version, candidate_evidence in sorted(candidates, key=lambda item: item[0], reverse=True):
                if candidate_version:
                    best_rank = rank
                    version = candidate_version
                    evidence = candidate_evidence
                    break

            if best_rank >= 4:
                confidence = "high"
            elif best_rank >= 3:
                confidence = "high"
            elif best_rank >= 2:
                confidence = "medium"
            elif best_rank >= 1:
                confidence = "medium"
            else:
                confidence = "low"

        if matched:
            detections.append(Detection(
                name=tech_name,
                category=category,
                version=version,
                confidence=confidence,
                evidence=evidence,
            ))

    return detections


def scan(
    url: str,
    timeout: int = 10,
    follow_redirects: bool = True,
    dns: bool = True,
    ssl_check: bool = True,
    api_key: Optional[str] = None,
    modules: Optional[list[str]] = None,
) -> ScanResult:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    headers_to_send = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }

    result = ScanResult(url=url, final_url=url, status_code=0, response_time_ms=0)

    try:
        t0 = time.time()
        with httpx.Client(timeout=timeout, follow_redirects=follow_redirects, verify=False) as client:
            resp = client.get(url, headers=headers_to_send)
        result.response_time_ms = round((time.time() - t0) * 1000, 1)
        result.final_url = str(resp.url)
        result.status_code = resp.status_code

        resp_headers = dict(resp.headers)
        result.headers = resp_headers
        result.server = resp_headers.get("server", resp_headers.get("Server", ""))

        cookies = {k: v for k, v in resp.cookies.items()}
        body = resp.text

        result.technologies = run_fingerprints(resp_headers, cookies, body, url=url)

    except httpx.ConnectError:
        # Try HTTP fallback
        try:
            http_url = url.replace("https://", "http://")
            t0 = time.time()
            with httpx.Client(timeout=timeout, follow_redirects=follow_redirects) as client:
                resp = client.get(http_url, headers=headers_to_send)
            result.response_time_ms = round((time.time() - t0) * 1000, 1)
            result.final_url = str(resp.url)
            result.status_code = resp.status_code
            resp_headers = dict(resp.headers)
            result.headers = resp_headers
            result.server = resp_headers.get("server", "")
            cookies = {k: v for k, v in resp.cookies.items()}
            body = resp.text
            result.technologies = run_fingerprints(resp_headers, cookies, body, url=http_url)
        except Exception as e:
            result.error = str(e)
            return result
    except Exception as e:
        result.error = str(e)
        return result

    plan = build_recon_plan(modules)
    result.ip = _resolve_ip(hostname)
    result.enriched = {
        "services": build_service_summary(result),
        "recon": build_recon_summary(result),
        "service_hints": [
            item for item in build_recon_summary(result) if item.get("service_hints")
        ],
    }

    if plan.get("headers"):
        result.enriched["headers"] = dict(result.headers)

    if plan.get("dns") and dns:
        result.dns_records = _get_dns(hostname)

    if plan.get("ssl") and ((ssl_check and parsed.scheme == "https") or result.final_url.startswith("https")):
        final_parsed = urlparse(result.final_url)
        result.ssl_info = _get_ssl_info(final_parsed.hostname or hostname)

    if plan.get("whois") and hostname:
        result.whois_info = _get_whois(hostname)

    if plan.get("mail") and hostname:
        result.mail_records = _get_mail_records(hostname)

    if plan.get("subdomains") and hostname:
        result.subdomains = _guess_subdomains(hostname)

    if plan.get("ports") and hostname:
        result.open_ports = _scan_common_ports(hostname, timeout=max(1, min(3, timeout // 4)))

    if plan.get("extra") and hostname:
        result.extra_intel = _fetch_public_intel(hostname, body)

    if hostname:
        external = _enrich_with_external_services(hostname, [tech.name for tech in result.technologies], api_key)
        if external:
            result.enriched.update(external)

    return result
