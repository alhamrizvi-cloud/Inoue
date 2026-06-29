"""
Core scanning engine - fetches target and runs all detections concurrently.
"""

import os
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

from fingerprints.signatures import SIGNATURES

VULNERABILITY_DB = {
    "Apache": [
        {"cve": "CVE-2021-41773", "summary": "Path traversal in Apache HTTP Server mod_proxy", "fixed_in": "2.4.50"},
        {"cve": "CVE-2021-44224", "summary": "HTTP request smuggling via mod_proxy", "fixed_in": "2.4.51"},
    ],
    "Nginx": [
        {"cve": "CVE-2023-44487", "summary": "HTTP/2 rapid reset vulnerability", "fixed_in": "1.25.1"},
        {"cve": "CVE-2021-23017", "summary": "Off-by-one in ngx_http_range_module", "fixed_in": "1.20.1"},
    ],
    "OpenSSH": [
        {"cve": "CVE-2024-6387", "summary": "Signal handler race condition in OpenSSH", "fixed_in": "9.6p1"},
    ],
    "PHP": [
        {"cve": "CVE-2024-5458", "summary": "PHP CGI argument injection issue", "fixed_in": "8.2.17"},
    ],
    "WordPress": [
        {"cve": "CVE-2024-28000", "summary": "WordPress core privilege escalation risk", "fixed_in": "6.4.3"},
    ],
    "Drupal": [
        {"cve": "CVE-2023-6063", "summary": "Drupal core arbitrary file upload issue", "fixed_in": "10.2.1"},
    ],
    "Joomla": [
        {"cve": "CVE-2023-23752", "summary": "Joomla access bypass vulnerability", "fixed_in": "4.4.6"},
    ],
    "Tomcat": [
        {"cve": "CVE-2024-50379", "summary": "Apache Tomcat request smuggling risk", "fixed_in": "9.0.95"},
    ],
    "Elasticsearch": [
        {"cve": "CVE-2024-23454", "summary": "Elasticsearch remote code execution risk", "fixed_in": "8.11.3"},
    ],
    "Redis": [
        {"cve": "CVE-2023-41056", "summary": "Redis Lua sandbox escape risk", "fixed_in": "7.2.4"},
    ],
    "PostgreSQL": [
        {"cve": "CVE-2024-0985", "summary": "PostgreSQL privilege escalation issue", "fixed_in": "16.4"},
    ],
    "MySQL": [
        {"cve": "CVE-2023-22102", "summary": "MySQL privilege escalation vulnerability", "fixed_in": "8.0.34"},
    ],
    "MongoDB": [
        {"cve": "CVE-2024-1014", "summary": "MongoDB authentication bypass risk", "fixed_in": "7.0.12"},
    ],
    "RabbitMQ": [
        {"cve": "CVE-2023-46118", "summary": "RabbitMQ credential exposure risk", "fixed_in": "3.12.0"},
    ],
    "Prometheus": [
        {"cve": "CVE-2023-45288", "summary": "Prometheus remote query exposure risk", "fixed_in": "2.46.0"},
    ],
    "Grafana": [
        {"cve": "CVE-2023-2801", "summary": "Grafana privilege escalation risk", "fixed_in": "9.3.0"},
    ],
    "GitLab": [
        {"cve": "CVE-2023-7028", "summary": "GitLab password reset vulnerability", "fixed_in": "16.7.7"},
    ],
    "Jira": [
        {"cve": "CVE-2023-22515", "summary": "Atlassian Jira privilege escalation issue", "fixed_in": "8.20.29"},
    ],
    "Confluence": [
        {"cve": "CVE-2023-22518", "summary": "Atlassian Confluence template injection issue", "fixed_in": "8.5.2"},
    ],
    "OpenSSL": [
        {"cve": "CVE-2023-2650", "summary": "OpenSSL policy processing issue", "fixed_in": "3.0.12"},
    ],
    "Node.js": [
        {"cve": "CVE-2024-21890", "summary": "Node.js HTTP request smuggling risk", "fixed_in": "20.11.1"},
    ],
}


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
    error: Optional[str] = None
    enriched: dict = field(default_factory=dict)


def _extract_version(pattern: str, text: str) -> Optional[str]:
    """Try to pull a version string from a regex match group 1."""
    try:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            try:
                return m.group(1) if m.lastindex else None
            except IndexError:
                return None
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
            return True, None, f"HTML: …{snippet[:60]}…"
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


def _normalize_version(version: Optional[str]) -> tuple[int, ...]:
    if not version:
        return (0,)
    digits = re.findall(r"\d+", str(version))
    return tuple(int(part) for part in digits) if digits else (0,)


def _compare_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    max_len = max(len(left), len(right))
    left_padded = left + (0,) * (max_len - len(left))
    right_padded = right + (0,) * (max_len - len(right))
    if left_padded < right_padded:
        return -1
    if left_padded > right_padded:
        return 1
    return 0


def find_vulnerabilities(detections: list[Detection]) -> list[dict]:
    findings = []
    for detection in detections:
        service = detection.name
        version = detection.version
        if not version:
            continue
        for entry in VULNERABILITY_DB.get(service, []):
            fixed_in = entry.get("fixed_in")
            if fixed_in and _compare_versions(_normalize_version(version), _normalize_version(fixed_in)) < 0:
                findings.append({
                    "service": service,
                    "version": version,
                    "cve": entry.get("cve", "unknown"),
                    "summary": entry.get("summary", "Known vulnerable version"),
                    "fixed_in": fixed_in,
                })
    return findings


def build_recon_summary(result: ScanResult) -> list[dict]:
    services = []
    for tech in result.technologies:
        services.append({
            "name": tech.name,
            "category": tech.category,
            "version": tech.version or "unknown",
            "confidence": tech.confidence,
            "evidence": tech.evidence,
            "vulnerabilities": [
                v for v in find_vulnerabilities([tech])
            ],
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


def run_fingerprints(headers: dict, cookies: dict, body: str) -> list[Detection]:
    scripts = _extract_scripts(body)
    meta = _extract_meta(body)
    detections = []

    for tech_name, sig in SIGNATURES.items():
        category = sig.get("category", "Other")
        matched, version, evidence = False, None, ""

        h_match, h_ver, h_ev = _match_headers(sig, headers)
        if h_match:
            matched, version, evidence = True, h_ver, h_ev

        if not matched:
            c_match, c_ev = _match_cookies(sig, cookies)
            if c_match:
                matched, evidence = True, c_ev

        if not matched:
            b_match, b_ver, b_ev = _match_html(sig, body)
            if b_match:
                matched, version, evidence = True, b_ver, b_ev

        if not matched:
            s_match, s_ver, s_ev = _match_scripts(sig, scripts)
            if s_match:
                matched, version, evidence = True, s_ver, s_ev

        if not matched:
            m_match, m_ver, m_ev = _match_meta(sig, meta)
            if m_match:
                matched, version, evidence = True, m_ver, m_ev

        if matched:
            confidence = "high"
            if not h_match and not c_match and not b_match and not s_match and not m_match:
                confidence = "low"
            elif not h_match and not c_match:
                confidence = "medium"
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

        result.technologies = run_fingerprints(resp_headers, cookies, body)

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
            result.technologies = run_fingerprints(resp_headers, cookies, body)
        except Exception as e:
            result.error = str(e)
            return result
    except Exception as e:
        result.error = str(e)
        return result

    result.ip = _resolve_ip(hostname)
    result.enriched = {
        "services": build_service_summary(result),
        "recon": build_recon_summary(result),
        "vulnerabilities": find_vulnerabilities(result.technologies),
    }

    if dns:
        result.dns_records = _get_dns(hostname)

    if ssl_check and parsed.scheme == "https" or (result.final_url.startswith("https")):
        final_parsed = urlparse(result.final_url)
        result.ssl_info = _get_ssl_info(final_parsed.hostname or hostname)

    if hostname:
        external = _enrich_with_external_services(hostname, [tech.name for tech in result.technologies], api_key)
        if external:
            result.enriched.update(external)

    return result
