#!/usr/bin/env python3
"""
Inoue - tech stack fingerprinting CLI
Author: Alham Rizvi
Repository: https://github.com/alhamrizvi-cloud/Inoue
"""

import json
import concurrent.futures
from collections import defaultdict
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.scanner import build_service_summary, scan, ScanResult

app = typer.Typer(help="Inoue — tech stack fingerprinting CLI", add_completion=False)
console = Console()

CATEGORY_COLORS = {
    "Web Server":       "cyan",
    "Language":         "green",
    "Framework":        "bright_green",
    "CMS":              "yellow",
    "CMS / E-Commerce": "yellow",
    "Site Builder":     "yellow",
    "JS Framework":     "bright_blue",
    "JS Library":       "blue",
    "CSS Framework":    "magenta",
    "CDN / Security":   "red",
    "CDN":              "bright_red",
    "WAF":              "bright_red",
    "Cache":            "orange3",
    "Analytics":        "purple",
    "Security Header":  "green",
    "Database":         "bright_cyan",
    "Search Engine":    "bright_cyan",
    "Hosting":          "bright_blue",
    "Payment":          "bright_yellow",
    "UI Library":       "bright_magenta",
    "Security":         "bright_green",
    "CRM / Chat":       "bright_white",
    "Other":            "white",
}


def print_banner():
    console.print(r"""[bold white]    _                      
   (_)___  ____  __  _____ 
  / / __ \/ __ \/ / / / _ \
 / / / / / /_/ / /_/ /  __/
/_/_/ /_/\____/\__,_/\___/ """ + "[/bold white][dim]v1.0.0  tech stack fingerprinting[/dim]\n")


def render_result(result: ScanResult, verbose: bool = False, evidence: bool = False):
    status_color = "green" if result.status_code < 300 else "yellow" if result.status_code < 400 else "red"

    console.print(f"  [dim]url[/dim]     {result.final_url}")
    console.print(f"  [dim]ip[/dim]      [cyan]{result.ip or 'unknown'}[/cyan]")
    console.print(f"  [dim]status[/dim]  [{status_color}]{result.status_code}[/{status_color}]  [dim]{result.response_time_ms}ms[/dim]")
    if result.server:
        console.print(f"  [dim]server[/dim]  {result.server}")
    console.print()

    service_summary = build_service_summary(result)
    if service_summary:
        by_category = defaultdict(list)
        for t in result.technologies:
            by_category[t.category].append(t)

        table = Table(box=None, show_header=True, header_style="dim", padding=(0, 2, 0, 0), show_edge=False)
        table.add_column("category", width=20)
        table.add_column("technology", width=22)
        table.add_column("version", width=14)
        table.add_column("confidence", width=12)
        if evidence:
            table.add_column("evidence", width=55)

        for category in sorted(by_category.keys()):
            techs = by_category[category]
            color = CATEGORY_COLORS.get(category, "white")
            for i, t in enumerate(techs):
                cat_label = f"[dim]{category}[/dim]" if i == 0 else ""
                ver_label = f"[dim]{t.version or 'unknown'}[/dim]"
                conf_label = f"[dim]{t.confidence}[/dim]"
                row = [cat_label, f"[{color}]{t.name}[/{color}]", ver_label, conf_label]
                if evidence:
                    row.append(f"[dim]{t.evidence[:70]}[/dim]" if t.evidence else "")
                table.add_row(*row)

        console.print(table)
        console.print(f"\n  [dim]{len(service_summary)} services detected[/dim]\n")
    else:
        console.print("  [dim]no technologies detected[/dim]\n")

    if verbose and result.enriched:
        console.print("  [dim]── recon ─────────────────────────────[/dim]")
        services = result.enriched.get("services", [])
        service_hints = result.enriched.get("service_hints", [])
        if services:
            console.print("  [cyan]services[/cyan]")
            for item in services[:10]:
                console.print(f"    - {item['name']} {item['version']} [{item['category']}]")
        if service_hints:
            console.print("  [yellow]service hints[/yellow]")
            for item in service_hints[:10]:
                console.print(f"    - {item['name']} -> {', '.join(item['service_hints'])}")
        if not services and not service_hints:
            console.print("  [dim]no enrichment data[/dim]")
        console.print()

    if result.ssl_info and not result.ssl_info.get("error") and verbose:
        ssl = result.ssl_info
        subject = ssl.get("subject", {})
        issuer = ssl.get("issuer", {})
        console.print("  [dim]── ssl ──────────────────────────────[/dim]")
        console.print(f"  [dim]protocol[/dim]  {ssl.get('protocol', '?')}  [dim]cipher[/dim] {ssl.get('cipher', '?')}")
        console.print(f"  [dim]issued to[/dim] {subject.get('commonName', '?')}")
        console.print(f"  [dim]issued by[/dim] {issuer.get('organizationName', '?')}")
        console.print(f"  [dim]valid[/dim]     {ssl.get('notBefore', '?')}  →  {ssl.get('notAfter', '?')}")
        if ssl.get("san"):
            sans = ssl["san"][:6]
            console.print(f"  [dim]san[/dim]       {', '.join(sans)}" + (" ..." if len(ssl["san"]) > 6 else ""))
        console.print()

    if result.dns_records and verbose:
        console.print("  [dim]── dns ───────────────────────────────[/dim]")
        for rtype, values in result.dns_records.items():
            for v in values[:5]:
                console.print(f"  [cyan]{rtype:<8}[/cyan] {v}")
        console.print()

    if verbose:
        sec_headers = [
            "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
            "X-XSS-Protection", "X-Content-Type-Options", "Referrer-Policy",
            "Permissions-Policy", "Cross-Origin-Opener-Policy",
        ]
        console.print("  [dim]── security headers ────────────────────[/dim]")
        for h in sec_headers:
            v = result.headers.get(h, result.headers.get(h.lower(), ""))
            if v:
                console.print(f"  [green]+[/green] [dim]{h}[/dim]")
            else:
                console.print(f"  [red]-[/red] [dim]{h}[/dim]")
        console.print()

    if verbose:
        console.print("  [dim]── response headers ────────────────────[/dim]")
        for k, v in result.headers.items():
            console.print(f"  [dim]{k}:[/dim] {v[:100]}")
        console.print()


@app.command()
def main(
    targets: list[str] = typer.Argument(..., help="Target URLs or IPs (e.g. example.com, 10.10.11.2)"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show SSL, DNS, security headers, all headers"),
    evidence: bool = typer.Option(False, "-e", "--evidence", help="Show detection evidence"),
    no_dns: bool = typer.Option(False, "--no-dns", help="Skip DNS enumeration"),
    no_ssl: bool = typer.Option(False, "--no-ssl", help="Skip SSL inspection"),
    timeout: int = typer.Option(10, "-t", "--timeout", help="Request timeout in seconds"),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Save JSON to file"),
    workers: int = typer.Option(5, "-w", "--workers", help="Concurrent workers"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress banner"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Optional API key for enrichment services"),
):
    """
    Inoue — tech stack fingerprinting CLI

    Detect frameworks, CMS, servers, CDN, WAF, analytics and more.

    Examples:\n
      inoue example.com\n
      inoue -v -e https://target.htb\n
      inoue --json -o out.json site1.com site2.com\n
      inoue --no-dns -t 5 10.10.11.55\n
    """
    if not no_banner and not json_out:
        print_banner()

    results = []

    def do_scan(target):
        return scan(target, timeout=timeout, dns=not no_dns, ssl_check=not no_ssl, api_key=api_key)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
        disable=json_out,
    ) as progress:
        tasks_map = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(do_scan, t): t for t in targets}
            for t in targets:
                tasks_map[t] = progress.add_task(f"  scanning {t}", total=None)

            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                progress.remove_task(tasks_map[target])
                try:
                    results.append(future.result())
                except Exception as e:
                    console.print(f"  [red]error[/red] {target}: {e}")

    if json_out or output:
        out = []
        for r in results:
            out.append({
                "url": r.url,
                "final_url": r.final_url,
                "ip": r.ip,
                "status_code": r.status_code,
                "response_time_ms": r.response_time_ms,
                "server": r.server,
                "technologies": [
                    {"name": t.name, "category": t.category, "version": t.version, "evidence": t.evidence}
                    for t in r.technologies
                ],
                "dns": r.dns_records,
                "ssl": r.ssl_info,
                "recon": r.enriched.get("recon", []) if r.enriched else [],
                "service_hints": r.enriched.get("service_hints", []) if r.enriched else [],
                "error": r.error,
            })
        json_str = json.dumps(out, indent=2)
        if output:
            with open(output, "w") as f:
                f.write(json_str)
            console.print(f"  [green]saved[/green] {output}")
        if json_out:
            print(json_str)
        return

    for result in results:
        if len(results) > 1:
            console.print(f"[dim]  ── {result.url} {'─' * max(0, 50 - len(result.url))}[/dim]")
        if result.error:
            console.print(f"  [red]error[/red] {result.error}\n")
            continue
        render_result(result, verbose=verbose, evidence=evidence)


if __name__ == "__main__":
    app()
