# Inoue commands and usage

This file documents the main commands and flags supported by Inoue.

## Run the scanner

```bash
python inoue.py <target>
```

Examples:

```bash
python inoue.py example.com
python inoue.py https://target.example
python inoue.py 10.10.10.10
```

## Verbose output

```bash
python inoue.py -v <target>
```

Shows SSL information, DNS records, security headers, and response headers.

## Show detection evidence

```bash
python inoue.py -e <target>
```

Shows the evidence string that triggered each fingerprint match.

## Full recon-style scan

```bash
python inoue.py -v -e <target>
```

## Disable DNS lookup

```bash
python inoue.py --no-dns <target>
```

## Disable SSL inspection

```bash
python inoue.py --no-ssl <target>
```

## Set request timeout

```bash
python inoue.py -t 5 <target>
```

## Scan multiple targets

```bash
python inoue.py site1.com site2.com site3.com
```

## JSON output

```bash
python inoue.py --json <target>
```

Save JSON to a file:

```bash
python inoue.py --json -o results.json <target>
```

## Worker count

```bash
python inoue.py -w 10 <target>
```

## Hide banner

```bash
python inoue.py --no-banner <target>
```

## Optional enrichment API key

```bash
python inoue.py --api-key <key> <target>
```

## Update the local clone from the repository

```bash
python inoue.py update
```

## Fast HTB/CTF style scan

```bash
python inoue.py --no-dns -t 5 10.10.11.55
```

## Common combinations

```bash
# Full recon with evidence and JSON export
python inoue.py -v -e --json -o results.json https://target.example

# Fast scan for a lab target
python inoue.py --no-dns -t 5 10.10.11.55

# Scan multiple hosts in parallel
python inoue.py -w 10 site1.com site2.com site3.com
```
