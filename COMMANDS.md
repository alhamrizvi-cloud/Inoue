# Inoue commands and usage

This file documents the main commands and flags supported by Inoue.

## Run the scanner

```bash
python inoue.py <target>
```

The CLI now shows live scan progress while each target is scanned and reports discoveries as they are identified.

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

Fetch and apply the latest fingerprints, scanner improvements, and catalog updates:

```bash
python inoue.py update
```

This command:
1. Runs `git fetch --all --prune` to pull all remote changes
2. Runs `git pull --ff-only` to merge fast-forward updates only
3. Displays a summary of recent commits and modified files
4. Updates cached signatures for immediate use

**What gets updated:**
- New fingerprints in `fingerprints/signatures.py` (700+ core signatures)
- Extended catalog entries in `fingerprints/extended_catalog.py`
- Scanner improvements in `core/scanner.py`
- CLI and command enhancements in `inoue.py`
- Documentation updates in `GUIDE.md`, `CONTRIBUTING.md`, `COMMANDS.md`

After running `update`, all future scans will use the new signatures and detection logic without restarting the tool.

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
